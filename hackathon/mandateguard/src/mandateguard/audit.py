"""Stage 3: signed, hash-chained decision records.

record_hash = sha256(JCS(record without hash/signature))   (RFC 8785 canonical JSON)
prev_hash   = hash of the previous record (genesis = 64 zeros)
signature   = ECDSA P-256 over record_hash (local key for dev, Cloud KMS in prod)

Backends: InMemoryChain (tests/dev) and FirestoreChain (transactional, create()-only so two
writers can never both claim the same seq).
"""

from __future__ import annotations

import base64
import hashlib
import threading
import time
from typing import Any, Protocol

import rfc8785
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

GENESIS = "0" * 64


def canonical(record: dict[str, Any]) -> bytes:
    body = {k: v for k, v in record.items() if k not in ("hash", "signature", "signer_kid")}
    return rfc8785.dumps(body)


def record_hash(record: dict[str, Any]) -> str:
    return hashlib.sha256(canonical(record)).hexdigest()


class Signer(Protocol):
    kid: str

    def sign(self, digest_hex: str) -> str: ...
    def verify(self, digest_hex: str, signature_b64: str) -> bool: ...
    def public_pem(self) -> str: ...


class LocalEcSigner:
    """P-256 signer for local runs. Pass a PEM private key or let it generate one."""

    def __init__(self, pem: str | None = None):
        if pem:
            self._key = serialization.load_pem_private_key(pem.encode(), password=None)
        else:
            self._key = ec.generate_private_key(ec.SECP256R1())
        pub = self._key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.kid = "local-" + hashlib.sha256(pub).hexdigest()[:16]

    def sign(self, digest_hex: str) -> str:
        sig = self._key.sign(bytes.fromhex(digest_hex), ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return base64.urlsafe_b64encode(sig).rstrip(b"=").decode()

    def verify(self, digest_hex: str, signature_b64: str) -> bool:
        try:
            sig = base64.urlsafe_b64decode(signature_b64 + "=" * (-len(signature_b64) % 4))
            self._key.public_key().verify(sig, bytes.fromhex(digest_hex), ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            return True
        except Exception:  # noqa: BLE001
            return False

    def public_pem(self) -> str:
        return self._key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


class KmsSigner:
    """Cloud KMS EC_SIGN_P256_SHA256 key version (ASYMMETRIC_SIGN)."""

    def __init__(self, key_version_name: str):
        from google.cloud import kms

        self.client = kms.KeyManagementServiceClient()
        self.name = key_version_name
        self.kid = "kms:" + key_version_name.rsplit("/cryptoKeys/", 1)[-1]
        self._pem = self.client.get_public_key(request={"name": self.name}).pem

    def sign(self, digest_hex: str) -> str:
        resp = self.client.asymmetric_sign(request={"name": self.name, "digest": {"sha256": bytes.fromhex(digest_hex)}})
        return base64.urlsafe_b64encode(resp.signature).rstrip(b"=").decode()

    def verify(self, digest_hex: str, signature_b64: str) -> bool:
        try:
            pub = serialization.load_pem_public_key(self._pem.encode())
            sig = base64.urlsafe_b64decode(signature_b64 + "=" * (-len(signature_b64) % 4))
            pub.verify(sig, bytes.fromhex(digest_hex), ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            return True
        except Exception:  # noqa: BLE001
            return False

    def public_pem(self) -> str:
        return self._pem


class InMemoryChain:
    name = "memory"

    def __init__(self):
        self.records: list[dict[str, Any]] = []
        self._lock = threading.Lock()   # records can be appended from worker threads, e.g. after a webhook delivery

    def append(self, payload: dict[str, Any], signer: Signer | None) -> dict[str, Any]:
        with self._lock:
            prev = self.records[-1]["hash"] if self.records else GENESIS
            rec = {"seq": len(self.records), "prev_hash": prev, "ts_ms": int(time.time() * 1000), **payload}
            rec["hash"] = record_hash(rec)
            if signer is not None:
                rec["signature"] = signer.sign(rec["hash"])
                rec["signer_kid"] = signer.kid
            self.records.append(rec)
            return rec

    def all(self) -> list[dict[str, Any]]:
        return list(self.records)

    def since(self, after_seq: int, limit: int = 200) -> list[dict[str, Any]]:
        return [r for r in self.records if r["seq"] > after_seq][:limit]

    def tail(self, limit: int = 200) -> list[dict[str, Any]]:
        return self.records[-limit:]

    def get(self, decision_id: str) -> dict[str, Any] | None:
        return next((r for r in self.records if r.get("decision_id") == decision_id), None)

    def find_by(self, field: str, value: Any, type_: str | None = None) -> list[dict[str, Any]]:
        """`field` may be a dotted path into nested maps, as Firestore field paths are."""
        def get(r: dict[str, Any]) -> Any:
            for part in field.split("."):
                r = r.get(part) if isinstance(r, dict) else None
            return r
        return [r for r in self.records if get(r) == value and (type_ is None or r.get("type") == type_)]

    def head(self) -> dict[str, Any] | None:
        return self.records[-1] if self.records else None


class FirestoreChain:
    """Fork-free append: head doc read + record create() inside one transaction."""

    def __init__(self, db: Any, collection: str = "mg_audit", head_doc: str | None = None):
        self.db = db
        self.name = collection
        self.col = db.collection(collection)
        self.head_ref = db.document(head_doc or f"{collection}_meta/head")

    def append(self, payload: dict[str, Any], signer: Signer | None) -> dict[str, Any]:
        from google.cloud import firestore

        @firestore.transactional
        def _tx(tx):
            head = self.head_ref.get(transaction=tx).to_dict() or {"seq": -1, "hash": GENESIS}
            seq = head["seq"] + 1
            rec = {"seq": seq, "prev_hash": head["hash"], "ts_ms": int(time.time() * 1000), **payload}
            rec["hash"] = record_hash(rec)
            if signer is not None:
                rec["signature"] = signer.sign(rec["hash"])
                rec["signer_kid"] = signer.kid
            tx.create(self.col.document(f"{seq:012d}"), rec)
            tx.set(self.head_ref, {"seq": seq, "hash": rec["hash"]})
            return rec

        return _tx(self.db.transaction())

    def all(self) -> list[dict[str, Any]]:
        return [d.to_dict() for d in self.col.order_by("seq").stream()]

    def since(self, after_seq: int, limit: int = 200) -> list[dict[str, Any]]:
        q = self.col.where("seq", ">", after_seq).order_by("seq").limit(limit)
        return [d.to_dict() for d in q.stream()]

    def tail(self, limit: int = 200) -> list[dict[str, Any]]:
        from google.cloud import firestore

        docs = [d.to_dict() for d in self.col.order_by("seq", direction=firestore.Query.DESCENDING).limit(limit).stream()]
        return list(reversed(docs))

    def get(self, decision_id: str) -> dict[str, Any] | None:
        docs = list(self.col.where("decision_id", "==", decision_id).limit(1).stream())
        return docs[0].to_dict() if docs else None

    def find_by(self, field: str, value: Any, type_: str | None = None) -> list[dict[str, Any]]:
        docs = [d.to_dict() for d in self.col.where(field, "==", value).stream()]
        return sorted([r for r in docs if type_ is None or r.get("type") == type_], key=lambda r: r["seq"])

    def head(self) -> dict[str, Any] | None:
        h = self.head_ref.get().to_dict()
        if not h:
            return None
        return self.col.document(f"{h['seq']:012d}").get().to_dict()


def verify_chain(records: list[dict[str, Any]], signer: Signer | None = None) -> dict[str, Any]:
    prev = GENESIS
    problems: list[dict[str, Any]] = []
    for i, rec in enumerate(records):
        if rec.get("seq") != i:
            problems.append({"seq": rec.get("seq"), "problem": f"sequence gap, expected {i}"})
        if rec.get("prev_hash") != prev:
            problems.append({"seq": rec.get("seq"), "problem": "prev_hash does not match previous record"})
        if record_hash(rec) != rec.get("hash"):
            problems.append({"seq": rec.get("seq"), "problem": "record hash mismatch (content altered)"})
        if signer is not None and rec.get("signature") and not signer.verify(rec["hash"], rec["signature"]):
            problems.append({"seq": rec.get("seq"), "problem": "signature invalid"})
        prev = rec.get("hash", "")
    return {"ok": not problems, "length": len(records), "head": prev, "problems": problems}


class PemVerifier:
    """Verifies ECDSA P-256 signatures over a sha256 digest with a published public key (processors, MandateGuard)."""

    def __init__(self, pem: str, kid: str):
        self.kid = kid
        self.pem = pem
        self._pub = serialization.load_pem_public_key(pem.encode())

    def verify(self, digest_hex: str, signature_b64: str) -> bool:
        try:
            sig = base64.urlsafe_b64decode(signature_b64 + "=" * (-len(signature_b64) % 4))
            self._pub.verify(sig, bytes.fromhex(digest_hex), ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            return True
        except Exception:  # noqa: BLE001
            return False


def kms_public_key(key_version_name: str) -> str:
    from google.cloud import kms

    return kms.KeyManagementServiceClient().get_public_key(request={"name": key_version_name}).pem
