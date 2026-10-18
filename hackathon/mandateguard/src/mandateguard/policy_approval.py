"""Policy packs are approved by signature, not by a name in the file.

An approver is registered by the operator with a public key. They sign each pack's file hash offline
(scripts/sign_policy.py) and the signatures ship next to the packs in `approvals.json`. When MandateGuard loads
policy it checks every signature against the registered key, and the policy record says which packs are proven
to be approved. With MG_REQUIRE_POLICY_APPROVAL=1, a pack without a valid approval blocks every purchase.

Signature: ECDSA P-256 over sha256(RFC 8785 JSON of the statement), DER, base64url, the same scheme as receipts.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from jwcrypto.jwk import JWK

APPROVALS_FILE = "approvals.json"


def statement(pack: str, version: str, file_sha256: str, approved_by: str, approved_at: str) -> dict[str, Any]:
    return {"type": "policy.approval", "pack": pack, "version": version, "file_sha256": file_sha256,
            "approved_by": approved_by, "approved_at": approved_at}


def _digest(obj: dict[str, Any]) -> bytes:
    return hashlib.sha256(rfc8785.dumps(obj)).digest()


def sign(obj: dict[str, Any], private_jwk: JWK) -> str:
    key = private_jwk.get_op_key("sign")
    sig = key.sign(_digest(obj), ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    return base64.urlsafe_b64encode(sig).rstrip(b"=").decode()


def verify(obj: dict[str, Any], signature: str, public_jwk: dict[str, Any]) -> bool:
    try:
        key = JWK.from_json(json.dumps(public_jwk)).get_op_key("verify")
        key.verify(base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)), _digest(obj), ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return True
    except (InvalidSignature, ValueError, TypeError, KeyError):
        return False


class ApprovalFile:
    """approvals.json in the packs directory, re-read when it changes."""

    def __init__(self, packs_dir: str):
        self.path = os.path.join(packs_dir, APPROVALS_FILE)
        self._mtime = -1.0
        self.entries: list[dict[str, Any]] = []

    def load(self) -> list[dict[str, Any]]:
        try:
            m = os.path.getmtime(self.path)
        except OSError:
            self._mtime, self.entries = -1.0, []
            return self.entries
        if m != self._mtime:
            with open(self.path, encoding="utf-8") as fh:
                self.entries = list((json.load(fh) or {}).get("approvals", []))
            self._mtime = m
        return self.entries


def check(packs: list[Any], approvals: list[dict[str, Any]], approvers: Any) -> list[dict[str, Any]]:
    """One line per loaded pack: who approved it, and whether the signature proves it."""
    out = []
    for p in packs:
        a = next((x for x in approvals if x.get("pack") == p.name and x.get("version") == p.version), None)
        row: dict[str, Any] = {"pack": p.name, "version": p.version, "file_sha256": p.file_sha256, "declared_approver": p.approved_by,
                               "verified": False, "problem": ""}
        if a is None:
            row["problem"] = "no signed approval"
        else:
            st = statement(p.name, p.version, str(a.get("file_sha256", "")), str(a.get("approved_by", "")), str(a.get("approved_at", "")))
            entry = approvers.get(st["approved_by"]) if approvers is not None else None
            row.update(approved_by=st["approved_by"], approved_at=st["approved_at"], statement=st, signature=a.get("signature", ""))
            if st["file_sha256"] != p.file_sha256:
                row["problem"] = "the approval is for a different version of this file"
            elif entry is None or entry.status != "active":
                row["problem"] = f"approver {st['approved_by']} is not registered"
            elif not verify(st, str(a.get("signature", "")), entry.public_jwk):
                row["problem"] = "the approval signature does not verify"
            else:
                row.update(verified=True, approver_thumbprint=entry.thumbprint)
        out.append(row)
    return out


def state_digest(rows: list[dict[str, Any]]) -> str:
    return hashlib.sha256(rfc8785.dumps([[r["pack"], r["version"], r["verified"], r.get("approved_by", "")] for r in rows])).hexdigest()[:16]
