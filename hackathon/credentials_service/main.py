"""Mock credentials service + mock payment processor (one Cloud Run service, Firestore-backed).

Who honours the payment, and who reports that money moved:
  POST /v1/tokens   Only MandateGuard's service account may call it, and only with a decision record that re-hashes
                    to its `hash` and carries a valid MandateGuard KMS signature. Mints a single-use token bound to
                    {decision record hash, checkout hash, closed payment reference, amount, currency, payee}, 5 minutes.
  POST /v1/charge   The processor: checks the token against the charge, uses it exactly once (Firestore transaction),
                    and issues a receipt in AP2 Payment Receipt form, signed with the processor's own KMS key. The
                    receipt is reported to MandateGuard, which reconciles it against the decision and chains it.
  POST /v1/refund   Authenticated callers only (CS_REFUND_CALLERS). Signed refund receipt, reported the same way.
  Every authenticated call needs a Google-signed ID token minted for this service (CS_TOKEN_AUDIENCES).
  GET  /health

The shopping agent holds nothing here except the opaque token MandateGuard handed it.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import secrets
import time
import uuid
from typing import Any

import requests
import rfc8785
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from fastapi import Depends, FastAPI, Header, HTTPException
from google.cloud import firestore
from pydantic import BaseModel

log = logging.getLogger("credentials")
PROJECT = os.environ.get("CS_GCP_PROJECT", os.environ.get("GOOGLE_CLOUD_PROJECT", ""))
KMS_KEY_VERSION = os.environ.get("CS_KMS_KEY_VERSION", "")                 # MandateGuard's decision-signing key (public part)
PROCESSOR_KEY_VERSION = os.environ.get("CS_PROCESSOR_KEY_VERSION", "")     # this processor's receipt-signing key
MANDATEGUARD_URL = os.environ.get("CS_MANDATEGUARD_URL", "").rstrip("/")
ISSUER = os.environ.get("CS_ISSUER_NAME", "mock-processor.hackathon")


def _split(v: str) -> list[str]:
    return [e.strip() for e in (v or "").replace(";", ",").split(",") if e.strip()]


ALLOWED_CALLERS = _split(os.environ.get("CS_ALLOWED_CALLERS", ""))
REFUND_CALLERS = _split(os.environ.get("CS_REFUND_CALLERS", ""))
AUDIENCES = [a.rstrip("/") for a in _split(os.environ.get("CS_TOKEN_AUDIENCES", ""))]  # this service's own URL(s)
TOKEN_TTL = int(os.environ.get("CS_TOKEN_TTL_SECONDS", "300"))

app = FastAPI(title="Mock credentials service + processor", version="0.2.0")
db = firestore.Client(project=PROJECT or None)
_mg_pem: str | None = None
_kms = None


def kms():
    global _kms
    if _kms is None:
        from google.cloud import kms as kms_mod

        _kms = kms_mod.KeyManagementServiceClient()
    return _kms


def processor_kid() -> str:
    return "kms:" + PROCESSOR_KEY_VERSION.rsplit("/cryptoKeys/", 1)[-1]


def digest(obj: dict[str, Any]) -> bytes:
    """sha256 over RFC 8785 JSON: the same statement digest MandateGuard and the console verify."""
    return hashlib.sha256(rfc8785.dumps(obj)).digest()


def sign_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    sig = kms().asymmetric_sign(request={"name": PROCESSOR_KEY_VERSION, "digest": {"sha256": digest(receipt)}}).signature
    return {"receipt": receipt, "signature": base64.urlsafe_b64encode(sig).rstrip(b"=").decode(), "kid": processor_kid()}


def mandateguard_public_pem() -> str:
    global _mg_pem
    if _mg_pem is None:
        _mg_pem = kms().get_public_key(request={"name": KMS_KEY_VERSION}).pem
    return _mg_pem


def record_hash(record: dict[str, Any]) -> str:
    body = {k: v for k, v in record.items() if k not in ("hash", "signature", "signer_kid")}
    return hashlib.sha256(rfc8785.dumps(body)).hexdigest()


def verify_mandateguard(digest_hex: str, signature_b64: str) -> bool:
    try:
        pub = serialization.load_pem_public_key(mandateguard_public_pem().encode())
        sig = base64.urlsafe_b64decode(signature_b64 + "=" * (-len(signature_b64) % 4))
        pub.verify(sig, bytes.fromhex(digest_hex), ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return True
    except Exception:  # noqa: BLE001
        return False


def _verify_caller(authorization: str | None, allowed: list[str], what: str) -> str:
    if not allowed:
        raise HTTPException(403, f"{what} is disabled (no callers configured)")
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer identity token")
    if not AUDIENCES:
        raise HTTPException(503, f"{what} needs CS_TOKEN_AUDIENCES (this service's URL) to be set")
    try:
        import google.auth.transport.requests
        import google.oauth2.id_token

        info = google.oauth2.id_token.verify_token(authorization.split(" ", 1)[1], google.auth.transport.requests.Request(), audience=AUDIENCES)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(401, f"invalid identity token: {e}") from e
    if info.get("email") not in allowed:
        raise HTTPException(403, f"caller is not allowed to use {what}")
    return info["email"]


def token_caller(authorization: str | None = Header(default=None)) -> str:
    return _verify_caller(authorization, ALLOWED_CALLERS, "token issuance")


def refund_caller(authorization: str | None = Header(default=None)) -> str:
    return _verify_caller(authorization, REFUND_CALLERS, "refunds")


def report(envelope: dict[str, Any]) -> dict[str, Any]:
    """Tell MandateGuard what happened to the money. Failure is logged and returned, never hidden."""
    if not MANDATEGUARD_URL:
        return {"reported": False, "reason": "CS_MANDATEGUARD_URL not set"}
    try:
        import google.auth.transport.requests
        import google.oauth2.id_token

        tok = google.oauth2.id_token.fetch_id_token(google.auth.transport.requests.Request(), MANDATEGUARD_URL)
        for attempt in range(3):
            r = requests.post(f"{MANDATEGUARD_URL}/v1/receipts", json=envelope, headers={"Authorization": f"Bearer {tok}"}, timeout=15)
            if r.status_code < 500:
                return {"reported": r.status_code == 200, "status": r.status_code, "mandateguard": r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text[:200]}
            time.sleep(0.5 * (attempt + 1))
        return {"reported": False, "status": r.status_code}
    except Exception as e:  # noqa: BLE001
        log.warning("receipt not reported to MandateGuard: %s", e)
        return {"reported": False, "reason": str(e)}


class TokenRequest(BaseModel):
    decision_record: dict[str, Any]


class ChargeRequest(BaseModel):
    payment_token: str
    checkout_hash: str
    amount_minor: int
    currency: str
    payee_id: str
    order_id: str | None = None


class RefundRequest(BaseModel):
    payment_id: str
    reason: str = "cancelled before shipping"


@app.get("/health")
def health() -> dict[str, Any]:
    return {"ok": True, "callers_configured": len(ALLOWED_CALLERS), "refund_callers_configured": len(REFUND_CALLERS),
            "processor_kid": processor_kid() if PROCESSOR_KEY_VERSION else None, "reports_to": MANDATEGUARD_URL or None}


@app.post("/v1/tokens")
def issue_token(req: TokenRequest, caller: str = Depends(token_caller)) -> dict[str, Any]:
    rec = req.decision_record
    if rec.get("verdict") not in ("ALLOW", "ALLOW_BY_HUMAN"):
        raise HTTPException(403, "decision record is not an ALLOW")
    if record_hash(rec) != rec.get("hash"):
        raise HTTPException(403, "decision record hash mismatch: content altered after signing")
    if not rec.get("signature") or not verify_mandateguard(rec["hash"], rec["signature"]):
        raise HTTPException(403, "decision record signature invalid: not signed by MandateGuard")
    jti = secrets.token_hex(16)
    token = f"mgtok_{jti}"
    bound = {"decision_record_hash": rec["hash"], "checkout_hash": rec["hashes"]["checkout"],
             "closed_payment_reference": rec["hashes"].get("closed_payment_reference", ""),
             "amount_minor": int(rec["payment"]["amount_minor"]), "currency": rec["payment"]["currency"], "payee_id": rec["payment"]["payee_id"]}
    claims = {"jti": jti, "decision_id": rec["decision_id"], "mandate_id": rec.get("mandate_id"), **bound,
              "issued_at": time.time(), "expires_at": time.time() + TOKEN_TTL, "status": "issued", "issued_to": caller}
    try:
        db.collection("cs_decisions").document(rec["hash"]).create({"jti_sha256": hashlib.sha256(jti.encode()).hexdigest(), "ts": time.time()})
    except Exception as e:  # noqa: BLE001  (AlreadyExists: a token was already minted for this record)
        raise HTTPException(409, f"a token was already issued for this decision record: {type(e).__name__}") from e
    db.collection("cs_tokens").document(jti).set(claims)
    return {"payment_token": token, "token_sha256": hashlib.sha256(token.encode()).hexdigest(), "expires_at": claims["expires_at"], "bound_to": bound}


@app.post("/v1/charge")
def charge(req: ChargeRequest) -> dict[str, Any]:
    if not req.payment_token.startswith("mgtok_"):
        raise HTTPException(400, "malformed token")
    ref = db.collection("cs_tokens").document(req.payment_token[len("mgtok_"):])
    payment_id = "pay_" + uuid.uuid4().hex[:16]

    @firestore.transactional
    def _tx(tx):
        snap = ref.get(transaction=tx)
        if not snap.exists:
            raise HTTPException(404, "unknown token")
        c = snap.to_dict()
        if c["status"] != "issued":
            raise HTTPException(409, f"token already {c['status']} (replay)")
        if time.time() > c["expires_at"]:
            raise HTTPException(410, "token expired")
        if (c["checkout_hash"], c["amount_minor"], c["currency"], c["payee_id"]) != (req.checkout_hash, req.amount_minor, req.currency, req.payee_id):
            raise HTTPException(403, "token is bound to a different cart / amount / payee")
        tx.update(ref, {"status": "charged", "charged_at": time.time(), "payment_id": payment_id, "order_id": req.order_id})
        return c

    c = _tx(db.transaction())
    receipt = {"type": "payment.executed", "status": "Success", "iss": ISSUER, "iat": int(time.time()), "reference": c["closed_payment_reference"],
               "payment_id": payment_id, "psp_confirmation_id": "psp_" + uuid.uuid4().hex[:12], "network_confirmation_id": "net_" + uuid.uuid4().hex[:12],
               "for_decision_id": c["decision_id"], "decision_record_hash": c["decision_record_hash"], "mandate_id": c.get("mandate_id"),
               "token_sha256": hashlib.sha256(req.payment_token.encode()).hexdigest(), "checkout_hash": req.checkout_hash,
               "amount_minor": req.amount_minor, "currency": req.currency, "payee_id": req.payee_id, "order_id": req.order_id or ""}
    env = sign_receipt(receipt)
    db.collection("cs_receipts").document(payment_id).set({**env, "refunded": False})
    return {"status": "charged", "payment_id": payment_id, "amount_minor": req.amount_minor, "currency": req.currency, "report": report(env)}


@app.post("/v1/refund")
def refund(req: RefundRequest, caller: str = Depends(refund_caller)) -> dict[str, Any]:
    ref = db.collection("cs_receipts").document(req.payment_id)
    snap = ref.get()
    if not snap.exists:
        raise HTTPException(404, "unknown payment")
    stored = snap.to_dict()
    if stored.get("refunded"):
        raise HTTPException(409, "already refunded")
    paid = stored["receipt"]
    receipt = {"type": "payment.refunded", "status": "Success", "iss": ISSUER, "iat": int(time.time()), "reference": paid["reference"],
               "payment_id": req.payment_id, "refund_id": "ref_" + uuid.uuid4().hex[:12], "for_decision_id": paid["for_decision_id"],
               "decision_record_hash": paid["decision_record_hash"], "mandate_id": paid.get("mandate_id"), "token_sha256": paid["token_sha256"],
               "checkout_hash": paid["checkout_hash"], "amount_minor": paid["amount_minor"], "currency": paid["currency"], "payee_id": paid["payee_id"],
               "requested_by": caller, "reason": req.reason}
    env = sign_receipt(receipt)
    ref.update({"refunded": True, "refund": env})
    return {"status": "refunded", "payment_id": req.payment_id, "report": report(env)}
