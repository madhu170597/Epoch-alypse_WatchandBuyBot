"""Credentials-service boundary: who releases the payment credential, and who reports that money moved.

* issue_token(record) is honoured only for a MandateGuard-signed ALLOW / ALLOW_BY_HUMAN record. The token is
  bound to the decision record hash, checkout hash, amount, currency and payee, and expires in minutes.
  MandateGuard records the release with the token's sha256, never the token itself.
* The processor charges a token once and returns a signed receipt (AP2 Payment Receipt fields plus the
  binding). The receipt goes back to MandateGuard, which reconciles it against the decision and chains it.

InProcessCredentials is the reference implementation used in tests and local runs; the deployed service
(credentials_service/main.py) follows the same contract over HTTP.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import uuid
from typing import Any, Protocol

import rfc8785


class CredentialsClient(Protocol):
    def issue_token(self, record: dict[str, Any]) -> dict[str, Any]: ...


class TokenRejected(Exception):
    pass


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def statement_digest(obj: dict[str, Any]) -> str:
    """Digest signed by processors and verified by MandateGuard and the console: sha256 over RFC 8785 JSON."""
    return hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


def binding_of(record: dict[str, Any]) -> dict[str, Any]:
    return {"decision_record_hash": record["hash"], "checkout_hash": record["hashes"]["checkout"],
            "closed_payment_reference": record["hashes"].get("closed_payment_reference", ""),
            "amount_minor": int(record["payment"]["amount_minor"]), "currency": record["payment"]["currency"],
            "payee_id": record["payment"]["payee_id"]}


class InProcessCredentials:
    def __init__(self, signer_verify, processor_signer=None, secret: bytes | None = None, ttl_s: int = 300,
                 issuer: str = "credentials.local", processor_name: str = "processor.local"):
        from .audit import LocalEcSigner

        self._verify = signer_verify  # callable(digest_hex, signature_b64) -> bool, MandateGuard's public key
        self._secret = secret or os.urandom(32)
        self.ttl = ttl_s
        self.issuer = issuer
        self.processor_name = processor_name
        self.processor = processor_signer or LocalEcSigner()
        self.redeemed: set[str] = set()
        self.issued: dict[str, dict[str, Any]] = {}
        self.receipts: dict[str, dict[str, Any]] = {}

    # ---- issuance: honoured only for a signed ALLOW record ---------------------------------------
    def issue_token(self, record: dict[str, Any]) -> dict[str, Any]:
        from .audit import record_hash

        if record.get("verdict") not in ("ALLOW", "ALLOW_BY_HUMAN"):
            raise TokenRejected("decision record is not an ALLOW")
        if record_hash(record) != record.get("hash"):
            raise TokenRejected("decision record hash mismatch: record content was altered after signing")
        if not record.get("signature") or not self._verify(record["hash"], record["signature"]):
            raise TokenRejected("decision record signature invalid: caller is not MandateGuard")
        bound = binding_of(record)
        claims = {"jti": uuid.uuid4().hex, "iat": int(time.time()), "exp": int(time.time()) + self.ttl, "aud": "processor",
                  "decision_id": record["decision_id"], "mandate_id": record.get("mandate_id", ""), **bound}
        body = base64.urlsafe_b64encode(json.dumps(claims, sort_keys=True).encode()).rstrip(b"=").decode()
        mac = hmac.new(self._secret, body.encode(), hashlib.sha256).hexdigest()
        token = f"mgtok.{body}.{mac}"
        self.issued[claims["jti"]] = claims
        return {"token": token, "token_sha256": token_hash(token), "expires_at": claims["exp"], "bound_to": bound,
                "issuer": {"name": self.issuer, "principal": "in-process"}}

    # ---- the processor --------------------------------------------------------------------------
    def _sign(self, receipt: dict[str, Any]) -> dict[str, Any]:
        return {"receipt": receipt, "signature": self.processor.sign(statement_digest(receipt)), "kid": self.processor.kid}

    def redeem(self, token: str, *, checkout_hash: str, amount_minor: int, currency: str, payee_id: str, order_id: str | None = None) -> dict[str, Any]:
        try:
            _, body, mac = token.split(".")
        except ValueError as e:
            raise TokenRejected("malformed token") from e
        if not hmac.compare_digest(mac, hmac.new(self._secret, body.encode(), hashlib.sha256).hexdigest()):
            raise TokenRejected("bad token signature")
        claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        if claims["exp"] < time.time():
            raise TokenRejected("token expired")
        if (claims["checkout_hash"], claims["amount_minor"], claims["currency"], claims["payee_id"]) != (checkout_hash, amount_minor, currency, payee_id):
            raise TokenRejected("token is bound to a different cart/amount/payee")
        if claims["jti"] in self.redeemed:
            raise TokenRejected("token already redeemed (replay)")
        self.redeemed.add(claims["jti"])
        pid = "pay_" + uuid.uuid4().hex[:16]
        receipt = {"type": "payment.executed", "status": "Success", "iss": self.processor_name, "iat": int(time.time()),
                   "reference": claims["closed_payment_reference"], "payment_id": pid,
                   "psp_confirmation_id": "psp_" + uuid.uuid4().hex[:12], "network_confirmation_id": "net_" + uuid.uuid4().hex[:12],
                   "for_decision_id": claims["decision_id"], "decision_record_hash": claims["decision_record_hash"], "mandate_id": claims["mandate_id"],
                   "token_sha256": token_hash(token), "checkout_hash": checkout_hash, "amount_minor": amount_minor, "currency": currency,
                   "payee_id": payee_id, "order_id": order_id or ""}
        self.receipts[pid] = dict(receipt)   # the processor's own copy; the signed receipt is never mutated afterwards
        return self._sign(receipt)

    def refund(self, payment_id: str, *, requested_by: str, reason: str = "cancelled before shipping") -> dict[str, Any]:
        paid = self.receipts.get(payment_id)
        if paid is None:
            raise TokenRejected("unknown payment")
        if paid.get("refunded"):
            raise TokenRejected("already refunded")
        paid["refunded"] = True
        receipt = {"type": "payment.refunded", "status": "Success", "iss": self.processor_name, "iat": int(time.time()),
                   "reference": paid["reference"], "payment_id": payment_id, "refund_id": "ref_" + uuid.uuid4().hex[:12],
                   "for_decision_id": paid["for_decision_id"], "decision_record_hash": paid["decision_record_hash"], "mandate_id": paid["mandate_id"],
                   "token_sha256": paid["token_sha256"], "checkout_hash": paid["checkout_hash"], "amount_minor": paid["amount_minor"],
                   "currency": paid["currency"], "payee_id": paid["payee_id"], "requested_by": requested_by, "reason": reason}
        return self._sign(receipt)


class HttpCredentialsClient:
    def __init__(self, base_url: str, audience: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.audience = audience or self.base_url

    def _id_token(self) -> str:
        import google.auth.transport.requests
        import google.oauth2.id_token

        return google.oauth2.id_token.fetch_id_token(google.auth.transport.requests.Request(), self.audience)

    def issue_token(self, record: dict[str, Any]) -> dict[str, Any]:
        import httpx

        try:
            r = httpx.post(f"{self.base_url}/v1/tokens", json={"decision_record": record},
                           headers={"Authorization": f"Bearer {self._id_token()}"}, timeout=15)
        except Exception as e:  # noqa: BLE001 - unreachable credentials service => no token, decision becomes DENY
            raise TokenRejected(f"credentials service unreachable: {e}") from e
        if r.status_code != 200:
            raise TokenRejected(f"credentials service refused: {r.status_code} {r.text[:200]}")
        d = r.json()
        return {"token": d["payment_token"], "token_sha256": d.get("token_sha256") or token_hash(d["payment_token"]),
                "expires_at": d.get("expires_at"), "bound_to": d.get("bound_to", {}),
                "issuer": {"name": "credentials-service", "principal": self.base_url}}
