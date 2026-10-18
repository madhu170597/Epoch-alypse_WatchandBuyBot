"""Events pushed to registered clients, so none of them has to poll.

  approval.opened           to channel clients: a purchase is held; carries the one-time approval link for the customer
  approval.answered         to the agent that asked: approved, rejected, failed or expired; the token is fetched with
                            GET /v1/approvals/{id}, never sent in an event
  mandate.consent_answered  to the trusted surface that registered the mandate: signed or declined

Each delivery is signed with MandateGuard's decision key (the one at /v1/audit/public-key):

  MandateGuard-Timestamp   unix seconds
  MandateGuard-Signature   base64url DER ECDSA P-256 over SHA-256 of "<timestamp>.<raw body>"
  MandateGuard-Key-Id      the signing key's id
  MandateGuard-Event, MandateGuard-Delivery   event type and a unique id for de-duplication

Delivery is one attempt with a short timeout, to https on a public address, without redirects. Decisions are still
answered synchronously, and the pull endpoints stay the source of truth: a failed delivery is logged, never retried
inside a payment request, and never changes an outcome.
"""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .pages import host_of, public_address

EVENTS = {"approval.opened": "channel", "approval.answered": "agent", "mandate.consent_answered": "trusted_surface"}
MAX_AGE_S = 300


class WebhookRefused(Exception):
    pass


def check_url(url: str) -> str:
    """Registration-time check. The address check happens at delivery, when the host is resolved."""
    url = (url or "").strip()
    if url and (urlsplit(url).scheme != "https" or not host_of(url)):
        raise ValueError("webhook_url must be an https URL")
    return url


def build(event: str, data: dict[str, Any], signer: Any, now: float) -> tuple[bytes, dict[str, str]]:
    delivery = "evt_" + uuid.uuid4().hex
    ts = str(int(now))
    body = json.dumps({"id": delivery, "type": event, "created_at": int(now), "data": data},
                      separators=(",", ":"), sort_keys=True, default=str).encode()
    signature = signer.sign(hashlib.sha256(ts.encode() + b"." + body).hexdigest())
    return body, {"Content-Type": "application/json", "User-Agent": "MandateGuard webhooks", "MandateGuard-Event": event,
                  "MandateGuard-Delivery": delivery, "MandateGuard-Timestamp": ts, "MandateGuard-Key-Id": signer.kid,
                  "MandateGuard-Signature": signature}


def verify(body: bytes, headers: dict[str, str], public_pem: str, now: float, max_age_s: int = MAX_AGE_S) -> dict[str, Any]:
    """What a receiver does, in Python: check the signature and the age, then use the event."""
    h = {k.lower(): v for k, v in headers.items()}
    ts = h.get("mandateguard-timestamp", "")
    if not ts.isdigit() or abs(now - int(ts)) > max_age_s:
        raise ValueError("stale or missing timestamp")
    sig = h.get("mandateguard-signature", "")
    try:
        key = serialization.load_pem_public_key(public_pem.encode())
        key.verify(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4)), ts.encode() + b"." + body, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError) as e:
        raise ValueError("signature does not verify") from e
    return json.loads(body)


class HttpWebhookSender:
    def __init__(self, timeout_s: float = 2.0):
        self.timeout = timeout_s

    def __call__(self, url: str, body: bytes, headers: dict[str, str]) -> int:
        import httpx

        if urlsplit(url).scheme != "https":
            raise WebhookRefused("only https endpoints receive events")
        if not public_address(host_of(url)):
            raise WebhookRefused("the address is not public")
        return httpx.post(url, content=body, headers=headers, timeout=self.timeout, follow_redirects=False).status_code
