"""MandateGuard channel-role client for the Telegram bot.

The bot is registered with MandateGuard as a `channel` client (by the operator:
`POST /v1/admin/clients role:"channel"` with the bot's service-account email and,
for push delivery, this service's `webhook_url`). With that in place the bot can:
  - receive signed `approval.opened` / `approval.answered` events (verify_event);
  - pull held approvals (pending_approvals);
  - redeem a Telegram reply for users without a passkey (redeem).

Auth is a Google-signed ID token with audience == MANDATE_GUARD_URL and an email
claim, minted from the channel service-account key (section 3 of the contract).
"""

import base64
import time

import httpx

from app.config import settings

_TIMEOUT = 15.0
_token_cache: tuple[float, str] | None = None
_public_pem_cache: str | None = None


def enabled() -> bool:
    return bool(settings.mandate_guard_url and settings.mg_channel_sa_key)


def _id_token() -> str:
    """Mint (and cache) a channel ID token for the MandateGuard audience."""
    global _token_cache
    now = time.time()
    if _token_cache and _token_cache[0] - 60 > now:
        return _token_cache[1]
    # Imported lazily so the bot runs without google-auth when MG is disabled.
    from google.auth.transport.requests import Request
    from google.oauth2 import service_account

    creds = service_account.IDTokenCredentials.from_service_account_file(
        settings.mg_channel_sa_key, target_audience=settings.mandate_guard_url
    )
    creds.refresh(Request())
    _token_cache = (creds.expiry.timestamp(), creds.token)
    return creds.token


def _headers() -> dict:
    return {"Authorization": f"Bearer {_id_token()}"}


async def pending_approvals(user_id: str) -> list[dict]:
    """GET /v1/approvals/pending?user_id= — held approvals for one user."""
    url = f"{settings.mandate_guard_url}/v1/approvals/pending"
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.get(url, params={"user_id": user_id}, headers=_headers())
    resp.raise_for_status()
    body = resp.json()
    return body if isinstance(body, list) else body.get("approvals", [])


async def redeem(approval_id: str, chat_id: str, decision: str = "approve") -> dict:
    """POST /v1/approvals/{id}/redeem — accept a Telegram reply as the answer.

    Only honored for users without a passkey, from the linked chat.
    """
    url = f"{settings.mandate_guard_url}/v1/approvals/{approval_id}/redeem"
    body = {"channel": "telegram", "chat_id": str(chat_id), "decision": decision}
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.post(url, json=body, headers=_headers())
    resp.raise_for_status()
    return resp.json()


async def _event_public_pem() -> str:
    """Fetch (and cache) MandateGuard's decision-signer public key PEM."""
    global _public_pem_cache
    if settings.mg_event_public_pem:
        return settings.mg_event_public_pem
    if _public_pem_cache:
        return _public_pem_cache
    url = f"{settings.mandate_guard_url}/v1/audit/public-key"
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.get(url)
    resp.raise_for_status()
    # The endpoint may return a bare PEM or {"public_key_pem": ...}.
    text = resp.text.strip()
    if text.startswith("{"):
        text = resp.json().get("public_key_pem") or resp.json().get("pem", "")
    _public_pem_cache = text
    return text


async def verify_event(raw_body: bytes, headers) -> dict:
    """Verify an approval webhook signature and return the parsed event.

    Mirrors the contract's reference verifier: reject stale timestamps, check the
    ECDSA P-256 signature over `<timestamp>.<raw body>`, then parse.
    """
    import json

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    ts = headers.get("MandateGuard-Timestamp") or headers.get("mandateguard-timestamp")
    sig = headers.get("MandateGuard-Signature") or headers.get("mandateguard-signature")
    if not ts or not sig:
        raise ValueError("missing signature headers")
    if abs(time.time() - int(ts)) > 300:
        raise ValueError("stale event")
    pem = await _event_public_pem()
    key = serialization.load_pem_public_key(pem.encode())
    key.verify(
        base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4)),
        ts.encode() + b"." + raw_body,
        ec.ECDSA(hashes.SHA256()),
    )
    return json.loads(raw_body)
