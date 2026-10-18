"""MandateGuard client — the real deployed contract (docs/INTEGRATION.md).

MandateGuard is a separate governance service (another team's) that vets every
payment. This module is the deterministic client the agent/web use:

  - web / identity (trusted_surface SA): register_mandate  -> POST /v1/admin/mandates
  - shopping agent (agent SA):           commit_plan       -> POST /v1/plans
                                         request_decision  -> POST /v1/decisions
  - anyone (token is the credential):    charge            -> POST /v1/charge (option A)

Auth is a Google-signed ID token, audience = MANDATE_GUARD_URL, email claim
required, minted from the role's registered service-account key. The companion
credentials service (/v1/charge) takes no auth — the payment_token is the credential.

Fail closed: a configured-but-unreachable guard, or a malformed reply, is DENY.
No payment proceeds without an explicit ALLOW.
"""

import base64
import hashlib
import logging
import os
import threading
import time
from typing import Any

import requests
from google.auth.transport.requests import Request as _GoogleRequest
from google.oauth2 import id_token as _idt
from google.oauth2 import service_account as _sa

_logger = logging.getLogger("shopping_agent")

ALLOW = "ALLOW"
ESCALATE = "ESCALATE"
DENY = "DENY"
_VERDICTS = (ALLOW, ESCALATE, DENY)

_GUARD_URL = os.environ.get("MANDATE_GUARD_URL", "").rstrip("/")
# Option A: companion credentials+processor service (/v1/charge).
_CHARGE_URL = os.environ.get(
    "CREDENTIALS_PROVIDER_URL",
    os.environ.get("PAYMENT_PROCESSOR_URL", ""),
).rstrip("/")
_TIMEOUT = float(os.environ.get("MANDATE_GUARD_TIMEOUT", "15"))

# Registered service-account key files (JSON) for each role's ID token.
_AGENT_SA_KEY = os.environ.get("MG_AGENT_SA_KEY", "")
_TRUSTED_SURFACE_SA_KEY = os.environ.get("MG_TRUSTED_SURFACE_SA_KEY", "")

_AGENT_ID = os.environ.get("MG_AGENT_ID", "shopper-agent")

# ── ID-token auth ───────────────────────────────────────────────────────────

_token_lock = threading.Lock()
_token_cache: dict[tuple[str, str], tuple[str, float]] = {}


def _id_token(sa_key_path: str, audience: str) -> str:
    """Mint (and cache) a Google-signed ID token for ``audience`` from an SA key.

    Falls back to ambient ADC when no key path is given (e.g. on Cloud Run,
    where the attached service account already carries the email claim).
    """
    key = (sa_key_path, audience)
    now = time.time()
    with _token_lock:
        cached = _token_cache.get(key)
        if cached and cached[1] - 60 > now:
            return cached[0]
    if sa_key_path:
        creds = _sa.IDTokenCredentials.from_service_account_file(
            sa_key_path, target_audience=audience
        )
        creds.refresh(_GoogleRequest())
        token, exp = creds.token, creds.expiry.timestamp()
    else:
        token = _idt.fetch_id_token(_GoogleRequest(), audience)
        exp = now + 3000
    with _token_lock:
        _token_cache[key] = (token, exp)
    return token


def _agent_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {_id_token(_AGENT_SA_KEY, _GUARD_URL)}"}


def _trusted_surface_headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {_id_token(_TRUSTED_SURFACE_SA_KEY, _GUARD_URL)}"
    }


# ── mg_conditions (docs/INTEGRATION.md §4.1; mandateguard.conditions) ────────


def new_salt() -> str:
    return base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode()


def normalize_address(address: str) -> str:
    return " ".join((address or "").lower().replace(",", " ").split())


def commit(text: str, salt: str) -> str:
    """Salted commitment; the salt stays with the trusted surface and MandateGuard."""
    return hashlib.sha256(f"{salt}\n{text}".encode()).hexdigest()


def build_conditions(
    *,
    intent_text: str,
    summary_text: str,
    salt: str,
    ship_to: str | None = None,
    address_salt: str | None = None,
    deliver_by: str | None = None,
    item_condition: str | None = None,
    min_seller_rating: float | None = None,
) -> dict[str, Any]:
    """Build the signed ``mg_conditions`` claim for the open checkout mandate."""
    out: dict[str, Any] = {
        "v": 1,
        "intent_sha256": commit(intent_text, salt),
        "summary_sha256": commit(summary_text, salt),
    }
    if ship_to:
        out["ship_to_sha256"] = commit(
            normalize_address(ship_to), address_salt or salt
        )
    if deliver_by:
        out["deliver_by"] = deliver_by
    if item_condition:
        out["item_condition"] = item_condition
    if min_seller_rating is not None:
        out["min_seller_rating"] = float(min_seller_rating)
    return out


# ── calls ────────────────────────────────────────────────────────────────────


def register_mandate(body: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/admin/mandates as the trusted-surface SA (web / identity).

    ``body`` carries mandate_id, user_id, intent/summary text + salt, both open
    SD-JWTs, user_public_jwk and consent (docs §4.2). Returns the service reply.
    """
    resp = requests.post(
        f"{_GUARD_URL}/v1/admin/mandates",
        json=body,
        headers=_trusted_surface_headers(),
        timeout=_TIMEOUT,
    )
    if resp.status_code >= 400:
        raise RuntimeError(f"register {resp.status_code}: {resp.text[:600]}")
    return resp.json()


def commit_plan(
    mandate_id: str, items: list[dict[str, Any]], payee_id: str
) -> dict[str, Any]:
    """POST /v1/plans as the agent SA, before reading any merchant page (docs §5.1)."""
    resp = requests.post(
        f"{_GUARD_URL}/v1/plans",
        json={"mandate_id": mandate_id, "items": items, "payee_id": payee_id},
        headers=_agent_headers(),
        timeout=_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


def request_decision(body: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/decisions as the agent SA (docs §5.2), replacing issue_payment_credential.

    Returns the service reply with the verdict normalized to ALLOW/ESCALATE/DENY.
    Fails closed to DENY on transport or parse errors.
    """
    if not _GUARD_URL:
        return {"verdict": DENY, "rationale": "MANDATE_GUARD_URL unset"}
    try:
        resp = requests.post(
            f"{_GUARD_URL}/v1/decisions",
            json=body,
            headers=_agent_headers(),
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError) as e:
        _logger.error("MandateGuard /v1/decisions failed, failing closed: %s", e)
        return {"verdict": DENY, "rationale": f"mandate_guard_unreachable: {e}"}
    verdict = str(data.get("verdict", DENY)).upper()
    data["verdict"] = verdict if verdict in _VERDICTS else DENY
    return data


def get_approval(approval_id: str) -> dict[str, Any]:
    """GET /v1/approvals/{id} as the agent SA — poll an ESCALATE (docs §5.2)."""
    resp = requests.get(
        f"{_GUARD_URL}/v1/approvals/{approval_id}",
        headers=_agent_headers(),
        timeout=_TIMEOUT,
    )
    if resp.status_code >= 400:
        raise RuntimeError(f"charge {resp.status_code}: {resp.text[:400]}")
    return resp.json()


def charge(
    payment_token: str,
    checkout_hash: str,
    amount_minor: int,
    currency: str,
    payee_id: str,
    order_id: str,
) -> dict[str, Any]:
    """POST /v1/charge on the companion service (option A) — no auth; the token is the credential."""
    resp = requests.post(
        f"{_CHARGE_URL}/v1/charge",
        json={
            "payment_token": payment_token,
            "checkout_hash": checkout_hash,
            "amount_minor": amount_minor,
            "currency": currency,
            "payee_id": payee_id,
            "order_id": order_id,
        },
        timeout=_TIMEOUT,
    )
    if resp.status_code >= 400:
        raise RuntimeError(f"charge {resp.status_code}: {resp.text[:400]}")
    return resp.json()
