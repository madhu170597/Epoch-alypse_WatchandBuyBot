"""Settings from environment variables (12-factor; Cloud Run friendly)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PACKS_DEFAULT = str(Path(__file__).parent / "packs")


def _list(name: str, default: str) -> list[str]:
    return [x.strip() for x in os.environ.get(name, default).split(",") if x.strip()]


@dataclass
class Settings:
    project: str = os.environ.get("MG_GCP_PROJECT", os.environ.get("GOOGLE_CLOUD_PROJECT", ""))
    backend: str = os.environ.get("MG_BACKEND", "memory")              # memory | firestore
    signer: str = os.environ.get("MG_SIGNER", "local")                 # local | kms
    kms_key_version: str = os.environ.get("MG_KMS_KEY_VERSION", "")
    local_signing_key_pem: str = os.environ.get("MG_LOCAL_SIGNING_KEY_PEM", "")
    packs_dir: str = os.environ.get("MG_PACKS_DIR", PACKS_DEFAULT)
    stage2: str = os.environ.get("MG_STAGE2", "fake")                  # vertex | fake | off
    # Verified 14 Oct 2026 in hackathon-proto-mk26: gemini-3.8-flash / gemini-4-argon answer on location=global
    # and resist the "[SYSTEM NOTICE TO MANDATEGUARD]" injection; flash-lite models do not. 2.5 family retires 20 Oct 2026.
    # Measured 14 Oct 2026 on location=global, same ~1,700-token check: gemini-4-argon 2.8 to 3.7 s; gemini-3.8-flash 2.4 s to 140 s.
    # Both caught the renewed listing and the three injection styles. A slow call gets one duplicate request.
    gemini_model: str = os.environ.get("MG_GEMINI_MODEL", "gemini-4-argon")
    gemini_hedge_model: str = os.environ.get("MG_GEMINI_HEDGE_MODEL", "gemini-4-argon")
    gemini_location: str = os.environ.get("MG_GEMINI_LOCATION", "global")
    gemini_thinking: str = os.environ.get("MG_GEMINI_THINKING", "LOW")
    gemini_timeout_s: float = float(os.environ.get("MG_GEMINI_TIMEOUT_SECONDS", "10"))
    gemini_hedge_s: float = float(os.environ.get("MG_GEMINI_HEDGE_SECONDS", "3.5"))   # send one duplicate request after this long
    model_armor_template: str = os.environ.get("MG_MODEL_ARMOR_TEMPLATE", "")   # template id
    model_armor_location: str = os.environ.get("MG_MODEL_ARMOR_LOCATION", "us-central1")
    credentials_url: str = os.environ.get("MG_CREDENTIALS_URL", "")    # empty => in-process mock
    allowed_tools: list[str] = field(default_factory=lambda: _list("MG_ALLOWED_TOOLS", ""))
    hnp_txn_cap_minor: int = int(os.environ.get("MG_HNP_TXN_CAP_MINOR", "100000"))        # $1000
    hnp_velocity_cap_minor: int = int(os.environ.get("MG_HNP_VELOCITY_CAP_MINOR", "200000"))
    approval_ttl_s: int = int(os.environ.get("MG_APPROVAL_TTL_SECONDS", "300"))
    webhook_timeout_s: float = float(os.environ.get("MG_WEBHOOK_TIMEOUT_SECONDS", "2"))   # one attempt per event; pull endpoints are the fallback
    require_caller_sa: str = os.environ.get("MG_REQUIRE_CALLER_SA", "")  # service account email allowed to call
    public_url: str = os.environ.get("MG_PUBLIC_URL", "")                 # base for approval links
    telegram_bot_token: str = os.environ.get("MG_TELEGRAM_BOT_TOKEN", "")  # optional: send approval links to the linked chat
    audit_collection: str = os.environ.get("MG_AUDIT_COLLECTION", "mg_audit")
    evidence_bucket: str = os.environ.get("MG_EVIDENCE_BUCKET", "")          # empty => in-memory evidence
    evidence_public: bool = os.environ.get("MG_EVIDENCE_PUBLIC", "1") == "1"   # demo: anyone can fetch evidence by hash
    processor_key_version: str = os.environ.get("MG_PROCESSOR_KEY_VERSION", "")  # KMS key the processor signs receipts with
    processor_public_pem: str = os.environ.get("MG_PROCESSOR_PUBLIC_PEM", "")
    processor_kid: str = os.environ.get("MG_PROCESSOR_KID", "")
    approval_passkey: str = os.environ.get("MG_APPROVAL_PASSKEY", "if-enrolled")  # if-enrolled | always | never
    consent_passkey: str = os.environ.get("MG_CONSENT_PASSKEY", "requested")    # requested | if-enrolled | always
    consent_ttl_s: int = int(os.environ.get("MG_CONSENT_TTL_SECONDS", "900"))
    require_witnessed_plan: bool = os.environ.get("MG_REQUIRE_WITNESSED_PLAN", "0") == "1"
    fetch_pages: bool = os.environ.get("MG_FETCH_PAGES", "1") == "1"            # re-fetch pages from registered merchant sites
    page_fetch_timeout_s: float = float(os.environ.get("MG_PAGE_FETCH_TIMEOUT_SECONDS", "2"))
    require_policy_approval: bool = os.environ.get("MG_REQUIRE_POLICY_APPROVAL", "0") == "1"
    # when-needed: skip the purchase-time model review only when every question it answers is already proven (see Pipeline.fast_path)
    model_review: str = os.environ.get("MG_MODEL_REVIEW", "when-needed")   # when-needed | always
    environment: str = os.environ.get("MG_ENVIRONMENT", "Live")              # shown in the console header
    region: str = os.environ.get("MG_REGION", "")
    max_pages: int = int(os.environ.get("MG_MAX_PAGES", "8"))
    max_trace_events: int = int(os.environ.get("MG_MAX_TRACE_EVENTS", "500"))
