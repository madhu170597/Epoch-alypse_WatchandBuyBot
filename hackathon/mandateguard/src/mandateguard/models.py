"""Wire models for the MandateGuard decision API."""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    ESCALATE = "ESCALATE"
    DENY = "DENY"

    @property
    def rank(self) -> int:
        return {"ALLOW": 0, "ESCALATE": 1, "DENY": 2}[self.value]


def tighten(*verdicts: Verdict) -> Verdict:
    """Combine verdicts so that the strictest one wins (monotone, never loosens)."""
    return max(verdicts, key=lambda v: v.rank)


class Stage(str, Enum):
    S0 = "stage0_guardrails"
    S1 = "stage1_rules"
    S2 = "stage2_gemini"
    S3 = "stage3_record"


class Finding(BaseModel):
    stage: Stage
    code: str
    outcome: Verdict
    message: str                      # one specific sentence with the real values
    title: str = ""                   # short label, e.g. "Price outside the signed range"
    source: str = ""                  # who decided: "Policy · mandate v2", "AP2 SDK", "Gemini 3.8 Flash", ...
    rank: int = 50                    # lower = more important when choosing the headline
    detail: Any = None
    data: dict[str, Any] | None = None  # supporting evidence (page excerpts, model points)
    pack: str | None = None
    rule: str | None = None
    check: str | None = None


class TraceEvent(BaseModel):
    """One step of the shopping agent's trace, recorded by its ADK callbacks.

    kind=plan       data: {"items":[{"sku","qty"}], "payee_id", "max_total_minor", "shipping_address_hash"}
    kind=page_read  data: {"url", "content_sha256"}
    kind=tool_call  data: tool args (never secrets); tool: tool name
    kind=tool_result data: {"items_introduced":[sku...]} optional
    """

    seq: int
    ts: str | None = None
    kind: Literal["plan", "tool_call", "tool_result", "page_read", "note"]
    tool: str | None = None
    summary: str = ""
    data: dict[str, Any] = Field(default_factory=dict)


class PageExcerpt(BaseModel):
    url: str
    content: str = Field(max_length=200_000)
    fetched_at: str | None = None


class AP2Bundle(BaseModel):
    """AP2 v0.2 artefacts for one purchase attempt.

    The open (user-signed) mandates are looked up by mandate_id from MandateGuard's own
    store; copies supplied here are only cross-checked, never trusted on their own.
    """

    checkout_jwt: str = Field(description="Merchant-signed JWT over the UCP Checkout object")
    payment_mandate_chain: str = Field(description="open payment mandate ~~ agent-signed closed payment mandate")
    payment_nonce: str = Field(description="Verifier nonce used in the closed payment mandate KB-JWT")
    checkout_mandate_chain: str | None = Field(default=None, description="open checkout mandate ~~ closed checkout mandate")
    checkout_nonce: str | None = None
    open_checkout_mandate: str | None = None
    open_payment_mandate: str | None = None


class DecisionRequest(BaseModel):
    """What the agent submits. `user_id` and `agent_id` are claims only: MandateGuard takes the user from the
    mandate and the agent from the verified caller, and rejects the request if either claim disagrees."""

    mandate_id: str
    user_id: str | None = None
    agent_id: str | None = None
    idempotency_key: str | None = None
    ap2: AP2Bundle
    trace: list[TraceEvent] = Field(default_factory=list)
    pages: list[PageExcerpt] = Field(default_factory=list)
    intent_text: str | None = Field(default=None, description="Ignored if the mandate store has the signed intent text")
    plan_id: str | None = Field(default=None, description="The plan the agent committed to MandateGuard before browsing (POST /v1/plans)")


class ApprovalInfo(BaseModel):
    approval_id: str
    expires_at: str
    summary: str
    raw_action: dict[str, Any]


class RecordInfo(BaseModel):
    seq: int
    hash: str
    prev_hash: str
    signature: str | None = None
    signer_kid: str | None = None


class DecisionResponse(BaseModel):
    decision_id: str
    verdict: Verdict
    stage1_verdict: Verdict
    stage2_verdict: Verdict | None = None
    stage2_ran: bool = False
    findings: list[Finding]
    rationale: str
    record: RecordInfo
    hashes: dict[str, str] = Field(default_factory=dict)
    payment_token: str | None = None
    approval: ApprovalInfo | None = None


class ApprovalRedeemRequest(BaseModel):
    channel: Literal["telegram", "app", "link"]
    channel_user_id: str = ""
    reply: Literal["approve", "reject"]
    reply_ref: str | None = Field(default=None, description="message id / nonce of the user's reply")


class ApprovalRedeemResponse(BaseModel):
    decision_id: str
    original_decision_id: str
    verdict: Verdict
    record: RecordInfo
    payment_token: str | None = None
    message: str


class Actor(BaseModel):
    """Who did something, and how we know. Every record in the chain names one."""

    principal: str
    role: Literal["user", "agent", "trusted_surface", "operator", "channel", "credentials_service", "processor", "merchant", "mandateguard"]
    verified_by: str


class RespondBody(BaseModel):
    action: Literal["approve", "decline"]
    assertion: dict[str, Any] | None = Field(default=None, description="WebAuthn assertion when the user approves with a passkey")


class PlanItem(BaseModel):
    sku: str
    qty: int = Field(default=1, ge=1)


class PlanBody(BaseModel):
    """What the agent intends to buy, committed before it reads any merchant page. MandateGuard records it with
    its own clock and signature, so the plan can't be rewritten after the agent has seen untrusted content."""

    mandate_id: str
    items: list[PlanItem] = Field(min_length=1)
    payee_id: str
    shipping_address_hash: str | None = None
    max_total_minor: int | None = None
    note: str = Field(default="", max_length=500)


class ConsentRespondBody(BaseModel):
    action: Literal["sign", "decline"]
    assertion: dict[str, Any] | None = Field(default=None, description="WebAuthn assertion over the mandate statement")


class FulfillmentBody(BaseModel):
    """A merchant's signed statement that an order shipped or arrived: a compact ES256 JWS made with its registered key."""

    event_jwt: str = Field(max_length=20_000)


class ReceiptEnvelope(BaseModel):
    """A processor's signed statement about money that moved: payment.executed or payment.refunded."""

    receipt: dict[str, Any]
    signature: str
    kid: str


# ---- registrations: what the trusted surface and the operator send ------------------------------------------------------------
class MandateRegistration(BaseModel):
    """What the trusted surface registers after the customer confirms the summary (docs/INTEGRATION.md, section 4).
    Fields beyond these are kept with the registration as submitted."""

    model_config = ConfigDict(extra="allow")

    mandate_id: str
    user_id: str = Field(description="The customer, e.g. the Firebase UID")
    intent_text: str = Field(description="The request text committed to in mg_conditions.intent_sha256")
    intent_salt: str = Field(default="", description="Salt behind intent_sha256 and summary_sha256")
    summary_text: str = Field(default="", description="Exactly the summary the customer was shown")
    open_checkout_mandate: str = Field(description="AP2 v0.2 open checkout mandate (SD-JWT) carrying the mg_conditions claim")
    open_payment_mandate: str = Field(description="AP2 v0.2 open payment mandate (SD-JWT)")
    user_public_jwk: dict[str, Any] = Field(description="Public P-256 JWK of the key that signed both open mandates")
    linked_channels: dict[str, Any] = Field(default_factory=dict, description='Where approval links may go, e.g. {"telegram": "<chat id>"}')
    consent: dict[str, Any] | None = Field(default=None, description='How the customer approved, as attested, e.g. {"method": "sms_otp", "verified_by": "identity service", "at": 1792000000}')
    instruction: dict[str, Any] | None = Field(default=None, description="The customer's own message: channel, message_id, received_at, text")
    passkey_consent: bool = Field(default=False, description="Hold the mandate until the customer signs it with a passkey on MandateGuard's consent page")


class AgentRegistration(BaseModel):
    """A shopping agent: the service accounts it calls as, and the keys customers may delegate mandates to. Registering it
    lets those service accounts call the agent endpoints."""

    agent_id: str
    principals: list[str] = Field(description="Service accounts the agent calls as (the ID token's email)")
    key_thumbprints: list[str] = Field(description="RFC 7638 thumbprints of the keys open mandates may name in cnf")
    operator: str = ""
    description: str = ""
    webhook_url: str = Field(default="", description="https endpoint for approval.answered events; empty means the agent polls")


class MerchantRegistration(BaseModel):
    """A merchant's profile and one signing key. A new kid rotates the key; the previous one is retired, not deleted."""

    id: str
    name: str
    kid: str = Field(description="Key id the merchant puts in the header of its checkout JWTs and delivery events")
    public_jwk: dict[str, Any] = Field(description="Public P-256 JWK")
    website: str = Field(default="", description="https origin of its product pages; MandateGuard fetches pages only from registered sites")
    rating: float | None = Field(default=None, description="Seller rating used for the signed min_seller_rating condition")
    rating_source: str | None = None


class ApproverRegistration(BaseModel):
    """Who may approve policy packs, by signature."""

    approver_id: str
    public_jwk: dict[str, Any] = Field(description="Public P-256 JWK")
    name: str = ""


class ClientRegistration(BaseModel):
    """A service allowed to call in one role, and where that role's events go. Shopping agents register at /v1/admin/agents."""

    client_id: str
    role: Literal["channel", "trusted_surface", "operator", "processor"]
    principals: list[str] = Field(description="Service accounts the client calls as (the ID token's email)")
    webhook_url: str = Field(default="", description="https endpoint for this role's events; empty means the client polls")
    description: str = ""
