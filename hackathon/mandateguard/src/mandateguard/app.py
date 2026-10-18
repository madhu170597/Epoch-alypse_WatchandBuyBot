"""Wiring + HTTP surface.

Who may call what (Google ID tokens, Cloud Run service-to-service style). Every write names its caller in the chain.
  agent       MG_REQUIRE_CALLER_SA   POST /v1/plans, POST /v1/decisions, GET /v1/decisions/{id}, GET /v1/approvals/{id}
  channel     MG_CHANNEL_CALLERS     GET /v1/approvals/pending, POST /v1/approvals/{id}/redeem      (Telegram / app service)
  surface     MG_ADMIN_CALLERS       POST /v1/admin/mandates, GET /v1/admin/mandates/{id}/consent,
                                     POST /v1/admin/users/{id}/passkey-enrollments                  (the web app)
  operator    MG_ADMIN_CALLERS       POST /v1/admin/agents, /v1/admin/merchants, /v1/admin/policy-approvers
  processor   MG_PROCESSOR_CALLERS   POST /v1/receipts                                              (credentials service)
  merchant    its registered key     POST /v1/fulfillment (an ES256-signed shipping or delivery event)
  the user    one-time link key      consent page, approval page and passkey enrollment page
  anyone                             GET /v1/audit/*, /v1/decisions/{id}/reverify, /v1/evidence/{sha}, /console, /health,
                                     /.well-known/mandateguard
The agent is in none of the other lists: it cannot register mandates, approve its own hold, or report payments.
Besides the environment lists, the operator registers callers by API (POST /v1/admin/clients, and POST /v1/admin/agents
for shopping agents). Each registration and revocation is a chained record and takes effect without a redeploy.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from dataclasses import asdict

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse, Response
from fastapi.routing import APIRoute
from fastapi.staticfiles import StaticFiles
from jwcrypto.jwk import JWK
from pydantic import BaseModel

from . import __version__, audit, webhooks
from .clients import ClientRegistry, FirestoreClientRegistry
from .config import Settings
from .credentials import HttpCredentialsClient, InProcessCredentials
from .evidence import GcsEvidence, InMemoryEvidence
from .gemini_checks import FakeGeminiClient, GeminiChecks, VertexGeminiClient
from .models import (Actor, AgentRegistration, ApprovalRedeemRequest, ApprovalRedeemResponse, ApproverRegistration, ClientRegistration,
                     ConsentRespondBody, DecisionRequest, DecisionResponse, FulfillmentBody, MandateRegistration, MerchantRegistration, PlanBody,
                     ReceiptEnvelope, RespondBody)
from .notifier import TelegramNotifier
from .passkeys import PasskeyError
from .pipeline import DEV_AGENT, Pipeline
from .registry import (AgentRegistry, ApproverRegistry, FirestoreAgentRegistry, FirestoreApproverRegistry, FirestoreMerchantRegistry,
                       MerchantRegistry)
from .rules.engine import PackStore
from .screener import CombinedScreener, HeuristicScreener, ModelArmorScreener
from .stores import FirestoreStores, InMemoryStores

log = logging.getLogger("mandateguard")
WEB = Path(__file__).parent / "web"


def _kms_kid(name: str) -> str:
    return "kms:" + name.rsplit("/cryptoKeys/", 1)[-1]


def build_pipeline(settings: Settings | None = None) -> Pipeline:
    s = settings or Settings()
    if s.backend == "firestore":
        from google.cloud import firestore

        db = firestore.Client(project=s.project or None)
        stores, chain = FirestoreStores(db), audit.FirestoreChain(db, collection=s.audit_collection)
        registry, agents, approvers = FirestoreMerchantRegistry(db), FirestoreAgentRegistry(db), FirestoreApproverRegistry(db)
        clients = FirestoreClientRegistry(db)
    else:
        stores, chain, registry, agents, approvers = InMemoryStores(), audit.InMemoryChain(), MerchantRegistry(), AgentRegistry(), ApproverRegistry()
        clients = ClientRegistry()
    evidence = GcsEvidence(s.evidence_bucket, s.project, ledger=s.audit_collection) if s.evidence_bucket else InMemoryEvidence()
    signer = audit.KmsSigner(s.kms_key_version) if s.signer == "kms" else audit.LocalEcSigner(s.local_signing_key_pem or None)
    screeners: list[Any] = [HeuristicScreener()]
    if s.model_armor_template and s.project:
        screeners.append(ModelArmorScreener(s.project, s.model_armor_location, s.model_armor_template))
    gemini = None
    if s.stage2 == "vertex":
        gemini = GeminiChecks(VertexGeminiClient(s.project, s.gemini_location), s.gemini_model, s.gemini_thinking, hedge_after_s=s.gemini_hedge_s,
                              hedge_model=s.gemini_hedge_model)
    elif s.stage2 == "fake":
        gemini = GeminiChecks(FakeGeminiClient(), "fake", None)
    credentials = HttpCredentialsClient(s.credentials_url) if s.credentials_url else InProcessCredentials(signer.verify)
    processor_keys: dict[str, Any] = {}
    if s.processor_key_version:
        processor_keys[_kms_kid(s.processor_key_version)] = audit.PemVerifier(audit.kms_public_key(s.processor_key_version), _kms_kid(s.processor_key_version))
    elif s.processor_public_pem and s.processor_kid:
        processor_keys[s.processor_kid] = audit.PemVerifier(s.processor_public_pem, s.processor_kid)
    elif isinstance(credentials, InProcessCredentials):
        p = credentials.processor
        processor_keys[p.kid] = audit.PemVerifier(p.public_pem(), p.kid)
    notifier = TelegramNotifier(s.telegram_bot_token) if s.telegram_bot_token else None
    return Pipeline(settings=s, stores=stores, registry=registry, agents=agents, packs=PackStore(s.packs_dir), screener=CombinedScreener(screeners),
                    gemini=gemini, chain=chain, signer=signer, credentials=credentials, evidence=evidence, processor_keys=processor_keys,
                    notifier=notifier, approvers=approvers, clients=clients)


class EnrollBody(BaseModel):
    credential: dict[str, Any]


def _split(v: str) -> list[str]:
    return [e.strip() for e in (v or "").replace(";", ",").split(",") if e.strip()]


def _trace_id(request: Request) -> str | None:
    h = request.headers.get("x-cloud-trace-context") or ""
    if h:
        return h.split("/", 1)[0]
    tp = request.headers.get("traceparent") or ""
    parts = tp.split("-")
    return parts[1] if len(parts) >= 3 else None


def create_app(pipeline: Pipeline | None = None) -> FastAPI:
    app = FastAPI(title="MandateGuard", version=__version__, docs_url="/api/docs", redoc_url=None)
    pl = pipeline or build_pipeline()
    app.state.pipeline = pl
    groups = {"agent": _split(pl.settings.require_caller_sa), "channel": _split(os.environ.get("MG_CHANNEL_CALLERS", "")),
              "admin": _split(os.environ.get("MG_ADMIN_CALLERS", "")), "processor": _split(os.environ.get("MG_PROCESSOR_CALLERS", ""))}
    dev = pl.settings.backend == "memory"
    # An ID token is accepted only if it was minted for this service. Without this, a token a caller minted for the
    # credentials service could be replayed here.
    audiences = [a.rstrip("/") for a in [pl.settings.public_url, *_split(os.environ.get("MG_TOKEN_AUDIENCES", ""))] if a]
    try:
        pl.ensure_policy_recorded()
    except Exception as e:  # noqa: BLE001
        log.warning("policy record not written at startup: %s", e)
    try:
        if (n := pl.anchor_tail()):
            log.warning("wrote %d missing checkpoints at startup", n)
    except Exception as e:  # noqa: BLE001 - /v1/audit/verify reports whatever is still missing
        log.warning("missing checkpoints not written at startup: %s", e)
    if pl.gemini is not None and pl.settings.stage2 == "vertex":
        import threading

        threading.Thread(target=pl.gemini.warm_up, name="gemini-warm-up", daemon=True).start()

    def _verify(authorization: str | None, allowed: list[str], role: str | None = None) -> str:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(401, "missing bearer identity token")
        if not audiences:
            raise HTTPException(503, "caller checks need MG_PUBLIC_URL (the token audience) to be set")
        try:
            import google.auth.transport.requests
            import google.oauth2.id_token

            info = google.oauth2.id_token.verify_token(authorization.split(" ", 1)[1], google.auth.transport.requests.Request(),
                                                       audience=audiences)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(401, f"invalid identity token: {e}") from e
        email, sub = info.get("email", ""), str(info.get("sub", ""))
        if any(p and (p in allowed or (role is not None and pl.caller_allowed(role, p))) for p in (email, sub)):
            return email or sub
        if not email:
            raise HTTPException(403, "identity token has no email claim; mint it with include_email (gcloud: --include-email)")
        raise HTTPException(403, "this caller is not allowed here")

    def group(name: str, role: str):
        listed = groups[name]

        def check(authorization: str | None = Header(default=None)) -> Actor:
            # dev mode skips authentication until a caller is configured for the role, by environment or by registration
            if dev and not listed and (role == "agent" or not pl.clients.active(role)):
                return Actor(principal=f"dev-{name}" if name != "agent" else "dev", role=role, verified_by="dev mode: caller not authenticated")
            return Actor(principal=_verify(authorization, listed, role), role=role, verified_by="Google-signed ID token")
        return check

    agent_check = group("agent", "agent")
    channel_check = group("channel", "channel")
    surface_check = group("admin", "trusted_surface")
    operator_check = group("admin", "operator")
    processor_check = group("processor", "processor")

    # ---- pages --------------------------------------------------------------------------------------------
    app.mount("/static", StaticFiles(directory=WEB), name="static")

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        return RedirectResponse("/console")

    @app.get("/dashboard", include_in_schema=False)
    def dashboard() -> RedirectResponse:
        return RedirectResponse("/console")

    @app.get("/console", include_in_schema=False)
    def console() -> FileResponse:
        return FileResponse(WEB / "console.html", headers={"Cache-Control": "no-cache"})

    @app.get("/approve/{approval_id}", include_in_schema=False)
    def approve_page(approval_id: str) -> FileResponse:
        return FileResponse(WEB / "approve.html", headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})

    @app.get("/enroll/{enrollment_id}", include_in_schema=False)
    def enroll_page(enrollment_id: str) -> FileResponse:
        return FileResponse(WEB / "enroll.html", headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})

    @app.get("/consent/{mandate_id}", include_in_schema=False)
    def consent_page(mandate_id: str) -> FileResponse:
        return FileResponse(WEB / "consent.html", headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})

    @app.get("/health", tags=["Transparency"])
    def health() -> dict[str, Any]:
        return {"ok": True, "packs_hash": pl.packs.packs_hash, "signer_kid": pl.signer.kid, "stage2": pl.settings.stage2,
                "model": pl.settings.gemini_model if pl.settings.stage2 == "vertex" else None, "backend": pl.settings.backend,
                "callers_configured": {k: len(v) for k, v in groups.items()}, "evidence": pl.evidence.describe()}

    @app.get("/v1/console/meta", tags=["Transparency"])
    def console_meta() -> dict[str, Any]:
        return {"project": pl.settings.project or "local", "environment": pl.settings.environment, "region": pl.settings.region,
                "backend": pl.settings.backend, "signer_kid": pl.signer.kid,
                "model": pl.gemini.label if pl.gemini else None, "prompt_version": pl.gemini.prompt_version if pl.gemini else None,
                "packs": [{"name": p.name, "version": p.version, "rules": len(p.rules), "owner": p.owner, "approved_by": p.approved_by} for p in pl.packs.packs],
                "packs_hash": pl.packs.packs_hash, "screens": [s.name for s in pl.screener.screeners], "evidence": pl.evidence.describe(),
                "revision": os.environ.get("K_REVISION", "local"),
                "limits": {"txn_minor": pl.settings.hnp_txn_cap_minor, "hour_minor": pl.settings.hnp_velocity_cap_minor,
                           "approval_ttl_s": pl.settings.approval_ttl_s}}

    # ---- agent ----------------------------------------------------------------------------------------------------
    @app.post("/v1/plans", tags=["Agent"])
    def commit_plan(body: PlanBody, caller: Actor = Depends(agent_check)) -> dict[str, Any]:
        try:
            return pl.commit_plan(body, caller if caller.principal != "dev" else DEV_AGENT)
        except PermissionError as e:
            raise HTTPException(403, str(e)) from e
        except LookupError as e:
            raise HTTPException(404, str(e)) from e

    @app.post("/v1/decisions", response_model=DecisionResponse, tags=["Agent"])
    def decide(req: DecisionRequest, request: Request, caller: Actor = Depends(agent_check)) -> DecisionResponse:
        return pl.decide(req, caller=caller if caller.principal != "dev" else DEV_AGENT, trace_id=_trace_id(request))

    @app.get("/v1/decisions/{decision_id}", tags=["Agent"])
    def get_decision(decision_id: str, caller: Actor = Depends(agent_check)) -> dict[str, Any]:
        d = pl.stores.get_decision(decision_id)
        if d is None:
            raise HTTPException(404, "unknown decision")
        return d

    @app.get("/v1/decisions/{decision_id}/reverify", tags=["Transparency"])
    def reverify(decision_id: str) -> dict[str, Any]:
        try:
            return pl.reverify(decision_id)
        except LookupError as e:
            raise HTTPException(404, str(e)) from e

    # ---- channel service (declared before /{approval_id}) ----------------------------------------------------------
    @app.get("/v1/approvals/pending", tags=["Channel"])
    def pending(user_id: str | None = None, caller: Actor = Depends(channel_check)) -> list[dict[str, Any]]:
        return pl.pending_approvals(user_id, caller)

    @app.post("/v1/approvals/{approval_id}/redeem", response_model=ApprovalRedeemResponse, tags=["Channel"])
    def redeem(approval_id: str, req: ApprovalRedeemRequest, caller: Actor = Depends(channel_check)) -> ApprovalRedeemResponse:
        if req.channel == "link":
            raise HTTPException(400, "link approvals go through /respond")
        try:
            return pl.redeem_approval(approval_id, req, channel_actor=caller)
        except LookupError as e:
            raise HTTPException(404, str(e)) from e
        except PermissionError as e:
            raise HTTPException(409, str(e)) from e

    @app.get("/v1/approvals/{approval_id}", tags=["Agent"])
    def approval_status(approval_id: str, caller: Actor = Depends(agent_check)) -> dict[str, Any]:
        try:
            return pl.approval_status(approval_id)
        except LookupError as e:
            raise HTTPException(404, str(e)) from e

    # ---- the user, holding a one-time link ---------------------------------------------------------------------------
    @app.get("/v1/approvals/{approval_id}/view", tags=["Customer links"])
    def approval_view(approval_id: str, x_approval_key: str | None = Header(default=None)) -> dict[str, Any]:
        try:
            return pl.approval_view(approval_id, x_approval_key or "")
        except PermissionError as e:
            raise HTTPException(403, str(e)) from e

    @app.post("/v1/approvals/{approval_id}/passkey-options", tags=["Customer links"])
    def approval_passkey_options(approval_id: str, x_approval_key: str | None = Header(default=None)) -> Response:
        try:
            return Response(pl.approval_passkey_options(approval_id, x_approval_key or ""), media_type="application/json")
        except PermissionError as e:
            raise HTTPException(403, str(e)) from e
        except PasskeyError as e:
            raise HTTPException(400, str(e)) from e

    @app.post("/v1/approvals/{approval_id}/respond", response_model=ApprovalRedeemResponse, tags=["Customer links"])
    def approval_respond(approval_id: str, body: RespondBody, x_approval_key: str | None = Header(default=None)) -> ApprovalRedeemResponse:
        try:
            pl.approval_view(approval_id, x_approval_key or "")  # key check before anything is written
            return pl.redeem_approval(approval_id, ApprovalRedeemRequest(channel="link", reply="approve" if body.action == "approve" else "reject"),
                                      link_key=x_approval_key, assertion=body.assertion)
        except PermissionError as e:
            raise HTTPException(403, str(e)) from e
        except LookupError as e:
            raise HTTPException(404, str(e)) from e

    @app.post("/v1/passkeys/enrollments/{enrollment_id}/options", tags=["Customer links"])
    def enroll_options(enrollment_id: str, x_enroll_key: str | None = Header(default=None)) -> Response:
        try:
            return Response(pl.passkeys.registration_options(enrollment_id, x_enroll_key or ""), media_type="application/json")
        except PasskeyError as e:
            raise HTTPException(403, str(e)) from e

    @app.post("/v1/passkeys/enrollments/{enrollment_id}/finish", tags=["Customer links"])
    def enroll_finish(enrollment_id: str, body: EnrollBody, x_enroll_key: str | None = Header(default=None)) -> dict[str, Any]:
        try:
            return pl.finish_passkey_enrollment(enrollment_id, x_enroll_key or "", body.credential)
        except PasskeyError as e:
            raise HTTPException(400, str(e)) from e

    # ---- the user signs a mandate with a passkey, holding a one-time link -------------------------------------------------
    @app.get("/v1/mandates/{mandate_id}/consent/view", tags=["Customer links"])
    def consent_view(mandate_id: str, x_consent_key: str | None = Header(default=None)) -> dict[str, Any]:
        try:
            return pl.consent_view(mandate_id, x_consent_key or "")
        except PermissionError as e:
            raise HTTPException(403, str(e)) from e

    @app.post("/v1/mandates/{mandate_id}/consent/passkey-options", tags=["Customer links"])
    def consent_options(mandate_id: str, x_consent_key: str | None = Header(default=None)) -> Response:
        try:
            return Response(pl.consent_passkey_options(mandate_id, x_consent_key or ""), media_type="application/json")
        except PermissionError as e:
            raise HTTPException(403, str(e)) from e
        except PasskeyError as e:
            raise HTTPException(400, str(e)) from e

    @app.post("/v1/mandates/{mandate_id}/consent/respond", tags=["Customer links"])
    def consent_respond(mandate_id: str, body: ConsentRespondBody, x_consent_key: str | None = Header(default=None)) -> dict[str, Any]:
        try:
            return pl.answer_consent(mandate_id, x_consent_key or "", body.action, body.assertion)
        except PermissionError as e:
            raise HTTPException(403, str(e)) from e

    # ---- a merchant reports that goods moved --------------------------------------------------------------------------
    @app.post("/v1/fulfillment", tags=["Merchant"])
    def fulfillment_event(body: FulfillmentBody) -> dict[str, Any]:
        try:
            return pl.record_fulfillment(body.event_jwt)
        except PermissionError as e:
            raise HTTPException(401, str(e)) from e
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        except LookupError as e:
            raise HTTPException(422, str(e)) from e

    # ---- the processor reports money that moved ----------------------------------------------------------------------
    @app.post("/v1/receipts", tags=["Processor"])
    def receipts(env: ReceiptEnvelope, caller: Actor = Depends(processor_check)) -> dict[str, Any]:
        try:
            return pl.record_receipt(env, caller)
        except PermissionError as e:
            raise HTTPException(422, str(e)) from e

    # ---- transparency -----------------------------------------------------------------------------------------------------
    @app.get("/v1/audit/records", tags=["Transparency"])
    def records(after: int | None = None, limit: int = 200) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 500))
        return pl.chain.since(after, limit) if after is not None else pl.chain.tail(limit)

    @app.get("/v1/audit/verify", tags=["Transparency"])
    def verify() -> dict[str, Any]:
        return pl.audit_verify()

    @app.get("/v1/audit/public-key", tags=["Transparency"])
    def public_key() -> dict[str, str]:
        return {"kid": pl.signer.kid, "pem": pl.signer.public_pem(), "alg": "ECDSA P-256 / SHA-256"}

    @app.get("/v1/audit/keys", tags=["Transparency"])
    def keys() -> dict[str, Any]:
        return pl.keys()

    @app.get("/v1/evidence/{sha256}", tags=["Transparency"])
    def evidence(sha256: str, authorization: str | None = Header(default=None)) -> Response:
        if not pl.settings.evidence_public and not dev:
            _verify(authorization, groups["admin"], "operator")
        data = pl.evidence.get(sha256)
        if data is None:
            raise HTTPException(404, "no evidence with that hash")
        return Response(data, media_type="application/json" if data[:1] in (b"{", b"[") else "text/plain; charset=utf-8")

    # ---- trusted surface and operator ------------------------------------------------------------------------------------
    @app.post("/v1/admin/mandates", tags=["Trusted surface"])
    def register_mandate(body: MandateRegistration, caller: Actor = Depends(surface_check)) -> dict[str, Any]:
        try:
            return pl.register_mandate(body.model_dump(exclude_unset=True), caller)
        except (ValueError, TypeError) as e:
            raise HTTPException(400, f"mandate not registered: {e}") from e

    @app.get("/v1/admin/mandates/{mandate_id}/consent", tags=["Trusted surface"])
    def mandate_consent_status(mandate_id: str, caller: Actor = Depends(surface_check)) -> dict[str, Any]:
        try:
            return pl.consent_status(mandate_id)
        except LookupError as e:
            raise HTTPException(404, str(e)) from e

    @app.post("/v1/admin/users/{user_id}/passkey-enrollments", tags=["Trusted surface"])
    def passkey_enrollment(user_id: str, caller: Actor = Depends(surface_check)) -> dict[str, Any]:
        return pl.start_passkey_enrollment(user_id, caller)

    @app.post("/v1/admin/agents", tags=["Operator"])
    def register_agent(body: AgentRegistration, caller: Actor = Depends(operator_check)) -> dict[str, Any]:
        try:
            return pl.register_agent(body.model_dump(), caller)
        except (ValueError, KeyError) as e:
            raise HTTPException(400, f"agent not registered: {e}") from e

    @app.post("/v1/admin/policy-approvers", tags=["Operator"])
    def register_policy_approver(body: ApproverRegistration, caller: Actor = Depends(operator_check)) -> dict[str, Any]:
        try:
            return pl.register_policy_approver(body.model_dump(), caller)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e

    @app.post("/v1/admin/merchants", tags=["Operator"])
    def register_merchant(body: MerchantRegistration, retire_previous: bool = True, caller: Actor = Depends(operator_check)) -> dict[str, Any]:
        entry = body.model_dump(exclude_unset=True)
        missing = [k for k in ("id", "name", "kid", "public_jwk") if not entry.get(k)]
        if missing:
            raise HTTPException(400, f"merchant entry is missing {missing}")
        try:
            return pl.register_merchant_key(entry, caller, retire_previous=retire_previous)
        except ValueError as e:
            raise HTTPException(409, str(e)) from e

    @app.delete("/v1/admin/agents/{agent_id}", tags=["Operator"])
    def revoke_agent(agent_id: str, caller: Actor = Depends(operator_check)) -> dict[str, Any]:
        try:
            return pl.revoke_agent(agent_id, caller)
        except LookupError as e:
            raise HTTPException(404, str(e)) from e

    @app.post("/v1/admin/clients", tags=["Operator"])
    def register_client(body: ClientRegistration, caller: Actor = Depends(operator_check)) -> dict[str, Any]:
        try:
            return pl.register_client(body.model_dump(), caller)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e

    @app.get("/v1/admin/clients", tags=["Operator"])
    def list_clients(caller: Actor = Depends(operator_check)) -> list[dict[str, Any]]:
        return [asdict(c) for c in pl.clients.all()]

    @app.delete("/v1/admin/clients/{client_id}", tags=["Operator"])
    def revoke_client(client_id: str, caller: Actor = Depends(operator_check)) -> dict[str, Any]:
        try:
            return pl.revoke_client(client_id, caller)
        except LookupError as e:
            raise HTTPException(404, str(e)) from e

    # ---- discovery: the base URL is the only setting a client needs ------------------------------------------------------
    @app.get("/.well-known/mandateguard", tags=["Transparency"])
    def discovery() -> dict[str, Any]:
        base = (pl.settings.public_url or "").rstrip("/")
        endpoints: dict[str, list[str]] = {}
        for r in app.routes:
            if isinstance(r, APIRoute) and r.include_in_schema:
                for tag in r.tags:
                    endpoints.setdefault(str(tag), []).extend(f"{m} {r.path}" for m in sorted(r.methods - {"HEAD"}))
        pem = pl.signer.public_pem()
        jwk = {**JWK.from_pem(pem.encode()).export_public(as_dict=True), "kid": pl.signer.kid, "alg": "ES256", "use": "sig"}
        return {
            "service": "MandateGuard", "version": __version__, "base_url": base or None,
            "openapi": f"{base}/openapi.json", "docs": f"{base}/api/docs", "console": f"{base}/console",
            "authentication": {"scheme": "Bearer: Google-signed ID token", "audience": base or None, "email_claim": "required",
                               "callers": "registered by the operator: POST /v1/admin/clients, or POST /v1/admin/agents for shopping agents",
                               "without_token": {"Customer links": "one-time key from the link", "Merchant": "ES256 signature with its registered key",
                                                 "Transparency": "public"}},
            "endpoints": endpoints,
            "ap2": {"version": "0.2", "sdk": "github.com/google-agentic-commerce/AP2 @ e1ea56d", "closed_payment_mandate_aud": "credential-provider",
                    "closed_checkout_mandate_aud": "merchant", "conditions_claim": "mg_conditions"},
            "webhooks": {"events": webhooks.EVENTS, "timeout_s": pl.settings.webhook_timeout_s, "retries": 0,
                         "signature": {"header": "MandateGuard-Signature", "algorithm": "ECDSA P-256 with SHA-256, DER, base64url",
                                       "signed_message": "<MandateGuard-Timestamp>.<raw body>", "key": "keys.decision_signer",
                                       "max_age_s": webhooks.MAX_AGE_S}},
            "keys": {"decision_signer": {"kid": pl.signer.kid, "pem": pem, "jwk": jwk}, "all": f"{base}/v1/audit/keys"},
            "limits": {"txn_minor": pl.settings.hnp_txn_cap_minor, "hour_minor": pl.settings.hnp_velocity_cap_minor,
                       "approval_ttl_s": pl.settings.approval_ttl_s, "consent_ttl_s": pl.settings.consent_ttl_s},
        }

    return app


app = create_app() if os.environ.get("MG_AUTOSTART", "0") == "1" else None
