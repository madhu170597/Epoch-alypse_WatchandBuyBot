"""The verdict pipeline and the chain of custody around it.

Stage 0  identity and input: the caller must be a registered agent, acting under a key the user delegated to;
         the user is taken from the mandate, never from the request. Then size limits, tool allow-list, page screen.
Stage 1  policy: verified AP2 facts and signed conditions against YAML packs (CEL). DENY is final.
Stage 2  Gemini: four isolated checks that can only tighten.
Stage 3  record: a signed, chained record naming the actor, with the request stored as evidence by hash.

Around the decision, every step that changes who may do what, or what happened to the money, is a chained
record too: policy loaded and approved, callers, agents and merchant keys registered or revoked, mandate registered and signed by the
user, passkey enrolled, plan committed before browsing, approval link issued, approval given or refused, credential
released, payment executed or refunded, order shipped and delivered.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from concurrent.futures import wait as wait_futures
from typing import Any

import rfc8785
from ap2.sdk.constraints import MandateContext
from jwcrypto.jwk import JWK

from jwcrypto.jws import JWS

from . import audit, fulfillment, obs, policy_approval, webhooks
from .ap2_adapter import AP2Verifier, VerifiedBundle, summarize_cart, summarize_open_mandates, summarize_payment
from .clients import ROLES as CLIENT_ROLES
from .clients import ClientEntry, ClientRegistry
from .counterparty import score_counterparty
from .credentials import TokenRejected, statement_digest
from .evidence import InMemoryEvidence, sha256_hex
from .gemini_checks import CheckOutput, GeminiChecks, to_findings
from .models import (Actor, ApprovalInfo, ApprovalRedeemRequest, ApprovalRedeemResponse, DecisionRequest, DecisionResponse, Finding,
                     PageExcerpt, PlanBody, ReceiptEnvelope, RecordInfo, Stage, Verdict, tighten)
from .pages import HttpPageFetcher, confirm_pages, host_of, merchant_hosts
from .passkeys import PasskeyError, Passkeys
from .registry import AgentEntry, AgentRegistry, ApproverEntry, ApproverRegistry, KeyConflict, MerchantRegistry, thumbprint
from .rules import engine as rules_engine
from .rules.facts import build_facts, normalize_plan
from .rules.render import money
from .stores import MandateRecord

log = logging.getLogger("mandateguard.pipeline")

HEADLINE_ALLOW = "Within mandate: merchant, items, amount, payee, conditions and expiry verified."
DISPOSITION = {"ALLOW": "Auto-Execute", "ESCALATE": "Escalate", "DENY": "Deny", "ALLOW_BY_HUMAN": "Escalate, approved by the user"}
DEV_AGENT = Actor(principal="dev", role="agent", verified_by="dev mode: caller not authenticated")
SELF = Actor(principal="mandateguard", role="mandateguard", verified_by="KMS signature on this record")


def _record_info(rec: dict[str, Any]) -> RecordInfo:
    return RecordInfo(seq=rec["seq"], hash=rec["hash"], prev_hash=rec["prev_hash"], signature=rec.get("signature"), signer_kid=rec.get("signer_kid"))


class _Snapshot:
    """The store reads one decision needs, started together up front so their round trips overlap with the AP2 checks.
    One payments read answers both the hourly-spend and the paid-before questions."""

    def __init__(self, stores: Any, pool: ThreadPoolExecutor, mandate_id: str, owner: str, nonce: str):
        self._s = stores
        self._f = {"consumed": pool.submit(stores.is_consumed, mandate_id), "nonce": pool.submit(stores.nonce_seen, nonce),
                   "payments": pool.submit(stores._payments, owner)}

    def __getattr__(self, name: str) -> Any:
        return getattr(self._s, name)

    def is_consumed(self, mandate_id: str) -> bool:
        return self._f["consumed"].result()

    def nonce_seen(self, nonce: str) -> bool:
        return self._f["nonce"].result()

    def velocity_minor(self, user_id: str, window_s: int = 3600) -> int:
        cutoff = time.time() - window_s
        return sum(int(p["amount_minor"]) for p in self._f["payments"].result() if p["ts"] >= cutoff)

    def paid_before(self, user_id: str, payee_id: str) -> bool:
        return any(p.get("payee_id") == payee_id for p in self._f["payments"].result())


def _service() -> dict[str, str]:
    return {"service": os.environ.get("K_SERVICE", "mandateguard-local"), "revision": os.environ.get("K_REVISION", "local")}


class Pipeline:
    def __init__(self, *, settings, stores, registry: MerchantRegistry, packs: rules_engine.PackStore, screener, gemini: GeminiChecks | None,
                 chain, signer, credentials, agents: AgentRegistry | None = None, evidence=None, processor_keys: dict[str, Any] | None = None,
                 clock=time.time, notifier=None, approvers: ApproverRegistry | None = None, page_fetcher=None,
                 clients: ClientRegistry | None = None, webhook_sender=None):
        self.settings = settings
        self.stores = stores
        self.registry = registry
        self.agents = agents or AgentRegistry()
        self.packs = packs
        self.screener = screener
        self.gemini = gemini
        self.chain = chain
        self.signer = signer
        self.credentials = credentials
        self.evidence = evidence or InMemoryEvidence()
        self.processor_keys = processor_keys or {}
        self.clock = clock
        self.notifier = notifier
        self.passkeys = Passkeys(settings.public_url, stores)
        self.verifier = AP2Verifier(registry, clock=clock)
        self.approvers = approvers or ApproverRegistry()
        self.approval_file = policy_approval.ApprovalFile(settings.packs_dir)
        self.policy_approvals: list[dict[str, Any]] = []
        self._approvals_checked = 0.0
        if page_fetcher is None and getattr(settings, "fetch_pages", False):
            page_fetcher = HttpPageFetcher(getattr(settings, "page_fetch_timeout_s", 3.0))
        self.page_fetcher = page_fetcher
        self.clients = clients or ClientRegistry()
        webhook_timeout = float(getattr(settings, "webhook_timeout_s", 2.0))
        self.webhook_sender = webhook_sender or webhooks.HttpWebhookSender(webhook_timeout)
        self._webhook_wait = webhook_timeout + 0.5
        self._io = ThreadPoolExecutor(max_workers=32, thread_name_prefix="mg-io")
        self._ledger = getattr(chain, "name", "chain")   # once-only markers are scoped to the ledger they were recorded in
        if hasattr(screener, "pool") and screener.pool is None:
            screener.pool = self._io
        self._policy_hash = ""

    # ======================================================================================= chain helper
    RESERVED = ("seq", "prev_hash", "ts_ms", "hash", "signature", "signer_kid")

    def _append(self, payload: dict[str, Any], actor: Actor, pending: list | None = None) -> dict[str, Any]:
        """Chain a record. With `pending`, its checkpoint is written in parallel with the rest of the request, which
        waits for it before answering (Cloud Run gives no CPU after the response, so nothing is left for later)."""
        clash = [k for k in self.RESERVED if k in payload]
        if clash:
            raise ValueError(f"record payload uses reserved chain fields: {clash}")
        rec = self.chain.append({**payload, "actor": actor.model_dump(), "by_service": _service()}, self.signer)
        if pending is not None:
            pending.append(self._io.submit(self._anchor, rec))
        else:
            self._anchor(rec)
        return rec

    def _anchor(self, rec: dict[str, Any]) -> None:
        try:
            self.evidence.anchor(rec)
        except Exception as e:  # noqa: BLE001 - a missed checkpoint is visible in /v1/audit/verify, it never blocks a decision
            log.warning("checkpoint for #%s not written: %s", rec["seq"], e)
            obs.emit("checkpoint_failed", "ERROR", seq=rec["seq"], error=str(e)[:200])

    def anchor_tail(self, limit: int = 500) -> int:
        """Write the checkpoints missing after the ledger's last one: records whose checkpoint write failed, or that were
        appended before checkpoints were kept per ledger. Each record is re-verified first (hash, link to the previous
        record, signature); anchoring stops at the first that fails, so a damaged record is never anchored."""
        cps = self.evidence.checkpoints(limit=1)
        last = cps[-1] if cps else None
        prev = last["hash"] if last else audit.GENESIS
        good = []
        for rec in self.chain.since(last["seq"] if last else -1, limit):
            if rec.get("prev_hash") != prev or audit.record_hash(rec) != rec.get("hash") or not self.signer.verify(rec["hash"], rec.get("signature") or ""):
                obs.emit("checkpoint_failed", "ERROR", seq=rec.get("seq"), error="record does not verify; not anchored")
                break
            good.append(rec)
            prev = rec["hash"]
        list(self._io.map(self._anchor, good))
        return len(good)

    def check_policy_approvals(self, force: bool = False) -> list[dict[str, Any]]:
        """Which loaded packs carry a valid approver signature. Re-checked at most once a minute, or when forced."""
        self.packs.maybe_reload()
        if force or self.clock() - self._approvals_checked > 60 or len(self.policy_approvals) != len(self.packs.packs):
            self.policy_approvals = policy_approval.check(self.packs.packs, self.approval_file.load(), self.approvers)
            self._approvals_checked = self.clock()
        return self.policy_approvals

    def ensure_policy_recorded(self, force: bool = False) -> None:
        """One chained `policy.loaded` record per distinct policy version and approval state, written once across all instances."""
        approvals = self.check_policy_approvals(force=force)
        h = self.packs.packs_hash
        key = f"{h}:{policy_approval.state_digest(approvals)}"
        if key == self._policy_hash:
            return
        if self.stores.mark_once("policy", f"{self._ledger}:{key}"):
            by_pack = {(a["pack"], a["version"]): a for a in approvals}
            packs = []
            for p in self.packs.packs:
                a = by_pack.get((p.name, p.version), {})
                packs.append({"name": p.name, "version": p.version, "owner": p.owner, "approved_by": p.approved_by, "effective": p.effective,
                              "rules": len(p.rules), "file_sha256": self.evidence.put(p.raw, "text/yaml"),
                              "approval": {k: a.get(k) for k in ("verified", "problem", "approved_by", "approved_at", "statement", "signature",
                                                                 "approver_thumbprint") if k in a}})
            n_ok = sum(1 for a in approvals if a["verified"])
            self._append({"type": "policy.loaded", "packs_hash": h, "packs": packs, "approvals_verified": n_ok, "approvals_total": len(approvals),
                          "headline": "Policy loaded: " + ", ".join(f"{p['name']} v{p['version']}" for p in packs)
                                      + f"; approver signatures verified: {n_ok} of {len(approvals)}."}, SELF)
        self._policy_hash = key

    # ======================================================================================= registrations
    def register_agent(self, body: dict[str, Any], actor: Actor) -> dict[str, Any]:
        entry = AgentEntry(agent_id=str(body["agent_id"]), principals=[str(p) for p in body.get("principals", [])],
                           key_thumbprints=[str(k) for k in body.get("key_thumbprints", [])], operator=str(body.get("operator", "")),
                           description=str(body.get("description", "")), registered_by=actor.principal,
                           webhook_url=webhooks.check_url(str(body.get("webhook_url") or "")))
        if not entry.principals or not entry.key_thumbprints:
            raise ValueError("an agent needs at least one principal and one key thumbprint")
        cur = self.agents.get(entry.agent_id)
        if cur and cur.status == "active" and (sorted(cur.principals), sorted(cur.key_thumbprints), cur.operator, cur.description, cur.webhook_url) == (
                sorted(entry.principals), sorted(entry.key_thumbprints), entry.operator, entry.description, entry.webhook_url) \
                and self.chain.find_by("agent_id", entry.agent_id, "agent.registered"):
            return {"agent_id": entry.agent_id, "unchanged": True}
        prev = self.agents.register(entry)
        rec = self._append({"type": "agent.registered", "agent_id": entry.agent_id, "principals": entry.principals,
                            "key_thumbprints": entry.key_thumbprints, "operator": entry.operator, "description": entry.description,
                            "webhook_host": host_of(entry.webhook_url) or None,
                            "previous": {"principals": prev.principals, "key_thumbprints": prev.key_thumbprints} if prev else None,
                            "headline": f"Agent {entry.agent_id} registered by {actor.principal}"}, actor)
        return {"agent_id": entry.agent_id, "record_seq": rec["seq"]}

    def revoke_agent(self, agent_id: str, actor: Actor) -> dict[str, Any]:
        cur = self.agents.get(agent_id)
        if cur is None:
            raise LookupError(f"agent {agent_id} is not registered")
        if cur.status != "active":
            return {"agent_id": agent_id, "unchanged": True}
        self.agents.revoke(agent_id)
        rec = self._append({"type": "agent.revoked", "agent_id": agent_id, "principals": cur.principals, "key_thumbprints": cur.key_thumbprints,
                            "headline": f"Agent {agent_id} revoked by {actor.principal}"}, actor)
        return {"agent_id": agent_id, "record_seq": rec["seq"]}

    def register_client(self, body: dict[str, Any], actor: Actor) -> dict[str, Any]:
        """The operator lets a service call in one role, and names where that role's events go. It takes effect at once,
        without a redeploy, and is a chained record."""
        entry = ClientEntry(client_id=str(body.get("client_id", "")), role=str(body.get("role", "")),
                            principals=[str(p) for p in body.get("principals", [])], webhook_url=webhooks.check_url(str(body.get("webhook_url") or "")),
                            description=str(body.get("description", "")), registered_by=actor.principal)
        if not entry.client_id or not entry.principals:
            raise ValueError("a client needs a client_id and at least one principal")
        if entry.role not in CLIENT_ROLES:
            raise ValueError(f"role must be one of {', '.join(CLIENT_ROLES)}; shopping agents are registered at /v1/admin/agents")
        cur = self.clients.get(entry.client_id)
        if cur and cur.status == "active" and (cur.role, sorted(cur.principals), cur.webhook_url, cur.description) == (
                entry.role, sorted(entry.principals), entry.webhook_url, entry.description) \
                and self.chain.find_by("client_id", entry.client_id, "client.registered"):
            return {"client_id": entry.client_id, "unchanged": True}
        prev = self.clients.register(entry)
        rec = self._append({"type": "client.registered", "client_id": entry.client_id, "role": entry.role, "principals": entry.principals,
                            "webhook_host": host_of(entry.webhook_url) or None, "description": entry.description,
                            "previous": {"role": prev.role, "principals": prev.principals, "status": prev.status} if prev else None,
                            "headline": f"Client {entry.client_id} registered as {entry.role.replace('_', ' ')} by {actor.principal}"}, actor)
        return {"client_id": entry.client_id, "role": entry.role, "record_seq": rec["seq"]}

    def revoke_client(self, client_id: str, actor: Actor) -> dict[str, Any]:
        cur = self.clients.get(client_id)
        if cur is None:
            raise LookupError(f"client {client_id} is not registered")
        if cur.status != "active":
            return {"client_id": client_id, "unchanged": True}
        self.clients.revoke(client_id)
        rec = self._append({"type": "client.revoked", "client_id": client_id, "role": cur.role, "principals": cur.principals,
                            "headline": f"Client {client_id} revoked by {actor.principal}"}, actor)
        return {"client_id": client_id, "record_seq": rec["seq"]}

    def caller_allowed(self, role: str, principal: str) -> bool:
        """Registered callers, in addition to the MG_*_CALLERS lists. A registered, active agent may call as an agent."""
        if role == "agent":
            return self.agents.by_principal(principal) is not None
        return self.clients.allows(role, principal) is not None

    # ======================================================================================= events to registered clients
    def _push(self, event: str, data: dict[str, Any], to: list[tuple[str, str]], pending: list, delivered=None) -> None:
        """Send one signed event to each (principal, url), alongside the rest of the request. See webhooks.py."""
        for principal, url in to:
            def send(principal: str = principal, url: str = url) -> None:
                try:
                    body, headers = webhooks.build(event, data, self.signer, self.clock())
                    status = self.webhook_sender(url, body, headers)
                    if not 200 <= status < 300:
                        obs.emit("webhook_failed", "WARNING", webhook_event=event, to=principal, status=status)
                        return
                    obs.emit("webhook", webhook_event=event, to=principal, status=status, delivery=headers["MandateGuard-Delivery"])
                    if delivered is not None:
                        delivered(principal, headers["MandateGuard-Delivery"])
                except Exception as e:  # noqa: BLE001 - a missed event is logged; the pull endpoints still answer
                    obs.emit("webhook_failed", "WARNING", webhook_event=event, to=principal, error=str(e)[:200])
            pending.append(self._io.submit(send))

    def _approval_answered(self, apr: dict[str, Any], original: dict[str, Any], status: str, record: dict[str, Any] | None) -> None:
        """Tell the agent that asked for the decision how the customer answered. The token itself stays behind GET /v1/approvals/{id}."""
        agent = self.agents.get(str(original.get("agent_id") or "")) if original.get("agent_id") else None
        if agent is None or agent.status != "active" or not agent.webhook_url:
            return
        pending: list = []
        self._push("approval.answered", {"approval_id": apr["approval_id"], "decision_id": apr["decision_id"], "status": status,
                                         "result_decision_id": (record or {}).get("decision_id"), "record_seq": (record or {}).get("seq")},
                   [(agent.principals[0], agent.webhook_url)], pending)
        wait_futures(pending, timeout=self._webhook_wait)

    def register_merchant_key(self, body: dict[str, Any], actor: Actor, retire_previous: bool = True) -> dict[str, Any]:
        try:
            change = self.registry.register_key(body, by=actor.principal, retire_previous=retire_previous)
        except KeyConflict as e:
            raise ValueError(str(e)) from e
        if change is None:
            if self.chain.find_by("kid", body["kid"], "merchant.key_registered"):
                return {"id": body["id"], "kid": body["kid"], "unchanged": True}
            key, prof = self.registry.lookup_key(body["kid"], include_retired=True)       # a fresh ledger: record the key in force
            change = {"profile": prof, "key": {k: key[k] for k in ("kid", "thumbprint", "status", "public_jwk")}, "retired_kids": []}
        prof = change["profile"]
        if "profile_changed" in change:
            what = "; ".join(f"{k} {v['from']} to {v['to']}" for k, v in change["profile_changed"].items())
            rec = self._append({"type": "merchant.profile_updated", "merchant": {k: prof.get(k) for k in ("id", "name", "website", "rating", "rating_source")},
                                "kid": body["kid"], "changes": change["profile_changed"],
                                "headline": f"Merchant {prof.get('name')} profile updated by {actor.principal}: {what}"}, actor)
            return {"id": body["id"], "kid": body["kid"], "record_seq": rec["seq"], "profile_changed": change["profile_changed"]}
        rec = self._append({"type": "merchant.key_registered", "merchant": {k: prof.get(k) for k in ("id", "name", "website", "rating", "rating_source")},
                            "kid": change["key"]["kid"], "key_thumbprint": change["key"]["thumbprint"], "public_jwk": change["key"]["public_jwk"],
                            "retired_kids": change["retired_kids"],
                            "headline": f"Merchant {prof.get('name')} signing key {change['key']['kid']} registered by {actor.principal}"}, actor)
        return {"id": body["id"], "kid": body["kid"], "record_seq": rec["seq"], "retired_kids": change["retired_kids"]}

    def register_policy_approver(self, body: dict[str, Any], actor: Actor) -> dict[str, Any]:
        """The operator names who may approve policy packs, with their public key. Approvals then verify by signature."""
        aid, jwk = str(body.get("approver_id", "")), body.get("public_jwk")
        if not aid or not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or "d" in jwk:
            raise ValueError("an approver needs an approver_id and a public P-256 key")
        tp = thumbprint(jwk)
        cur = self.approvers.get(aid)
        if cur and cur.thumbprint == tp and cur.status == "active" and cur.name == str(body.get("name", cur.name)) \
                and self.chain.find_by("approver_id", aid, "policy.approver_registered"):
            return {"approver_id": aid, "unchanged": True}
        entry = ApproverEntry(approver_id=aid, public_jwk={k: jwk[k] for k in ("kty", "crv", "x", "y")}, thumbprint=tp,
                              name=str(body.get("name", "")), registered_by=actor.principal)
        prev = self.approvers.register(entry)
        rec = self._append({"type": "policy.approver_registered", "approver_id": aid, "name": entry.name, "public_jwk": entry.public_jwk,
                            "key_thumbprint": tp, "previous_thumbprint": prev.thumbprint if prev else None,
                            "headline": f"Policy approver {aid} registered by {actor.principal}"}, actor)
        self.ensure_policy_recorded(force=True)
        return {"approver_id": aid, "record_seq": rec["seq"]}

    def register_mandate(self, body: dict[str, Any], actor: Actor) -> dict[str, Any]:
        """Called by the user's trusted surface after the user approved the summary. Verifies the signed open mandates
        and the signed intent commitment before anything is stored, and chains who registered it and how consent was given."""
        for f in ("mandate_id", "user_id", "intent_text", "open_checkout_mandate", "open_payment_mandate", "user_public_jwk"):
            if not body.get(f):
                raise ValueError(f"missing {f}")
        mode = getattr(self.settings, "consent_passkey", "requested")
        enrolled = self.passkeys.has_passkey(str(body["user_id"]))
        want_passkey = bool(body.get("passkey_consent")) or mode == "always" or (mode == "if-enrolled" and enrolled)
        if want_passkey and not enrolled:
            raise ValueError("customer has no registered passkey; issue an enrollment link first")
        reg_bytes = rfc8785.dumps(body)
        reg_sha = self.evidence.put(reg_bytes)
        vb = VerifiedBundle()
        signer = JWK.from_json(json.dumps(body["user_public_jwk"]))
        self.verifier.verify_open_mandates(vb, body["open_checkout_mandate"], body["open_payment_mandate"], signer)
        problems = list(vb.errors)
        conds = vb.conditions or {}
        if conds:
            from .conditions import commit

            salt = str(body.get("intent_salt", ""))
            if commit(body["intent_text"], salt) != conds.get("intent_sha256"):
                problems.append("the request text does not match the signed intent commitment")
            if commit(str(body.get("summary_text", "")), salt) != conds.get("summary_sha256"):
                problems.append("the summary shown does not match the signed summary commitment")
        review = None
        if not problems:
            review = self._intent_review(body, vb)
            if review and review["verdict"] == "DENY":
                problems.append("signed mandate does not match the customer's request: " + (review["findings"] or [review["rationale"]])[0])
        if problems:
            self._append({"type": "mandate.rejected", "mandate_id": body["mandate_id"], "user_id": body["user_id"], "problems": problems,
                          "evidence": {"sha256": reg_sha, "uri": self.evidence.uri(reg_sha)},
                          "headline": f"Mandate {body['mandate_id']} refused: {problems[0]}"}, actor)
            raise ValueError("; ".join(problems))
        agent = self.agents.by_key(vb.agent_key_thumbprint or "")
        consent = dict(body.get("consent") or {"method": "not recorded"})
        consent["attested_by"] = actor.principal
        consent["passkey_required"] = want_passkey
        summary = summarize_open_mandates(vb)
        instruction = None
        if isinstance(body.get("instruction"), dict):
            ins = body["instruction"]
            ins_sha = self.evidence.put(rfc8785.dumps(ins))
            instruction = {"channel": str(ins.get("channel", "")), "message_id": str(ins.get("message_id", "")), "received_at": ins.get("received_at"),
                           "sha256": ins_sha, "uri": self.evidence.uri(ins_sha), "attested_by": actor.principal}
        rec = self._append({
            "type": "mandate.registered", "mandate_id": body["mandate_id"], "user_id": body["user_id"],
            "signer_thumbprint": vb.signer_thumbprint, "open_checkout_hash": vb.open_checkout_hash, "open_payment_hash": vb.open_payment_hash,
            "delegated_key_thumbprint": vb.agent_key_thumbprint, "delegated_agent_id": agent.agent_id if agent else None,
            "constraints": {"merchants": summary["allowed_merchants"], "items": summary["allowed_items"], "min_minor": summary["min_minor"],
                            "max_minor": summary["max_minor"], "currency": summary["currency"], "expires_at": summary["exp"]},
            "conditions": conds, "intent_commitment_verified": bool(conds), "consent": consent,
            "consent_status": "awaiting the user's passkey" if want_passkey else "attested by the trusted surface",
            "intent_review": review,
            "instruction": instruction,
            "linked_channels": sorted((body.get("linked_channels") or {}).keys()),
            "evidence": {"sha256": reg_sha, "uri": self.evidence.uri(reg_sha)},
            "headline": f"Mandate {body['mandate_id']} registered for {body['user_id']} by {actor.principal}"}, actor)
        known = {k for k in MandateRecord.__dataclass_fields__}
        mrec = MandateRecord(**{k: v for k, v in body.items() if k in known and k not in ("conditions", "consent", "registered_by", "registration_seq",
                                                                                          "registration_evidence", "signer_thumbprint", "delegated_key_thumbprint")})
        mrec.conditions, mrec.consent, mrec.registered_by = conds, consent, actor.principal
        mrec.registration_seq, mrec.registration_evidence = rec["seq"], reg_sha
        mrec.signer_thumbprint, mrec.delegated_key_thumbprint = vb.signer_thumbprint or "", vb.agent_key_thumbprint or ""
        mrec.consent_required = want_passkey
        mrec.intent_review = review or {}
        self.stores.put_mandate(mrec)
        out = {"mandate_id": body["mandate_id"], "record_seq": rec["seq"], "delegated_agent_id": agent.agent_id if agent else None,
               "conditions_signed": bool(conds), "consent_required": want_passkey}
        if want_passkey:
            statement = {"type": "mandate.consent", "mandate_id": body["mandate_id"], "user_id": body["user_id"],
                         "registration_record_hash": rec["hash"], "open_checkout_hash": vb.open_checkout_hash, "open_payment_hash": vb.open_payment_hash,
                         "intent_sha256": conds.get("intent_sha256"), "summary_sha256": conds.get("summary_sha256"),
                         "conditions_sha256": sha256_hex(rfc8785.dumps(conds)) if conds else None,
                         "min_minor": summary["min_minor"], "max_minor": summary["max_minor"], "currency": summary["currency"],
                         "merchant_ids": [m["id"] for m in summary["allowed_merchants"]], "expires_at": summary["exp"]}
            display = {"intent_text": body["intent_text"], "summary_text": body.get("summary_text", ""), "merchants": summary["allowed_merchants"],
                       "items": summary["allowed_items"], "min_minor": summary["min_minor"], "max_minor": summary["max_minor"],
                       "currency": summary["currency"], "expires_at": summary["exp"], "conditions": conds,
                       "instruction_text": str((body.get("instruction") or {}).get("text", ""))[:2000]}
            creq = self.stores.create_consent_request(body["mandate_id"], {"user_id": body["user_id"], "statement": statement, "display": display,
                                                                           "registration_seq": rec["seq"]}, getattr(self.settings, "consent_ttl_s", 900))
            out["consent_link"] = self.consent_link(creq)
            out["consent_expires_at"] = creq["expires_at"]
        return out

    def _intent_review(self, body: dict[str, Any], vb: VerifiedBundle) -> dict[str, Any] | None:
        """Once per mandate, while nobody is waiting on a purchase: do the signed limits say what the user's own words said?"""
        if self.gemini is None:
            return None
        words = str((body.get("instruction") or {}).get("text") or body["intent_text"])
        budget = float(getattr(self.settings, "gemini_timeout_s", 10.0)) + 5
        fut = self._io.submit(self.gemini.intent_fidelity, words, str(body.get("summary_text", "")), summarize_open_mandates(vb), vb.conditions)
        try:
            out = fut.result(timeout=budget)
        except FutureTimeout:
            return {"verdict": "ESCALATE", "findings": [], "rationale": "timeout", "model": self.gemini.label}
        m = out._meta or {}
        return {"verdict": out.verdict, "findings": out.findings, "rationale": out.rationale, "model": self.gemini.label,
                "model_version": m.get("model_version"), "ms": m.get("ms"), "words_sha256": sha256_hex(words.encode())}

    # ======================================================================================= the user signs the mandate
    def consent_link(self, creq: dict[str, Any]) -> str:
        return f"{(self.settings.public_url or '').rstrip('/')}/consent/{creq['mandate_id']}#k={creq['key']}"

    def _open_consent(self, mandate_id: str, key: str) -> dict[str, Any]:
        c = self.stores.get_consent(mandate_id)
        if c is None or not hmac.compare_digest(str(c.get("key", "")), str(key or "")):
            raise PermissionError("Invalid link.")
        return c

    def _consent_status(self, c: dict[str, Any]) -> str:
        return "expired" if c["status"] == "awaiting" and self.clock() > c["expires_at"] else c["status"]

    def consent_view(self, mandate_id: str, key: str) -> dict[str, Any]:
        c = self._open_consent(mandate_id, key)
        return {"mandate_id": mandate_id, "user_id": c["user_id"], "status": self._consent_status(c), "expires_at": c["expires_at"], "now": self.clock(),
                "display": c.get("display", {}), "statement": {**c["statement"], "action": "sign"},
                "passkey": {"enrolled": self.passkeys.has_passkey(c["user_id"])}, "result_seq": c.get("result_seq")}

    def consent_passkey_options(self, mandate_id: str, key: str) -> str:
        c = self._open_consent(mandate_id, key)
        if self._consent_status(c) != "awaiting":
            raise PermissionError("Mandate is no longer open for signing.")
        return self.passkeys.assertion_options(c["user_id"], Passkeys.statement_challenge({**c["statement"], "action": "sign"}))

    def answer_consent(self, mandate_id: str, key: str, action: str, assertion: dict[str, Any] | None = None) -> dict[str, Any]:
        c = self._open_consent(mandate_id, key)
        user = c["user_id"]
        statement = {**c["statement"], "action": "sign" if action == "sign" else "decline"}
        reason, human = None, None
        status = self._consent_status(c)
        if status == "expired":
            reason = "Signing request expired."
        elif status != "awaiting":
            reason = "Mandate already answered."
        elif action == "sign":
            if not assertion:
                reason = "Passkey signature required."
            else:
                try:
                    human = {**self.passkeys.verify_assertion(user, assertion, Passkeys.statement_challenge(statement)), "statement": statement}
                except PasskeyError as e:
                    reason = str(e)
        if reason:
            self._append({"type": "mandate.consent_refused", "mandate_id": mandate_id, "user_id": user, "reason": reason,
                          "headline": f"Mandate {mandate_id} signature refused: {reason}"},
                         Actor(principal="holder of the consent link", role="user", verified_by="one-time consent link; no valid passkey signature"))
            obs.emit("consent_refused", "WARNING", mandate_id=mandate_id, reason=reason)
            raise PermissionError(reason)
        result = "signed" if action == "sign" else "declined"
        try:
            self.stores.answer_consent(mandate_id, result)
        except ValueError as e:
            raise PermissionError(str(e)) from e
        if result == "signed":
            rec = self._append({"type": "mandate.consented", "mandate_id": mandate_id, "user_id": user, "registration_seq": c.get("registration_seq"),
                                "statement": statement, "human": human,
                                "headline": f"Mandate {mandate_id} signed by {user} (passkey)"},
                               Actor(principal=user, role="user", verified_by="passkey assertion over the mandate statement"))
        else:
            rec = self._append({"type": "mandate.consent_declined", "mandate_id": mandate_id, "user_id": user, "registration_seq": c.get("registration_seq"),
                                "headline": f"Mandate {mandate_id} declined by {user}"},
                               Actor(principal=user, role="user", verified_by="one-time consent link"))
        self.stores.update_consent(mandate_id, {"result_seq": rec["seq"]})
        obs.emit("consent", mandate_id=mandate_id, result=result, seq=rec["seq"])
        by = getattr(self.stores.get_mandate(mandate_id), "registered_by", "")
        to = [(by, c.webhook_url) for c in self.clients.active("trusted_surface") if c.webhook_url and by in c.principals]
        if to:
            pending: list = []
            self._push("mandate.consent_answered", {"mandate_id": mandate_id, "user_id": user, "status": result, "record_seq": rec["seq"]}, to, pending)
            wait_futures(pending, timeout=self._webhook_wait)
        return {"mandate_id": mandate_id, "status": result, "record_seq": rec["seq"]}

    def consent_status(self, mandate_id: str) -> dict[str, Any]:
        """For the trusted surface: has the user signed yet."""
        c = self.stores.get_consent(mandate_id)
        if c is None:
            if self.stores.get_mandate(mandate_id) is None:
                raise LookupError("unknown mandate")
            return {"mandate_id": mandate_id, "status": "not required"}
        return {"mandate_id": mandate_id, "status": self._consent_status(c), "expires_at": c["expires_at"], "record_seq": c.get("result_seq")}

    # ======================================================================================= the agent commits its plan
    def commit_plan(self, body: PlanBody, caller: Actor) -> dict[str, Any]:
        """Before browsing, the agent states what it means to buy. MandateGuard's clock and signature fix that plan,
        so the drift check compares the cart with a plan the agent could not rewrite after reading a page."""
        agent = self.agents.by_principal(caller.principal)
        if agent is None:
            raise PermissionError(f"{caller.principal} is not a registered shopping agent")
        mrec = self.stores.get_mandate(body.mandate_id)
        if mrec is None:
            raise LookupError(f"mandate {body.mandate_id} is not on record")
        if mrec.delegated_key_thumbprint and mrec.delegated_key_thumbprint not in agent.key_thumbprints:
            raise PermissionError(f"mandate {body.mandate_id} is delegated to another agent's key")
        plan = normalize_plan(body.model_dump())
        sha = sha256_hex(rfc8785.dumps(plan))
        pid = "pln_" + uuid.uuid4().hex[:20]
        items = ", ".join(f"{i['qty']}× {i['sku']}" for i in plan["items"])
        rec = self._append({"type": "plan.committed", "plan_id": pid, "mandate_id": body.mandate_id, "user_id": mrec.user_id, "agent_id": agent.agent_id,
                            "plan": plan, "plan_sha256": sha, "note": body.note,
                            "headline": f"Plan committed by {agent.agent_id}: {items}; payee {plan['payee_id']}"}, caller)
        committed_at = rec["ts_ms"] / 1000
        self.stores.put_plan({"plan_id": pid, "mandate_id": body.mandate_id, "agent_id": agent.agent_id, "plan": plan, "plan_sha256": sha,
                              "record_seq": rec["seq"], "committed_at": committed_at})
        return {"plan_id": pid, "plan_sha256": sha, "record_seq": rec["seq"], "committed_at": committed_at}

    def plan_checks(self, req: DecisionRequest, agent: AgentEntry | None, wplan: dict[str, Any] | None) -> list[Finding]:
        out: list[Finding] = []

        def deny(code: str, title: str, message: str) -> None:
            out.append(Finding(stage=Stage.S0, code=code, outcome=Verdict.DENY, title=title, message=message, rank=3, source="Plan witness"))

        if req.plan_id and wplan is None:
            deny("plan.unknown", "Plan not on record", f"Plan {req.plan_id} is not on record.")
        elif wplan is not None and wplan["mandate_id"] != req.mandate_id:
            deny("plan.other_mandate", "Plan bound to another mandate", f"Plan {req.plan_id} was committed for mandate {wplan['mandate_id']}, not {req.mandate_id}.")
        elif wplan is not None and agent is not None and wplan["agent_id"] != agent.agent_id:
            deny("plan.other_agent", "Plan committed by another agent", f"Plan {req.plan_id} was committed by {wplan['agent_id']}, not {agent.agent_id}.")
        return out

    def start_passkey_enrollment(self, user_id: str, actor: Actor) -> dict[str, Any]:
        enr = self.passkeys.start_enrollment(user_id, actor.principal)
        base = (self.settings.public_url or "").rstrip("/")
        return {"enrollment_id": enr["enrollment_id"], "user_id": user_id, "expires_at": enr["expires_at"],
                "link": f"{base}/enroll/{enr['enrollment_id']}#k={enr['key']}"}

    def finish_passkey_enrollment(self, enrollment_id: str, key: str, credential: dict[str, Any]) -> dict[str, Any]:
        pk = self.passkeys.finish_enrollment(enrollment_id, key, credential)
        rec = self._append({"type": "user.passkey_enrolled", "user_id": pk["user_id"], "credential_id_sha256": pk["credential_id_sha256"],
                            "public_jwk": pk["public_jwk"], "aaguid": pk["aaguid"], "device_type": pk["device_type"], "backed_up": pk["backed_up"],
                            "rp_id": pk["rp_id"], "enrollment_id": enrollment_id, "enrollment_created_by": pk["enrollment_created_by"],
                            "headline": f"{pk['user_id']} enrolled a passkey"},
                           Actor(principal=pk["user_id"], role="user",
                                 verified_by=f"passkey created through a one-time link issued by {pk['enrollment_created_by']}"))
        self.stores.update_passkey(pk["credential_id"], {"enrolled_record_seq": rec["seq"]})
        return {"user_id": pk["user_id"], "record_seq": rec["seq"], "credential_id_sha256": pk["credential_id_sha256"]}

    # ======================================================================================= stage 0
    def identity(self, req: DecisionRequest, caller: Actor, mrec: MandateRecord | None) -> tuple[list[Finding], AgentEntry | None]:
        """SAFR's Agent Identity component: before policy, confirm who is asking and on whose behalf."""
        out: list[Finding] = []

        def deny(code: str, title: str, message: str, rank: int = 1) -> None:
            out.append(Finding(stage=Stage.S0, code=code, outcome=Verdict.DENY, title=title, message=message, rank=rank, source="Agent identity"))

        agent = self.agents.by_principal(caller.principal)
        if agent is None:
            deny("identity.agent_unregistered", "Unregistered caller", f"Caller {caller.principal} is not a registered agent.")
        elif req.agent_id and req.agent_id != agent.agent_id:
            deny("identity.agent_claim_mismatch", "Agent identity mismatch", f"Request names agent {req.agent_id}; verified caller is {agent.agent_id}.")
        if mrec is None:
            deny("identity.mandate_unknown", "Mandate not registered", f"Mandate {req.mandate_id} is not registered.", rank=2)
        elif req.user_id and req.user_id != mrec.user_id:
            deny("identity.user_mismatch", "Customer mismatch", f"Request names customer {req.user_id}; mandate belongs to {mrec.user_id}.")
        if mrec is not None and getattr(mrec, "consent_required", False):
            st = (self.stores.get_consent(mrec.mandate_id) or {}).get("status")
            if st == "declined":
                deny("identity.consent_declined", "Mandate declined", f"Mandate {mrec.mandate_id} was declined by {mrec.user_id}.")
            elif st != "signed":
                deny("identity.consent_missing", "Mandate not signed", f"Mandate {mrec.mandate_id} awaits the customer's passkey signature.")
        return out, agent

    def stage0(self, req: DecisionRequest, page_checks: list[dict[str, Any]] | None = None,
               agent_screen: Any = None) -> tuple[list[Finding], dict[str, Any], list[dict[str, Any]]]:
        findings: list[Finding] = []
        s = self.settings

        def add(code: str, title: str, message: str, detail: Any = None) -> None:
            findings.append(Finding(stage=Stage.S0, code=code, outcome=Verdict.DENY, title=title, message=message,
                                    detail=detail, rank=9, source="Input guardrails"))

        if len(req.pages) > s.max_pages:
            add("too_many_pages", "Page limit exceeded", f"{len(req.pages)} page excerpts submitted; limit {s.max_pages}.")
        if len(req.trace) > s.max_trace_events:
            add("trace_too_long", "Trace limit exceeded", f"{len(req.trace)} trace steps submitted; limit {s.max_trace_events}.")
        seqs = [e.seq for e in req.trace]
        if len(seqs) != len(set(seqs)):
            add("trace_seq_duplicate", "Trace inconsistent", "Duplicate sequence numbers in the agent trace.")
        bad_tools = sorted({e.tool for e in req.trace if e.kind == "tool_call" and s.allowed_tools and e.tool not in s.allowed_tools})
        if bad_tools:
            add("tool_not_allowed", "Tool not permitted", f"Agent invoked tools outside its allow-list: {', '.join(bad_tools)}.", bad_tools)
        if page_checks is None:
            page_checks = confirm_pages(req.pages, merchant_hosts(self.registry.all()), self.page_fetcher) if req.pages else []
        # a page that differs from the merchant's own copy is screened in both versions; the stricter result applies
        differing = [PageExcerpt(url=f"{c['url']} (MandateGuard's copy)", content=c["text"][:200_000])
                     for c in page_checks if c.get("fetched") and c.get("matches") is False]
        if agent_screen is not None and not differing:
            screen = agent_screen.result()
        elif req.pages:
            screen = self.screener.screen_pages(list(req.pages) + differing)
        else:
            screen = {"match": False, "confidence": "NONE", "signals": [], "addressed_to_guard": False, "provider": "none",
                      "pages_screened": 0, "excerpts": [], "by_provider": {}}
        if screen["match"]:
            findings.append(Finding(stage=Stage.S0, code="page_injection_screen", outcome=Verdict.DENY if screen["confidence"] == "HIGH" else Verdict.ESCALATE,
                                    title="Page screen", message=f"Page screen risk: {screen['confidence'].lower()}.",
                                    detail=screen["signals"], rank=90, source=f"Injection screen · {screen.get('provider', '')}"))
        return findings, screen, page_checks

    # ======================================================================================= stage 1
    def stage1(self, req: DecisionRequest, screen: dict[str, Any], rec: MandateRecord | None, witnessed_plan: dict[str, Any] | None = None,
               page_checks: list[dict[str, Any]] | None = None, snapshot: Any = None,
               timings: dict[str, int] | None = None) -> tuple[rules_engine.RuleResult, VerifiedBundle, dict[str, Any]]:
        stores = snapshot or self.stores
        t = [time.perf_counter()]

        def mark(name: str) -> None:
            t.append(time.perf_counter())
            if timings is not None:
                timings[name] = int((t[-1] - t[-2]) * 1000)

        if rec is None:
            vb = VerifiedBundle(errors=[f"mandate {req.mandate_id} is not on record"])
        else:
            user_pub = JWK.from_json(json.dumps(rec.user_public_jwk))
            vb = self.verifier.verify(
                open_checkout=rec.open_checkout_mandate, open_payment=rec.open_payment_mandate, user_pub=user_pub,
                checkout_jwt=req.ap2.checkout_jwt, payment_chain=req.ap2.payment_mandate_chain, payment_nonce=req.ap2.payment_nonce,
                checkout_chain=req.ap2.checkout_mandate_chain, checkout_nonce=req.ap2.checkout_nonce, usage=self.stores.usage_for(""),
            )
        mark("ap2_verify")
        cart = summarize_cart(vb)
        owner = rec.user_id if rec else (req.user_id or "")
        payee_src = summarize_payment(vb)["payee"] if vb.closed_payment else cart["merchant"]
        payee_scores = score_counterparty(payee_src, self.registry.all(), paid_before=stores.paid_before(owner, payee_src.get("id", "")))
        mark("counterparty")
        facts = build_facts(req, vb, mandate_rec=rec, stores=stores, payee_scores=payee_scores, screen=screen,
                            settings=self.settings, now=self.clock(), witnessed_plan=witnessed_plan, page_checks=page_checks)
        mark("facts")
        result = rules_engine.evaluate(self.packs, facts)
        mark("rules")
        for f in result.findings:
            if f.code in ("fraud.injection_high", "fraud.injection_suspected") and screen.get("excerpts"):
                f.data = {"excerpts": screen["excerpts"]}
        return result, vb, facts

    # ======================================================================================= stage 2
    CONDITION_WORDS = re.compile(r"\b(refurbished|renewed|reconditioned|pre-?owned|used|open[- ]box|second[- ]hand|grade [abc])\b", re.I)

    def fast_path(self, facts: dict[str, Any], screen: dict[str, Any], page_checks: list[dict[str, Any]], mrec: MandateRecord | None,
                  page_texts: dict[str, str]) -> tuple[bool, list[str]]:
        """Can the purchase-time model review be skipped without losing anything it would catch? Only when the user's words were
        checked against the signed mandate at registration, and every comparison the model would make here is proven by code."""
        if getattr(self.settings, "model_review", "always") != "when-needed":
            return False, ["model review is set to always"]
        proven = self.proven_by_code(facts)
        why: list[str] = []
        if (getattr(mrec, "intent_review", None) or {}).get("verdict") != "NONE":
            why.append("Request not confirmed against the mandate at registration")
        if "trace_drift" not in proven:
            why.append("Cart not matched to a committed plan")
        if "counterparty_identity" not in proven:
            why.append("Merchant not proven")
        signed_titles = {i.get("id"): i.get("title") for i in facts["mandate"].get("allowed_items", [])}
        if any(signed_titles.get(i["sku"]) != i.get("title") for i in facts["cart"]["items"]):
            why.append("Item title differs from the signed title")
        if facts["cond"].get("bad_condition_items"):
            why.append("Item condition differs from the signed condition")
        if any(not c.get("fetched") or c.get("matches") is not True for c in page_checks):
            why.append("Page not confirmed from the merchant site")
        if screen.get("match"):
            why.append("Page screen match")
        cond = str((facts.get("cond") or {}).get("item_condition") or "").lower()
        if cond == "new" and any(self.CONDITION_WORDS.search(t) for t in page_texts.values()):
            why.append("Merchant page states a non-new condition")
        if why:
            return False, why
        return True, ["Request matched to mandate at registration", *proven.values(), "Item titles and conditions as signed",
                      "Pages confirmed from the merchant site; no screen match"]

    @staticmethod
    def proven_by_code(facts: dict[str, Any]) -> dict[str, str]:
        """Model questions that deterministic checks have already answered, so asking would only add latency and cost.
        The request-versus-listing check and the page screen are never skipped: no rule can read a listing."""
        out: dict[str, str] = {}
        t, cart, ap2 = facts["trace"], facts["cart"], facts["ap2"]
        if t.get("plan_witnessed") and t.get("plan_matches_witnessed") and not t.get("items_not_in_plan") \
                and not t.get("payee_changed_after_page_read") and not t.get("shipping_changed_after_page_read"):
            out["trace_drift"] = "Cart and payee match the committed plan"
        allowed = {m.get("id") for m in facts["mandate"].get("allowed_merchants", [])}
        merchant = cart.get("merchant", {}).get("id")
        if ap2.get("merchant_known") and ap2.get("merchant_signature_valid") and merchant in allowed \
                and facts["payment"]["payee"].get("id") == merchant and not facts["payee"].get("lookalike_of"):
            out["counterparty_identity"] = "Checkout signed by a registered, authorized merchant that is the payee"
        return out

    def stage2(self, req: DecisionRequest, vb: VerifiedBundle, facts: dict[str, Any], rec: MandateRecord | None,
               page_texts: dict[str, str] | None = None, witnessed_plan: dict[str, Any] | None = None) -> tuple[Verdict | None, list[Finding], dict[str, Any]]:
        if self.gemini is None:
            return None, [], {"ran": False}
        intent_text = rec.intent_text if rec else (req.intent_text or "")
        cart, payment = facts["cart"], facts["payment"]
        trace_sorted = sorted(req.trace, key=lambda e: e.seq)
        pages = [{"url": p.url, "content": (page_texts or {}).get(p.url, p.content)} for p in req.pages]
        jobs = {
            "semantic_fit": lambda: self.gemini.semantic_fit(intent_text, summarize_open_mandates(vb), cart, vb.conditions, pages),
            "trace_drift": lambda: self.gemini.trace_drift(
                witnessed_plan or next((e.data for e in trace_sorted if e.kind == "plan"), None),
                [{"seq": e.seq, "kind": e.kind, "tool": e.tool, "summary": e.summary[:300]} for e in trace_sorted], cart, payment["payee"]),
            "counterparty_identity": lambda: self.gemini.counterparty_identity(
                cart["merchant"], [{"id": m["id"], "name": m.get("name", ""), "website": m.get("website", "")} for m in self.registry.all()], facts["payee"]),
        }
        if pages:
            jobs["page_screen"] = lambda: self.gemini.page_screen(pages)
        skipped = self.proven_by_code(facts)
        for name in skipped:
            jobs.pop(name, None)
        t0 = time.perf_counter()
        budget = float(getattr(self.settings, "gemini_timeout_s", 10.0))
        pool = ThreadPoolExecutor(max_workers=max(1, len(jobs)))
        pending = {pool.submit(fn): name for name, fn in jobs.items()}
        outs: dict[str, CheckOutput] = {}
        stopped: list[str] = []
        try:
            # Checks can only tighten, so the first DENY settles the decision: stop waiting for the rest.
            while pending:
                remaining = budget - (time.perf_counter() - t0)
                if remaining <= 0:
                    break
                done, _ = wait_futures(list(pending), timeout=remaining, return_when="FIRST_COMPLETED")
                for fut in done:
                    outs[pending.pop(fut)] = fut.result()
                if any(o.verdict == "DENY" for o in outs.values()):
                    stopped = sorted(pending.values())
                    pending = {}
            for name in pending.values():
                o = CheckOutput(verdict="ESCALATE", rationale="timeout",
                                findings=[f"Model review exceeded {budget:g} s; held for customer approval."])
                o._meta = {"ms": int(budget * 1000), "tokens": None, "model_version": None, "timed_out": True}
                outs[name] = o
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
        verdict: Verdict | None = None
        findings: list[Finding] = []
        summary: dict[str, Any] = {"ran": True, "model": self.gemini.model, "label": self.gemini.label, "prompt_version": self.gemini.prompt_version,
                                   "ms": int((time.perf_counter() - t0) * 1000), "checks": {}, "skipped": skipped, "stopped_after_block": stopped}
        for name, out in outs.items():
            v, fs = to_findings(name, out, source=self.gemini.label)
            m = out._meta or {}
            summary["checks"][name] = {"verdict": out.verdict, "findings": out.findings, "rationale": out.rationale,
                                       "data_contained_instructions": out.data_contained_instructions,
                                       "ms": m.get("ms"), "tokens": m.get("tokens"), "model_version": m.get("model_version"),
                                       "attempts": m.get("attempts", 1)}
            findings.extend(fs)
            if v is not None:
                verdict = v if verdict is None else tighten(verdict, v)
        tokens = [c["tokens"] for c in summary["checks"].values() if c.get("tokens")]
        summary["tokens"] = sum(tokens) if tokens else None
        summary["model_version"] = next((c["model_version"] for c in summary["checks"].values() if c.get("model_version")), None)
        return verdict, findings, summary

    # ======================================================================================= record helpers
    @staticmethod
    def _evidence(findings: list[Finding], final: Verdict) -> list[dict[str, Any]]:
        if final == Verdict.ALLOW:
            return []
        keep = [f for f in findings if f.outcome in (Verdict.DENY, Verdict.ESCALATE) and f.code != "page_injection_screen"]
        keep.sort(key=lambda f: (0 if f.outcome == Verdict.DENY else 1, f.rank))
        out, seen = [], set()
        for f in keep:
            if f.code in seen:
                continue
            seen.add(f.code)
            item = {"id": f.code, "outcome": f.outcome.value, "title": f.title or f.code, "detail": f.message, "source": f.source}
            if f.data:
                item["data"] = f.data
            out.append(item)
        return out

    @staticmethod
    def _authorized(facts: dict[str, Any], rec: MandateRecord | None) -> dict[str, Any]:
        m = facts["mandate"]
        return {"intent_text": m.get("intent_text", ""), "summary_text": getattr(rec, "summary_text", "") if rec else "",
                "merchants": m.get("allowed_merchants", []), "items": m.get("allowed_items", []),
                "min_minor": m.get("min_minor", 0), "max_minor": m.get("max_minor", 0), "currency": m.get("currency", ""),
                "payee_ids": m.get("allowed_payee_ids", []), "signed_at": m.get("iat", 0), "expires_at": m.get("exp", 0),
                "conditions": getattr(rec, "conditions", {}) if rec else {}}

    @staticmethod
    def _attempted(facts: dict[str, Any]) -> dict[str, Any]:
        c, p = facts["cart"], facts["payment"]
        return {"merchant": c["merchant"], "items": c["items"], "total_minor": c["total_minor"], "currency": c["currency"],
                "payee": p["payee"], "payment_minor": p["amount_minor"], "merchant_key": facts["ap2"]["merchant_kid"],
                "merchant_registered": facts["ap2"]["merchant_known"], "fulfillment": c.get("fulfillment", {}), "item_facts": c.get("item_facts", {})}

    def _release(self, record: dict[str, Any], user_id: str, pending: list | None = None) -> str:
        """Ask the credentials service to honour a signed ALLOW, and chain the release (token hash only)."""
        issuance = self.credentials.issue_token(record)
        self._append({"type": "credential.released", "for_decision_id": record["decision_id"], "mandate_id": record.get("mandate_id"),
                      "user_id": user_id, "token_sha256": issuance["token_sha256"], "bound_to": issuance.get("bound_to", {}),
                      "expires_at": issuance.get("expires_at"), "issuer": issuance.get("issuer", {}),
                      "headline": f"Single-use payment token issued: {money(record['payment']['amount_minor'], record['payment']['currency'])} to {record['payment']['payee_id']}"},
                     Actor(principal=str(issuance.get("issuer", {}).get("principal", "credentials-service")), role="credentials_service",
                           verified_by="response to MandateGuard's authenticated call"), pending)
        return issuance["token"]

    # ======================================================================================= decide
    def decide(self, req: DecisionRequest, caller: Actor | None = None, trace_id: str | None = None) -> DecisionResponse:
        caller = caller or DEV_AGENT
        if req.idempotency_key and req.idempotency_key in self.stores.idempotency:
            cached = self.stores.get_decision(self.stores.idempotency[req.idempotency_key])
            if cached:
                return DecisionResponse.model_validate(cached)
        self.ensure_policy_recorded()
        t_start = time.perf_counter()
        decision_id = "dec_" + uuid.uuid4().hex
        pending: list = []          # checkpoint writes running alongside the rest of this request
        io = self._io
        # Everything that waits on the network starts now and runs side by side: MandateGuard's own copies of the pages,
        # the page screens, the evidence upload, the plan lookup and the store reads. The AP2 checks run meanwhile.
        pages_f = io.submit(confirm_pages, req.pages, merchant_hosts(self.registry.all()), self.page_fetcher) if req.pages else None
        screen_f = io.submit(self.screener.screen_pages, list(req.pages)) if req.pages else None
        envelope = rfc8785.dumps(req.model_dump(mode="json"))
        env_f = io.submit(self.evidence.put, envelope)
        plan_f = io.submit(self.stores.get_plan, req.plan_id) if req.plan_id else None
        mrec = self.stores.get_mandate(req.mandate_id)
        owner = mrec.user_id if mrec else (req.user_id or "")
        snapshot = _Snapshot(self.stores, io, req.mandate_id, owner, req.ap2.payment_nonce)
        f_id, agent = self.identity(req, caller, mrec)
        wplan = plan_f.result() if plan_f else None
        f_id += self.plan_checks(req, agent, wplan)
        plan_ok = wplan is not None and not any(f.code.startswith("plan.") for f in f_id)
        page_checks = pages_f.result() if pages_f else []
        t_pages = time.perf_counter()
        f0, screen, page_checks = self.stage0(req, page_checks, screen_f)
        page_texts = {c["url"]: c["text"] for c in page_checks if c.get("fetched")}
        copies = {c["url"]: io.submit(self.evidence.put, c["text"].encode("utf-8"), "text/html") for c in page_checks if c.get("fetched")}
        t_s0 = time.perf_counter()
        policy_timings: dict[str, int] = {}
        result, vb, facts = self.stage1(req, screen, mrec, witnessed_plan=wplan["plan"] if plan_ok else None, page_checks=page_checks,
                                        snapshot=snapshot, timings=policy_timings)
        public_pages = []
        for c in page_checks:
            row = {k: v for k, v in c.items() if k != "text"}
            if c["url"] in copies:
                sha = copies[c["url"]].result()
                row.update(fetched_evidence_sha256=sha, fetched_evidence_uri=self.evidence.uri(sha))
            public_pages.append(row)
        env_sha = env_f.result()
        if getattr(self.settings, "require_policy_approval", False):
            for a in self.policy_approvals:
                if not a["verified"]:
                    f_id.append(Finding(stage=Stage.S1, code="policy.unapproved", outcome=Verdict.DENY, title="Policy pack not approved",
                                        message=f"Policy pack {a['pack']} v{a['version']} lacks a valid approval: {a['problem']}.",
                                        rank=2, source="Policy approval"))
        if agent is not None and vb.agent_key_thumbprint and vb.agent_key_thumbprint not in agent.key_thumbprints:
            f_id.append(Finding(stage=Stage.S0, code="identity.key_not_delegated", outcome=Verdict.DENY, title="Mandate delegated to another agent",
                                message=f"Mandate delegated to key {vb.agent_key_thumbprint[:12]}…, not registered to {agent.agent_id}.",
                                rank=1, source="Agent identity"))
        t_s1 = time.perf_counter()
        findings = f_id + f0 + result.findings
        stage1_verdict = tighten(Verdict.ALLOW, *[f.outcome for f in f_id + f0], result.verdict)
        stage2_verdict, stage2_summary = None, {"ran": False, "skipped_reason": "Policy blocked the purchase; model review not needed."}
        fast, fast_why = self.fast_path(facts, screen, page_checks, mrec, page_texts) if stage1_verdict == Verdict.ALLOW else (False, [])
        if fast:
            stage2_summary = {"ran": False, "fast_path": True, "skipped_reason": "Every question the model would answer is already proven.",
                              "proven": fast_why}
        elif stage1_verdict != Verdict.DENY:
            stage2_verdict, f2, stage2_summary = self.stage2(req, vb, facts, mrec, page_texts, wplan["plan"] if plan_ok else None)
            stage2_summary["why_model_ran"] = fast_why
            findings += f2
        t_s2 = time.perf_counter()
        final = stage1_verdict if stage2_verdict is None else tighten(stage1_verdict, stage2_verdict)
        assert final.rank >= stage1_verdict.rank, "stage 2 may never loosen stage 1"

        if final == Verdict.ALLOW and not self.stores.consume(req.mandate_id, decision_id):
            final = Verdict.DENY
            findings.append(Finding(stage=Stage.S3, code="consume_race", outcome=Verdict.DENY, title="Mandate already used",
                                    message="Mandate consumed by a concurrent request.", rank=4, source="MandateGuard"))
        if final == Verdict.ALLOW and vb.closed_payment_reference:
            self.stores.mark_presented(req.ap2.payment_nonce, vb.closed_payment_reference)

        payment = facts["payment"]
        evidence = self._evidence(findings, final)
        headline = evidence[0]["detail"] if evidence else HEADLINE_ALLOW
        hashes = {"open_checkout": vb.open_checkout_hash or "", "open_payment": vb.open_payment_hash or "",
                  "checkout": vb.checkout_hash or "", "closed_payment_reference": vb.closed_payment_reference or "",
                  "plan": facts["trace"]["plan_hash"], "packs": result.packs_hash, "envelope": env_sha}
        gemini_passed = [n for n, c in stage2_summary.get("checks", {}).items() if c.get("verdict") == "NONE"]
        trace = {k: facts["trace"][k] for k in ("steps", "plan_seq", "first_page_seq", "first_unplanned_seq", "items_not_in_plan", "pages_read")}
        trace["witnessed_plan"] = ({"plan_id": wplan["plan_id"], "record_seq": wplan["record_seq"], "plan_sha256": wplan["plan_sha256"],
                                    "committed_at": wplan["committed_at"], "plan": wplan["plan"], "used": plan_ok,
                                    "matches_trace": facts["trace"]["plan_matches_witnessed"]} if wplan else None)
        consent = None
        if mrec is not None:
            c = self.stores.get_consent(mrec.mandate_id) if getattr(mrec, "consent_required", False) else None
            consent = {"required": bool(getattr(mrec, "consent_required", False)), "status": (c or {}).get("status", "attested"),
                       "record_seq": (c or {}).get("result_seq")}
        payload = {
            "type": "decision", "schema": 3, "decision_id": decision_id, "mandate_id": req.mandate_id, "user_id": owner,
            "agent_id": agent.agent_id if agent else None,
            "verdict": final.value, "disposition": DISPOSITION[final.value], "stage1_verdict": stage1_verdict.value,
            "stage2_verdict": stage2_verdict.value if stage2_verdict else None,
            "headline": headline,
            "identity": {
                "agent": {"agent_id": agent.agent_id if agent else None, "principal": caller.principal, "verified_by": caller.verified_by,
                          "claimed": req.agent_id, "registered": agent is not None},
                "user": {"user_id": owner, "claimed": req.user_id, "source": "mandate" if mrec else "request claim"},
                "delegated_key_thumbprint": vb.agent_key_thumbprint, "signer_thumbprint": vb.signer_thumbprint,
                "mandate_registered_by": getattr(mrec, "registered_by", None), "mandate_record_seq": getattr(mrec, "registration_seq", None),
                "merchant_kid": vb.merchant_kid, "merchant_key_status": (vb.merchant_registry_entry or {}).get("status"),
                "consent": consent,
            },
            "authorized": self._authorized(facts, mrec),
            "attempted": self._attempted(facts),
            "evidence": evidence,
            "conditions": {"signed": vb.conditions or {}, "checked": {k: v for k, v in facts["cond"].items()}},
            "checks": {
                "policy": {"evaluated": result.evaluated, "passed": result.passed, "packs": result.packs,
                           "approvals_verified": sum(1 for a in self.policy_approvals if a["verified"]), "approvals_total": len(self.policy_approvals)},
                "pages": public_pages,
                "gemini": {"ran": bool(stage2_summary.get("ran")), "model": stage2_summary.get("label"), "passed": gemini_passed,
                           "ms": stage2_summary.get("ms"), "tokens": stage2_summary.get("tokens")},
                "screen": {"provider": screen.get("provider"), "confidence": screen.get("confidence"), "by_provider": screen.get("by_provider", {}),
                           "pages": screen.get("pages_screened", 0)},
                "ap2": {"sdk_payment_violations": list(vb.payment_violations), "sdk_checkout_violations": list(vb.checkout_violations)},
            },
            "trace": trace,
            "hashes": hashes,
            "envelope": {"sha256": env_sha, "bytes": len(envelope), "uri": self.evidence.uri(env_sha)},
            "payment": {"amount_minor": payment["amount_minor"], "currency": payment["currency"], "payee_id": payment["payee"]["id"]},
            "provenance": {**_service(), "packs_hash": result.packs_hash, "model": stage2_summary.get("label"),
                           "model_version": stage2_summary.get("model_version"), "prompt_version": stage2_summary.get("prompt_version"),
                           "trace_id": trace_id,
                           "timings_ms": {"identity_and_input": int((t_s0 - t_start) * 1000), "page_checks": int((t_pages - t_start) * 1000),
                                          "policy": int((t_s1 - t_s0) * 1000), "policy_parts": policy_timings,
                                          "model_review": int((t_s2 - t_s1) * 1000)}},
            "stage2": stage2_summary,
            "rules_fired": result.fired, "rule_errors": result.errors,
            "latency_ms": int((time.perf_counter() - t_start) * 1000),
        }
        record = self._append(payload, caller, pending)

        token, approval = None, None
        if final == Verdict.ALLOW:
            try:
                spend = io.submit(self.stores.record_payment, owner, payment["payee"]["id"], payment["amount_minor"], vb.open_payment_hash or "")
                pending.append(spend)
                token = self._release(record, owner, pending)
            except TokenRejected as e:
                findings.append(Finding(stage=Stage.S3, code="token_refused", outcome=Verdict.DENY, title="Credentials service refused",
                                        message=str(e), rank=3, source="Credentials service"))
                final = Verdict.DENY
        elif final == Verdict.ESCALATE:
            approval = self._open_approval(decision_id, record, req, owner, facts, evidence, mrec, pending)

        resp = DecisionResponse(
            decision_id=decision_id, verdict=final, stage1_verdict=stage1_verdict, stage2_verdict=stage2_verdict,
            stage2_ran=bool(stage2_summary.get("ran")), findings=findings, rationale=headline, record=_record_info(record),
            hashes=hashes, payment_token=token, approval=approval,
        )
        obs.emit("decision", "WARNING" if final != Verdict.ALLOW else "INFO", decision_id=decision_id, verdict=final.value, seq=record["seq"],
                 mandate_id=req.mandate_id, agent_id=agent.agent_id if agent else None, latency_ms=payload["latency_ms"],
                 timings_ms=payload["provenance"]["timings_ms"], gemini=bool(stage2_summary.get("ran")), tokens=stage2_summary.get("tokens"),
                 codes=[e["id"] for e in evidence][:8])
        stored = resp.model_dump(mode="json")
        stored["payment_token"] = None  # never persist or re-serve a live token
        pending.append(io.submit(self.stores.put_decision, decision_id, stored))
        if req.idempotency_key:
            self.stores.idempotency[req.idempotency_key] = decision_id
        wait_futures(pending, timeout=10)
        return resp

    # ======================================================================================= approvals
    def _approval_policy(self, user_id: str) -> tuple[bool, bool]:
        """(enrolled, passkey_required)"""
        enrolled = self.passkeys.has_passkey(user_id)
        mode = getattr(self.settings, "approval_passkey", "if-enrolled")
        return enrolled, (mode == "always") or (mode == "if-enrolled" and enrolled)

    def _open_approval(self, decision_id: str, record: dict[str, Any], req: DecisionRequest, owner: str, facts: dict[str, Any],
                       evidence: list[dict[str, Any]], mrec: MandateRecord | None, pending: list | None = None) -> ApprovalInfo:
        c, p = facts["cart"], facts["payment"]
        apr = self.stores.create_approval({
            "decision_id": decision_id, "decision_record_hash": record["hash"], "mandate_id": req.mandate_id, "user_id": owner,
            "authorized": self._authorized(facts, mrec), "attempted": self._attempted(facts),
            "reasons": [{"title": e["title"], "detail": e["detail"]} for e in evidence if e["outcome"] == "ESCALATE"],
            "linked_channels": dict(getattr(mrec, "linked_channels", {}) or {}),
            "statement_base": {"decision_id": decision_id, "decision_record_hash": record["hash"], "mandate_id": req.mandate_id, "user_id": owner,
                               "merchant_id": c["merchant"]["id"], "payee_id": p["payee"]["id"], "amount_minor": p["amount_minor"],
                               "currency": p["currency"], "checkout_hash": record["hashes"]["checkout"]},
        }, self.settings.approval_ttl_s)
        if self.notifier is not None:
            try:
                sent = self.notifier.approval_opened(apr, self.approval_link(apr))
                if sent:
                    self._append({"type": "approval.link_sent", "approval_id": apr["approval_id"], "original_decision_id": decision_id,
                                  "user_id": owner, "channel": sent.get("channel"), "message_id": sent.get("message_id"),
                                  "headline": f"Approval link sent to {owner} via {sent.get('channel')}"},
                                 Actor(principal="mandateguard", role="mandateguard", verified_by=f"{sent.get('channel')} accepted the message"))
            except Exception as e:  # noqa: BLE001 - a failed notification leaves the approval to expire; it never approves
                log.warning("approval notification failed: %s", e)
                obs.emit("approval_link_failed", "WARNING", approval_id=apr["approval_id"], error=str(e)[:200])
        to = [(c.principals[0], c.webhook_url) for c in self.clients.active("channel") if c.webhook_url]
        if to and pending is not None:
            # the link goes to the channel service, as when it pulls /v1/approvals/pending; each accepted delivery is a record
            self._push("approval.opened", self._approval_item(apr), to, pending,
                       delivered=lambda p, d: self._link_issued(apr, p, Actor(principal="mandateguard", role="mandateguard",
                                                                           verified_by=f"{p} accepted webhook delivery {d}"), "webhook"))
        items =", ".join(f"{i['qty']}× {i['title'] or i['sku']}" for i in c["items"])
        summary = f"{c['merchant']['name']}: {items}, {money(c['total_minor'], c['currency'])}. " + " ".join(r["detail"] for r in apr["reasons"][:2])
        return ApprovalInfo(approval_id=apr["approval_id"], expires_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(apr["expires_at"])),
                            summary=summary.strip(), raw_action=apr["attempted"])

    @staticmethod
    def statement(apr: dict[str, Any], action: str) -> dict[str, Any]:
        """What the user's passkey signs: the exact purchase, the decision it answers, and the answer."""
        return {**apr["statement_base"], "approval_id": apr["approval_id"], "action": action, "expires_at": int(apr["expires_at"])}

    def approval_link(self, apr: dict[str, Any]) -> str:
        return f"{(self.settings.public_url or '').rstrip('/')}/approve/{apr['approval_id']}#k={apr['link_key']}"

    def _open_with_key(self, approval_id: str, link_key: str) -> dict[str, Any]:
        apr = self.stores.get_approval(approval_id)
        if apr is None or not hmac.compare_digest(str(apr.get("link_key", "")), str(link_key or "")):
            raise PermissionError("This approval link is not valid.")
        return apr

    def approval_view(self, approval_id: str, link_key: str) -> dict[str, Any]:
        apr = self._open_with_key(approval_id, link_key)
        status = apr["status"]
        if status == "issued" and self.clock() > apr["expires_at"]:
            status = "expired"
        enrolled, required = self._approval_policy(apr["user_id"])
        return {"approval_id": approval_id, "status": status, "expires_at": apr["expires_at"], "now": self.clock(),
                "authorized": apr.get("authorized", {}), "attempted": apr.get("attempted", {}), "reasons": apr.get("reasons", []),
                "passkey": {"enrolled": enrolled, "required": required}, "result_seq": apr.get("result_seq"),
                "statement": self.statement(apr, "approve")}

    def approval_passkey_options(self, approval_id: str, link_key: str) -> str:
        apr = self._open_with_key(approval_id, link_key)
        challenge = Passkeys.statement_challenge(self.statement(apr, "approve"))
        return self.passkeys.assertion_options(apr["user_id"], challenge)

    def approval_status(self, approval_id: str) -> dict[str, Any]:
        """For the shopping agent: has the user answered, and if approved, the single-use token."""
        apr = self.stores.get_approval(approval_id)
        if apr is None:
            raise LookupError("unknown approval")
        status = apr["status"]
        if status == "issued" and self.clock() > apr["expires_at"]:
            status = "expired"
        if status == "approved" and not apr.get("payment_token"):
            # the user said yes; the signed record and the token are still being written, or the release failed
            status = "failed" if apr.get("release_error") else "approving"
        return {"approval_id": approval_id, "status": status, "decision_id": apr.get("result_decision_id"),
                "error": apr.get("release_error"),
                "payment_token": apr.get("payment_token") if status == "approved" else None}

    def redeem_approval(self, approval_id: str, req: ApprovalRedeemRequest, link_key: str | None = None,
                        assertion: dict[str, Any] | None = None, channel_actor: Actor | None = None) -> ApprovalRedeemResponse:
        apr = self.stores.get_approval(approval_id)
        if apr is None:
            raise LookupError("unknown approval")
        base = {"type": "approval", "approval_id": approval_id, "channel": req.channel, "reply_ref": req.reply_ref,
                "original_decision_id": apr["decision_id"], "mandate_id": apr["mandate_id"], "user_id": apr["user_id"]}
        original = self.chain.get(apr["decision_id"]) or {}
        enrolled, passkey_required = self._approval_policy(apr["user_id"])
        reason, human = None, None
        if apr["status"] != "issued":
            reason = "Approval already answered."
        elif self.clock() > apr["expires_at"]:
            reason = "Approval expired."
        elif req.channel == "link":
            if not hmac.compare_digest(str(apr.get("link_key", "")), str(link_key or "")):
                reason = "Invalid approval link."
        elif apr.get("linked_channels", {}).get(req.channel) != req.channel_user_id:
            reason = f"Reply not from the {req.channel} account linked to this customer."
        elif req.reply == "approve" and passkey_required:
            reason = "Passkey approval required for this customer."
        if reason is None and original.get("stage1_verdict") == "DENY":
            reason = "Policy block cannot be overridden."
        if reason is None and req.reply == "approve":
            if req.channel == "link" and passkey_required:
                if not assertion:
                    reason = "Passkey signature required."
                else:
                    statement = self.statement(apr, "approve")
                    try:
                        human = {**self.passkeys.verify_assertion(apr["user_id"], assertion, Passkeys.statement_challenge(statement)),
                                 "statement": statement}
                    except PasskeyError as e:
                        reason = str(e)
            elif req.channel == "link":
                human = {"method": "approval link", "note": "no passkey enrolled; the link was delivered to the user's linked channel"}
            else:
                human = {"method": req.channel, "channel_user_id_sha256": sha256_hex(req.channel_user_id.encode())}

        def actor_for(verified: bool) -> Actor:
            if human and human.get("method") == "passkey":
                return Actor(principal=apr["user_id"], role="user", verified_by="passkey signature over the purchase statement")
            if verified and req.channel == "link":
                return Actor(principal=apr["user_id"], role="user", verified_by="one-time approval link delivered to the user's linked channel")
            if verified:
                return Actor(principal=apr["user_id"], role="user",
                             verified_by=f"reply from the linked {req.channel} account, relayed by {channel_actor.principal if channel_actor else 'channel service'}")
            return Actor(principal=req.channel_user_id or "holder of an approval link", role="user", verified_by="not verified")

        def append(verdict: str, headline: str, override: dict[str, Any], extra: dict[str, Any] | None, verified: bool) -> dict[str, Any]:
            return self._append({**base, "decision_id": "dec_" + uuid.uuid4().hex, "verdict": verdict, "disposition": DISPOSITION.get(verdict, verdict),
                                 "headline": headline, "human_override": override, "human": human, **(extra or {})}, actor_for(verified))

        if reason:
            expired_now = False
            if apr["status"] == "issued" and self.clock() > apr["expires_at"]:
                try:
                    self.stores.redeem_approval(approval_id, "expired")
                    expired_now = True
                except ValueError:
                    pass
            record = append("DENY", reason, {"accepted": False, "reason": reason}, None, verified=False)
            if expired_now:
                self._approval_answered(apr, original, "expired", record)
            return ApprovalRedeemResponse(decision_id=record["decision_id"], original_decision_id=apr["decision_id"], verdict=Verdict.DENY,
                                          record=_record_info(record), message=reason)

        if req.reply == "reject":
            try:
                self.stores.redeem_approval(approval_id, "rejected")
            except ValueError as e:
                raise PermissionError(str(e)) from e
            msg = "Declined by customer."
            human = human or {"method": req.channel}
            record = append("DENY", msg, {"accepted": True, "reply": "reject", "channel": req.channel}, None, verified=True)
            self.stores.update_approval(approval_id, {"result_decision_id": record["decision_id"], "result_seq": record["seq"]})
            self._approval_answered(apr, original, "rejected", record)
            return ApprovalRedeemResponse(decision_id=record["decision_id"], original_decision_id=apr["decision_id"], verdict=Verdict.DENY,
                                          record=_record_info(record), message=msg)

        if not self.stores.consume(apr["mandate_id"], apr["decision_id"]):
            raise PermissionError("Mandate already consumed.")
        try:
            self.stores.redeem_approval(approval_id, "approved")
        except ValueError as e:
            raise PermissionError(str(e)) from e
        how = "passkey" if human and human.get("method") == "passkey" else ("approval link" if req.channel == "link" else req.channel)
        msg = f"Approved by {apr['user_id']} ({how})."
        record = append("ALLOW_BY_HUMAN", msg, {"accepted": True, "reply": "approve", "channel": req.channel},
                        {"hashes": original.get("hashes", {}), "payment": original.get("payment", {})}, verified=True)
        try:
            token = self._release(record, apr["user_id"])
        except Exception as e:  # noqa: BLE001
            self.stores.update_approval(approval_id, {"result_decision_id": record["decision_id"], "result_seq": record["seq"],
                                                      "release_error": f"Token not released by the credentials service: {e}"[:300]})
            self._approval_answered(apr, original, "failed", record)
            raise PermissionError("Approved; payment credential not released. No charge was made.") from e
        pay = original.get("payment", {})
        self.stores.record_payment(apr["user_id"], pay.get("payee_id", ""), int(pay.get("amount_minor", 0)), original.get("hashes", {}).get("open_payment", ""))
        self.stores.update_approval(approval_id, {"result_decision_id": record["decision_id"], "result_seq": record["seq"], "payment_token": token})
        self._approval_answered(apr, original, "approved", record)
        return ApprovalRedeemResponse(decision_id=record["decision_id"], original_decision_id=apr["decision_id"], verdict=Verdict.ALLOW,
                                      record=_record_info(record), payment_token=None, message=msg)

    def pending_approvals(self, user_id: str | None = None, caller: Actor | None = None) -> list[dict[str, Any]]:
        """For the channel service that delivers links: the same items the approval.opened event carries."""
        out = []
        for apr in self.stores.pending_approvals(user_id):
            if caller is not None:
                self._link_issued(apr, caller.principal, caller, "pull")
            out.append(self._approval_item(apr))
        return out

    def _approval_item(self, apr: dict[str, Any]) -> dict[str, Any]:
        att = apr.get("attempted", {})
        return {"approval_id": apr["approval_id"], "decision_id": apr["decision_id"], "user_id": apr.get("user_id"), "expires_at": apr["expires_at"],
                "link": self.approval_link(apr), "linked_channels": apr.get("linked_channels", {}),
                "merchant": att.get("merchant", {}).get("name"), "total": money(att.get("total_minor", 0), att.get("currency", "USD")),
                "reasons": apr.get("reasons", [])}

    def _link_issued(self, apr: dict[str, Any], to: str, actor: Actor, via: str) -> None:
        """Handing an approval link to a channel service is recorded once per approval and recipient, pulled or pushed."""
        if self.stores.mark_once("link_issued", f"{self._ledger}:{apr['approval_id']}:{to}"):
            self._append({"type": "approval.link_issued", "approval_id": apr["approval_id"], "original_decision_id": apr["decision_id"],
                          "user_id": apr.get("user_id"), "to": to, "via": via, "linked_channels": sorted((apr.get("linked_channels") or {}).keys()),
                          "headline": f"Approval link for {apr.get('user_id')} issued to {to}" + (" by webhook" if via == "webhook" else "")}, actor)

    # ======================================================================================= money moved
    def record_receipt(self, env: ReceiptEnvelope, actor: Actor) -> dict[str, Any]:
        """A processor reports that money moved. Verify its signature, reconcile with what was allowed, chain it."""
        r = env.receipt
        problems: list[str] = []
        verifier = self.processor_keys.get(env.kid)
        if verifier is None:
            problems.append(f"receipt signed with unknown processor key {env.kid}")
        elif not verifier.verify(statement_digest(r), env.signature):
            problems.append("processor signature does not verify")
        rtype = r.get("type")
        if rtype not in ("payment.executed", "payment.refunded"):
            problems.append(f"unknown receipt type {rtype!r}")
        dec = self.chain.get(str(r.get("for_decision_id", "")))
        if dec is None:
            problems.append("receipt names a decision that is not on record")
        releases = self.chain.find_by("for_decision_id", r.get("for_decision_id"), "credential.released")
        if not releases:
            problems.append("no credential was released for that decision")
        elif releases[-1].get("token_sha256") != r.get("token_sha256"):
            problems.append("receipt is for a different token than the one released")
        if problems:
            self._append({"type": "payment.receipt_rejected", "for_decision_id": r.get("for_decision_id"), "receipt": r, "receipt_kid": env.kid,
                          "receipt_signature": env.signature, "problems": problems, "headline": f"Receipt refused: {problems[0]}"}, actor)
            obs.emit("receipt_rejected", "ERROR", decision_id=r.get("for_decision_id"), problems=problems)
            raise PermissionError("; ".join(problems))
        mismatches = []
        expected = {"amount_minor": dec["payment"]["amount_minor"], "currency": dec["payment"]["currency"], "payee_id": dec["payment"]["payee_id"],
                    "checkout_hash": dec["hashes"]["checkout"], "reference": dec["hashes"].get("closed_payment_reference", ""),
                    "decision_record_hash": dec["hash"]}
        for k, want in expected.items():
            if r.get(k) != want:
                mismatches.append({"field": k, "allowed": want, "reported": r.get(k)})
        amt = money(r.get("amount_minor"), r.get("currency", "USD"))
        if rtype == "payment.executed":
            headline = (f"Charged {amt} to {r.get('payee_id')}; reconciled with the decision." if not mismatches
                        else f"Charge differs from the decision: {', '.join(m['field'] for m in mismatches)}.")
        else:
            headline = f"Refunded {amt}; requested by {r.get('requested_by', 'unknown')}."
        rec = self._append({"type": rtype, "for_decision_id": r["for_decision_id"], "mandate_id": r.get("mandate_id"), "user_id": dec.get("user_id"),
                            "receipt": r, "receipt_signature": env.signature, "receipt_kid": env.kid,
                            "reconciliation": {"matches": not mismatches, "mismatches": mismatches}, "headline": headline}, actor)
        obs.emit("receipt", "ERROR" if mismatches else "INFO", kind=rtype, decision_id=r["for_decision_id"], seq=rec["seq"],
                 reconciled=not mismatches, mismatches=[m["field"] for m in mismatches])
        return {"record_seq": rec["seq"], "reconciled": not mismatches, "mismatches": mismatches}

    # ======================================================================================= goods moved
    def record_fulfillment(self, event_jwt: str) -> dict[str, Any]:
        """A merchant reports that an order shipped or arrived, signed with its registered key. MandateGuard ties the
        event to the payment by checkout hash and compares it with what the user signed and the merchant promised.
        Events that don't verify are refused without a record, so anonymous callers can't write to the chain."""
        try:
            head = fulfillment.jws_header(event_jwt)
        except Exception as e:  # noqa: BLE001
            raise ValueError("the event is not a compact JWS") from e
        if head.get("alg") != "ES256":
            raise ValueError("delivery events must be signed with ES256")
        entry = self.registry.lookup(kid=head.get("kid"))
        if entry is None:
            raise PermissionError("the event is signed with a key that is not in the merchant registry")
        try:
            jws = JWS()
            jws.deserialize(event_jwt, key=JWK.from_json(json.dumps(entry["public_jwk"])))
            claims = json.loads(jws.payload)
        except Exception as e:  # noqa: BLE001
            raise PermissionError("the merchant's signature does not verify") from e
        problems = fulfillment.validate(claims, self.clock())
        if problems:
            raise ValueError("; ".join(problems))
        merchant = {"id": entry["id"], "name": entry.get("name") or entry["id"]}
        actor = Actor(principal=merchant["id"], role="merchant", verified_by=f"ES256 signature with registered key {entry['kid']}")
        h = str(claims["checkout_hash"])
        jwt_sha = self.evidence.put(event_jwt.encode("utf-8"))
        base = {"checkout_hash": h, "merchant": merchant, "kid": entry["kid"], "event": claims, "event_jwt": event_jwt,
                "evidence": {"sha256": jwt_sha, "uri": self.evidence.uri(jwt_sha)}}
        pays = self.chain.find_by("receipt.checkout_hash", h, "payment.executed")
        pay = pays[-1] if pays else None
        dec = self.chain.get(pay["for_decision_id"]) if pay else None
        basis = dec if (dec and dec.get("type") == "decision") else (self.chain.get(dec.get("original_decision_id", "")) if dec else None)
        problems = []
        if pay is None:
            problems.append("no payment on record for this checkout")
        elif basis is None:
            problems.append("the decision behind this payment is not on record")
        elif (basis.get("attempted") or {}).get("merchant", {}).get("id") != merchant["id"]:
            problems.append(f"the order was placed with {basis['attempted']['merchant'].get('name')}, not {merchant['name']}")
        if problems:
            self._append({"type": "fulfillment.rejected", **base, "problems": problems, "headline": f"Delivery event refused: {problems[0]}"}, actor)
            obs.emit("fulfillment_rejected", "WARNING", checkout_hash=h, merchant=merchant["id"], problems=problems)
            raise LookupError("; ".join(problems))
        kind = str(claims["type"]).split(".", 1)[1]
        if not self.stores.mark_once("fulfillment", f"{self._ledger}:{h}:{kind}"):
            return {"duplicate": True, "kind": kind}
        signed = (basis.get("conditions") or {}).get("signed") or {}
        promise = (basis.get("attempted") or {}).get("fulfillment") or {}
        mismatches = fulfillment.reconcile(claims, signed=signed, promise=promise, paid_items=basis["attempted"].get("items", []))
        rec = self._append({"type": f"fulfillment.{kind}", **base, "for_decision_id": pay["for_decision_id"],
                            "payment_id": (pay.get("receipt") or {}).get("payment_id"), "mandate_id": basis.get("mandate_id"), "user_id": basis.get("user_id"),
                            "signed": {k: signed.get(k) for k in ("ship_to_sha256", "deliver_by", "item_condition") if signed.get(k)},
                            "promised": promise, "reconciliation": {"matches": not mismatches, "mismatches": mismatches},
                            "headline": fulfillment.headline(claims, merchant["name"], mismatches, signed)}, actor)
        obs.emit("fulfillment", "ERROR" if mismatches else "INFO", kind=kind, checkout_hash=h, seq=rec["seq"], reconciled=not mismatches,
                 mismatches=[m["field"] for m in mismatches])
        return {"record_seq": rec["seq"], "kind": kind, "reconciled": not mismatches, "mismatches": mismatches}

    # ======================================================================================= verification
    def audit_verify(self) -> dict[str, Any]:
        records = self.chain.all()
        res = audit.verify_chain(records, self.signer)
        try:
            cps = self.evidence.checkpoints(limit=1000)
        except Exception as e:  # noqa: BLE001
            cps, res["anchoring_error"] = [], str(e)
        by_seq = {r["seq"]: r for r in records}
        bad = [c["seq"] for c in cps if by_seq.get(c["seq"], {}).get("hash") != c["hash"]]
        res["anchoring"] = {**self.evidence.describe(), "checkpoints": len(cps), "latest": cps[-1]["seq"] if cps else None,
                            "mismatched_seqs": bad, "missing_tail": (records[-1]["seq"] if records else -1) > (cps[-1]["seq"] if cps else -1)}
        res["ok"] = res["ok"] and not bad
        obs.emit("chain_verify", "INFO" if res["ok"] else "ERROR", ok=res["ok"], length=res.get("length"), problems=len(res.get("problems", [])),
                 mismatched_checkpoints=len(bad), missing_tail=res["anchoring"]["missing_tail"])
        return res

    def reverify(self, decision_id: str) -> dict[str, Any]:
        """Re-run the cryptographic checks for a past decision from stored evidence, as a dispute team would."""
        rec = self.chain.get(decision_id)
        if rec is None or rec.get("type") != "decision":
            raise LookupError("unknown decision")
        checks: list[dict[str, Any]] = []

        def check(label: str, ok: bool, detail: str = "") -> None:
            checks.append({"label": label, "ok": bool(ok), "detail": detail})

        env_sha = (rec.get("envelope") or {}).get("sha256")
        data = self.evidence.get(env_sha) if env_sha else None
        check("Submitted request on file; hash matches", data is not None and sha256_hex(data) == env_sha)
        regs = self.chain.find_by("mandate_id", rec["mandate_id"], "mandate.registered")
        reg_sha = regs[0]["evidence"]["sha256"] if regs else None
        reg = self.evidence.get(reg_sha) if reg_sha else None
        check("Mandate registration on file; hash matches", reg is not None and sha256_hex(reg) == reg_sha)
        if data is None or reg is None:
            return {"decision_id": decision_id, "ok": False, "checks": checks}
        req = DecisionRequest.model_validate_json(data)
        body = json.loads(reg)
        signer = JWK.from_json(json.dumps(body["user_public_jwk"]))
        v = AP2Verifier(self.registry, clock=lambda: rec["ts_ms"] / 1000, include_retired_keys=True).verify(
            open_checkout=body["open_checkout_mandate"], open_payment=body["open_payment_mandate"], user_pub=signer,
            checkout_jwt=req.ap2.checkout_jwt, payment_chain=req.ap2.payment_mandate_chain, payment_nonce=req.ap2.payment_nonce,
            checkout_chain=req.ap2.checkout_mandate_chain, checkout_nonce=req.ap2.checkout_nonce, usage=MandateContext())
        open_errs = [e for e in v.errors if e.startswith("open_")]
        check("Mandate signature valid for the registered key", not open_errs and v.signer_thumbprint == regs[0].get("signer_thumbprint"),
              "; ".join(open_errs))
        check("Mandate identical to the one decided on", (v.open_checkout_hash, v.open_payment_hash) == (rec["hashes"]["open_checkout"], rec["hashes"]["open_payment"]))
        entry = v.merchant_registry_entry or {}
        check(f"Merchant signature valid with key {v.merchant_kid}", v.merchant_signature_valid,
              f"key status: {entry.get('status', 'not registered')}")
        pay_errs = [e for e in v.errors if e.startswith(("payment_mandate_chain", "closed payment", "payment chain"))]
        check("Payment authorization valid and rooted in the mandate", not pay_errs and v.chain_open_matches_record, "; ".join(pay_errs))
        check("Checkout and payment hashes match the record",
              (v.checkout_hash, v.closed_payment_reference) == (rec["hashes"]["checkout"], rec["hashes"].get("closed_payment_reference")))
        same = sorted(v.payment_violations + v.checkout_violations) == sorted(rec["checks"]["ap2"]["sdk_payment_violations"] + rec["checks"]["ap2"]["sdk_checkout_violations"])
        check("AP2 constraint results unchanged since the decision", same)
        return {"decision_id": decision_id, "ok": all(c["ok"] for c in checks), "checks": checks}

    def keys(self) -> dict[str, Any]:
        return {"mandateguard": {"kid": self.signer.kid, "pem": self.signer.public_pem(), "alg": "ECDSA P-256 / SHA-256"},
                "processors": [{"kid": k, "pem": v.pem} for k, v in self.processor_keys.items()],
                "merchants": self.registry.public_keys(),
                "agents": [{"agent_id": a.agent_id, "key_thumbprints": a.key_thumbprints} for a in self.agents.all()],
                "approvers": [{"approver_id": a.approver_id, "public_jwk": a.public_jwk, "thumbprint": a.thumbprint, "status": a.status}
                              for a in self.approvers.all()]}
