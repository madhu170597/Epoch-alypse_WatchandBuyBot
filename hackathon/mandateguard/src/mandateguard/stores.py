"""State the guard owns: registered mandates, single-use markers, approvals, payments, passkeys.

In-memory implementations serve tests and local runs. Firestore implementations use create()-only writes
for anything that must happen exactly once, and always read approvals and payments through, so every
Cloud Run instance sees the same state.
"""

from __future__ import annotations

import secrets
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from ap2.sdk.constraints import MandateContext


@dataclass
class MandateRecord:
    """Registered by the user's trusted surface (the web app) when the user signs."""

    mandate_id: str
    user_id: str
    intent_text: str
    open_checkout_mandate: str
    open_payment_mandate: str
    user_public_jwk: dict[str, Any]                       # key that signed the open mandates
    agent_key_thumbprint: str = ""                        # delegated agent key the trusted surface expects
    linked_channels: dict[str, str] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    single_use: bool = True
    intent_salt: str = ""                                 # salt behind the signed intent and summary commitments
    summary_text: str = ""                                # the summary the user was shown before signing
    conditions: dict[str, Any] = field(default_factory=dict)   # copy of the signed mg_conditions, for display
    consent: dict[str, Any] = field(default_factory=dict)      # how the user approved, as attested at registration
    registered_by: str = ""
    registration_seq: int = -1
    registration_evidence: str = ""
    signer_thumbprint: str = ""
    delegated_key_thumbprint: str = ""
    consent_required: bool = False                        # the user must sign this mandate with a passkey before it can be used
    intent_review: dict[str, Any] = field(default_factory=dict)  # model check at registration: does the signed mandate match the user's words


class InMemoryStores:
    def __init__(self):
        self.mandates: dict[str, MandateRecord] = {}
        self.consumed: dict[str, str] = {}
        self.seen_nonces: set[str] = set()
        self.seen_references: set[str] = set()
        self.approvals: dict[str, dict[str, Any]] = {}
        self.decisions: dict[str, dict[str, Any]] = {}
        self.idempotency: dict[str, str] = {}
        self.payments: list[dict[str, Any]] = []
        self.usage: dict[str, MandateContext] = {}
        self.passkeys: dict[str, dict[str, Any]] = {}
        self.enrollments: dict[str, dict[str, Any]] = {}
        self.once: set[str] = set()
        self.consents: dict[str, dict[str, Any]] = {}
        self.plans: dict[str, dict[str, Any]] = {}

    # mandates -----------------------------------------------------------------------------------------
    def get_mandate(self, mandate_id: str) -> MandateRecord | None:
        return self.mandates.get(mandate_id)

    def put_mandate(self, rec: MandateRecord) -> None:
        self.mandates[rec.mandate_id] = rec

    # exactly-once markers --------------------------------------------------------------------------------
    def mark_once(self, kind: str, key: str) -> bool:
        k = f"{kind}:{key}"
        if k in self.once:
            return False
        self.once.add(k)
        return True

    def is_consumed(self, mandate_id: str) -> bool:
        return mandate_id in self.consumed

    def consume(self, mandate_id: str, decision_id: str) -> bool:
        if mandate_id in self.consumed:
            return False
        self.consumed[mandate_id] = decision_id
        return True

    def nonce_seen(self, nonce: str) -> bool:
        return nonce in self.seen_nonces

    def reference_seen(self, ref: str) -> bool:
        return ref in self.seen_references

    def mark_presented(self, nonce: str, ref: str) -> None:
        self.seen_nonces.add(nonce)
        self.seen_references.add(ref)

    # usage / velocity ----------------------------------------------------------------------------------
    def usage_for(self, open_payment_hash: str) -> MandateContext:
        return self.usage.get(open_payment_hash, MandateContext())

    def record_payment(self, user_id: str, payee_id: str, amount_minor: int, open_payment_hash: str) -> None:
        self.payments.append({"user_id": user_id, "payee_id": payee_id, "amount_minor": amount_minor, "ts": time.time()})
        u = self.usage_for(open_payment_hash)
        self.usage[open_payment_hash] = MandateContext(total_amount=u.total_amount + amount_minor, total_uses=u.total_uses + 1, last_used_date=time.time())

    def _payments(self, user_id: str) -> list[dict[str, Any]]:
        return [p for p in self.payments if p["user_id"] == user_id]

    def velocity_minor(self, user_id: str, window_s: int = 3600) -> int:
        cutoff = time.time() - window_s
        return sum(int(p["amount_minor"]) for p in self._payments(user_id) if p["ts"] >= cutoff)

    def paid_before(self, user_id: str, payee_id: str) -> bool:
        return any(p.get("payee_id") == payee_id for p in self._payments(user_id))

    # approvals -------------------------------------------------------------------------------------------
    # Created on ESCALATE. The link key goes only to the user's linked channel, never to the agent.
    def create_approval(self, data: dict[str, Any], ttl_s: int) -> dict[str, Any]:
        now = time.time()
        rec = {"approval_id": "apr_" + uuid.uuid4().hex, "status": "issued", "created_at": now, "expires_at": now + ttl_s,
               "link_key": secrets.token_urlsafe(24), **data}
        self._save_approval(rec)
        return rec

    def _save_approval(self, rec: dict[str, Any]) -> None:
        self.approvals[rec["approval_id"]] = rec

    def get_approval(self, aid: str) -> dict[str, Any] | None:
        a = self.approvals.get(aid)
        return dict(a) if a else None

    def redeem_approval(self, aid: str, status: str, extra: dict[str, Any] | None = None) -> None:
        rec = self.approvals[aid]
        if rec["status"] != "issued":
            raise ValueError("approval already answered")
        rec.update({"status": status, "answered_at": time.time(), **(extra or {})})

    def update_approval(self, aid: str, fields: dict[str, Any]) -> None:
        self.approvals[aid].update(fields)

    def pending_approvals(self, user_id: str | None = None) -> list[dict[str, Any]]:
        now = time.time()
        return [dict(a) for a in self.approvals.values()
                if a["status"] == "issued" and a["expires_at"] > now and (user_id is None or a.get("user_id") == user_id)]

    # decisions (API responses, without tokens) --------------------------------------------------------------
    def put_decision(self, decision_id: str, response: dict[str, Any]) -> None:
        self.decisions[decision_id] = response

    def get_decision(self, decision_id: str) -> dict[str, Any] | None:
        return self.decisions.get(decision_id)

    # mandate consent: the user signs the registered mandate with a passkey ------------------------------------
    def create_consent_request(self, mandate_id: str, data: dict[str, Any], ttl_s: int) -> dict[str, Any]:
        now = time.time()
        rec = {"mandate_id": mandate_id, "status": "awaiting", "created_at": now, "expires_at": now + ttl_s,
               "key": secrets.token_urlsafe(24), **data}
        self._save_consent(rec)
        return dict(rec)

    def _save_consent(self, rec: dict[str, Any]) -> None:
        self.consents[rec["mandate_id"]] = dict(rec)

    def get_consent(self, mandate_id: str) -> dict[str, Any] | None:
        c = self.consents.get(mandate_id)
        return dict(c) if c else None

    def answer_consent(self, mandate_id: str, status: str, extra: dict[str, Any] | None = None) -> None:
        rec = self.consents[mandate_id]
        if rec["status"] != "awaiting":
            raise ValueError("this mandate was already answered")
        rec.update({"status": status, "answered_at": time.time(), **(extra or {})})

    def update_consent(self, mandate_id: str, fields: dict[str, Any]) -> None:
        self.consents[mandate_id].update(fields)

    # plans the agent committed before browsing -------------------------------------------------------------
    def put_plan(self, plan: dict[str, Any]) -> bool:
        if plan["plan_id"] in self.plans:
            return False
        self.plans[plan["plan_id"]] = dict(plan)
        return True

    def get_plan(self, plan_id: str) -> dict[str, Any] | None:
        p = self.plans.get(plan_id)
        return dict(p) if p else None

    # passkeys ------------------------------------------------------------------------------------------------
    def put_enrollment(self, enr: dict[str, Any]) -> None:
        self.enrollments[enr["enrollment_id"]] = dict(enr)

    def get_enrollment(self, enrollment_id: str) -> dict[str, Any] | None:
        e = self.enrollments.get(enrollment_id)
        return dict(e) if e else None

    def update_enrollment(self, enrollment_id: str, fields: dict[str, Any]) -> None:
        self.enrollments[enrollment_id].update(fields)

    def put_passkey(self, pk: dict[str, Any]) -> None:
        self.passkeys[pk["credential_id"]] = dict(pk)

    def passkeys_for(self, user_id: str) -> list[dict[str, Any]]:
        return [dict(p) for p in self.passkeys.values() if p["user_id"] == user_id]

    def update_passkey(self, credential_id: str, fields: dict[str, Any]) -> None:
        self.passkeys[credential_id].update(fields)


class FirestoreStores(InMemoryStores):
    """Collections: mg_mandates, mg_consumed, mg_nonces, mg_references, mg_approvals, mg_decisions, mg_payments,
    mg_passkeys, mg_enrollments, mg_once, mg_consents, mg_plans."""

    def __init__(self, db: Any):
        super().__init__()
        self.db = db

    def _create_once(self, collection: str, doc_id: str, data: dict[str, Any]) -> bool:
        from google.api_core import exceptions as gexc

        try:
            self.db.collection(collection).document(doc_id).create(data)
            return True
        except gexc.AlreadyExists:
            return False

    # mandates
    def get_mandate(self, mandate_id: str) -> MandateRecord | None:
        rec = super().get_mandate(mandate_id)
        if rec is not None:
            return rec
        snap = self.db.collection("mg_mandates").document(mandate_id).get()
        if not snap.exists:
            return None
        d = snap.to_dict()
        rec = MandateRecord(**{k: d[k] for k in MandateRecord.__dataclass_fields__ if k in d})
        self.mandates[mandate_id] = rec
        return rec

    def put_mandate(self, rec: MandateRecord) -> None:
        super().put_mandate(rec)
        self.db.collection("mg_mandates").document(rec.mandate_id).set(rec.__dict__)

    # exactly-once
    def mark_once(self, kind: str, key: str) -> bool:
        return self._create_once("mg_once", f"{kind}:{key}"[:1500].replace("/", "_"), {"ts": time.time()})

    def is_consumed(self, mandate_id: str) -> bool:
        return self.db.collection("mg_consumed").document(mandate_id).get().exists

    def consume(self, mandate_id: str, decision_id: str) -> bool:
        return self._create_once("mg_consumed", mandate_id, {"decision_id": decision_id, "ts": time.time()})

    def nonce_seen(self, nonce: str) -> bool:
        return self.db.collection("mg_nonces").document(nonce).get().exists

    def reference_seen(self, ref: str) -> bool:
        return self.db.collection("mg_references").document(ref).get().exists

    def mark_presented(self, nonce: str, ref: str) -> None:
        self._create_once("mg_nonces", nonce, {"ts": time.time()})
        self._create_once("mg_references", ref, {"ts": time.time()})

    # payments: persisted so the hourly envelope holds across instances
    def record_payment(self, user_id: str, payee_id: str, amount_minor: int, open_payment_hash: str) -> None:
        super().record_payment(user_id, payee_id, amount_minor, open_payment_hash)
        self.db.collection("mg_payments").add({"user_id": user_id, "payee_id": payee_id, "amount_minor": int(amount_minor), "ts": time.time()})

    def _payments(self, user_id: str) -> list[dict[str, Any]]:
        return [d.to_dict() for d in self.db.collection("mg_payments").where("user_id", "==", user_id).stream()]

    # approvals: always read through
    def _save_approval(self, rec: dict[str, Any]) -> None:
        self.db.collection("mg_approvals").document(rec["approval_id"]).set(rec)

    def get_approval(self, aid: str) -> dict[str, Any] | None:
        snap = self.db.collection("mg_approvals").document(aid).get()
        return snap.to_dict() if snap.exists else None

    def redeem_approval(self, aid: str, status: str, extra: dict[str, Any] | None = None) -> None:
        from google.cloud import firestore

        ref = self.db.collection("mg_approvals").document(aid)

        @firestore.transactional
        def _tx(tx):
            cur = ref.get(transaction=tx).to_dict() or {}
            if cur.get("status") != "issued":
                raise ValueError("approval already answered")
            tx.update(ref, {"status": status, "answered_at": time.time(), **(extra or {})})

        _tx(self.db.transaction())

    def update_approval(self, aid: str, fields: dict[str, Any]) -> None:
        self.db.collection("mg_approvals").document(aid).update(fields)

    def pending_approvals(self, user_id: str | None = None) -> list[dict[str, Any]]:
        now = time.time()
        docs = [d.to_dict() for d in self.db.collection("mg_approvals").where("status", "==", "issued").stream()]
        return [a for a in docs if a["expires_at"] > now and (user_id is None or a.get("user_id") == user_id)]

    # decisions
    def put_decision(self, decision_id: str, response: dict[str, Any]) -> None:
        super().put_decision(decision_id, response)
        self.db.collection("mg_decisions").document(decision_id).set(response)

    def get_decision(self, decision_id: str) -> dict[str, Any] | None:
        d = super().get_decision(decision_id)
        if d is None:
            snap = self.db.collection("mg_decisions").document(decision_id).get()
            d = snap.to_dict() if snap.exists else None
        return d

    # consent: always read through, answered in a transaction
    def _save_consent(self, rec: dict[str, Any]) -> None:
        self.db.collection("mg_consents").document(rec["mandate_id"]).set(rec)

    def get_consent(self, mandate_id: str) -> dict[str, Any] | None:
        snap = self.db.collection("mg_consents").document(mandate_id).get()
        return snap.to_dict() if snap.exists else None

    def answer_consent(self, mandate_id: str, status: str, extra: dict[str, Any] | None = None) -> None:
        from google.cloud import firestore

        ref = self.db.collection("mg_consents").document(mandate_id)

        @firestore.transactional
        def _tx(tx):
            cur = ref.get(transaction=tx).to_dict() or {}
            if cur.get("status") != "awaiting":
                raise ValueError("this mandate was already answered")
            tx.update(ref, {"status": status, "answered_at": time.time(), **(extra or {})})

        _tx(self.db.transaction())

    def update_consent(self, mandate_id: str, fields: dict[str, Any]) -> None:
        self.db.collection("mg_consents").document(mandate_id).update(fields)

    # plans: create-only
    def put_plan(self, plan: dict[str, Any]) -> bool:
        return self._create_once("mg_plans", plan["plan_id"], plan)

    def get_plan(self, plan_id: str) -> dict[str, Any] | None:
        snap = self.db.collection("mg_plans").document(plan_id).get()
        return snap.to_dict() if snap.exists else None

    # passkeys
    def put_enrollment(self, enr: dict[str, Any]) -> None:
        self.db.collection("mg_enrollments").document(enr["enrollment_id"]).set(enr)

    def get_enrollment(self, enrollment_id: str) -> dict[str, Any] | None:
        snap = self.db.collection("mg_enrollments").document(enrollment_id).get()
        return snap.to_dict() if snap.exists else None

    def update_enrollment(self, enrollment_id: str, fields: dict[str, Any]) -> None:
        self.db.collection("mg_enrollments").document(enrollment_id).update(fields)

    def put_passkey(self, pk: dict[str, Any]) -> None:
        self.db.collection("mg_passkeys").document(pk["credential_id"]).set(pk)

    def passkeys_for(self, user_id: str) -> list[dict[str, Any]]:
        return [d.to_dict() for d in self.db.collection("mg_passkeys").where("user_id", "==", user_id).stream()]

    def update_passkey(self, credential_id: str, fields: dict[str, Any]) -> None:
        self.db.collection("mg_passkeys").document(credential_id).update(fields)
