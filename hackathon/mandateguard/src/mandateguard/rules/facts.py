"""Build the fact dictionary the rule packs evaluate. Every key is always present (CEL fails closed
on a missing key, so defaults matter)."""

from __future__ import annotations

import hashlib
import time
from typing import Any

import rfc8785

from ..ap2_adapter import VerifiedBundle, summarize_cart, summarize_open_mandates, summarize_payment
from ..conditions import condition_facts
from ..models import DecisionRequest

_CHECKOUT_ERROR_PREFIXES = ("checkout_jwt", "checkout payload")


def normalize_plan(data: dict[str, Any] | None) -> dict[str, Any]:
    """The comparable part of a plan: items, payee, and the optional address hash and spend cap."""
    data = data or {}
    items = sorted(({"sku": str(i.get("sku")), "qty": int(i.get("qty", 1) or 1)} for i in data.get("items", []) if isinstance(i, dict)),
                   key=lambda i: (i["sku"], i["qty"]))
    out: dict[str, Any] = {"items": items, "payee_id": str(data.get("payee_id", ""))}
    if data.get("shipping_address_hash"):
        out["shipping_address_hash"] = str(data["shipping_address_hash"])
    if data.get("max_total_minor") is not None:
        out["max_total_minor"] = int(data["max_total_minor"])
    return out


def plan_differs(reported: dict[str, Any], witnessed: dict[str, Any]) -> bool:
    """Items and payee must match; the address hash and spend cap must match when the committed plan set them."""
    r, w = normalize_plan(reported), normalize_plan(witnessed)
    keys = ["items", "payee_id"] + [k for k in ("shipping_address_hash", "max_total_minor") if k in w]
    return any(r.get(k) != w.get(k) for k in keys)


def analyze_trace(trace: list[Any], cart: dict[str, Any], payee: dict[str, Any], allowed_tools: list[str],
                  witnessed: dict[str, Any] | None = None) -> dict[str, Any]:
    """Plan locking: the reference plan is the one the agent committed to MandateGuard before browsing (witnessed),
    or else the last `plan` event before the first `page_read` in its own trace. Everything the agent does after
    reading untrusted content is compared to it."""
    events = sorted(trace, key=lambda e: e.seq)
    first_page = next((e.seq for e in events if e.kind == "page_read"), None)
    plans_before = [e for e in events if e.kind == "plan" and (first_page is None or e.seq < first_page)]
    trace_locked = plans_before[-1].data if plans_before else None
    locked = witnessed if witnessed is not None else trace_locked
    plan_matches = True if (witnessed is None or trace_locked is None) else not plan_differs(trace_locked, witnessed)
    plan_seq = plans_before[-1].seq if plans_before else None
    plan_skus = [str(i.get("sku")) for i in (locked or {}).get("items", [])] if locked else []
    items_not_in_plan = [s for s in cart["skus"] if s not in plan_skus] if locked else []
    # where did an unplanned item first show up in the agent's own actions?
    first_unplanned_seq = None
    if items_not_in_plan:
        for e in events:
            skus = [str(i.get("sku")) for i in (e.data.get("items") or []) if isinstance(i, dict)]
            if any(s in items_not_in_plan for s in skus):
                first_unplanned_seq = e.seq
                break
    plan_payee = (locked or {}).get("payee_id", "")
    payee_changed = bool(locked and plan_payee and plan_payee != payee.get("id"))
    ship_locked = (locked or {}).get("shipping_address_hash")
    ship_changed = False
    if ship_locked and first_page is not None:
        for e in events:
            if e.seq > first_page and e.data.get("shipping_address_hash") and e.data["shipping_address_hash"] != ship_locked:
                ship_changed = True
        if cart.get("shipping_address_hash") and cart["shipping_address_hash"] != ship_locked:
            ship_changed = True
    tools = sorted({e.tool for e in events if e.kind == "tool_call" and e.tool})
    disallowed = [t for t in tools if allowed_tools and t not in allowed_tools]
    plan_hash = hashlib.sha256(rfc8785.dumps(normalize_plan(locked) if witnessed is not None else locked)).hexdigest() if locked else ""
    steps = []
    for e in events:
        skus = [str(i.get("sku")) for i in (e.data.get("items") or []) if isinstance(i, dict)]
        steps.append({"seq": e.seq, "kind": e.kind, "tool": e.tool or "", "summary": (e.summary or "")[:160],
                      "url": str(e.data.get("url", ""))[:200], "skus": skus})
    return {
        "plan_before_first_page": locked is not None,
        "plan_witnessed": witnessed is not None,
        "trace_plan_present": trace_locked is not None,
        "plan_matches_witnessed": plan_matches,
        "plan_items": plan_skus,
        "plan_payee_id": plan_payee,
        "plan_seq": plan_seq if plan_seq is not None else -1,
        "first_page_seq": first_page if first_page is not None else -1,
        "first_unplanned_seq": first_unplanned_seq if first_unplanned_seq is not None else -1,
        "items_not_in_plan": items_not_in_plan,
        "payee_changed_after_page_read": payee_changed,
        "shipping_changed_after_page_read": ship_changed,
        "pages_read": sum(1 for e in events if e.kind == "page_read"),
        "tools_used": tools,
        "disallowed_tools": disallowed,
        "plan_hash": plan_hash,
        "steps_count": len(events),
        "steps": steps,
    }


def build_facts(req: DecisionRequest, vb: VerifiedBundle, *, mandate_rec: Any, stores: Any, payee_scores: dict[str, Any],
                screen: dict[str, Any], settings: Any, now: float | None = None, witnessed_plan: dict[str, Any] | None = None,
                page_checks: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """The user is always the mandate's owner, never the agent's claim (a claim that differs is denied in stage 0)."""
    now = now or time.time()
    owner = mandate_rec.user_id if mandate_rec else (req.user_id or "")
    cart = summarize_cart(vb)
    payment = summarize_payment(vb)
    mandate = summarize_open_mandates(vb)
    mandate.update({
        "id": req.mandate_id,
        "intent_text": mandate_rec.intent_text if mandate_rec else (req.intent_text or ""),
        "consumed": stores.is_consumed(req.mandate_id),
        "single_use": bool(getattr(mandate_rec, "single_use", True)),
        "user_id": owner,
        "agent_key_thumbprint": vb.agent_key_thumbprint or "",
        "expected_agent_key_thumbprint": getattr(mandate_rec, "agent_key_thumbprint", "") or "",
    })
    trace = analyze_trace(req.trace, cart, payment["payee"], list(settings.allowed_tools), witnessed=witnessed_plan)
    checks = page_checks or []
    differing = [c["url"] for c in checks if c.get("fetched") and c.get("matches") is False]
    screen_defaults = {"match": False, "confidence": "NONE", "signals": [], "addressed_to_guard": False, "provider": "", "excerpts": []}
    rating = (vb.merchant_registry_entry or {}).get("rating")
    cond = condition_facts(vb.conditions, intent_text=getattr(mandate_rec, "intent_text", "") or "",
                           summary_text=getattr(mandate_rec, "summary_text", "") or "", salt=getattr(mandate_rec, "intent_salt", "") or "",
                           checkout=vb.checkout_payload, cart_items=cart["items"], seller_rating=rating)
    return {
        "ap2": {
            "ok": vb.ok,
            "errors": list(vb.errors),
            "chain_errors": [e for e in vb.errors if not e.startswith(_CHECKOUT_ERROR_PREFIXES)],
            "merchant_signature_valid": vb.merchant_signature_valid,
            "merchant_known": vb.merchant_registry_entry is not None,
            "merchant_kid": vb.merchant_kid or "(none)",
            "payment_violations": list(vb.payment_violations),
            "checkout_violations": list(vb.checkout_violations),
            "chain_open_matches_record": vb.chain_open_matches_record,
            "aud_nonce_ok": vb.aud_nonce_ok,
        },
        "mandate": mandate,
        "cart": cart,
        "payment": payment,
        "payee": payee_scores,
        "trace": trace,
        "cond": cond,
        "screen": {k: screen.get(k, v) for k, v in screen_defaults.items()},
        "pages": {"reported": len(checks), "fetched": sum(1 for c in checks if c.get("fetched")),
                  "confirmed": sum(1 for c in checks if c.get("matches") is True), "differs": len(differing), "differing_urls": differing},
        "replay": {
            "payment_nonce_seen": stores.nonce_seen(req.ap2.payment_nonce),
            "closed_reference_seen": bool(vb.closed_payment_reference) and stores.reference_seen(vb.closed_payment_reference),
            "mandate_consumed": mandate["consumed"],
        },
        "ctx": {
            "now": int(now),
            "velocity_1h_minor": int(stores.velocity_minor(owner)),
            "hnp_txn_cap_minor": int(settings.hnp_txn_cap_minor),
            "hnp_velocity_cap_minor": int(settings.hnp_velocity_cap_minor),
            "agent_id": req.agent_id or "",
            "user_id": owner,
            "require_witnessed_plan": bool(getattr(settings, "require_witnessed_plan", False)),
        },
    }
