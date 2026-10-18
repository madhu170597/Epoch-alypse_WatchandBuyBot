"""AP2 v0.2 verification adapter.

Wraps the AP2 SDK (``ap2.sdk``) so stage 1 reasons over *verified facts* rather than
over strings the agent sent. Everything here is deterministic.

What is verified:
  * open checkout / payment mandates: user-key SD-JWT signature, exp/iat
  * checkout_jwt: merchant ES256 signature against the merchant registry (kid lookup)
  * payment chain: dSD-JWT chain (cnf walk), terminal aud + nonce, sd_hash binding,
    constraints (amount range, allowed payees, payment.reference, budget, recurrence)
  * checkout chain (if present): same, plus checkout_hash == sha256(checkout_jwt)
  * closed mandates were derived from the *stored* open mandates (sd_hash equality)
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from ap2.sdk.checkout_mandate_chain import CheckoutMandateChain
from ap2.sdk.constraints import MandateContext, check_checkout_constraints
from ap2.sdk.generated.open_checkout_mandate import OpenCheckoutMandate
from ap2.sdk.generated.open_payment_mandate import OpenPaymentMandate
from ap2.sdk.generated.payment_mandate import PaymentMandate
from ap2.sdk.generated.types.checkout import Checkout
from ap2.sdk.jwt_helper import verify_jwt
from ap2.sdk.mandate import MandateClient
from ap2.sdk.payment_mandate_chain import PaymentMandateChain
from ap2.sdk.sdjwt import compute_sd_hash, parse_token
from ap2.sdk.utils import b64url_decode, compute_sha256_b64url
from jwcrypto.jwk import JWK

from .conditions import GuardedOpenCheckoutMandate


def decode_jwt_part(token: str, index: int) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a compact JWS")
    return json.loads(b64url_decode(parts[index]).decode("utf-8"))


def jwk_thumbprint(jwk: dict[str, Any] | JWK) -> str:
    key = jwk if isinstance(jwk, JWK) else JWK.from_json(json.dumps(jwk))
    return key.thumbprint()


def _open_segment(chain: str) -> str:
    seg = chain.split("~~")[0]
    return seg if seg.endswith("~") else seg + "~"


@dataclass
class VerifiedBundle:
    errors: list[str] = field(default_factory=list)
    open_checkout: OpenCheckoutMandate | None = None
    open_payment: OpenPaymentMandate | None = None
    open_checkout_hash: str | None = None
    open_payment_hash: str | None = None
    checkout: Checkout | None = None
    checkout_payload: dict[str, Any] = field(default_factory=dict)
    checkout_hash: str | None = None
    merchant_signature_valid: bool = False
    merchant_kid: str | None = None
    merchant_registry_entry: dict[str, Any] | None = None
    closed_payment: PaymentMandate | None = None
    closed_payment_reference: str | None = None
    payment_violations: list[str] = field(default_factory=list)
    checkout_violations: list[str] = field(default_factory=list)
    chain_open_matches_record: bool = False
    aud_nonce_ok: bool = False
    agent_key_thumbprint: str | None = None
    signer_thumbprint: str | None = None
    conditions: dict[str, Any] | None = None

    @property
    def ok(self) -> bool:
        return (
            not self.errors
            and self.merchant_signature_valid
            and not self.payment_violations
            and not self.checkout_violations
            and self.chain_open_matches_record
            and self.aud_nonce_ok
        )


class AP2Verifier:
    def __init__(self, merchant_registry, clock=time.time, include_retired_keys: bool = False):
        self.registry = merchant_registry
        self.clock = clock
        self.include_retired_keys = include_retired_keys  # True only when re-verifying past decisions

    # ---- open mandates ---------------------------------------------------
    def verify_open_mandates(self, vb: VerifiedBundle, open_checkout: str, open_payment: str, user_pub: JWK) -> None:
        client = MandateClient()
        vb.signer_thumbprint = user_pub.thumbprint()
        try:
            guarded = client.verify(
                token=open_checkout, key_or_provider=user_pub, payload_type=GuardedOpenCheckoutMandate,
                current_time=int(self.clock()),
            ).mandate_payload
            vb.conditions = guarded.mg_conditions or None
            vb.open_checkout = OpenCheckoutMandate.model_validate(guarded.model_dump(exclude={"mg_conditions"}))
            vb.open_checkout_hash = compute_sd_hash(parse_token(open_checkout))
        except Exception as e:  # noqa: BLE001 - every failure is a DENY fact
            vb.errors.append(f"open_checkout_mandate: {e}")
        try:
            vb.open_payment = client.verify(
                token=open_payment, key_or_provider=user_pub, payload_type=OpenPaymentMandate,
                current_time=int(self.clock()),
            ).mandate_payload
            vb.open_payment_hash = compute_sd_hash(parse_token(open_payment))
        except Exception as e:  # noqa: BLE001
            vb.errors.append(f"open_payment_mandate: {e}")
        if vb.open_checkout is not None:
            try:
                vb.agent_key_thumbprint = jwk_thumbprint(vb.open_checkout.cnf["jwk"])
            except Exception as e:  # noqa: BLE001
                vb.errors.append(f"open_checkout_mandate cnf: {e}")

    # ---- merchant-signed checkout ---------------------------------------
    def verify_checkout_jwt(self, vb: VerifiedBundle, checkout_jwt: str) -> None:
        try:
            header = decode_jwt_part(checkout_jwt, 0)
            vb.checkout_payload = decode_jwt_part(checkout_jwt, 1)
        except Exception as e:  # noqa: BLE001
            vb.errors.append(f"checkout_jwt malformed: {e}")
            return
        vb.checkout_hash = compute_sha256_b64url(checkout_jwt)
        vb.merchant_kid = header.get("kid")
        merchant = vb.checkout_payload.get("merchant") or {}
        entry = self.registry.lookup(kid=vb.merchant_kid, include_retired=self.include_retired_keys)
        vb.merchant_registry_entry = entry
        if entry is None:
            vb.errors.append(f"checkout_jwt signed by a key that is not registered and active (kid={vb.merchant_kid}, merchant id={merchant.get('id')})")
            return
        try:
            verify_jwt(checkout_jwt, JWK.from_json(json.dumps(entry["public_jwk"])))
            vb.merchant_signature_valid = True
        except Exception as e:  # noqa: BLE001
            vb.errors.append(f"checkout_jwt signature invalid for registered merchant {entry.get('id')}: {e}")
            return
        if entry.get("id") != merchant.get("id"):
            vb.merchant_signature_valid = False
            vb.errors.append(f"checkout_jwt merchant.id {merchant.get('id')!r} does not match registered id {entry.get('id')!r} for kid {vb.merchant_kid}")
        try:
            vb.checkout = Checkout.model_validate(vb.checkout_payload)
        except Exception as e:  # noqa: BLE001
            vb.errors.append(f"checkout payload failed UCP schema validation: {e}")

    # ---- closed chains ---------------------------------------------------
    def verify_payment_chain(self, vb: VerifiedBundle, chain: str, nonce: str, user_pub: JWK, usage: MandateContext) -> None:
        client = MandateClient()
        try:
            payloads = client.verify(
                token=chain, key_or_provider=lambda _t: user_pub,
                expected_aud="credential-provider", expected_nonce=nonce,
                current_time=int(self.clock()),
            )
            parsed = PaymentMandateChain.parse(payloads)
        except Exception as e:  # noqa: BLE001
            vb.errors.append(f"payment_mandate_chain: {e}")
            return
        vb.closed_payment = parsed.closed_mandate
        leaf = client.get_closed_mandate_jwt(chain)
        vb.closed_payment_reference = compute_sha256_b64url(leaf)
        # Defence in depth: re-check aud/nonce on the leaf ourselves.
        try:
            leaf_payload = decode_jwt_part(leaf, 1)
            vb.aud_nonce_ok = leaf_payload.get("aud") == "credential-provider" and leaf_payload.get("nonce") == nonce
        except Exception:  # noqa: BLE001
            vb.aud_nonce_ok = False
        if not vb.aud_nonce_ok:
            vb.errors.append("closed payment mandate aud/nonce mismatch")
        # The chain must start from the open payment mandate the user actually signed.
        try:
            vb.chain_open_matches_record = compute_sd_hash(parse_token(_open_segment(chain))) == vb.open_payment_hash
        except Exception:  # noqa: BLE001
            vb.chain_open_matches_record = False
        if not vb.chain_open_matches_record:
            vb.errors.append("payment chain is not rooted in the open payment mandate on record")
        vb.payment_violations = parsed.verify(
            expected_transaction_id=vb.checkout_hash,
            expected_open_checkout_hash=vb.open_checkout_hash,
            mandate_context=usage,
        )

    def verify_checkout_chain(self, vb: VerifiedBundle, chain: str | None, nonce: str | None, checkout_jwt: str, user_pub: JWK) -> None:
        if vb.open_checkout is None or vb.checkout is None:
            return
        if not chain:
            # No agent-signed closed checkout mandate yet: evaluate the open constraints directly.
            vb.checkout_violations = check_checkout_constraints(vb.open_checkout, vb.checkout)
            return
        client = MandateClient()
        try:
            payloads = client.verify(
                token=chain, key_or_provider=lambda _t: user_pub,
                expected_aud="merchant", expected_nonce=nonce, current_time=int(self.clock()),
            )
            parsed = CheckoutMandateChain.parse(payloads)
        except Exception as e:  # noqa: BLE001
            vb.errors.append(f"checkout_mandate_chain: {e}")
            return
        if compute_sd_hash(parse_token(_open_segment(chain))) != vb.open_checkout_hash:
            vb.errors.append("checkout chain is not rooted in the open checkout mandate on record")
        if parsed.closed_mandate.checkout_jwt != checkout_jwt:
            vb.errors.append("closed checkout mandate wraps a different checkout_jwt than the one presented")
        vb.checkout_violations = parsed.verify(expected_checkout_hash=vb.checkout_hash, checkout_jwt=checkout_jwt)

    # ---- orchestration ---------------------------------------------------
    def verify(self, *, open_checkout: str, open_payment: str, user_pub: JWK, checkout_jwt: str,
               payment_chain: str, payment_nonce: str, checkout_chain: str | None,
               checkout_nonce: str | None, usage: MandateContext) -> VerifiedBundle:
        vb = VerifiedBundle()
        self.verify_open_mandates(vb, open_checkout, open_payment, user_pub)
        self.verify_checkout_jwt(vb, checkout_jwt)
        self.verify_payment_chain(vb, payment_chain, payment_nonce, user_pub, usage)
        self.verify_checkout_chain(vb, checkout_chain, checkout_nonce, checkout_jwt, user_pub)
        return vb


def summarize_cart(vb: VerifiedBundle) -> dict[str, Any]:
    """Cart facts derived only from the merchant-signed checkout payload."""
    p = vb.checkout_payload or {}
    items = []
    for li in p.get("line_items", []) or []:
        item = li.get("item") or {}
        qty = int(li.get("quantity", 1))
        unit = int(item.get("price", 0))
        line_total = next((t["amount"] for t in li.get("totals", []) if t.get("type") == "total"), unit * qty)
        items.append({
            "sku": str(item.get("id", "")), "title": str(item.get("title", "")), "qty": qty,
            "unit_minor": unit, "line_minor": int(line_total),
            "category": str(item.get("category", "")),
        })
    totals = {t.get("type"): int(t.get("amount", 0)) for t in p.get("totals", []) or []}
    merchant = p.get("merchant") or {}
    ful = p.get("fulfillment") or {}
    return {
        "fulfillment": {"ship_to_sha256": str(ful.get("ship_to_sha256") or ""), "promised_by": str(ful.get("promised_by") or "")},
        "item_facts": {str(k): dict(v) for k, v in (p.get("item_facts") or {}).items() if isinstance(v, dict)},
        "id": str(p.get("id", "")),
        "items": items,
        "skus": [i["sku"] for i in items],
        "item_count": len(items),
        "subtotal_minor": totals.get("subtotal", sum(i["line_minor"] for i in items)),
        "total_minor": totals.get("total", sum(i["line_minor"] for i in items)),
        "currency": str(p.get("currency", "")),
        "merchant": {"id": str(merchant.get("id", "")), "name": str(merchant.get("name", "")), "website": str(merchant.get("website") or "")},
        "hash": vb.checkout_hash or "",
        "shipping_address_hash": str((p.get("buyer") or {}).get("address_hash", "")),
    }


def summarize_open_mandates(vb: VerifiedBundle) -> dict[str, Any]:
    """Flatten the user-signed constraints into plain facts for the rule packs."""
    out: dict[str, Any] = {
        "allowed_merchant_ids": [], "allowed_merchants": [], "allowed_skus": [], "allowed_items": [], "required_qty_by_line": [],
        "max_minor": 0, "min_minor": 0, "currency": "", "allowed_payee_ids": [],
        "exp_open_checkout": 0, "exp_open_payment": 0, "exp": 0, "iat": 0, "budget_max": 0.0,
    }
    oc, op = vb.open_checkout, vb.open_payment
    if oc is not None:
        out["exp_open_checkout"] = int(oc.exp or 0)
        out["iat"] = int(oc.iat or 0)
        for c in oc.constraints:
            t = getattr(c, "type", "")
            if t == "checkout.allowed_merchants":
                out["allowed_merchant_ids"] = [m.id for m in c.allowed]
                out["allowed_merchants"] = [{"id": m.id, "name": m.name, "website": m.website or ""} for m in c.allowed]
            elif t == "checkout.line_items":
                for req in c.items:
                    out["allowed_skus"].extend(i.id for i in req.acceptable_items)
                    out["allowed_items"].extend({"id": i.id, "title": i.title, "quantity": req.quantity} for i in req.acceptable_items)
                    out["required_qty_by_line"].append({"id": req.id, "quantity": req.quantity})
    if op is not None:
        out["exp_open_payment"] = int(op.exp or 0)
        for c in op.constraints:
            t = getattr(c, "type", "")
            if t == "payment.amount_range":
                out["max_minor"] = int(c.max)
                out["min_minor"] = int(c.min or 0)
                out["currency"] = c.currency
            elif t == "payment.allowed_payees":
                out["allowed_payee_ids"] = [m.id for m in c.allowed]
            elif t == "payment.budget":
                out["budget_max"] = float(c.max)
    exps = [e for e in (out["exp_open_checkout"], out["exp_open_payment"]) if e]
    out["exp"] = min(exps) if exps else 0
    return out


def summarize_payment(vb: VerifiedBundle) -> dict[str, Any]:
    cp = vb.closed_payment
    if cp is None:
        return {"amount_minor": 0, "currency": "", "payee": {"id": "", "name": "", "website": ""},
                "instrument_type": "", "transaction_id": "", "reference": ""}
    return {
        "amount_minor": int(cp.payment_amount.amount),
        "currency": cp.payment_amount.currency,
        "payee": {"id": cp.payee.id, "name": cp.payee.name, "website": cp.payee.website or ""},
        "instrument_type": cp.payment_instrument.type,
        "transaction_id": cp.transaction_id,
        "reference": vb.closed_payment_reference or "",
    }
