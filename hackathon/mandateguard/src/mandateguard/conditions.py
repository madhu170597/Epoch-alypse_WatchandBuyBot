"""Conditions the user sets that AP2 v0.2 cannot express, signed inside the mandate itself.

AP2 v0.2 constraints cover merchant, items, amount, payee, instrument, budget, recurrence and execution date.
The user's own words, the delivery address, a delivery deadline, item condition and a minimum seller rating
have no constraint type. They travel as an extra claim, `mg_conditions`, in the user-signed open checkout
mandate:

  * standard AP2 verifiers (the merchant's chain check included) validate the mandate and ignore the claim,
    which is why it is a claim and not a constraint: AP2 requires unknown constraints to fail;
  * the claim sits in the same signed disclosure as the price and merchant limits, so editing it voids the
    whole mandate;
  * private values (the sentence, the summary shown, the address) are salted hashes, so a merchant reading
    the mandate learns nothing from them.

The merchant states the matching facts in its signed checkout (`fulfillment`, `item_facts`), so every
condition becomes a comparison between two signatures.
"""

from __future__ import annotations

import base64
import hashlib
import os
from typing import Any

from ap2.sdk.generated.open_checkout_mandate import OpenCheckoutMandate


class GuardedOpenCheckoutMandate(OpenCheckoutMandate):
    """AP2 v0.2 open checkout mandate plus the signed `mg_conditions` claim."""

    mg_conditions: dict[str, Any] | None = None


def new_salt() -> str:
    return base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode()


def normalize_address(address: str) -> str:
    return " ".join((address or "").lower().replace(",", " ").split())


def commit(text: str, salt: str) -> str:
    """Salted commitment. The salt is never in the mandate; the user's trusted surface and MandateGuard keep it."""
    return hashlib.sha256(f"{salt}\n{text}".encode()).hexdigest()


def build_conditions(*, intent_text: str, summary_text: str, salt: str, ship_to: str | None = None, address_salt: str | None = None,
                     deliver_by: str | None = None, item_condition: str | None = None, min_seller_rating: float | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"v": 1, "intent_sha256": commit(intent_text, salt), "summary_sha256": commit(summary_text, salt)}
    if ship_to:
        out["ship_to_sha256"] = commit(normalize_address(ship_to), address_salt or salt)
    if deliver_by:
        out["deliver_by"] = deliver_by
    if item_condition:
        out["item_condition"] = item_condition
    if min_seller_rating is not None:
        out["min_seller_rating"] = float(min_seller_rating)
    return out


def condition_facts(conditions: dict[str, Any] | None, *, intent_text: str, summary_text: str, salt: str,
                    checkout: dict[str, Any], cart_items: list[dict[str, Any]], seller_rating: float | None) -> dict[str, Any]:
    """Compare what the user signed with what the merchant signed. Every key is always present for CEL."""
    c = conditions or {}
    ful = (checkout or {}).get("fulfillment") or {}
    facts_by_sku = (checkout or {}).get("item_facts") or {}
    required_condition = str(c.get("item_condition") or "")
    bad = []
    if required_condition:
        for it in cart_items:
            stated = str((facts_by_sku.get(it["sku"]) or {}).get("condition") or "")
            if stated != required_condition:
                bad.append({"sku": it["sku"], "title": it.get("title", ""), "condition": stated or "not stated"})
    ship_req = bool(c.get("ship_to_sha256"))
    ship_stated = bool(ful.get("ship_to_sha256"))
    return {
        "present": bool(c),
        "intent_signed": bool(c.get("intent_sha256")),
        "intent_matches": bool(c) and commit(intent_text or "", salt or "") == c.get("intent_sha256"),
        "summary_matches": bool(c) and commit(summary_text or "", salt or "") == c.get("summary_sha256"),
        "ship_to_required": ship_req,
        "ship_to_stated": ship_stated,
        "ship_to_matches": ship_req and ship_stated and ful.get("ship_to_sha256") == c.get("ship_to_sha256"),
        "deliver_by": str(c.get("deliver_by") or ""),
        "promised_by": str(ful.get("promised_by") or ""),
        "item_condition": required_condition,
        "bad_condition_items": bad,
        "min_seller_rating": float(c.get("min_seller_rating") or 0.0),
        "seller_rating": float(seller_rating) if seller_rating is not None else -1.0,
        "count": len([k for k in c if k != "v"]),
    }
