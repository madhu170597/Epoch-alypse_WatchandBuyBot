"""Did the user get what they signed for? A merchant reports shipping and delivery as ES256-signed events made
with its registered key. Each event is compared with what the user signed (address, deadline, item condition)
and what the merchant itself promised in the signed checkout (delivery date).

Event claims:
  type               "order.shipped" | "order.delivered"
  checkout_hash      base64url sha256 of the checkout JWT the payment was for
  order_id           merchant order id
  ship_to_sha256     salted address commitment, the same scheme the checkout used
  items              [{"sku", "qty", "condition"}]
  shipped_at         ISO time (shipped), with optional estimated_delivery (date)
  delivered_at       ISO time (delivered)
  carrier, tracking_ref, iat
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Any

KINDS = ("order.shipped", "order.delivered")
SKEW_S = 300


def jws_header(token: str) -> dict[str, Any]:
    head = token.split(".")[0]
    return json.loads(base64.urlsafe_b64decode(head + "=" * (-len(head) % 4)))


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    v = value.strip().replace("Z", "+00:00")
    try:
        d = datetime.fromisoformat(v) if "T" in v else datetime.fromisoformat(v + "T00:00:00+00:00")
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def day(iso: str) -> str:
    d = parse_time(iso)
    return f"{d.day} {d:%b %Y}" if d else str(iso)


def validate(claims: dict[str, Any], now: float) -> list[str]:
    """Problems that make the event unusable, before it is matched to any payment."""
    problems = []
    if claims.get("type") not in KINDS:
        problems.append(f"unknown event type {claims.get('type')!r}")
    if not claims.get("checkout_hash"):
        problems.append("the event names no checkout")
    if not isinstance(claims.get("items"), list) or not claims["items"]:
        problems.append("the event lists no items")
    if not isinstance(claims.get("iat"), (int, float)) or claims["iat"] > now + SKEW_S:
        problems.append("the event has no valid issue time")
    stamp = "delivered_at" if claims.get("type") == "order.delivered" else "shipped_at"
    t = parse_time(claims.get(stamp))
    if t is None:
        problems.append(f"{stamp} is missing or not a date")
    elif t.timestamp() > now + SKEW_S:
        problems.append(f"{stamp} is in the future")
    return problems


def reconcile(claims: dict[str, Any], *, signed: dict[str, Any], promise: dict[str, Any], paid_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """What the merchant reports, against what the user signed and the merchant promised. Empty list: it matches."""
    out: list[dict[str, Any]] = []
    if signed.get("ship_to_sha256") and claims.get("ship_to_sha256") != signed["ship_to_sha256"]:
        out.append({"field": "ship_to", "signed": "the address the user signed for",
                    "reported": "a different address" if claims.get("ship_to_sha256") else "no address"})
    want = sorted((str(i.get("sku")), int(i.get("qty", 1))) for i in paid_items)
    got = sorted((str(i.get("sku")), int(i.get("qty", 1))) for i in claims.get("items", []))
    if got != want:
        out.append({"field": "items", "signed": ", ".join(f"{q}× {s}" for s, q in want), "reported": ", ".join(f"{q}× {s}" for s, q in got)})
    cond = str(signed.get("item_condition") or "").lower()
    if cond:
        bad = sorted({str(i.get("condition", "unstated")).lower() for i in claims.get("items", []) if str(i.get("condition", "")).lower() != cond})
        if bad:
            out.append({"field": "condition", "signed": cond, "reported": ", ".join(bad)})
    deadline, promised = signed.get("deliver_by"), promise.get("promised_by")
    if claims.get("type") == "order.delivered":
        d = (parse_time(claims.get("delivered_at")) or datetime.max.replace(tzinfo=timezone.utc)).date().isoformat()
        if deadline and d > deadline:
            out.append({"field": "deliver_by", "signed": deadline, "reported": d})
        if promised and d > promised:
            out.append({"field": "promised_by", "signed": promised, "reported": d})
    else:
        eta = str(claims.get("estimated_delivery") or "")[:10]
        if eta and deadline and eta > deadline:
            out.append({"field": "deliver_by", "signed": deadline, "reported": f"expected {eta}"})
    return out


def headline(claims: dict[str, Any], merchant: str, mismatches: list[dict[str, Any]], signed: dict[str, Any]) -> str:
    kind = "Delivered" if claims.get("type") == "order.delivered" else "Shipped"
    if mismatches:
        labels = {"ship_to": "ship-to address", "items": "items", "condition": "condition", "deliver_by": "deadline", "promised_by": "promised date"}
        return f"{kind} with exceptions: {', '.join(labels[m['field']] for m in mismatches)}."
    if claims.get("type") == "order.delivered":
        bits = [f"Delivered {day(claims['delivered_at'])}"]
        if signed.get("ship_to_sha256"):
            bits.append("signed address")
        if signed.get("item_condition"):
            bits.append(f"condition {signed['item_condition']}")
        if signed.get("deliver_by"):
            bits.append(f"within deadline {day(signed['deliver_by'])}")
        return "; ".join(bits) + "."
    bits = ["Shipped" + (f" via {claims['carrier']}" if claims.get("carrier") else "")]
    if claims.get("estimated_delivery"):
        bits.append(f"estimated {day(claims['estimated_delivery'])}")
    if signed.get("ship_to_sha256"):
        bits.append("signed address")
    return "; ".join(bits) + "."
