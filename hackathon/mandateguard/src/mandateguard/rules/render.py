"""Render rule reasons with real values.

A pack rule's `reason` is a template over the fact tree, e.g.

    "The cart total is {cart.total_minor|money}. The user signed for {mandate.min_minor|money} to {mandate.max_minor|money}."

`{detail}` refers to the rule's CEL `detail` expression. Filters: money, items, join, first, pct, time.
Rendering never raises into the decision path: on any error the caller falls back to the rule title.
"""

from __future__ import annotations

import re
import time
from typing import Any

_TOKEN = re.compile(r"\{([A-Za-z_][\w.]*)(?:\|(\w+))?\}")
_SYMBOLS = {"USD": "$", "EUR": "€", "GBP": "£", "INR": "₹"}


def money(minor: Any, currency: str = "USD") -> str:
    try:
        n = int(minor)
    except (TypeError, ValueError):
        return str(minor)
    body = f"{abs(n) / 100:,.2f}"
    sign = "-" if n < 0 else ""
    sym = _SYMBOLS.get(currency or "")
    return f"{sign}{sym}{body}" if sym else f"{sign}{currency} {body}".strip()


def _join(values: list[str]) -> str:
    values = [v for v in values if v]
    if len(values) <= 1:
        return "".join(values)
    return ", ".join(values[:-1]) + " and " + values[-1]


def _items(value: Any, currency: str) -> str:
    out = []
    for it in value or []:
        if isinstance(it, dict):
            title = it.get("title") or it.get("sku", "")
            sku = it.get("sku", "")
            line = it.get("line_minor")
            bits = [b for b in (sku if sku and sku != title else "", money(line, currency) if line is not None else "") if b]
            out.append(f"{title} ({', '.join(bits)})" if bits else title)
        else:
            out.append(str(it))
    return _join(out)


_AP2_AMOUNT = re.compile(r"\b(Amount|maximum|minimum|budget|total)\s+(\d+)\b")


def _ap2(values: Any, currency: str) -> str:
    """AP2 SDK violation messages, with their minor-unit amounts shown as money."""
    out = [_AP2_AMOUNT.sub(lambda m: f"{m.group(1)} {money(m.group(2), currency)}", str(v)) for v in (values or []) if v]
    return "; ".join(out)


def _lookup(facts: dict[str, Any], path: str, detail: Any) -> Any:
    if path == "detail":
        return detail
    cur: Any = facts
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            raise KeyError(path)
    return cur


def render(template: str, facts: dict[str, Any], detail: Any = None) -> str:
    currency = (facts.get("cart") or {}).get("currency") or (facts.get("mandate") or {}).get("currency") or "USD"

    def sub(m: re.Match) -> str:
        value = _lookup(facts, m.group(1), detail)
        f = m.group(2)
        if f == "money":
            return money(value, currency)
        if f == "items":
            return _items(value, currency)
        if f == "join":
            return _join([str(v) for v in (value or [])])
        if f == "first":
            return str(value[0]) if value else ""
        if f == "pct":
            return f"{float(value) * 100:.0f}%"
        if f == "time":
            return time.strftime("%d %b %Y, %H:%M UTC", time.gmtime(int(value)))
        if f == "date":
            try:
                return time.strftime("%d %b %Y", time.strptime(str(value), "%Y-%m-%d"))
            except ValueError:
                return str(value)
        if f == "conditions":
            return _join([f"{it.get('title') or it.get('sku')} as {it.get('condition')}" for it in (value or []) if isinstance(it, dict)])
        if f == "ap2":
            return _ap2(value, currency)
        if f == "rating":
            return f"{float(value):.1f}"
        if f:
            raise ValueError(f"unknown filter {f}")
        return str(value)

    return _TOKEN.sub(sub, template)
