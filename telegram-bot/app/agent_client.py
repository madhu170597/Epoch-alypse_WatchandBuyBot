"""Minimal A2A client for the shopping agent.

Mirrors the web client's a2aClient.ts: POST JSON-RPC `message/stream` and read
the SSE response. A turn returns both the aggregated text and the structured
artifacts (mandate_request, monitoring, purchase_complete, held, error) so the
orchestrator can drive the conversation the way the web UI does.

Threading matches the web client exactly:
  - the JSON-RPC `id` is the conversation task id, reused across turns;
  - `metadata.sessionId` is stable per chat;
  - string turns go as a text part, control payloads as a data part
    ({"kind": "data", "data": {...}, "mimeType": "application/json"}).
"""

import json
import logging
import re
import uuid
from dataclasses import dataclass, field

import httpx

from app.config import settings

_log = logging.getLogger("telegram_bot")
_DATA_PREFIX = "data: "
# Artifact types the orchestrator reacts to (everything else is prose).
_STRUCTURED = {
    "product_preview_unavailable",
    "mandate_request",
    "monitoring",
    "purchase_complete",
    "error",
    "held",
}


@dataclass
class AgentTurn:
    """One agent turn: joined prose plus any structured artifacts seen."""

    text: str = ""
    artifacts: list[dict] = field(default_factory=list)

    def first(self, *types: str) -> dict | None:
        for art in self.artifacts:
            if art.get("type") in types:
                return art
        return None


def _format_data_part(data: dict) -> str | None:
    """Render a structured artifact briefly for the chat (None = stay quiet).

    Errors are not rendered here: the orchestrator turns them into a plain-language
    message (friendly_error) with a retry button where that helps.
    """
    if data.get("type") == "purchase_complete":
        ref = data.get("order_id") or data.get("payment_id")
        return "✅ Order placed!" + (f"\nReference: {ref}" if ref else "")
    return None


_MODEL_BUSY = ("Model check unavailable", "Model review exceeded")


def friendly_error(err: dict) -> tuple[str, bool]:
    """Plain-language text for an agent error artifact, and whether retrying can help.

    End users never see error codes or stack-style text.
    """
    code, msg = err.get("error", ""), err.get("message") or ""
    nothing = "Nothing was charged."
    if code == "unsupported_task":
        return ("🛍️ I can only help with shopping orders. Tell me a product and the most "
                "you'd pay, e.g. “Buy JBL Charge 5 under $200”."), False
    if code in ("mandate_guard_escalate", "held") and any(m in msg for m in _MODEL_BUSY):
        return (f"⏳ The safety check (MandateGuard) is busy right now, so I paused the "
                f"order. {nothing} Tap Try again in a moment."), True
    if code in ("mandate_guard_escalate", "held"):
        return (f"✋ MandateGuard wants your approval before this order goes through: "
                f"{msg} {nothing}"), False
    if code == "mandate_guard_deny":
        return f"🛡️ MandateGuard blocked this order: {msg} {nothing}", False
    if code in ("out_of_stock", "item_not_found"):
        return f"🔎 The item isn't available to buy right now. {nothing}", True
    if code in ("charge_failed", "mandate_guard_unreachable"):
        return f"💳 The payment didn't go through. {nothing}", True
    return f"😕 Something went wrong while placing the order. {nothing}", True


def _json_objects(text: str) -> list[tuple[int, int, dict]]:
    """(start, end, object) for every JSON object with a "type" key embedded in text.

    The agent emits its cards (mandate_request, monitoring, ...) as JSON inside the
    reply prose, the way the web client parses them (utils/parsing.ts).
    """
    found, i = [], 0
    while (i := text.find("{", i)) >= 0:
        depth, j, in_str, esc = 0, i, False, False
        while j < len(text):
            c = text[j]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
            elif c == '"':
                in_str = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        try:
            obj = json.loads(text[i:j + 1])
        except ValueError:
            i += 1
            continue
        if isinstance(obj, dict) and "type" in obj:
            found.append((i, j + 1, obj))
            i = j + 1
        else:
            i += 1
    return found


# Framework/tool error lines that must never reach an end user.
_INTERNAL_LINE = re.compile(
    r"^\s*(Tool '[^']*' not found\.?.*|Available tools:.*|Traceback .*|"
    r"(Function|Tool) call .*failed.*|[A-Za-z_.]+(Error|Exception): .*)$",
    re.MULTILINE,
)


def _split_cards(text: str) -> tuple[str, list[dict]]:
    """Prose with the embedded JSON cards removed, plus the cards themselves."""
    cards = _json_objects(text)
    for start, end, _ in reversed(cards):
        text = text[:start] + text[end:]
    text = re.sub(r"```(?:json)?\s*```", "", text)       # emptied code fences
    text = _INTERNAL_LINE.sub("", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text, [c for _, _, c in cards]


def _collect_parts(parts: list, out_text: list[str], out_arts: list[dict]) -> None:
    for part in parts or []:
        if part.get("kind") == "text" or "text" in part:
            text = (part.get("text") or "").strip()
            if text:
                out_text.append(text)
        elif part.get("kind") == "data" and isinstance(part.get("data"), dict):
            data = part["data"]
            if data.get("type") in _STRUCTURED:
                out_arts.append(data)
            rendered = _format_data_part(data)
            if rendered:
                out_text.append(rendered)


async def send_to_agent(
    message: str | dict,
    session_id: str,
    task_id: str | None = None,
) -> AgentTurn:
    """Send one turn (text or control payload); return text + artifacts."""
    if isinstance(message, str):
        parts = [{"kind": "text", "text": message}]
    else:
        parts = [{"kind": "data", "data": message, "mimeType": "application/json"}]

    payload = {
        "jsonrpc": "2.0",
        "id": task_id or uuid.uuid4().hex,
        "method": "message/stream",
        "params": {
            "message": {
                "role": "user",
                "parts": parts,
                "messageId": uuid.uuid4().hex,
            },
            "configuration": {"historyLength": 20},
            "metadata": {"sessionId": session_id},
        },
    }
    headers = {"Content-Type": "application/json", "Accept": "text/event-stream"}
    collected: list[str] = []
    artifacts: list[dict] = []
    try:
        async with httpx.AsyncClient(timeout=settings.agent_timeout_seconds) as client:
            async with client.stream(
                "POST", settings.agent_url, json=payload, headers=headers
            ) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if not line.startswith(_DATA_PREFIX):
                        continue
                    try:
                        obj = json.loads(line[len(_DATA_PREFIX):])
                    except json.JSONDecodeError:
                        continue
                    result = obj.get("result") or {}
                    status = result.get("status") or {}
                    message = status.get("message") or {}
                    if message.get("role") == "agent":  # never echo the user's own turn
                        _collect_parts(message.get("parts", []), collected, artifacts)
                    if result.get("artifact"):
                        _collect_parts(
                            result["artifact"].get("parts", []), collected, artifacts
                        )
                    for art in result.get("artifacts") or []:
                        _collect_parts(art.get("parts", []), collected, artifacts)
    except httpx.HTTPError as e:
        _log.warning("agent request failed: %s", e)
        return AgentTurn(text="😕 I couldn't reach the shopping assistant just now. "
                              "Please try again in a moment.")

    # Status updates and the final artifact repeat the same text: keep each once.
    blocks: list[str] = []
    for block in collected:
        if block not in blocks:
            blocks.append(block)
    prose: list[str] = []
    seen_cards: set[str] = set()
    for block in blocks:
        text, cards = _split_cards(block)
        for card in cards:
            key = json.dumps(card, sort_keys=True)
            if key in seen_cards or card.get("type") not in _STRUCTURED:
                continue
            seen_cards.add(key)
            artifacts.append(card)
            rendered = _format_data_part(card)
            if rendered:
                prose.append(rendered)
        if text and text not in prose:
            prose.append(text)
    return AgentTurn(text="\n\n".join(prose), artifacts=artifacts)
