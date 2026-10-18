"""Per-chat conversation orchestration for the Telegram-only flow.

Replicates the web client's choreography (useChat.ts) over Telegram:

  user text ─► agent ─► mandate_request artifact
                           └─► bot shows [Approve]/[Reject] buttons
  Approve   ─► {type: mandate_approved} ─► agent signs + registers + monitors
            ─► bot polls {type: check_product_now} until a terminal artifact:
                 purchase_complete  → "Order placed"
                 held (ESCALATE)    → deliver the approval to the phone
                 error              → report and stop

Mandate approval here is the demo attestation path (no passkey). Real passkey
signing stays in the web app; this is the self-contained mobile channel.

State is in-process (fine for a single Cloud Run instance / local run). A second
instance would not share pending mandates or poll loops — noted for later.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field

from app import agent_client, identity, mandate_guard
from app.config import settings
from app.telegram_api import (
    answer_callback_query,
    edit_reply_markup,
    inline_buttons,
    send_message,
)


@dataclass
class ChatState:
    chat_id: int
    session_id: str
    task_id: str
    pending_mandate: dict | None = None  # last mandate_request awaiting approval
    user_id: str | None = None
    wallet: dict = field(default_factory=dict)  # {card, ship_to, address}
    poll_task: asyncio.Task | None = None
    seen_deliveries: set[str] = field(default_factory=set)
    history: list[tuple[str, str]] = field(default_factory=list)  # (role, text)
    last_mon: dict | None = None  # what the price watch polls; reused by "Try again"


_log = logging.getLogger("telegram_bot")
_chats: dict[int, ChatState] = {}


def _retry_button() -> dict:
    return inline_buttons([[{"text": "🔄 Try again", "callback_data": "retry"}]])
# approval_id -> chat_id, so a pushed/pulled approval reaches the right chat.
_approval_chat: dict[str, int] = {}


def _state(chat_id: int) -> ChatState:
    st = _chats.get(chat_id)
    if st is None:
        st = ChatState(
            chat_id=chat_id,
            # New agent session per ChatState: /reset must also drop the agent-side
            # mandate and plan (the agent keys its state by this id).
            session_id=f"telegram:{chat_id}:{int(time.time())}",
            task_id=f"tg-{chat_id}-{int(time.time())}",
        )
        _chats[chat_id] = st
    return st


def reset(chat_id: int) -> None:
    st = _chats.get(chat_id)
    if st and st.poll_task:
        st.poll_task.cancel()
    _chats.pop(chat_id, None)


async def _handle_turn(st: ChatState, turn: agent_client.AgentTurn) -> None:
    """Send the agent's prose, then act on any structured artifact."""
    mandate = turn.first("mandate_request")
    if mandate:
        st.pending_mandate = mandate
        summary = (
            mandate.get("item_name", "item")
            + f" · cap ${mandate.get('price_cap', '?')}"
            + (f" · now ${mandate['current_price']}" if mandate.get("current_price") else "")
        )
        card = st.wallet.get("card")
        if card:
            summary += f"\nPay: {card['brand']} ••{card['last4']}"
        if st.wallet.get("ship_to"):
            summary += f"\nShip: {st.wallet['ship_to']}"
        if turn.text:
            await send_message(st.chat_id, turn.text)
        await send_message(
            st.chat_id,
            f"Approve this order?\n{summary}",
            reply_markup=inline_buttons(
                [[{"text": "✅ Approve", "callback_data": "mr:yes"},
                  {"text": "❌ Reject", "callback_data": "mr:no"}]]
            ),
        )
        return

    if turn.text:
        await send_message(st.chat_id, turn.text)

    held = turn.first("held")
    if held:
        await _deliver_held(st, held)
    err = turn.first("error")
    if err and not turn.first("purchase_complete"):
        await _report_error(st, err)


async def _report_error(st: ChatState, err: dict) -> None:
    """Tell the user what happened in plain words; offer Try again when it can help."""
    text, retry = agent_client.friendly_error(err)
    markup = None
    if retry and st.last_mon:
        markup = _retry_button()
    await send_message(st.chat_id, text, reply_markup=markup)


async def _ensure_user(st: ChatState) -> bool:
    """Resolve + cache the linked user and wallet. True if ready to order.

    When ENFORCE_LINK is off this is a no-op that always returns True.
    """
    if not settings.enforce_link:
        return True
    if not st.user_id:
        st.user_id = await identity.resolve_chat(str(st.chat_id))
    if not st.user_id:
        await send_message(
            st.chat_id,
            "Please sign in on the web app, add a card + address, then link this "
            "chat with /link YOURCODE before I can order for you.",
        )
        return False
    if not st.wallet:
        st.wallet = await identity.get_wallet(st.user_id)
    return True


def _with_context(st: ChatState, text: str) -> str:
    """Prefix the recent thread, as the web app does (useChat.augmentUserMessageForAgent).

    Every A2A message reaches the agent as a fresh ADK session, so without this a
    bare "yes, $250 is fine" carries no product or budget.
    """
    if len(text) >= 220 or not st.history:
        return text
    users = [t for r, t in st.history if r == "user"][-8:]
    agents = [t for r, t in st.history if r == "agent"][-4:]
    return "\n".join([
        "Thread context (user last 8):",
        *[f"  U: {m[:200]}" for m in users],
        "Agent last 4:",
        *[f"  A: {m[:300]}" for m in agents],
        "",
        "Do not re-ask for product or budget. If user is confirming after "
        "product_preview_unavailable, build slug_0 item_id, call check_product with "
        "limited_drop=true, then emit mandate_request — do NOT call search_inventory.",
        "",
        f"User says: {text}",
    ])


async def handle_text(chat_id: int, text: str) -> None:
    """A free-text message from the user: relay to the agent, act on the reply."""
    st = _state(chat_id)
    if not await _ensure_user(st):
        return
    turn = await agent_client.send_to_agent(_with_context(st, text), st.session_id, st.task_id)
    st.history.append(("user", text))
    if turn.text:
        st.history.append(("agent", turn.text))
    del st.history[:-24]
    await _handle_turn(st, turn)


async def handle_callback(chat_id: int, query_id: str, data: str, message_id: int) -> None:
    """An inline button tap."""
    st = _state(chat_id)
    if data == "mr:no":
        await answer_callback_query(query_id, "Cancelled")
        await edit_reply_markup(chat_id, message_id)
        st.pending_mandate = None
        await send_message(chat_id, "Order cancelled.")
        return
    if data == "mr:yes":
        await answer_callback_query(query_id, "Approved")
        await edit_reply_markup(chat_id, message_id)
        if not st.pending_mandate:
            await send_message(chat_id, "Nothing to approve.")
            return
        mandate = dict(st.pending_mandate)
        st.pending_mandate = None  # claim it now: a double tap must not sign twice
        if st.user_id:
            mandate["user_id"] = st.user_id
        # ship_to is shown for context but not signed: the demo merchant's
        # checkout does not state a ship-to, so MandateGuard would deny a signed one.
        card = st.wallet.get("card")
        if card:
            mandate["payment_instrument"] = card["instrument_id"]
            mandate.setdefault("payment_method_description", f"{card['brand']} ••{card['last4']}")
        turn = await agent_client.send_to_agent(
            {"type": "mandate_approved", "mandate_request": mandate},
            st.session_id,
            st.task_id,
        )
        st.user_id = st.user_id or mandate.get("user_id")
        await _handle_turn(st, turn)
        if _start_monitor(st, turn, mandate):
            await send_message(chat_id, "Mandate signed. Watching for your conditions…")
        return
    if data == "retry":
        await answer_callback_query(query_id, "Trying again…")
        await edit_reply_markup(chat_id, message_id)
        if not st.last_mon:
            await send_message(chat_id, "There's no order to retry. Tell me what you'd like to buy.")
            return
        if st.poll_task and not st.poll_task.done():
            st.poll_task.cancel()
        await send_message(chat_id, "🔄 Trying again…")
        st.poll_task = asyncio.create_task(_monitor_loop(st, st.last_mon))
        return
    if data.startswith("ap:"):  # approval decision from a held purchase
        _, approval_id, decision = data.split(":", 2)
        await answer_callback_query(query_id, "Sending…")
        await edit_reply_markup(chat_id, message_id)
        await _redeem_approval(st, approval_id, decision)
        return
    await answer_callback_query(query_id)


# ── Autonomous monitoring loop ─────────────────────────────────────────────
def _monitoring_payload(st: ChatState, mon: dict) -> dict:
    return {
        "type": "check_product_now",
        "item_id": mon.get("item_id"),
        "price_cap": mon.get("price_cap"),
        "qty": mon.get("qty", 1),
        "open_checkout_mandate": mon.get("open_checkout_mandate"),
        "open_payment_mandate": mon.get("open_payment_mandate"),
        "message": "Check product now",
        "source": "telegram_poll",
    }


def _start_monitor(st: ChatState, turn: agent_client.AgentTurn, mandate: dict) -> bool:
    """Start polling unless the turn already ended the order. True if started.

    Falls back to the approved mandate's item and cap when the agent's reply
    carried no monitoring artifact, so a terse model reply never stalls the order.
    """
    if any(turn.first(t) for t in ("purchase_complete", "held", "error")):
        return False
    mon = turn.first("monitoring") or {
        "item_id": mandate.get("item_id"),
        "price_cap": mandate.get("price_cap"),
        "qty": mandate.get("qty", 1),
    }
    if not mon.get("item_id"):
        return False
    if st.poll_task and not st.poll_task.done():
        st.poll_task.cancel()
    st.last_mon = mon
    st.poll_task = asyncio.create_task(_monitor_loop(st, mon))
    return True


async def _monitor_loop(st: ChatState, mon: dict) -> None:
    deadline = time.time() + settings.monitor_max_seconds
    failures = 0
    last_status = None
    try:
        while time.time() < deadline:
            await asyncio.sleep(settings.monitor_poll_seconds)
            try:
                turn = await agent_client.send_to_agent(
                    _monitoring_payload(st, mon), st.session_id, st.task_id
                )
                failures = 0
            except Exception as e:  # noqa: BLE001 - a transient agent error retries
                _log.warning("price watch poll failed (%s/5): %s", failures + 1, e)
                failures += 1
                if failures >= 5:
                    await send_message(
                        st.chat_id,
                        "😕 I lost contact with the shopping assistant, so I stopped watching. "
                        "Nothing was charged. Tap Try again.",
                        reply_markup=_retry_button(),
                    )
                    return
                continue
            mon_now = turn.first("monitoring")
            if mon_now:
                price, ok = mon_now.get("current_price"), mon_now.get("available")
                status = (price, ok)
                if status != last_status and price is not None:
                    last_status = status
                    cap = mon_now.get("price_cap", mon.get("price_cap"))
                    await send_message(
                        st.chat_id,
                        f"👀 Now ${price} ({'in stock' if ok else 'unavailable'}) · "
                        f"buying at ≤ ${cap}",
                    )
            if turn.first("purchase_complete"):
                if turn.text:
                    await send_message(st.chat_id, turn.text)
                return
            held = turn.first("held")
            if held:
                await _deliver_held(st, held)
                return
            err = turn.first("error")
            if err:
                await _report_error(st, err)
                return
        await send_message(
            st.chat_id,
            "⌛ I stopped watching for now (time limit). Tap Try again to keep watching.",
            reply_markup=_retry_button(),
        )
    except asyncio.CancelledError:
        pass


# ── Approval delivery (ESCALATE) ───────────────────────────────────────────
async def _deliver_held(st: ChatState, held: dict) -> None:
    approval_id = held.get("approval_id")
    if approval_id:
        _approval_chat[approval_id] = st.chat_id
    # If MandateGuard pushes/pulls the link we use it; otherwise tell the user
    # it is held (the link needs the channel registration).
    link = held.get("link")
    if link:
        await _send_approval(st.chat_id, approval_id, link, held.get("summary", ""))
    else:
        await send_message(
            st.chat_id,
            "🔒 This purchase is waiting for your approval. Nothing was charged. "
            "I'll send the approve button here as soon as it arrives.",
        )


async def _send_approval(chat_id: int, approval_id: str | None, link: str, summary: str) -> None:
    rows = [[{"text": "🔓 Review & approve", "url": link}]]
    if approval_id and mandate_guard.enabled():
        rows.append(
            [{"text": "✅ Approve here", "callback_data": f"ap:{approval_id}:approve"},
             {"text": "❌ Reject", "callback_data": f"ap:{approval_id}:reject"}]
        )
    await send_message(
        chat_id,
        "🔒 Purchase held for approval." + (f"\n{summary}" if summary else ""),
        reply_markup=inline_buttons(rows),
    )


async def _redeem_approval(st: ChatState, approval_id: str, decision: str) -> None:
    if not mandate_guard.enabled():
        await send_message(st.chat_id, "Approval channel not configured.")
        return
    try:
        await mandate_guard.redeem(approval_id, str(st.chat_id), decision)
        await send_message(
            st.chat_id,
            "Approved — completing your order…" if decision == "approve" else "Rejected.",
        )
    except Exception as e:  # noqa: BLE001 — surface any redeem failure to the user
        await send_message(st.chat_id, f"Could not send your answer: {e}")


# ── Inbound MandateGuard events (webhook) ──────────────────────────────────
async def on_event(event: dict) -> None:
    """Handle a verified approval webhook event."""
    etype = event.get("type")
    data = event.get("data") or {}
    if etype == "approval.opened":
        approval_id = data.get("approval_id")
        chat_id = _approval_chat.get(approval_id)
        if chat_id is None:
            tg = (data.get("linked_channels") or {}).get("telegram")
            chat_id = int(tg) if tg else None
        if chat_id is None:
            return
        _approval_chat[approval_id] = chat_id
        total = data.get("total")
        merchant = data.get("merchant")
        summary = " · ".join(
            x for x in [merchant, f"${total}" if total is not None else None] if x
        )
        await _send_approval(chat_id, approval_id, data.get("link", ""), summary)
    elif etype == "approval.answered":
        approval_id = data.get("approval_id")
        chat_id = _approval_chat.get(approval_id)
        if chat_id is None:
            return
        status = data.get("status")
        msg = {
            "approved": "✅ Approved. Your order is being placed.",
            "rejected": "❌ Rejected. No purchase made.",
            "expired": "⌛ Approval expired. No purchase made.",
            "failed": "⚠️ Approval could not be completed.",
        }.get(status, f"Approval update: {status}")
        await send_message(chat_id, msg)
        if status in ("rejected", "expired", "failed", "approved"):
            _approval_chat.pop(approval_id, None)
