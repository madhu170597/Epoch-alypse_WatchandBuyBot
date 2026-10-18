"""Telegram bot webhook service.

Commands:
  /start        — welcome + how it works.
  /link <CODE>  — redeem the one-time code from the web app to link this chat.
  /reset        — forget this chat's conversation state and start fresh.
  <any text>    — relayed to the shopping agent; the conversation is driven to an
                  autonomous purchase (mandate approve → monitor → buy/held).

Mandate signing is the demo attestation path here; real passkey signing stays in
the web app. Signed approval events from MandateGuard arrive at /mg/events.

For local mobile testing without a public URL, run `run_polling.py` instead of a
webhook — it long-polls Telegram and shares the same dispatch.
"""

import asyncio
import logging
from collections import deque

from fastapi import FastAPI, Header, HTTPException, Request

from app import dispatch, mandate_guard, orchestrator
from app.config import settings
from app.telegram_api import send_message, set_bot_profile

app = FastAPI(title="Telegram Bot", version="0.2.0")

# Delivery ids already processed (idempotent event handling).
_seen_events: set[str] = set()


@app.on_event("startup")
async def _bot_profile() -> None:
    try:
        await set_bot_profile()
    except Exception:  # noqa: BLE001 - profile text is cosmetic
        _log.warning("could not set bot commands/description", exc_info=True)


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


# Telegram re-delivers an update it did not get a fast 200 for; agent turns take
# far longer, so ack at once, process in the background (Cloud Run must run
# with CPU always allocated) and drop re-deliveries by update_id.
_recent_updates: deque[int] = deque(maxlen=500)
_tasks: set[asyncio.Task] = set()
_log = logging.getLogger("telegram_bot")


async def _process(update: dict) -> None:
    try:
        await dispatch.process_update(update)
    except Exception:  # noqa: BLE001 - one bad update must not kill the bot
        _log.exception("update %s failed", update.get("update_id"))


@app.post("/webhook/{secret}")
async def webhook(secret: str, request: Request) -> dict:
    if not settings.webhook_secret or secret != settings.webhook_secret:
        raise HTTPException(status_code=404, detail="not_found")
    update = await request.json()
    uid = update.get("update_id")
    if uid is not None:
        if uid in _recent_updates:
            return {"ok": True}
        _recent_updates.append(uid)
    task = asyncio.create_task(_process(update))
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
    return {"ok": True}


@app.post("/mg/events")
async def mandateguard_events(request: Request) -> dict:
    """Signed approval webhook from MandateGuard (channel role)."""
    if not mandate_guard.enabled():
        raise HTTPException(status_code=404, detail="not_found")
    raw = await request.body()
    try:
        event = await mandate_guard.verify_event(raw, request.headers)
    except Exception:  # noqa: BLE001 — reject anything that does not verify
        raise HTTPException(status_code=400, detail="bad_signature")
    delivery = request.headers.get("MandateGuard-Delivery") or event.get("id")
    if delivery:
        if delivery in _seen_events:
            return {"ok": True}
        _seen_events.add(delivery)
    await orchestrator.on_event(event)
    return {"ok": True}


@app.post("/notify")
async def notify(
    request: Request, x_notify_secret: str | None = Header(default=None)
) -> dict:
    """Internal: push an event to a user's chat (agent, price watcher)."""
    if not settings.notify_secret or x_notify_secret != settings.notify_secret:
        raise HTTPException(status_code=401, detail="bad_secret")
    body = await request.json()
    chat_id = body.get("chat_id")
    text = body.get("text")
    if not chat_id or not text:
        raise HTTPException(status_code=400, detail="chat_id and text required")
    await send_message(chat_id, text)
    return {"ok": True}
