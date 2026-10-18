"""Thin Telegram Bot API client (sendMessage + inline keyboards)."""

from typing import Any

import httpx

from app.config import settings

_API = "https://api.telegram.org"


async def _post(method: str, body: dict) -> dict:
    if not settings.bot_token:
        return {}
    url = f"{_API}/bot{settings.bot_token}/{method}"
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(url, json=body)
    try:
        return resp.json()
    except ValueError:
        return {}


async def send_message(
    chat_id: str | int,
    text: str,
    reply_markup: dict | None = None,
) -> dict:
    """Send a text message to a chat. Best-effort; logs nothing sensitive."""
    body: dict[str, Any] = {"chat_id": chat_id, "text": text}
    if reply_markup is not None:
        body["reply_markup"] = reply_markup
    return await _post("sendMessage", body)


def inline_buttons(rows: list[list[dict]]) -> dict:
    """Build an inline_keyboard reply_markup from rows of button dicts.

    Each button is {"text": ..., "callback_data": ...} or {"text": ..., "url": ...}.
    """
    return {"inline_keyboard": rows}


async def answer_callback_query(callback_query_id: str, text: str = "") -> dict:
    """Acknowledge a tapped inline button so Telegram stops the spinner."""
    body: dict[str, Any] = {"callback_query_id": callback_query_id}
    if text:
        body["text"] = text
    return await _post("answerCallbackQuery", body)


async def edit_reply_markup(chat_id: str | int, message_id: int) -> dict:
    """Remove the inline keyboard from a message (after it is acted on)."""
    return await _post(
        "editMessageReplyMarkup", {"chat_id": chat_id, "message_id": message_id}
    )


async def set_bot_profile() -> None:
    """Command menu and the texts Telegram shows before a user's first message."""
    await _post("setMyCommands", {"commands": [
        {"command": "start", "description": "How it works + example orders"},
        {"command": "reset", "description": "Start a new order"},
        {"command": "help", "description": "Show instructions again"},
    ]})
    await _post("setMyShortDescription", {"short_description":
        "Tell me what to buy and your budget; I buy it when the price fits, "
        "with every payment checked by MandateGuard."})
    await _post("setMyDescription", {"description":
        "I'm a shopping agent demo. Tell me a product and your max price, approve "
        "the order once, and I'll buy it automatically when the price is right. "
        "MandateGuard checks every payment and blocks anything suspicious. "
        "Demo only: dummy card, no real money. Tap Start to begin."})
