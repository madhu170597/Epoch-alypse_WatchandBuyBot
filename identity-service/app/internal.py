"""Service-to-service endpoints for the Telegram bot and the shopping agent.

Authenticated with a shared service secret (X-Service-Secret), not a user token,
because the agent acts autonomously under a signed mandate. Exposes only the
minimum the channel/agent need: resolve a linked chat to a uid, and read a
user's default dummy card + shipping address to put in the mandate.
"""

from fastapi import APIRouter, Header, HTTPException

from app import store
from app.config import settings

router = APIRouter(prefix="/internal", tags=["internal"])


def _check(secret: str | None) -> None:
    expected = settings.service_secret or settings.telegram_bot_secret
    if not expected or secret != expected:
        raise HTTPException(status_code=401, detail="bad_service_secret")


def _default(items: list[dict]) -> dict | None:
    if not items:
        return None
    return next((i for i in items if i.get("default")), items[0])


def _format_address(addr: dict) -> str:
    parts = [
        addr.get("name"),
        addr.get("line1"),
        addr.get("line2"),
        " ".join(x for x in [addr.get("city"), addr.get("region"), addr.get("postal")] if x),
        addr.get("country"),
    ]
    return ", ".join(p for p in parts if p)


@router.get("/user-by-chat/{chat_id}")
def user_by_chat(chat_id: str, x_service_secret: str | None = Header(default=None)) -> dict:
    _check(x_service_secret)
    uid = store.uid_by_chat(chat_id)
    if not uid:
        raise HTTPException(status_code=404, detail="not_linked")
    return {"uid": uid}


@router.get("/wallet/{uid}")
def wallet(uid: str, x_service_secret: str | None = Header(default=None)) -> dict:
    _check(x_service_secret)
    card = _default(store.list_cards(uid))
    addr = _default(store.list_addresses(uid))
    return {
        "uid": uid,
        "card": (
            {
                "brand": card["brand"],
                "last4": card["last4"],
                "instrument_id": card["instrument_id"],
                "exp": f"{card['exp_month']:02d}/{card['exp_year']}",
            }
            if card
            else None
        ),
        "ship_to": _format_address(addr) if addr else None,
        "address": addr,
    }
