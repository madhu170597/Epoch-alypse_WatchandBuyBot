"""Calls to the identity service for Telegram account linking + wallet."""

import httpx

from app.config import settings


def _service_secret() -> str:
    return settings.service_secret or settings.telegram_bot_secret


async def resolve_chat(telegram_chat_id: str) -> str | None:
    """Return the linked Firebase uid for a chat, or None if not linked."""
    url = f"{settings.identity_url.rstrip('/')}/internal/user-by-chat/{telegram_chat_id}"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers={"X-Service-Secret": _service_secret()})
        if resp.status_code == 200:
            return resp.json().get("uid")
        return None
    except httpx.HTTPError:
        return None


async def get_wallet(uid: str) -> dict:
    """Return {card, ship_to, address} for a uid (empty dict on failure)."""
    url = f"{settings.identity_url.rstrip('/')}/internal/wallet/{uid}"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers={"X-Service-Secret": _service_secret()})
        return resp.json() if resp.status_code == 200 else {}
    except httpx.HTTPError:
        return {}


async def link_account(code: str, telegram_chat_id: str) -> tuple[bool, str]:
    """Redeem a one-time link code. Returns (ok, message)."""
    url = f"{settings.identity_url.rstrip('/')}/telegram/link/verify"
    headers = {"X-Bot-Secret": settings.telegram_bot_secret}
    body = {"code": code, "telegram_chat_id": str(telegram_chat_id)}
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(url, json=body, headers=headers)
        if resp.status_code == 200:
            return True, "Your Telegram is now linked to your account."
        detail = resp.json().get("detail", resp.text)
        return False, f"Link failed: {detail}"
    except httpx.HTTPError as e:
        return False, f"Link service unreachable: {e}"
