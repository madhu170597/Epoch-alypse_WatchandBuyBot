"""Telegram account linking.

Flow: a signed-in user calls /telegram/link/start and gets a short one-time
code. They send that code to the Telegram bot; the bot calls /telegram/link/verify
(authenticated with a shared secret) to bind telegram_chat_id -> uid.
"""

import secrets

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel

from app import store
from app.auth import require_user
from app.config import settings

router = APIRouter(prefix="/telegram", tags=["telegram"])

_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # no ambiguous chars


class LinkVerifyBody(BaseModel):
    code: str
    telegram_chat_id: str


@router.post("/link/start")
def link_start(user: dict = Depends(require_user)) -> dict:
    code = "".join(secrets.choice(_ALPHABET) for _ in range(6))
    store.put_link_code(code, user["uid"], settings.link_code_ttl_seconds)
    return {"code": code, "expires_in": settings.link_code_ttl_seconds}


@router.post("/link/verify")
def link_verify(
    body: LinkVerifyBody, x_bot_secret: str | None = Header(default=None)
) -> dict:
    if not settings.telegram_bot_secret or x_bot_secret != settings.telegram_bot_secret:
        raise HTTPException(status_code=401, detail="bad_bot_secret")
    uid = store.take_link_code(body.code.strip().upper())
    if not uid:
        raise HTTPException(status_code=400, detail="invalid_or_expired_code")
    store.set_telegram_chat_id(uid, body.telegram_chat_id)
    return {"uid": uid}
