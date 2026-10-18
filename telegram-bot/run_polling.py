"""Local runner: long-poll Telegram (getUpdates) — no public URL needed.

Use this to test on a phone without a webhook/tunnel: the bot pulls updates from
Telegram and drives the same conversation as the webhook. Approval push events
(/mg/events) are not received in this mode; the ALLOW autonomous-purchase path
works fully, and held approvals fall back to the pull/redeem channel if the bot
is registered.

    uv run python run_polling.py
"""

import asyncio

import httpx

from app import dispatch
from app.config import settings

_API = "https://api.telegram.org"


async def _get_updates(client: httpx.AsyncClient, offset: int) -> list[dict]:
    resp = await client.get(
        f"{_API}/bot{settings.bot_token}/getUpdates",
        params={"offset": offset, "timeout": 25,
                "allowed_updates": '["message","edited_message","callback_query"]'},
    )
    resp.raise_for_status()
    return resp.json().get("result", [])


async def main() -> None:
    if not settings.bot_token:
        raise SystemExit("BOT_TOKEN is not set — put it in telegram-bot/.env")
    # Drop any webhook so getUpdates is allowed.
    async with httpx.AsyncClient(timeout=30.0) as client:
        await client.get(f"{_API}/bot{settings.bot_token}/deleteWebhook")
        me = (await client.get(f"{_API}/bot{settings.bot_token}/getMe")).json()
        print(f"Polling as @{me.get('result', {}).get('username', '?')} — Ctrl+C to stop")
        offset = 0
        while True:
            try:
                updates = await _get_updates(client, offset)
            except httpx.HTTPError as e:
                print(f"getUpdates error: {e}; retrying in 3s")
                await asyncio.sleep(3)
                continue
            for update in updates:
                offset = update["update_id"] + 1
                try:
                    await dispatch.process_update(update)
                except Exception as e:  # noqa: BLE001 — one bad update must not kill the loop
                    print(f"update {update['update_id']} failed: {e}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
