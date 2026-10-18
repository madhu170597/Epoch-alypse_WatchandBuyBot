"""Delivers approval links to the user's linked channel.

The link carries a one-time key, so it must go to the user and never to the shopping agent.
Telegram is optional: set MG_TELEGRAM_BOT_TOKEN and the mandate's linked_channels["telegram"] chat id.
Without it, the channel service fetches links from GET /v1/approvals/pending.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from .rules.render import money

log = logging.getLogger("mandateguard.notifier")


class TelegramNotifier:
    def __init__(self, bot_token: str, timeout_s: float = 4.0):
        self.url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        self.timeout = timeout_s

    def approval_opened(self, apr: dict[str, Any], link: str) -> dict[str, Any] | None:
        """Sends the link; returns what to record about the delivery, or None when nothing was sent."""
        chat_id = (apr.get("linked_channels") or {}).get("telegram")
        if not chat_id:
            return None
        att = apr.get("attempted", {})
        items = ", ".join(f"{i.get('qty', 1)}× {i.get('title') or i.get('sku')}" for i in att.get("items", []))
        why = "\n".join(f"• {r['detail']}" for r in apr.get("reasons", [])[:3])
        until = time.strftime("%H:%M UTC", time.gmtime(apr["expires_at"]))
        text = (f"Purchase approval required\n\n"
                f"{att.get('merchant', {}).get('name', '')}: {items}\n"
                f"Amount: {money(att.get('total_minor', 0), att.get('currency', 'USD'))}\n\n"
                f"Reason:\n{why}\n\nExpires {until}. No action means no purchase.")
        r = httpx.post(self.url, timeout=self.timeout, json={
            "chat_id": chat_id, "text": text, "disable_web_page_preview": True,
            "reply_markup": {"inline_keyboard": [[{"text": "Review and approve", "url": link}]]},
        })
        if r.status_code != 200:
            log.warning("telegram sendMessage failed: %s %s", r.status_code, r.text[:200])
            return None
        return {"channel": "telegram", "message_id": str((r.json().get("result") or {}).get("message_id", ""))}
