"""Shared Telegram update dispatch, used by both the webhook and the poller."""

from app import identity, orchestrator
from app.telegram_api import answer_callback_query, inline_buttons, send_message

# One-tap example orders on the welcome card (callback data "ex:<n>").
EXAMPLES = [
    ("📉 Wait for a price drop", "Buy Sony WH-1000XM5 black from SoundHub if it drops to $250 this week"),
    ("⚡ Buy now within budget", "Get me a JBL Charge 5 blue speaker under $200"),
    ("🛡️ See a scam page blocked", "Buy Bose QuietComfort Ultra earbuds if under $260"),
]

WELCOME = (
    "👋 Hi! I'm your shopping agent. Tell me what to buy and your budget once — "
    "I watch the price and buy it for you the moment it fits. Every payment is "
    "checked by MandateGuard, an independent safety service, before any money moves.\n\n"
    "How it works:\n"
    "1️⃣ Tell me the product, your max price and (optionally) a deadline.\n"
    "   e.g. “Buy Sony WH-1000XM5 black if it drops to $250 this week”\n"
    "2️⃣ I check the price and show you an order card.\n"
    "3️⃣ Tap ✅ Approve. Only that button authorises me — typing “yes” never spends money.\n"
    "4️⃣ I watch the price and buy automatically when it's within your budget. "
    "You'll get ✅ Order placed with a reference.\n\n"
    "Good to know:\n"
    "• This is a demo: dummy card, no real money. Orders are fulfilled by the demo store SoundHub.\n"
    "• If something looks off on the merchant's page, MandateGuard blocks it and nothing is charged.\n"
    "• If I say the safety check is busy, tap 🔄 Try again.\n\n"
    "Commands: /reset start a new order · /help show this again\n\n"
    "Try one of these 👇"
)


def _welcome_buttons() -> dict:
    return inline_buttons([[{"text": label, "callback_data": f"ex:{i}"}]
                           for i, (label, _) in enumerate(EXAMPLES)])


async def process_update(update: dict) -> None:
    """Handle one Telegram update (message or callback_query)."""
    callback = update.get("callback_query")
    if callback:
        msg = callback.get("message") or {}
        chat_id = msg.get("chat", {}).get("id")
        data = callback.get("data", "")
        if chat_id is not None and data.startswith("ex:"):
            await answer_callback_query(callback.get("id"))
            try:
                example = EXAMPLES[int(data[3:])][1]
            except (ValueError, IndexError):
                return
            orchestrator.reset(chat_id)  # an example always starts a fresh order
            await send_message(chat_id, f"🛒 {example}")
            await orchestrator.handle_text(chat_id, example)
            return
        if chat_id is not None:
            await orchestrator.handle_callback(
                chat_id, callback.get("id"), callback.get("data", ""), msg.get("message_id")
            )
        return

    message = update.get("message") or update.get("edited_message")
    if not message:
        return

    chat_id = message.get("chat", {}).get("id")
    text = (message.get("text") or "").strip()
    if chat_id is None or not text:
        return

    if text.startswith("/start") or text.startswith("/help"):
        await send_message(chat_id, WELCOME, reply_markup=_welcome_buttons())
    elif text.startswith("/reset"):
        orchestrator.reset(chat_id)
        await send_message(
            chat_id,
            "🆕 Fresh start. What would you like to order? Tell me the product and your "
            "max price, or pick an example 👇",
            reply_markup=_welcome_buttons(),
        )
    elif text.startswith("/link"):
        parts = text.split(maxsplit=1)
        if len(parts) < 2 or not parts[1].strip():
            await send_message(chat_id, "Usage: /link YOURCODE")
        else:
            _, resp = await identity.link_account(parts[1].strip(), str(chat_id))
            await send_message(chat_id, resp)
    else:
        await orchestrator.handle_text(chat_id, text)
