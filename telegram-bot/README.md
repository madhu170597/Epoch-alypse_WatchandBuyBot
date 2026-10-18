# Telegram Bot

Telegram channel for the agentic ordering bot. It drives the whole conditional
order from chat: you state the order, approve it with a button, and the shopping
agent buys autonomously the moment your conditions are met (through MandateGuard).

## What it does
- `/start` — welcome + how it works.
- `/reset` — forget this chat's conversation state and start fresh.
- `/link <CODE>` — redeems the one-time code from the web app via the identity
  service (`/telegram/link/verify`, shared-secret authed) to bind this chat to a
  Firebase user.
- any other text — relayed to the shopping agent over A2A (`message/stream`). The
  bot replicates the web client's choreography:
  1. agent proposes the order → bot shows **✅ Approve / ❌ Reject** buttons;
  2. Approve → mandate is signed & registered, bot starts watching;
  3. bot polls the agent until the order **completes** (autonomous purchase) or is
     **held** for approval (ESCALATE).
- `POST /mg/events` — signed approval webhook from MandateGuard (`approval.opened`
  delivers the approve button to your phone; `approval.answered` reports the
  outcome). Signature-verified per the integration contract.
- `POST /notify` — internal endpoint (secret-authed) for the agent / price watcher
  to push events to a chat.

Mandate **signing** here is the demo attestation path (no passkey), so the flow is
self-contained on the phone. Real passkey signing stays in the web app.

## Prerequisites
1. **Bot token:** chat with **@BotFather** on Telegram → `/newbot` → copy the token
   into `BOT_TOKEN` in `.env`. (The token *is* the bot's identity — keep it secret.)
2. **MandateGuard channel** (only for the held-approval path): the operator
   registers the bot's service account as a `channel` client. See
   `../hackathon/register-telegram-channel.sh`.

## Run for mobile testing (no public URL)
The fastest path — long-poll Telegram, no webhook/tunnel:
```bash
cp .env.example .env    # set BOT_TOKEN (and AGENT_URL if not localhost)
uv sync
uv run python run_polling.py
```
Start the AP2 stack in another terminal so the agent is up on :8080:
```bash
bash ../AP2/code/samples/python/scenarios/a2a/human-not-present/a2a-run.sh
```
Then message your bot from the Telegram app on your phone. To fire the drop that
triggers the autonomous buy, write the Firestore `merchant_trigger` row (the
a2a-run.sh output prints the exact one-liner for your item).

## Run as a webhook (Cloud Run / tunnel)
```bash
uv run uvicorn app.main:app --port 8091
curl "https://api.telegram.org/bot<BOT_TOKEN>/setWebhook?url=https://<service-url>/webhook/<WEBHOOK_SECRET>"
```

## Endpoints
| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/healthz` | — | liveness |
| POST | `/webhook/{secret}` | path secret | Telegram updates |
| POST | `/mg/events` | MandateGuard signature | approval events |
| POST | `/notify` | `X-Notify-Secret` | push event to a chat |

## Notes
- Conversation state is in-process (fine for one Cloud Run instance / local run). A
  second instance would not share pending mandates or poll loops.
