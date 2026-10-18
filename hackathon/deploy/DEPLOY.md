# Deploy & test — web app + Telegram on Cloud Run

Everything runs on Cloud Run in `hackathon-proto-mk26` (`us-central1`). No sign-in:
the web app opens straight into the chat, and the Telegram bot works for any chat.

## Prerequisites
1. gcloud login + project
   ```bash
   gcloud auth login
   gcloud config set project hackathon-proto-mk26
   ```
2. `AP2/.secrets/` holds `shopping-agent-sa.json`, `trusted-surface-sa.json` and
   `mandateguard-fixed-keys.json` (gitignored; never commit them).
3. Telegram (optional): create a bot with @BotFather and export its token once.
   The script stores it in Secret Manager (`tg-bot-token`) and reuses it later.
   ```bash
   export BOT_TOKEN=<token from BotFather>
   ```

## Deploy
```bash
bash hackathon/deploy/deploy-all.sh
```
The script checks its prerequisites first, builds every image in parallel with Cloud
Build, deploys in dependency order, sets the Telegram webhook, and finishes with smoke
checks. It stops at the first failure and prints that step's log. It is safe to re-run.

Useful options:
```bash
ONLY="shopping-agent web" bash hackathon/deploy/deploy-all.sh     # just these services
SKIP_BUILD=1 bash hackathon/deploy/deploy-all.sh                  # config-only redeploy
```

## What gets deployed
| Service | Notes |
|---|---|
| `soundhub` | Merchant site registered with MandateGuard (same URL). Serves the static catalog plus on-demand listings and timed demo price drops from Firestore. |
| `merchant-agent` | A2A merchant for SoundHub. Lists unknown products on SoundHub and schedules demo price drops. |
| `credentials-provider-agent`, `merchant-payment-processor-agent` | A2A roles. |
| `shopping-agent` | ADK agent. Exactly one always-on instance (sessions and signed mandates are in-process). |
| `identity-service` | Dummy wallet / linking (optional; sign-in is off). |
| `telegram-bot` | One always-on instance with CPU always allocated (price-watch loops run in-process). |
| `web` | Static chat UI (nginx). |

## Demo behaviour
- Any product, any store name, any budget. Every order is fulfilled by SoundHub, the one
  merchant MandateGuard trusts.
- If the item is in stock within budget when the mandate is signed, the agent buys at once.
- Otherwise the merchant schedules a price drop to just under the budget (and under $480,
  inside MandateGuard's $500/hour unattended-spend limit) that goes live after a random 0–30 s. The page,
  cart and MandateGuard's own re-fetch all show the same price, then the agent buys.
- Drops expire after 30 minutes and the listing returns to its normal price.
- Each web browser session / Telegram chat is its own customer, so one chat's orders never
  affect another's (state and MandateGuard velocity limits are per chat). Several orders in one chat within an
  hour can pass $500 and be held for approval; start a new chat to avoid that.

## Try it
Web: open the `web` URL printed at the end. Telegram: message your bot.
```
Buy Sony WH-1000XM5 black from SoundHub if it drops to $250 this week
yes, $250 is fine
(approve)
```
Expected: signed → watching → price drops under $250 within ~30 s → order placed.
