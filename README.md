# Agentic Conditional Ordering Bot (AP2 + ADK + MandateGuard)

Tell an agent **what to buy and the most you'll pay** — once. Approve a signed,
limited **AP2 mandate**, and the agent watches the price and buys **autonomously**
the first time your conditions are met. Before any money moves, an independent
governance service, **MandateGuard**, checks every payment and blocks anything that
falls outside what you signed or looks like an attack.

Works from a **web app** and a **Telegram bot**. Demo only: dummy card, mock
payments, no real money.

Built on Google's **Agent Payments Protocol (AP2) v0.2.0** reference samples and the
**Agent Development Kit (ADK)**, running on **Cloud Run** with Gemini on Vertex AI.

---

## Live demo

| | URL |
|---|---|
| Web app | https://web-55485752139.us-central1.run.app |
| Telegram | message the bot, then `/start` |
| Shopping agent (A2A) | https://shopping-agent-55485752139.us-central1.run.app/a2a/shopping_agent |
| Demo store (SoundHub) | https://soundhub-55485752139.us-central1.run.app |
| MandateGuard | https://mandateguard-55485752139.us-central1.run.app |

---

## What happens in one order

```
You:   "Buy Sony WH-1000XM5 black if it drops to $250 this week"
Agent: checks the live price, shows an order card            ── nothing signed yet
You:   tap ✅ Approve                                           ── the ONLY thing that authorises spending
Agent: signs open AP2 mandates (item, max $250, merchant, expiry)
       registers them with MandateGuard, then watches the price
Price: drops under $250
Agent: builds the cart → merchant signs the checkout → agent signs closed mandates
       → asks MandateGuard to decide
MandateGuard: re-checks everything independently → ALLOW + single-use payment token
Agent: charges the token → ✅ Order placed (reference pay_…)
```

If the price is already within budget when you approve, it buys straight away.
If anything is wrong — a different item, a higher price, a look-alike merchant,
hidden instructions on the product page — MandateGuard denies or holds it and
**nothing is charged**.

---

## Architecture

```
 Web app (React) ─┐                       ┌─► Merchant agent (A2A) ─► SoundHub site
                  ├─► Shopping agent ─────┤        (cart, signed checkout, listings, demo drops)
 Telegram bot ────┘   (ADK + Gemini)      ├─► MandateGuard  /v1/admin/mandates  /v1/plans  /v1/decisions
                      consent → monitor   │        (independent governance; re-fetches pages itself)
                      → purchase          └─► Credentials service  /v1/charge  (single-use token)
                                                     shared state: Firestore
```

| Service | Cloud Run name | What it does |
|---|---|---|
| Shopping agent | `shopping-agent` | ADK agent with three sub-agents: **consent** (find product, confirm budget, sign on approval), **monitoring** (watch price/stock), **purchase** (cart → checkout → MandateGuard → charge). Holds no payment credentials. |
| Merchant agent | `merchant-agent` | A2A service for the SoundHub store: price checks, product pages, carts, merchant-signed checkout JWTs. Lists any product on SoundHub on demand and schedules demo price drops. |
| SoundHub | `soundhub` | The merchant website registered with MandateGuard. Static demo catalog (including one page with hidden prompt-injection) plus on-demand listings and timed drops from Firestore. |
| MandateGuard | `mandateguard` | Separate governance service (owned by another team). Verifies the AP2 chain, rule packs (price, merchant, items, replay, velocity, injection…), a model review when needed, then issues a single-use token. |
| Credentials | `credentials` | MandateGuard's companion: charges the single-use token. |
| Credentials provider / payment processor | `credentials-provider-agent`, `merchant-payment-processor-agent` | AP2 sample roles (A2A). |
| Identity | `identity-service` | Optional dummy wallet (test cards, addresses) and Telegram linking. Sign-in is off for the demo. |
| Telegram bot | `telegram-bot` | Telegram front end: approval card with buttons, price updates, plain-language results. |
| Web app | `web` | Chat UI and approval surface (Vite + React, served by nginx). |

All services run in GCP project `hackathon-proto-mk26`, region `us-central1`, as
the runtime service account `shopping-agent-sa`.

---

## Safety model

| Guarantee | How |
|---|---|
| Only the user authorises spending | The signing tool runs **only** when the turn carries the approval button's `mandate_approved` payload, signs exactly those approved values, and at most once per approval. Typed "yes" / "buy it now" never signs. |
| Limits are cryptographic | AP2 SD-JWT open mandates fix item, quantity, max price, merchant, payee and expiry. The closed mandates bind the exact checkout. |
| Independent second opinion | MandateGuard re-verifies the chain, compares the cart with a plan committed **before** pages were read, re-fetches every product page from the registered site, and screens it for hidden instructions. |
| Prompt injection can't spend money | Product pages are untrusted data. The agent reports every page it paid for; MandateGuard blocks pages with concealed instructions (try the Bose earbuds). |
| No replays | Nonces are generated server-side; tokens are single-use; mandates are one purchase each. |
| No cross-user leakage | Agent state is scoped per chat (A2A `metadata.sessionId`); each chat is its own customer for MandateGuard's velocity limits. |
| The model can't corrupt payments | Checkout JWT, hashes, amounts, chain ids and nonces are taken from server state, not relayed by the LLM. |
| Fail closed | MandateGuard unreachable, malformed reply or anything other than ALLOW means no charge. |

---

## Demo behaviour (what's simulated)

- **One store.** Whatever store the user names (Amazon, Best Buy, Nike…), SoundHub
  fulfils the order — it is the only merchant MandateGuard trusts. The agent says so.
- **Any product.** Real products are found with Gemini + Google Search grounding.
  If SoundHub doesn't carry the item, the merchant lists it on SoundHub (search
  price, or a little above budget if no price was found).
- **Price drops on demand.** When you approve and the item is over budget or out of
  stock, the merchant schedules a drop to just under your budget that goes live after
  a random **0–30 s** (while pending, the item shows as temporarily unavailable). The
  drop lives on SoundHub itself, so the page, the cart and MandateGuard's own re-fetch
  all agree. Drops expire after 30 minutes.
- **Spend cap.** MandateGuard holds unattended payments over **$500 per hour per
  customer**, so drops are capped at **$480**. A MacBook "under $1,500" is bought for
  under $480 in the demo.
- **Payments are mock**: dummy card, mock processor.

---

## Using it

### Web
Open the web app and type an order. Approve on the card that appears; the page polls
the agent every 10 s while watching.

### Telegram
Send `/start` for the guide and three one-tap example orders. Commands:
`/start` (how it works), `/reset` (new order), `/help`.

You'll see: an order card with **✅ Approve / ❌ Reject**, "👀 Now $X · buying at ≤ $Y"
updates, then **✅ Order placed** with a reference. Problems come back in plain words
("Nothing was charged.") with a **🔄 Try again** button when retrying can help.

### Demo script
Run orders **one at a time** and `/reset` between them.

| # | Say | You'll see |
|---|---|---|
| 1 | `/start` | Guide + example buttons |
| 2 | `Buy Sony WH-1000XM5 black from SoundHub if it drops to $250 this week` → `yes, $250 is fine` → Approve | Watching at $279.99 → drop under $250 within ~30 s → ✅ Order placed |
| 3 | `Get me a JBL Charge 5 blue speaker from Amazon under $200` → pick one → Approve | Already within budget → ✅ Order placed on the first check |
| 4 | `Buy an Apple Watch Series 10 from Amazon if it drops to $350` → `first one` → Approve | Real product from web search, fulfilled by SoundHub → ✅ Order placed |
| 5 | `I want Sony WH-1000XM5 silver if under $275` → Approve | Back-ordered item → back in stock under budget → ✅ Order placed |
| 6 | `Get me 2 Logitech MX Master 3S mice, max $180 total` → Approve | Quantity 2, total under $180 → ✅ Order placed |
| 7 | `Buy Bose QuietComfort Ultra earbuds if under $260` → Approve | 🛡️ Blocked: hidden instructions on the merchant page. Nothing charged |
| 8 | After any order card appears, type `yes, buy it now` instead of tapping Approve | Card shown again; nothing signed or bought |
| 9 | `Order a MacBook Air M3 from Best Buy, my budget is $1500` → Approve | Spend cap: price drops under $480 → ✅ Order placed |
| 10 | `Write me a poem` | Politely declines: only handles purchases |

---

## Deploy

One script deploys and wires everything, in dependency order, with smoke checks.
It's idempotent and stops at the first failure with that step's log.

**Prerequisites**
1. `gcloud auth login && gcloud config set project hackathon-proto-mk26`
2. `AP2/.secrets/` contains `shopping-agent-sa.json`, `trusted-surface-sa.json` and
   `mandateguard-fixed-keys.json` (gitignored — never commit them).
3. Telegram (once): put the BotFather token in your shell without echoing it, then
   deploy. It's stored in Secret Manager (`tg-bot-token`) and reused afterwards.
   ```bash
   read -rs BOT_TOKEN && export BOT_TOKEN
   ```

**Run**
```bash
bash hackathon/deploy/deploy-all.sh
```
Options:
```bash
ONLY="shopping-agent web" bash hackathon/deploy/deploy-all.sh   # just these services
SKIP_BUILD=1 bash hackathon/deploy/deploy-all.sh                # config-only redeploy
```

The script: checks tools, login, keys and Firestore → uploads secrets (a new version
only when changed) → builds all images in parallel with Cloud Build → deploys
SoundHub, the A2A roles, the agent (one always-on instance), identity, the bot (one
always-on instance with CPU always allocated) and the web app → sets the Telegram
webhook → smoke-checks every service. See [`hackathon/deploy/DEPLOY.md`](hackathon/deploy/DEPLOY.md).

---

## Local development

```bash
cd AP2
uv sync --all-packages
cp code/samples/python/src/roles/shopping_agent_v2/.env.example .env   # then edit
bash code/samples/python/scenarios/a2a/human-not-present/a2a-run.sh    # agent 8080, roles 8001-8003, web 5173
```

Minimal `.env`:
```bash
GOOGLE_GENAI_USE_VERTEXAI=true
GOOGLE_CLOUD_PROJECT=hackathon-proto-mk26
GOOGLE_CLOUD_LOCATION=global
GOOGLE_APPLICATION_CREDENTIALS=/absolute/path/to/sa-key.json
AGENT_MODEL=gemini-2.5-flash
FIRESTORE_ENABLED=true
FLOW=card
MANDATE_GUARD_URL=https://mandateguard-55485752139.us-central1.run.app
MG_AGENT_SA_KEY=/absolute/path/to/.secrets/shopping-agent-sa.json
MG_TRUSTED_SURFACE_SA_KEY=/absolute/path/to/.secrets/trusted-surface-sa.json
```
Without `MANDATE_GUARD_URL` no payment can be approved (the client fails closed).

Telegram locally (no public URL needed):
```bash
cd telegram-bot && uv run python run_polling.py   # BOT_TOKEN + AGENT_URL in telegram-bot/.env
```

---

## Repository layout

```
AP2/                                   AP2 v0.2.0 fork: agent, A2A roles, web app
  Dockerfile.role, Dockerfile.agent    images for the A2A roles and the agent
  code/web-client/                     web app (Vite + React; Dockerfile + nginx.conf)
  code/samples/python/src/
    roles/shopping_agent_v2/           the agent
      shopping_agent/agent.py          sub-agents, approval-gated signing, plan commit
      shopping_agent/a2a_tools.py      merchant calls, MandateGuard decision + retry, page reporting
      shopping_agent/mandate_tools.py  AP2 mandate signing / presentations
      shopping_agent/mandate_guard.py  MandateGuard client (ID-token auth, fail closed)
      shopping_agent/session_state.py  per-chat state keys
      shopping_agent/prompts/          consent / monitoring / purchase prompts
    roles/merchant_agent/              merchant A2A service (listings, drops, checkout)
    common/                            A2A server, Firestore KV store
telegram-bot/                          Telegram webhook service
identity-service/                      dummy wallet + Telegram linking
hackathon/merchant_site/               SoundHub storefront
hackathon/mandateguard/                MandateGuard (other team's service)
hackathon/credentials_service/         MandateGuard companion (/v1/charge)
hackathon/deploy/                      deploy-all.sh, cloudbuild config, DEPLOY.md
hackathon/docs/                        integration contract, design, pitch
```

---

## Configuration reference

| Variable | Service | Meaning |
|---|---|---|
| `AGENT_MODEL` | agent | Gemini model for the agent (default deploy: `gemini-2.5-flash`) |
| `MANDATE_GUARD_URL` | agent, bot | MandateGuard base URL; unset means nothing can be approved |
| `MG_MERCHANT_ID` / `_NAME` / `_WEBSITE` | agent, merchant | The registered merchant (`merchant_clean` / SoundHub) |
| `MG_AGENT_SA_KEY`, `MG_TRUSTED_SURFACE_SA_KEY` | agent | Mounted SA keys for MandateGuard ID tokens |
| `MERCHANT_SITE_URL` | merchant | SoundHub URL (enables listings and drops) |
| `MG_HNP_SPEND_CAP` | merchant | Max demo drop price (default `480`) |
| `DEMO_DROP_MAX_DELAY_SECONDS` / `DEMO_DROP_TTL_SECONDS` | merchant | Drop delay (default 30) and lifetime (default 1800) |
| `FIRESTORE_ENABLED` | agent, roles, SoundHub | Shared state across services |
| `A2A_PUBLIC_URL` | roles | Public origin the agent card advertises |
| `ENFORCE_LINK` | bot | Require a linked account before ordering (demo: `false`) |
| `MONITOR_POLL_SECONDS` | bot | Price-watch interval (deploy: 8) |

Secrets live in Secret Manager: `mg-agent-sa`, `mg-trusted-sa`, `agent-priv`,
`agent-provider`, `merchant-key`, `svc-secret`, `tg-bot-secret`, `tg-webhook-secret`,
`tg-bot-token`, `mg-channel-sa`.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| "⏳ The safety check is busy" / `Model review exceeded …` / `Model check unavailable` | MandateGuard's own Gemini model is slow or out of capacity. The agent already retries twice with fresh signatures; tap **Try again** later. MandateGuard's model and timeout are its env vars `MG_GEMINI_MODEL` / `MG_GEMINI_TIMEOUT_SECONDS` (its owner's call). |
| Order held: "Unattended spend in the last hour…" | MandateGuard's $500/hour per-customer limit. Start a new chat (`/reset` or a new browser session). |
| Agent invents a different product | The client must send the thread recap with each message (web and bot do). Each A2A message is a fresh ADK session. |
| Smoke check 404 on `/healthz` | Cloud Run reserves paths ending in `z`; the script checks `/openapi.json` instead. |
| See what happened on an order | `gcloud logging read 'resource.labels.service_name="shopping-agent"' --freshness 30m` — MandateGuard decisions that aren't ALLOW are logged in full. Its public audit chain: `/v1/audit/records`. |

---

## Known limitations

- A held (ESCALATE) order is not resumed automatically after the customer approves
  it on MandateGuard's approval page.
- While one chat's drop is pending, the same item shows as unavailable to other
  chats for up to 30 s.
- Agent sessions live in memory on one instance; redeploying the agent resets
  in-flight conversations.
- Before you approve, the agent's wording sometimes sounds as if the mandate is
  already set up; only the Approve button signs.
