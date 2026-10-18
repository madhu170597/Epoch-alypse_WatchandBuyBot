# MandateGuard

Governance service for AP2 agent payments. It sits between a shopping agent and the credentials service.
Every purchase attempt gets **ALLOW**, **ESCALATE** or **DENY** before any payment token exists. Every step,
from the user's own message to the merchant's delivery report, is a signed record that anyone can re-check.

```
web app ──signed mandate──▶ MandateGuard ◀── shopping agent: commits its plan, then asks for a decision
user's phone ──passkey──▶     │ ALLOW    ──▶ credentials service mints a token bound to the signed record
                              │ ESCALATE ──▶ one-time link to the user, who approves with a passkey
                              │ DENY     ──▶ nothing to redeem
processor ──signed receipt──▶ │ reconciled against what was allowed
merchant ──signed delivery──▶ │ reconciled against what the user signed
                              └ every step ──▶ signed hash chain + evidence + anchored checkpoints
```

Pipeline: **stage 0** identity and input checks, with MandateGuard's own copy of each merchant page; **stage 1**
YAML rule packs (CEL, DENY is final, default deny); **stage 2** Gemini checks that can only tighten, asked only
what code has not already proven; **stage 3** signed record and a token only on ALLOW.

Design notes: [`../docs/MandateGuard-Design.md`](../docs/MandateGuard-Design.md). Pitch: [`../docs/PITCH.md`](../docs/PITCH.md).

## Who authorised this

Each link is a record in the same signed log. Identity comes from proof, never from what a caller claims.

| Link | Proven by | Record |
|---|---|---|
| Person | The user's passkey signs the mandate on MandateGuard's consent page; otherwise the web app attests consent | `mandate.consented` |
| Their words | The original message is kept as evidence; a model checks it against the signed limits once, at registration | `mandate.registered` |
| Mandate | AP2 SDK verification, salted commitments to the request text and summary, the web app's signature checkable in the browser | `mandate.registered` |
| Agent | Google-signed ID token, the agent registry, and the delegated `cnf` key | `agent.registered`, `identity` in each decision |
| Plan | The agent commits what it will buy before browsing; MandateGuard's clock and signature fix it | `plan.committed` |
| Merchant | Checkout JWT signature against the operator's key registry; profile and key changes are records | `merchant.key_registered`, `merchant.profile_updated` |
| Pages | MandateGuard fetches registered merchant pages itself and compares them with the agent's copy | `checks.pages` in each decision |
| Rules | Each pack signed by a registered approver; with `MG_REQUIRE_POLICY_APPROVAL=1` an unsigned pack blocks every purchase | `policy.approver_registered`, `policy.loaded` |
| Decision | MandateGuard's KMS signature, with the request kept by hash | `decision` |
| Approval | Who received the link, then a passkey assertion over the exact amount, payee and decision | `approval.link_issued`, `approval.link_sent`, `approval` |
| Credential | A token bound to the decision record hash; only its hash is recorded | `credential.released` |
| Payment | The processor's own KMS-signed receipt, reconciled against the decision | `payment.executed` |
| Delivery | The merchant's ES256-signed shipping and delivery events, reconciled against the signed address, deadline and condition | `fulfillment.shipped`, `fulfillment.delivered` |
| Refund | A signed refund receipt naming who asked | `payment.refunded` |

## Console

`/console` is the operator view. **Decisions** lists every purchase with its outcome and short reason; **Audit log** lists every
record. A decision opens in five tabs:
- **Summary:** outcome, reasons, model review, decision time, parties, settlement.
- **Authorization:** the chain from customer to delivery, one row per link: party, proof, time, status. "Verify signatures" checks
  every signature in the browser with WebCrypto, each with its signer's published key: MandateGuard, the mandate issuer, the
  customer's passkey, the merchant, the policy approver and the processor.
- **Mandate vs. cart:** the customer's own message, the signed request, and each term as signed, as checked out and as delivered.
- **Evidence:** findings with quoted page text, pages MandateGuard fetched, model checks, the agent trace.
- **Record:** the signed record, re-verification from stored evidence, JSON download.

"Export evidence" downloads every record behind a decision, the stored evidence and the public keys, for offline verification.

## Does this purchase honour what the user signed

| Condition | User signs | Merchant signs at checkout | Merchant reports after payment |
|---|---|---|---|
| Ship-to address | `ship_to_sha256`, salted | `fulfillment.ship_to_sha256` | delivery event `ship_to_sha256` |
| Deliver by | `deliver_by` | `fulfillment.promised_by` | `delivered_at` |
| Item condition | `item_condition` | `item_facts[sku].condition` | each item's `condition` |
| Items | the allowed SKUs and quantities | the cart | the items delivered |
| Seller rating | `min_seller_rating` | | from the operator's registry |

Rules compare the first two columns before payment (`15-conditions`); `/v1/fulfillment` compares all three after it.

## Speed

Measured on the deployed service on 14 October 2026, warm instances. The times are server time from Cloud Run's request logs.

| Purchase | Time | What runs |
|---|---|---|
| Blocked by policy | 0.5 to 0.85 s | identity, page checks, rules, signed record |
| Allowed, fully proven | 1.2 to 1.45 s | the same, plus the token from the credentials service and its record |
| Needs the model | 3.2 to 5.4 s | the same, plus Gemini 4 Argon checks in parallel |

How it stays fast without dropping a check:
- **The model is asked only what code can't answer.** Plan drift and merchant identity are skipped when the cart
  matches the committed plan and the checkout is signed by a registered, authorized merchant.
- **The whole model review is skipped only when every question is proven.** That means:
  - the user's words matched the signed mandate at registration;
  - titles and conditions are exactly what was signed;
  - every page was confirmed from the merchant's own site;
  - no screen found instructions, and no condition words like "renewed" appear.
  The record lists each reason (`MG_MODEL_REVIEW=when-needed`; `always` restores the full review).
- **Network work overlaps.** Page fetches, page screens, evidence uploads, store reads and checkpoint writes run in
  parallel; the response waits for all of them, because Cloud Run gives no CPU after it answers.
- **Slow model calls are hedged.** After 3.5 s, one duplicate request goes out and the first answer wins.
  Measured: Gemini 4 Argon answered in 2.5 to 3.9 s; Gemini 3.8 Flash took 2.4 to 140 s on the same check that day.
- **The first block ends the review.** Checks can only tighten, so once one blocks, MandateGuard stops waiting for the rest.
- **Model review is capped at 10 s.** A purchase that hits the cap is held for the user, never allowed.

## Run locally (no GCP needed)

```bash
cd mandateguard
uv venv --python 3.12 && source .venv/bin/activate     # 3.12, as in the Dockerfile
uv pip install -e ".[dev]"          # pulls the AP2 v0.2 SDK from GitHub (pinned commit)
pytest -q                            # 93 tests: attacks, traceability, layers, passkeys, receipts, deliveries, integration, HTTP
MG_STAGE2=fake MG_PUBLIC_URL=http://127.0.0.1:8090 uvicorn mandateguard.main:app --port 8090
```

Live checks against the real Gemini and Model Armor: `MG_ACCESS_TOKEN="$(gcloud auth print-access-token)" python scripts/live_smoke.py`.

## Demo against the deployed services

`scripts/demo.sh` mints a Google ID token per role by impersonating that role's service account, so no personal
identity appears in the public log. SoundHub's pages come from a mock storefront at
https://soundhub-55485752139.us-central1.run.app, which MandateGuard also reads to check the agent's copy.

It needs a gcloud login with Token Creator on the three role service accounts, and the demo keys in `.demo/keys.json`.
Keep that login in its own gcloud folder, so other gcloud logins on the machine stay as they are; `demo.sh` uses
`~/.gcloud-hackathon` automatically when it exists:

```bash
export CLOUDSDK_CONFIG="$HOME/.gcloud-hackathon"
gcloud auth login
gcloud config set project hackathon-proto-mk26
```

```bash
bash scripts/demo.sh --enroll       # one-time link and QR code to create the demo user's passkey
bash scripts/demo.sh --consent      # six purchases; the user first signs purchases 1 and 6's mandates on the phone
bash scripts/demo.sh --misdeliver   # SoundHub reports purchase 1 delivered to a different address
bash scripts/demo.sh --refund       # also refunds purchase 1
```

| # | Purchase | Outcome |
|---|---|---|
| 1 | Sony WH-1000XM5 at $279.99 | Allowed without a model call, charged, shipped, delivered |
| 2 | Bose earbuds; the page hides an order for a $500 gift card | Denied: item not signed, hidden instructions quoted |
| 3 | AirPods from a look-alike store | Denied: unregistered signing key, merchant not authorized |
| 4 | Headphones promised after the signed delivery date | Denied by rule |
| 5 | Merchant signs "new", its own listing says renewed | Denied by the Gemini review |
| 6 | JBL speaker in the same hour | Held at the $500 hourly limit; approved with a passkey, charged, delivered |

Demo keys persist in `.demo/keys.json`, which is gitignored and never uploaded. After a pack change, run
`python scripts/sign_policy.py` and redeploy, or every purchase is blocked while approvals are required.

## Integration with the agent and the web app

Services plug in with API calls only: the operator registers each one, MandateGuard pushes signed events to the ones
that give a `webhook_url`, and `GET /.well-known/mandateguard` publishes the endpoints by role, the token audience, the
AP2 profile, the event types and the public key. The full contract is [`../docs/INTEGRATION.md`](../docs/INTEGRATION.md).

| Who | Calls | When |
|---|---|---|
| Operator | `POST /v1/admin/clients` (web app, bot, processor) and `POST /v1/admin/agents` (agent), each with an optional `webhook_url` | once per service; access applies to the next call, no redeploy |
|---|---|---|
| Web app | `POST /v1/admin/mandates` with `instruction` (the user's message) and `passkey_consent: true` | after the user confirms the summary; then send the user to the returned `consent_link` |
| Agent | `POST /v1/plans` with the items and payee it means to buy | before reading any merchant page; pass the `plan_id` in the decision |
| Agent | `POST /v1/decisions`; when held, the `approval.answered` event or `GET /v1/approvals/{id}` | for every purchase |
| Bot | the `approval.opened` event, or `GET /v1/approvals/pending` | when a purchase is held |
| Merchant | `POST /v1/fulfillment` with an ES256 JWS made with its registered key | when the order ships and when it arrives |

Without `instruction`, the words check uses the extracted request text. Without a plan, the plan link shows as the agent's own
account, and `MG_REQUIRE_WITNESSED_PLAN=1` holds such purchases for the user.

Registering a service as the operator, here the Telegram bot as a channel client with its event endpoint:

```bash
MG=https://mandateguard-55485752139.us-central1.run.app
OPS=$(gcloud auth print-identity-token --impersonate-service-account=mandateguard-ops-sa@hackathon-proto-mk26.iam.gserviceaccount.com \
  --audiences="$MG" --include-email)
curl -s -X POST "$MG/v1/admin/clients" -H "Authorization: Bearer $OPS" -H "Content-Type: application/json" \
  -d '{"client_id": "telegram-bot", "role": "channel", "principals": ["<bot service account>"], "webhook_url": "https://<bot host>/mandateguard-events"}'
```

## Callers

| Group | Registered by API | Env (bootstrap) | Endpoints |
|---|---|---|---|
| Agent | `POST /v1/admin/agents` | `MG_REQUIRE_CALLER_SA` | `POST /v1/plans`, `POST /v1/decisions`, `GET /v1/decisions/{id}`, `GET /v1/approvals/{id}` |
| Channel | client, role `channel` | `MG_CHANNEL_CALLERS` | `GET /v1/approvals/pending`, `POST /v1/approvals/{id}/redeem` |
| Trusted surface | client, role `trusted_surface` | `MG_ADMIN_CALLERS` | `/v1/admin/mandates`, `/v1/admin/mandates/{id}/consent`, `/v1/admin/users/{id}/passkey-enrollments` |
| Operator | client, role `operator` | `MG_ADMIN_CALLERS` | `/v1/admin/agents`, `/v1/admin/merchants`, `/v1/admin/policy-approvers`, `/v1/admin/clients` |
| Processor | client, role `processor` | `MG_PROCESSOR_CALLERS` | `POST /v1/receipts` |
| Merchant | `POST /v1/admin/merchants` (its key) | | `POST /v1/fulfillment` |
| The user, by one-time key | | | `/consent/{id}#k=…`, `/approve/{id}#k=…`, `/enroll/{id}#k=…` and their API calls |
| Anyone | | | `/console`, `/.well-known/mandateguard`, `/v1/audit/records`, `/v1/audit/verify`, `/v1/audit/keys`, `/v1/decisions/{id}/reverify`, `/v1/evidence/{sha256}` |

Every authenticated call needs a Google-signed ID token minted for this service's URL, with the email claim. The environment
lists bootstrap the first operator. Every caller registered after that is a signed record (`client.registered`,
`agent.registered`), as is every revocation (`DELETE /v1/admin/clients/{id}`, `DELETE /v1/admin/agents/{id}`). The
environment lists grant both trusted-surface and operator access. A registered client gets one role only.

## Configuration (env)

| Var | Default | Meaning |
|---|---|---|
| `MG_BACKEND` / `MG_SIGNER` | `memory` / `local` | `firestore` and `kms` with `MG_KMS_KEY_VERSION` in Cloud Run |
| `MG_STAGE2` | `fake` | `vertex` for real Gemini; `off` to skip |
| `MG_GEMINI_MODEL` / `MG_GEMINI_HEDGE_MODEL` | `gemini-4-argon` / `gemini-4-argon` | Primary model, and the model a slow call's duplicate goes to |
| `MG_GEMINI_TIMEOUT_SECONDS` / `MG_GEMINI_HEDGE_SECONDS` | 10 / 3.5 | Review cap (then the purchase is held), and when to send the duplicate |
| `MG_MODEL_REVIEW` | `when-needed` | `always` runs the purchase-time review even when everything is proven |
| `MG_MODEL_ARMOR_TEMPLATE` | none | Template id in `MG_MODEL_ARMOR_LOCATION` (`us-central1`) |
| `MG_FETCH_PAGES` / `MG_PAGE_FETCH_TIMEOUT_SECONDS` | `1` / 2 | Fetch registered merchant pages to compare with the agent's copy |
| `MG_CONSENT_PASSKEY` / `MG_CONSENT_TTL_SECONDS` | `requested` / 900 | `requested`, `if-enrolled` or `always`: when a mandate needs the user's passkey |
| `MG_APPROVAL_PASSKEY` | `if-enrolled` | `always`, `if-enrolled` or `never`: when an approval needs a passkey |
| `MG_REQUIRE_WITNESSED_PLAN` | `0` | `1` holds purchases whose agent did not commit a plan first |
| `MG_REQUIRE_POLICY_APPROVAL` | `0` | `1` blocks every purchase while any pack lacks a valid approver signature |
| `MG_HNP_TXN_CAP_MINOR` / `MG_HNP_VELOCITY_CAP_MINOR` | 100000 / 200000 | Unattended spend limits in minor units |
| `MG_APPROVAL_TTL_SECONDS` | 300 | How long an approval link works |
| `MG_WEBHOOK_TIMEOUT_SECONDS` | 2 | One delivery attempt per event; the pull endpoints are the fallback |
| `MG_EVIDENCE_BUCKET` / `MG_EVIDENCE_PUBLIC` | none / `1` | Create-only evidence and checkpoints; `0` limits evidence to admin callers |
| `MG_PROCESSOR_KEY_VERSION` | none | KMS key whose receipt signatures are accepted |
| `MG_CREDENTIALS_URL` | none | Remote credentials service; empty uses the in-process one |
| `MG_PUBLIC_URL` / `MG_TOKEN_AUDIENCES` | none | Base for links and the ID token audience; extra accepted audiences |
| `MG_TELEGRAM_BOT_TOKEN` | none | Optional: send approval links to the linked chat, recorded as `approval.link_sent` |
| `MG_AUDIT_COLLECTION` | `mg_audit` | Firestore collection for the chain |
| `MG_OBS_LOG` | `1` | `0` silences the JSON operational events |
| `MG_ENVIRONMENT` / `MG_REGION` | `Live` / none | Shown in the console header |

## Monitoring

MandateGuard writes one JSON line per event, which Cloud Logging stores as `jsonPayload`: `decision` (verdict, timings, model calls),
`receipt`, `receipt_rejected`, `fulfillment`, `fulfillment_rejected`, `chain_verify`, `checkpoint_failed`, `consent`.
In the project:
- **Metrics:** log-based metrics `mg_decisions` by verdict, `mg_decision_latency` (distribution), `mg_money_mismatch`, `mg_delivery_mismatch` and `mg_chain_integrity`.
- **Alerts:** chain or checkpoint problems, payments or deliveries that don't match, and p95 decision time over 8 s. They open incidents in Cloud Monitoring; add a notification channel to receive them.
- **Scheduled check:** Cloud Scheduler job `mandateguard-chain-verify` calls `/v1/audit/verify` every 15 minutes.
- **Dashboard:** "MandateGuard operations" in Cloud Monitoring.

Each decision record also carries its timings: identity and input, page checks, policy and its parts, and model review.

## Credentials service and processor (`../credentials_service`)

* `POST /v1/tokens` accepts only MandateGuard's service account. It re-hashes the decision record with RFC 8785, verifies
  MandateGuard's KMS signature, and mints a 5-minute token bound to the record hash, checkout, amount, currency and payee.
* `POST /v1/charge` uses a token once, signs an AP2-style receipt with the processor's own KMS key, and reports it.
* `POST /v1/refund` accepts only `CS_REFUND_CALLERS` and reports a signed refund receipt the same way.

## Live deployment (project `hackathon-proto-mk26`, us-central1)

| Service | URL | Runs as |
|---|---|---|
| MandateGuard and console | https://mandateguard-55485752139.us-central1.run.app/console | `mandateguard-sa`, one warm instance |
| Credentials and mock processor | https://credentials-55485752139.us-central1.run.app | `credentials-sa`, one warm instance |
| SoundHub mock storefront | https://soundhub-55485752139.us-central1.run.app | `soundhub-site-sa` (no permissions), one warm instance |

Resources:
- **Data:** Firestore `(default)`, with the chain in `mg_audit_v5`. Earlier ledgers remain in `mg_audit` to `mg_audit_v4`.
- **Keys:** KMS keys `mandateguard/decision-signer` and `mandateguard/processor-signer`.
- **Evidence:** the bucket `mandateguard-evidence-hackathon-proto-mk26`, with a 30-day retention policy that is not locked.
  Evidence objects are shared by hash under `evidence/`. Checkpoints sit under `checkpoints/<ledger>/`, one prefix per Firestore
  collection. At startup MandateGuard writes any checkpoints its ledger is missing, after re-checking each record's hash, link
  and signature.
- **Model Armor:** template `mandateguard-page-screen`.

The warm instances cost roughly a dollar a day in total at idle rates. Remove them with
`gcloud run services update <service> --min-instances=0`.

Use `--update-env-vars` to change one variable, because `--set-env-vars` replaces the whole set. Health is at `/health`.

## Layout

```
src/mandateguard/
  pipeline.py        stages 0 to 3, registrations, consent, plans, approvals, receipts, deliveries, reverify
  app.py / main.py   FastAPI, caller groups, discovery document
  models.py          wire models
  ap2_adapter.py     AP2 v0.2 verification through ap2.sdk
  conditions.py      signed conditions, salted commitments, condition facts
  fulfillment.py     delivery event validation and reconciliation
  pages.py           MandateGuard's own page fetch, with the private-address guard
  policy_approval.py approver signatures on policy packs
  registry.py        merchants (key rotation, profile changes), agents, policy approvers
  clients.py         callers registered by API, by role, with their webhook URLs
  webhooks.py        signed events to registered clients, and the reference verifier
  passkeys.py        WebAuthn enrollment and statement signing (py_webauthn 2.x)
  evidence.py        content-addressed evidence and anchored checkpoints
  rules/             engine, facts (witnessed plans, page checks), reason templates
  packs/             10-mandate, 15-conditions, 20-fraud, 30-compliance, approvals.json
  gemini_checks.py   tighten-only checks, intent fidelity, hedged calls
  screener.py        Model Armor plus a heuristic screen, run in parallel
  obs.py             JSON operational events
  web/               console, consent, approval and enrollment pages, in-browser verification
tests/               93 tests
scripts/             demo.sh, demo_story.py, sign_policy.py, live_smoke.py
../merchant_site/    the SoundHub mock storefront
```
