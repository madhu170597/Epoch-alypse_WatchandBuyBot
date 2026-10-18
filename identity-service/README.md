# Identity Service

Python / FastAPI service for the agentic ordering bot's identity layer. Runs on
Cloud Run; project-agnostic (all config via env).

## What it provides
- **Firebase ID-token verification** and an **MFA gate** (`app/auth.py`). Email +
  SMS second factor is handled by the Firebase client SDK in the web app; this
  service verifies the resulting ID token and can require that it carries a
  second factor (`REQUIRE_MFA=true`).
- **WebAuthn passkeys** (`app/passkey.py`): register a passkey against a signed-in
  Firebase user, and usernameless passkey login that mints a Firebase custom
  token (exchanged client-side for an ID token).
- **Telegram linking** (`app/telegram_link.py`): one-time code issued to a
  signed-in user, redeemed by the bot (shared-secret authed) to bind
  `telegram_chat_id -> uid`.

## Endpoints
| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/healthz` | — | liveness |
| POST | `/passkey/register/options` | ID token | begin passkey registration |
| POST | `/passkey/register/verify` | ID token | finish registration |
| POST | `/passkey/login/options` | — | begin passkey login |
| POST | `/passkey/login/verify` | — | finish login → `{custom_token}` |
| POST | `/telegram/link/start` | ID token | issue one-time link code |
| POST | `/telegram/link/verify` | `X-Bot-Secret` | bot redeems code → bind chat id |
| POST/GET/DELETE | `/wallet/cards[/{id}]` | ID token | dummy cards (test PAN → brand+last4+`dmtok_`; PAN never stored) |
| POST/GET/DELETE | `/wallet/addresses[/{id}]` | ID token | dummy shipping addresses |
| GET | `/internal/user-by-chat/{chat_id}` | `X-Service-Secret` | bot: linked uid for a chat |
| GET | `/internal/wallet/{uid}` | `X-Service-Secret` | agent/bot: default card + ship_to for the mandate |

## Firestore collections
`users/{uid}`, `users/{uid}/passkeys/{cred_id}`, `passkey_index/{cred_id}`,
`webauthn_challenges/{handle}`, `link_codes/{code}`.

## Run locally
```bash
cp .env.example .env            # set RP_ID/EXPECTED_ORIGIN, TELEGRAM_BOT_SECRET
gcloud auth application-default login   # for firebase-admin / Firestore
uv run uvicorn app.main:app --reload --port 8090
```

## Notes
- SMS MFA requires the Firebase project to be upgraded to **Firebase
  Authentication with Identity Platform** (Blaze billing). Enablement is a
  project-config step; this service's code is ready for it.
- `RP_ID` is the registrable domain (no scheme/port): `localhost` for dev, the
  web app's domain in prod. `EXPECTED_ORIGIN` is the full browser origin.
