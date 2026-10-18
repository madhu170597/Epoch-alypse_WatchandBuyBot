# MandateGuard integration contract

For the services in the agent, channel, identity and gateway layers. MandateGuard is live at:

```
MANDATE_GUARD_URL=https://mandateguard-55485752139.us-central1.run.app
```

Console: `$MANDATE_GUARD_URL/console`. API reference: `$MANDATE_GUARD_URL/api/docs`, grouped by role.

Discovery: `GET $MANDATE_GUARD_URL/.well-known/mandateguard` returns the endpoints for each role, the token audience, the AP2 profile, the event types and MandateGuard's public key. The base URL is the only setting your services need.

## 1. Who calls what

| Your service | Role in MandateGuard | Calls MandateGuard | Authenticates as |
|---|---|---|---|
| Web app / identity service (`IDENTITY_URL`) | Trusted surface | `POST /v1/admin/mandates`, `GET /v1/admin/mandates/{id}/consent`, `POST /v1/admin/users/{uid}/passkey-enrollments` | its Cloud Run service account |
| Shopping agent (`AGENT_URL`) | Agent | `POST /v1/plans`, `POST /v1/decisions`, `GET /v1/approvals/{id}` | its service account, plus the agent key the user delegates to |
| Telegram bot | Channel | `GET /v1/approvals/pending`, optionally `POST /v1/approvals/{id}/redeem` | its service account |
| Merchant agent (`MERCHANT_AGENT_URL`) | Merchant | `POST /v1/fulfillment` | its ES256 signing key, registered with MandateGuard |
| Credentials provider (`CREDENTIALS_PROVIDER_URL`) | Credentials service | none: MandateGuard calls its `POST /v1/tokens` | checks MandateGuard's signature |
| Payment processor (`PAYMENT_PROCESSOR_URL`) | Processor | `POST /v1/receipts` | its service account, plus its receipt-signing key |

The agent is never registered in the trusted surface, operator, channel or processor roles. It cannot register mandates, answer its own approval or report a payment.

**Getting access.** The operator registers each service account by API; nothing is redeployed, and access applies to the next call:
- shopping agent: `POST /v1/admin/agents` with its service accounts and delegated key thumbprints;
- every other role: `POST /v1/admin/clients` with `role` set to `trusted_surface`, `channel` or `processor`.

Each registration takes an optional `webhook_url` for that role's events (section 9). Registrations and revocations (`DELETE /v1/admin/clients/{id}`, `DELETE /v1/admin/agents/{id}`) are signed records in the audit log.

## 2. What we exchange

You send:
- **Service account emails** for the web app or identity service, the agent, the bot and the processor. The operator registers them (section 1).
- **Webhook URLs**, optional: one https endpoint per service that should receive events instead of polling (section 9).
- **The agent's public key** (JWK), the one each open mandate's `cnf` names. It is registered to agent id `shopper-agent`.
- **Each mock merchant** you want trusted: id, name, website (public HTTPS), rating, signing key id (`kid`) and public JWK. The impersonator merchant stays unregistered.
- **The processor's receipt key**: a Cloud KMS key version, or a P-256 public key PEM with a `kid`.
- **If you keep your own credentials provider:** its base URL.

You get:
- `MANDATE_GUARD_URL` above, and MandateGuard's public key: `GET /v1/audit/public-key` (ECDSA P-256, KMS `decision-signer` v1).
- This contract, and the reference code in the repository: `mandateguard/tests/conftest.py` builds every artefact below with the AP2 SDK.

## 3. Authentication

Every call except the user's one-time links and `POST /v1/fulfillment` carries a Google-signed ID token:
- **Audience:** exactly `MANDATE_GUARD_URL`.
- **Email claim:** included.

Requests fail with 401 for a missing or wrong-audience token, and with 403 for a caller not registered in that role.

```python
import google.auth.transport.requests, google.oauth2.id_token
token = google.oauth2.id_token.fetch_id_token(google.auth.transport.requests.Request(), MANDATE_GUARD_URL)
headers = {"Authorization": f"Bearer {token}"}
```

```js
import { GoogleAuth } from "google-auth-library";
const client = await new GoogleAuth().getIdTokenClient(process.env.MANDATE_GUARD_URL);
const headers = await client.getRequestHeaders();   // { Authorization: "Bearer ..." }
```

On Cloud Run the service account's token includes the email. A 403 saying "no email claim" means the token came from a user account or was minted without `--include-email`.

## 4. Registering a mandate (web app / identity service)

After the user confirms the summary, the web app builds the two AP2 v0.2 open mandates, signs them, and registers them.

### 4.1 Open mandates

Both are SD-JWTs from `ap2.sdk.mandate.MandateClient().create(payloads=[...], issuer_key=<web app ES256 key>)`, AP2 tag v0.2.0 (commit `e1ea56d`). Both carry `cnf = {"jwk": <agent public JWK>}`, `iat` and `exp`.

- **Open checkout mandate:**
  - `constraints`: `LineItems` with the acceptable SKUs and titles, and `AllowedMerchants`.
  - One extra claim, `mg_conditions`. AP2 verifiers ignore it; changing it breaks the signature.
- **Open payment mandate:** `constraints` are:
  - `AmountRange` with `currency`, and `min` and `max` in minor units.
  - `AllowedPayees`.
  - `PaymentReference(conditional_transaction_id = sd_hash(open checkout mandate))`.

```json
"mg_conditions": {
  "v": 1,
  "intent_sha256":  "<sha256 hex of salt + \"\\n\" + intent_text>",
  "summary_sha256": "<sha256 hex of salt + \"\\n\" + summary_text>",
  "ship_to_sha256": "<sha256 hex of address_salt + \"\\n\" + normalized address>",
  "deliver_by": "2026-10-21",
  "item_condition": "new",
  "min_seller_rating": 4.0
}
```

The address is normalized as lowercase, commas replaced by spaces, whitespace collapsed. `mandateguard.conditions.build_conditions()` computes all of this. Every field after `summary_sha256` is optional; MandateGuard enforces each one present.

### 4.2 Request

`POST /v1/admin/mandates`

```json
{
  "mandate_id": "mnd_8d069e0f83",
  "user_id": "<Firebase UID>",
  "intent_text": "Buy 1 Sony WH-1000XM5 in black from SoundHub if the price is between $200 and $300 in the next 7 days.",
  "intent_salt": "<the salt used for intent_sha256 and summary_sha256>",
  "summary_text": "<exactly the text the user was shown>",
  "open_checkout_mandate": "<SD-JWT>",
  "open_payment_mandate": "<SD-JWT>",
  "user_public_jwk": {"kty": "EC", "crv": "P-256", "x": "...", "y": "..."},
  "linked_channels": {"telegram": "<chat id>"},
  "consent": {"method": "passkey", "verified_by": "web app", "at": 1792000000},
  "instruction": {"channel": "telegram", "message_id": "981", "received_at": 1792000000, "text": "<the user's own message>"},
  "passkey_consent": true
}
```

`user_public_jwk` is the public half of the key that signed the open mandates.

Response:

```json
{"mandate_id": "mnd_8d069e0f83", "record_seq": 7, "delegated_agent_id": "shopper-agent", "conditions_signed": true,
 "consent_required": true, "consent_link": "https://.../consent/mnd_8d069e0f83#k=...", "consent_expires_at": 1792000900}
```

Errors (400): a bad signature, a commitment that does not match the texts, or a mandate that contradicts the user's own message. MandateGuard checks the message once, here, with Gemini.

### 4.3 The user's signature

- **With `passkey_consent: true`:** send the user to `consent_link`. They sign on MandateGuard's page with a passkey.
  - With a `webhook_url` registered, the `mandate.consent_answered` event reports `signed` or `declined`. Otherwise poll `GET /v1/admin/mandates/{id}/consent` until `status` is `signed`; the other outcomes are `declined` and `expired`.
  - Until it is signed, every purchase under the mandate is blocked.
- **Without it:** your `consent` block is recorded as your attestation, for example `{"method": "sms_otp", "verified_by": "identity service", "at": ...}`. Approvals then use the approval link or a reply from the linked Telegram chat.
- **The passkey:** a user needs one passkey with MandateGuard. `POST /v1/admin/users/{uid}/passkey-enrollments` returns a 15-minute `link` to send the user.

## 5. Buying (shopping agent)

### 5.1 Commit the plan, before reading any merchant page

`POST /v1/plans`

```json
{"mandate_id": "mnd_8d069e0f83", "items": [{"sku": "WH1000XM5-BLK", "qty": 1}], "payee_id": "merchant_clean"}
```

Response: `{"plan_id": "pln_...", "plan_sha256": "...", "record_seq": 23, "committed_at": 1792001234.5}`.

### 5.2 Ask for a decision, instead of asking the credentials provider

`POST /v1/decisions`

```json
{
  "mandate_id": "mnd_8d069e0f83",
  "user_id": "<Firebase UID>",
  "agent_id": "shopper-agent",
  "plan_id": "pln_...",
  "idempotency_key": "<uuid>",
  "ap2": {
    "checkout_jwt": "<merchant-signed checkout JWT, section 6>",
    "payment_mandate_chain": "<open payment SD-JWT>~~<closed payment KB-SD-JWT>~",
    "payment_nonce": "<nonce in the closed payment mandate>",
    "checkout_mandate_chain": "<open checkout SD-JWT>~~<closed checkout KB-SD-JWT>~",
    "checkout_nonce": "<nonce in the closed checkout mandate>"
  },
  "trace": [
    {"seq": 1, "kind": "plan", "summary": "Price alert", "data": {"items": [{"sku": "WH1000XM5-BLK", "qty": 1}], "payee_id": "merchant_clean"}},
    {"seq": 2, "kind": "tool_call", "tool": "read_page", "summary": "Read product page", "data": {"url": "https://..."}},
    {"seq": 3, "kind": "page_read", "data": {"url": "https://...", "content_sha256": "..."}},
    {"seq": 4, "kind": "tool_call", "tool": "assemble_cart", "data": {"items": [{"sku": "WH1000XM5-BLK", "qty": 1}]}}
  ],
  "pages": [{"url": "https://...", "content": "<page HTML or text as read, up to 200,000 characters>"}]
}
```

- **`user_id` and `agent_id` are claims.** MandateGuard takes the user from the mandate and the agent from the verified caller. A mismatch blocks the purchase.
- **The closed payment mandate** is made with `MandateClient().present(holder_key=<agent key>, mandate_token=<open payment mandate>, ...)`. It needs:
  - a `PaymentMandate` with `transaction_id = b64url(sha256(checkout_jwt))`, `payee`, `payment_amount` and `payment_instrument`;
  - `aud="credential-provider"` and `nonce=payment_nonce`.
- **The closed checkout mandate** uses `aud="merchant"` and carries `checkout_hash = b64url(sha256(checkout_jwt))`.
- **`pages` must hold the page exactly as read.** MandateGuard fetches pages on registered merchant sites itself and compares.

Response:

```json
{
  "decision_id": "dec_...", "verdict": "ALLOW", "rationale": "Within mandate: ...",
  "findings": [{"code": "...", "outcome": "DENY", "title": "...", "message": "...", "source": "..."}],
  "record": {"seq": 28, "hash": "...", "prev_hash": "...", "signature": "...", "signer_kid": "kms:decision-signer/cryptoKeyVersions/1"},
  "hashes": {"checkout": "...", "closed_payment_reference": "...", "open_checkout": "...", "open_payment": "...", "plan": "...", "envelope": "..."},
  "payment_token": "mgtok_...",
  "approval": null
}
```

What the agent does with each verdict:

| Verdict | What the agent does |
|---|---|
| `ALLOW` | Pays with `payment_token`. It is single-use, valid for 5 minutes, and bound to this checkout hash, amount, currency and payee. |
| `ESCALATE` | `approval` holds `approval_id`, `expires_at` and `summary`, never the link. Wait for the `approval.answered` event (section 9), or poll `GET /v1/approvals/{approval_id}` every 2 to 3 seconds. On `approved`, fetch `payment_token` with that GET and pay; `approving` means wait. On `rejected`, `expired` or `failed`, skip this match. |
| `DENY` | Do not pay. `rationale` and `findings` say why. |

Times, measured on the service:

| Purchase | Time |
|---|---|
| Blocked | 0.5 to 0.85 s |
| Allowed, fully proven | 1.2 to 1.45 s |
| With a Gemini review | 3 to 5 s |

Allow up to 15 s before timing out.

## 6. Merchant agent

Three things are required of the merchant agent.

**The checkout JWT** has an ES256 header carrying the registered `kid`. Its payload is the UCP Checkout (`id`, `merchant`, `line_items`, `totals`, `currency`, `status`) plus:

```json
"fulfillment": {"ship_to_sha256": "<same commitment scheme as the mandate>", "promised_by": "2026-10-17"},
"item_facts": {"WH1000XM5-BLK": {"condition": "new"}}
```

- **The address commitment** needs the shipping address and the address salt. Your web app and agent pass both to the merchant with the order.
- **A missing promise date, address or condition** is checked against the mandate's conditions. It blocks or holds the purchase when the mandate requires that field.

**Delivery events.** When an order ships or arrives, `POST /v1/fulfillment` with `{"event_jwt": "<compact ES256 JWS, same key>"}`. The claims:

```json
{"type": "order.shipped", "checkout_hash": "<b64url sha256 of the checkout JWT>", "order_id": "ord_1",
 "items": [{"sku": "WH1000XM5-BLK", "qty": 1, "condition": "new"}], "ship_to_sha256": "...",
 "shipped_at": "2026-10-15T10:00:00Z", "estimated_delivery": "2026-10-17", "carrier": "SingPost", "tracking_ref": "SG123", "iat": 1792050000}
```

For `order.delivered`, send `delivered_at` instead of `shipped_at`. MandateGuard compares each event with:
- the address, deadline and condition the user signed;
- the date the merchant promised.

Responses:

| Status | Meaning |
|---|---|
| 200 | `{"record_seq", "kind", "reconciled", "mismatches"}` |
| 401 | Unknown key or bad signature. Nothing is recorded. |
| 422 | No payment found for this checkout. |

**Product pages** sit on the registered website, over public HTTPS.

## 7. Credentials provider and processor

Pick one option.

**Option A: use MandateGuard's companion service** for both roles.

```
CREDENTIALS_PROVIDER_URL=PAYMENT_PROCESSOR_URL=https://credentials-55485752139.us-central1.run.app
```

To charge, `POST /v1/charge` with the following body, and no auth header (the token is the credential):

```json
{"payment_token": "mgtok_...", "checkout_hash": "<hashes.checkout>", "amount_minor": 27999, "currency": "USD", "payee_id": "merchant_clean", "order_id": "ord_..."}
```

- **Success:** `{"status": "charged", "payment_id": "pay_...", ...}`.
- **Failures:** 409 for a token already used, 410 for an expired token, 403 for a token bound to a different checkout, amount or payee.
- **Receipts** are signed and reported to MandateGuard automatically.

**Option B: keep your own services**, and implement two hooks.

1. **Your credentials provider** exposes `POST /v1/tokens`. MandateGuard calls it with an ID token (audience = your URL, email `mandateguard-sa@hackathon-proto-mk26.iam.gserviceaccount.com`). The body is `{"decision_record": {...}}`. Before issuing a token:
   - check `verdict` is `ALLOW` or `ALLOW_BY_HUMAN`;
   - recompute `hash` as the SHA-256 hex of RFC 8785 JSON of the record without `hash`, `signature` and `signer_kid`;
   - verify `signature`: base64url DER ECDSA P-256 over that hash, with MandateGuard's public key.

   Then respond:

```json
{"payment_token": "<opaque>", "token_sha256": "<sha256 hex of the token>", "expires_at": 1792001534,
 "bound_to": {"decision_record_hash": "...", "checkout_hash": "...", "amount_minor": 27999, "currency": "USD", "payee_id": "merchant_clean"}}
```

   Issue at most one token per record hash. Any non-200 response blocks the purchase.

2. **Your processor** charges the token once, checks it against the checkout hash, amount, currency and payee, and signs a receipt.
   - **Signature:** base64url DER ECDSA P-256 over `sha256(RFC 8785 JSON of the receipt)`.
   - **Report:** `POST /v1/receipts` with an ID token for MandateGuard, and the body `{"receipt": {...}, "signature": "...", "kid": "..."}`.

```json
{"type": "payment.executed", "status": "Success", "iss": "your-processor", "iat": 1792001300,
 "payment_id": "pay_...", "psp_confirmation_id": "...", "network_confirmation_id": "...",
 "for_decision_id": "<record.decision_id>", "decision_record_hash": "<record.hash>",
 "reference": "<hashes.closed_payment_reference>", "token_sha256": "<sha256 hex of the token>",
 "checkout_hash": "...", "amount_minor": 27999, "currency": "USD", "payee_id": "merchant_clean", "mandate_id": "...", "order_id": "..."}
```

   For a refund, send `type: "payment.refunded"` with `refund_id`, `requested_by` and `reason`. MandateGuard reconciles every receipt against the decision and the released token, and flags any mismatch.

## 8. Approvals (Telegram bot)

The approval link (`$MANDATE_GUARD_URL/approve/{id}#k=...`) goes to the user only. The bot has three ways to deliver it:

1. **Push to the bot's endpoint.** Register the bot as a `channel` client with a `webhook_url`. Each held purchase arrives as an `approval.opened` event carrying the link (section 9). Send `link` to the user's chat as a button. Each accepted delivery is recorded as the handoff.
2. **Pull.** `GET /v1/approvals/pending?user_id=<uid>`, as the bot's service account, returns the same items: `[{"approval_id", "decision_id", "user_id", "expires_at", "link", "linked_channels", "merchant", "total", "reasons"}]`. Each handoff is recorded once per approval and recipient, whether pushed or pulled.
3. **MandateGuard sends it.** Set the bot token on MandateGuard (`MG_TELEGRAM_BOT_TOKEN`) and register `linked_channels.telegram`. MandateGuard posts the message itself.

When the user has a passkey, approval is passkey-only on MandateGuard's page. A Telegram reply (`POST /v1/approvals/{id}/redeem` with `channel: "telegram"`) is accepted only for users without a passkey, from the linked chat.

## 9. Events

A service registered with a `webhook_url` receives its role's events as an https `POST`:

| Event | Sent to | When | `data` |
|---|---|---|---|
| `approval.opened` | channel clients | a purchase is held for the customer | `approval_id`, `decision_id`, `user_id`, `expires_at`, `link`, `linked_channels`, `merchant`, `total`, `reasons` |
| `approval.answered` | the agent that asked for the decision | the customer approved or rejected, the approval expired, or the token was not released | `approval_id`, `decision_id`, `status` (`approved`, `rejected`, `expired`, `failed`), `result_decision_id`, `record_seq` |
| `mandate.consent_answered` | the trusted surface that registered the mandate | the customer signed or declined it | `mandate_id`, `user_id`, `status` (`signed`, `declined`), `record_seq` |

```json
{"id": "evt_6f1c…", "type": "approval.answered", "created_at": 1792001412,
 "data": {"approval_id": "apr_…", "decision_id": "dec_…", "status": "approved", "result_decision_id": "dec_…", "record_seq": 31}}
```

No event carries a payment token. On `approved`, the agent fetches it with `GET /v1/approvals/{approval_id}`.

**Headers:**
- `MandateGuard-Event`: the event type.
- `MandateGuard-Delivery`: equal to the body's `id`.
- `MandateGuard-Timestamp`: Unix seconds.
- `MandateGuard-Key-Id`: the signing key's id.
- `MandateGuard-Signature`: base64url DER ECDSA P-256 over SHA-256 of `<timestamp>.<raw body>`, made with MandateGuard's decision key. The key is `keys.decision_signer` in the discovery document, or `GET /v1/audit/public-key`.

**Receiving:**
- Verify the signature over the raw bytes before parsing.
- Reject timestamps more than 300 s old.
- Ignore an `id` you have already processed.
- Answer 2xx within 2 s.

**Delivery** is one attempt, to https on a public address, without redirects. A missed event changes no outcome; the pull endpoints above still answer. Decisions themselves are never sent as events: `POST /v1/decisions` answers synchronously.

```python
import base64, json, time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

def mandateguard_event(raw_body: bytes, headers, public_pem: str) -> dict:
    ts, sig = headers["MandateGuard-Timestamp"], headers["MandateGuard-Signature"]
    if abs(time.time() - int(ts)) > 300:
        raise ValueError("stale event")
    key = serialization.load_pem_public_key(public_pem.encode())
    key.verify(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4)), ts.encode() + b"." + raw_body, ec.ECDSA(hashes.SHA256()))
    return json.loads(raw_body)
```

```js
import crypto from "node:crypto";

function mandateGuardEvent(rawBody, headers, publicKeyPem) {      // rawBody: Buffer, as received
  const ts = headers["mandateguard-timestamp"];
  if (Math.abs(Date.now() / 1000 - Number(ts)) > 300) throw new Error("stale event");
  const ok = crypto.verify("sha256", Buffer.concat([Buffer.from(`${ts}.`), rawBody]),
    { key: publicKeyPem, dsaEncoding: "der" }, Buffer.from(headers["mandateguard-signature"], "base64url"));
  if (!ok) throw new Error("signature does not verify");
  return JSON.parse(rawBody);
}
```

## 10. Decisions to make together

1. **Credentials provider and processor:** option A or B in section 7. Each MandateGuard deployment calls one credentials provider (`MG_CREDENTIALS_URL`) and accepts receipts signed with one processor key. With option B, `scripts/demo.sh` no longer charges through the companion service, so record the demo before switching.
2. **Passkeys:** your identity service uses SMS MFA for the pilot, so MandateGuard's passkey is the only one. Either the user enrolls one MandateGuard passkey and signs each mandate with it (`passkey_consent: true`), or you send `passkey_consent: false` with `consent.method: "sms_otp"` and MandateGuard records your attestation. Both work with no MandateGuard change.
3. **Approval delivery:** push to the bot's endpoint, pull, or MandateGuard sends it (section 8).
4. **AP2 version:** MandateGuard verifies AP2 v0.2 open and closed SD-JWT mandates only. Code that uses the v0.1 `IntentMandate` and `CartMandate` objects needs an adapter.

## 11. Where the calls go in the AP2 sample

For a flow built on the AP2 v0.2 Python sample `scenarios/a2a/human-not-present/cards` (commit `e1ea56d`, the one MandateGuard pins): consent agent, monitoring agent, purchase agent, and MCP servers for the merchant, credentials provider and payment processor.

MandateGuard takes the place of one call: the purchase agent asks MandateGuard instead of calling `issue_payment_credential`, and MandateGuard asks the credentials provider. Three calls are added around it.

| Step in the sample | Change | MandateGuard |
|---|---|---|
| Consent agent: `assemble_and_sign_mandates` signs both open mandates with the agent-provider key | After signing, `POST /v1/admin/mandates` (section 4). `user_public_jwk` is the agent-provider public key; `instruction` is the customer's message. | Verifies both mandates with the AP2 SDK, checks the customer's words against the limits once, keeps its own copy of the mandate, records `mandate.registered` |
| `_build_open_checkout_mandate` | Add the `mg_conditions` claim (section 4.1) | Compares each condition with the merchant's signed checkout. Without the claim, every purchase is held for the customer. |
| Monitoring agent hands over to the purchase agent | Before `check_product`, `POST /v1/plans` with `mandate_id`, `items`, `payee_id: "merchant_1"` | Fixes the plan with its own clock and signature; later steps are compared with it |
| Purchase agent: `check_product` → `check_constraints_against_mandate` → `assemble_cart` → `create_checkout` → `create_payment_presentation` | No change. Record each tool call in the trace with an ADK `before_tool_callback`, and keep the `check_product` results as `pages`. | The trace and pages are checked for drift and screened for instructions |
| `issue_payment_credential` | Replace with `POST /v1/decisions` (section 5.2) | Decides; on ALLOW, calls the credentials provider's `POST /v1/tokens` and returns `payment_token` |
| `create_checkout_presentation` → `complete_checkout` | No change | The merchant and processor charge as before |
| Processor: `initiate_payment` | After charging, `POST /v1/receipts` (section 7) | Reconciles the amount, payee and token with the decision |

The replacement tool is deterministic code. The model never assembles the request:

```python
def request_mandateguard_decision(payment_mandate_chain_id: str, payment_nonce: str, checkout_jwt: str, tool_context: ToolContext) -> dict:
    s = tool_context.state
    body = {"mandate_id": s["mandate_id"], "plan_id": s["plan_id"], "idempotency_key": payment_nonce,
            "ap2": {"checkout_jwt": checkout_jwt, "payment_nonce": payment_nonce,
                    "payment_mandate_chain": _load_persisted_mandate(f"{payment_mandate_chain_id}.sdjwt")},
            "trace": s.get("mg_trace", []), "pages": s.get("mg_pages", [])}
    out = httpx.post(f"{MANDATE_GUARD_URL}/v1/decisions", json=body, headers=id_token_headers(MANDATE_GUARD_URL), timeout=15).json()
    if out["verdict"] == "ALLOW":
        return {"payment_token": out["payment_token"]}
    if out["verdict"] == "ESCALATE":       # the customer answers on the phone: wait for approval.answered, or poll /v1/approvals/{id}
        return {"status": "held", "approval_id": out["approval"]["approval_id"]}
    return {"error": "denied", "message": out["rationale"]}
```

Changes outside the agent:

1. **Fixed keys.** `run.sh` deletes `.temp-db` on every start, so the agent, agent-provider and merchant keys are generated anew each run, and a registered key stops matching. Set the three keys the sample already reads from the environment. Each holds JWK JSON, despite the `_PEM` in its name:
   - `AGENT_PRIVATE_KEY_PEM`
   - `AGENT_PROVIDER_SIGNING_KEY_PEM`
   - `MERCHANT_SIGNING_KEY_PEM`

   Keep them in Secret Manager.
2. **Credentials provider.** Expose the issuing logic of `issue_payment_credential` as `POST /v1/tokens`:
   - accept only MandateGuard's service account;
   - verify MandateGuard's signature on the decision record (section 7, option B);
   - then issue as now, into the same token store, so the merchant and processor are unchanged.
3. **Remove `issue_payment_credential` from the purchase agent's toolset.** While the agent can still call it, it can skip MandateGuard.
4. **Registration, by the operator:**
   - the agent's public key, added to `shopper-agent`;
   - merchant `merchant_1` with key `merchant-key-1` and its public JWK;
   - the processor's receipt key.

## 12. First end-to-end test

1. Send the details in section 2. The operator registers the agent, the merchants and the clients, with any webhook URLs.
2. The web app registers one mandate. Check the console's Audit log for `Mandate registered`.
3. The agent commits a plan and asks for a decision on an in-range cart. Expect `ALLOW` and a token.
4. Charge the token, then send `order.shipped` and `order.delivered`.
5. Open the decision in the console. The Authorization tab should show Verified on every row.
