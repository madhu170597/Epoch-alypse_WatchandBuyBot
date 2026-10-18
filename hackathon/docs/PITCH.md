# How to pitch MandateGuard

For the two of us presenting. Everything below was measured on our deployment on 14 October 2026 or is cited. Use these numbers and sentences as they are; don't round them up.

## The sentence

**When an AI agent pays for someone, MandateGuard answers two questions before any money moves: who authorised this, and is this the purchase they asked for. Every answer is a signed record that anyone can check.**

If a judge remembers one thing, it should be that sentence.

## The problem, in four facts

1. **Signatures don't cover the decision.** Agent payment protocols such as Google's AP2, Visa's Trusted Agent Protocol and Mastercard Agent Pay sign the transaction. A 2026 security analysis of AP2 concludes that "valid mandate signatures alone do not ensure that an agent-mediated transaction reflects the user's intent" ([arXiv 2608.23858](https://arxiv.org/abs/2608.23858)).
2. **Ordinary product text steers agents.** Researchers got Gemini Flash-Lite shopping agents to build signed but wrong carts in 56 to 90 percent of attempts, using nothing but product descriptions ([arXiv 2609.11757](https://arxiv.org/abs/2609.11757)).
3. **Attackers have started.** Zscaler found two live campaigns aimed at AI shopping agents, with no payments reported yet. In its own test, 4 of 26 models paid, Gemini 3 Flash among them (SecurityWeek, 6 July 2026).
4. **Off-the-shelf filters miss it.** On our own test page, Google Cloud Model Armor flagged 1 of 4 injection styles. The two Flash-Lite models we tried accepted a cart the page claimed was "pre-approved by the user". Gemini 3.8 Flash did not.

The consequence for a bank or wallet is direct. A wrong purchase goes through, the customer disputes it, and nobody can show who authorised what.

## Who pays for this

The party that releases the payment credential: a card issuer, a wallet, or a payment service provider. In AP2 terms this is the Credential Provider, which "MUST verify the Payment Mandate" before releasing a token. The spec lets that verification be delegated to a technology provider. MandateGuard is that technology provider.

What they get:
- **Fewer bad payments.** Losses are bounded by what the customer signed, enforced in code.
- **Dispute evidence.** For every payment, a chain from the person's signature to the processor's receipt. Anyone can verify it.
- **Policy they control.** Compliance rules are files they add or remove without a release, each with a named owner.

This fits the hackathon category, BFSI: Intelligent Risk, Fraud and Financial Experiences, without stretching.

## What it does, in four parts

1. **Identity from proof, never from claims.** The person signs the mandate with their own passkey. The agent is identified by its Google-signed service identity and the key the user delegated to. It commits its plan to MandateGuard before it reads any page.
2. **Hard limits from what the user signed.** Price range, merchant, items, payee, expiry and single use, checked with the official AP2 v0.2 SDK. The user also signs conditions: deliver by a date, new items only, a minimum seller rating, a hashed ship-to address. The merchant signs its delivery promise, the address hash and each item's condition. Rules compare the two. No model output and no chat reply can override a block.
3. **Judgment only where rules can't reach.** When the mandate is registered, Gemini checks the user's own words against the signed limits, once. At purchase time it reads the merchant's listing against the signed facts and screens pages for instructions aimed at agents. It is asked only what code has not already proven, and its answer can make a decision stricter and never looser.
4. **A chain of custody anyone can check.** Every step is a signed record: the mandate and the user's passkey on it, the plan, the decision, the approval, the token, the processor's receipt and the merchant's delivery report. Checkpoints go to a write-once bucket. The console re-verifies every signature in the viewer's browser.

## Who authorised this: the chain for one payment

The console's Authorization tab shows this for every purchase. For the speaker bought after a passkey approval, on the deployed service:

| Step | Party | Proof | Status |
|---|---|---|---|
| Customer | cus_9TR4WD | Passkey signature over the mandate | Verified |
| Request | Telegram message | Fidelity check: match | Verified |
| Mandate | Mandate issuer key | AP2 open mandates · 4 signed conditions | Verified |
| Agent | shopper-agent | Delegated key | Verified |
| Plan | shopper-agent | 1× JBL-CHARGE5-BLU · cart matches | Verified |
| Merchant | SoundHub | Checkout signed · key soundhub-2026-10 | Verified |
| Policy | 4 packs | Approved by head-of-payments-risk | Verified |
| Decision | MandateGuard | Escalate · KMS decision key | Verified |
| Approval | cus_9TR4WD | Passkey signature over amount, payee and decision | Verified |
| Token | Credentials service | Single-use · $249.99 | Verified |
| Payment | Processor | Receipt reconciled | Verified |
| Shipment, Delivery | SoundHub | Signed events · as signed | Verified |

"Verify signatures" reports **26 of 26 signatures valid**, checked in the browser. They come from six signing parties, each with its own published key: MandateGuard, the mandate issuer, the customer's passkey, the merchant's checkout and delivery events, the policy approver and the processor.

A link shows as Attested, not Verified, whenever only someone's word stands behind it. A user without a passkey is one case; an agent that skipped the plan step is another. The console says so instead of hiding it.

## Proof: live results

Run on the deployed service in `hackathon-proto-mk26` with real AP2 mandates, Cloud KMS, Firestore, Cloud Storage and Gemini 4 Argon. The reasons are the exact text the console shows.

| What the agent tried | Outcome | Reason shown |
|---|---|---|
| Sony WH-1000XM5 at $279.99, inside a $200 to $300 mandate | Allowed without a model call, charged, delivered | Within mandate: merchant, items, amount, payee, conditions and expiry verified. |
| Bose earbuds, but the page hid an instruction to add a $500 gift card | Blocked | Cart contains items outside the mandate: SoundHub gift card (GIFT-500, $500.00). |
| AirPods from "SoundHub Official", a look-alike store | Blocked | SoundHub Official (https://soundhub-official-store.example) is not an authorized merchant for this mandate. Also: checkout signed with key soundhub-official-1, which is not in the merchant registry. |
| Silver headphones that ship in 10 to 12 days | Blocked by a rule | Promised delivery 25 Oct 2026; signed deadline 19 Oct 2026. |
| Earbuds the merchant signed as "new", while its listing says renewed | Blocked by Gemini | The cart item is renewed, which violates the customer's requirement for a new item. |
| A $249.99 speaker in the same hour as the headphones | Held, approved with a passkey, charged, delivered | Unattended spend in the last hour would reach $529.98; limit $500.00. |

At registration, the words check also refused a mandate signed with a $300 ceiling for a request that said $260 at most.

Speed, as server time from Cloud Run's request logs, with warm instances:

| Purchase | Time |
|---|---|
| Blocked by policy | 0.5 to 0.85 s |
| Allowed, every question proven by code | 1.2 to 1.45 s, including the token and its signed records |
| Allowed or held after a Gemini review | 3.2 to 5.4 s |

Other operating numbers:

| Measure | Value |
|---|---|
| Model calls per purchase | 0 when everything is proven; 2 in parallel otherwise, capped at 10 s, then the purchase is held |
| Gemini usage per reviewed purchase | 2,586 to 2,795 tokens, about nine tenths of it input |
| Model cost per reviewed purchase | Roughly 1 to 2 cents at the $4 / $20 per million tokens reported for Gemini 4 Argon after its introductory price. That rate comes from secondary sources; confirm it on Google's price sheet before quoting it |
| Model latency, same check, same day | Gemini 4 Argon 2.5 to 3.9 s; Gemini 3.8 Flash 2.4 to 140 s, which is why Argon is the model |
| Automated tests | 93, covering the attack matrix, every link of the chain, passkeys, receipts, deliveries, the fast path, callers registered by API and signed events |

## What is real and what is mocked

Say this plainly when asked. It makes the rest believable.

- **Real:** AP2 v0.2 SD-JWT mandates signed and verified with Google's SDK; Cloud Run; Firestore; Cloud KMS P-256 signatures for decisions and receipts; Cloud Storage with a retention policy for evidence; Gemini 4 Argon on Vertex AI; Model Armor; Google-signed identity for every caller; WebAuthn passkeys with user verification; log-based metrics, alerts and a scheduled chain check in Cloud Monitoring.
- **Mocked:** the merchants, the money and the payment processor. SoundHub is a small storefront we host, and our demo script holds its signing key. It signs checkouts and delivery events the way a real merchant would. The processor still uses each token once and signs its receipts with its own KMS key.
- **Played by our demo script:** the web app that signs the user's mandate, calling as that web app's own service account.
- **Not locked yet:** the evidence bucket's retention policy. Locking makes the checkpoints impossible to delete for 30 days, and cannot be undone, so we do it only for a real deployment.

## The 3-minute video

One user, six purchases. Show the console and a phone side by side. No slides in the video.

| Time | On screen | Say |
|---|---|---|
| 0:00 to 0:20 | Telegram: "can you grab the sony xm5 headphones in black if they go under $300 this week". The phone opens MandateGuard's page with the limits and conditions. Face ID. | "Asha asks in her own words. She signs the exact limits with her passkey, once." |
| 0:20 to 0:35 | Console row: **Allowed, $279.99**, in about a second. Then the receipt and the delivery arrive. | "Everything was provable by code, so no model was needed. The processor's receipt and SoundHub's signed delivery close the loop." |
| 0:35 to 1:00 | The Bose run. **Blocked, $729.00.** The gift card in red; the quoted hidden comment; the trace marker. | "This page hides instructions for shopping agents. The agent followed them. The cart is signed, but it isn't what Asha signed." |
| 1:00 to 1:25 | The late delivery, then the renewed earbuds. | "The store promised the 25th; Asha signed for the 19th. And here Gemini read the store's own listing: renewed, not new." |
| 1:25 to 1:40 | The look-alike store. **Blocked.** | "Same brand, different business. Its checkout key isn't one we know." |
| 1:40 to 2:15 | The speaker. **Held.** The phone opens the approval page. Face ID. The row turns to **Approved**, then charged and delivered. | "Two purchases in an hour cross the unattended limit, so Asha decides. Her passkey signs this exact purchase." |
| 2:15 to 2:50 | The speaker's Authorization tab. **Verify signatures**: 26 of 26 valid, six signing parties. | "Every link has a name and a proof: Asha, the agent, its plan, the store, the rules' approver, the processor, the delivery. Anyone can check them in a browser, without trusting us." |
| 2:50 to 3:00 | The sentence. | "Signed isn't the same as intended. MandateGuard shows who authorised it, and blocks what they didn't." |

Before recording:

1. Run `bash scripts/demo.sh --enroll` once and scan the QR code with the phone to create the passkey.
2. Run `bash scripts/demo.sh --consent`. Scan each QR code as it appears: two mandates to sign, then the approval, each within five minutes.
3. The hourly limit counts earlier runs, so wait an hour between full runs, or the first purchase is held too.

## The deck: eight slides

The submission asks for problem, solution, architecture, Gen AI use, feasibility and scalability. Give each slide a title that is a full claim, not a label.

1. **"Signed is not the same as intended."** The sentence and one screenshot of the blocked gift-card decision.
2. **"Agents can be steered by the pages they read."** The four facts from this document, each with its source. No icons.
3. **"MandateGuard sits where the payment credential is released."** The locked architecture diagram, with MandateGuard highlighted between the agent and the credentials service.
4. **"Every payment answers: who authorised this?"** The Authorization tab, showing 26 of 26 signatures valid.
5. **"Hard limits first, judgment second, evidence always."** The signed conditions, each with one example from the live results, ending with the delivery check.
6. **"Gemini is asked only what code can't answer."** The user's words checked once at registration; listing and page checks at purchase time; tighten-only; 10-second cap; hedged slow calls.
7. **"About a second when it's provable, four when it needs judgment."** The speed table, the scaling story (stateless Cloud Run, create-once writes, overlapped I/O) and the monitoring dashboard.
8. **"Next: real credential providers."** A wallet or PSP sandbox, the teammate's agent committing plans, merchants sending signed delivery events, a published record format for dispute teams.

## Keeping it from looking generated

Judges have seen a hundred AI-made decks this year. The tells are generic language, decoration and numbers nobody measured.

- **Write claims with numbers.** "SoundHub promises delivery by 25 Oct 2026. The user needs it by 19 Oct 2026" beats "intelligent anomaly detection".
- **Show the product, not illustrations.** Use real screenshots of the console and the phone. Skip stock icons, gradients, robots and glowing shields.
- **Name things the way a bank would.** Say mandate, payee, dispute, unattended spend, receipt and approval. Avoid "AI-powered", "seamless", "next-gen", "revolutionary" and "leverage".
- **Show the limits honestly.** Model Armor catching 1 of 4, and Gemini 3.8 Flash taking up to 140 s on a 3-second check, show we tested rather than guessed.
- **Keep the visual system plain.** The console's neutral grey with red, amber and green for outcomes works for slides too. One typeface; numbers in tabular figures.
- **Never claim what you can't show.** Don't say "production-ready" or "bank-grade". Say what runs, and how it was tested.

## Questions to expect

- **"Who authorised this payment?"** Open the console and walk the chain: the person and their passkey, their words, the mandate, the agent and its plan, the merchant, the rules and their approver, the decision, the approval, the credential, the receipt, the delivery. Each row names the account or key and links the signed record.
- **"How does a bank or gateway plug this in?"** By API only. The operator registers each service, and each registration is a signed record. MandateGuard pushes signed events instead of making services poll. `/.well-known/mandateguard` lists every endpoint by role, the AP2 profile and the public keys, so the base URL is the only setting a service needs. Decisions stay synchronous, so the payment path doesn't wait on an event.
- **"How much latency does this add?"** About half a second to block, about a second to allow when everything is provable, three to five seconds when Gemini has to read a listing. Each record carries its own timing breakdown, and the dashboard tracks p50 and p95.
- **"What if Gemini is slow or fooled?"** A slow call gets one duplicate request after 3.5 seconds, the first block ends the review, and the review is capped at 10 seconds, after which the purchase is held, never allowed. Gemini can only add blocks: a judge that answers "approve" is treated as malformed.
- **"Why skip the model at all?"** Only when every question it would answer is already proven. That means the user's words matched the mandate at registration, the cart equals the committed plan, the titles and conditions are exactly what was signed, and the page came from the merchant's own site. Anything else gets the full review, and the record lists the reason.
- **"What if the web app gets the user's request wrong?"** Gemini compares the user's own message with the signed limits when the mandate is registered. On the live service it refused a mandate signed with a $300 ceiling for a request that said $260 at most, and in a direct test one that said silver when the user asked for black.
- **"Can someone edit the log?"** Each record carries the previous record's hash and a KMS signature, and checkpoints go to a write-once bucket that a scheduled job verifies every 15 minutes. Editing a record breaks its signature; deleting the newest records no longer matches the checkpoints.
- **"What stops the agent approving its own hold?"** The link goes only to the user, and handing it out is itself a record. With a passkey enrolled, an approval without the user's signature is refused. Each link works once, within five minutes.
- **"What if the store ships something else?"** Its delivery event is signed with its registered key and compared with the address, deadline and condition the user signed. A mismatch is recorded, shown as broken and raises an alert.
- **"How is this different from AP2 itself?"** AP2 defines the mandates and verifies signatures and constraints; we use its SDK for exactly that. It leaves manipulation before checkout, impersonation, unattended spend limits, replay storage, delivery and dispute evidence to the implementer. That is what MandateGuard adds.
