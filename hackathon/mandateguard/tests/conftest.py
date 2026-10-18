"""Test world: every party in an AP2 human-not-present purchase, built with the real AP2 SDK.

  trusted surface  signs the user's open mandates (with signed conditions) and registers them
  operator         registers the shopping agent and the merchant's signing key
  agent            signs closed mandates with the key the user delegated to; calls as principal "dev"
  merchant         signs checkouts (delivery promise, ship-to hash, item condition) and later its shipping and delivery events
  impostor         a look-alike store with its own unregistered key
  processor        charges tokens and signs receipts
  approver         signs policy packs
  the web          what each merchant URL really serves, for MandateGuard's own page checks (no network in tests)
"""

from __future__ import annotations

import json
import time
import uuid

import pytest
from ap2.sdk.generated.checkout_mandate import CheckoutMandate
from ap2.sdk.generated.open_checkout_mandate import AllowedMerchants, Item, LineItemRequirements, LineItems
from ap2.sdk.generated.open_payment_mandate import AllowedPayees, AmountRange, OpenPaymentMandate, PaymentReference
from ap2.sdk.generated.payment_mandate import PaymentMandate
from ap2.sdk.generated.types.amount import Amount
from ap2.sdk.generated.types.checkout import Checkout, Status
from ap2.sdk.generated.types.item import Item as CItem
from ap2.sdk.generated.types.line_item import LineItem
from ap2.sdk.generated.types.merchant import Merchant
from ap2.sdk.generated.types.payment_instrument import PaymentInstrument
from ap2.sdk.generated.types.total import Total
from ap2.sdk.jwt_helper import create_jwt
from ap2.sdk.mandate import MandateClient
from ap2.sdk.sdjwt import compute_sd_hash, parse_token
from ap2.sdk.utils import compute_sha256_b64url
from cryptography.hazmat.primitives.asymmetric import ec
from jwcrypto.jwk import JWK

from mandateguard import audit
from mandateguard.conditions import GuardedOpenCheckoutMandate, build_conditions, commit, new_salt, normalize_address
from mandateguard.config import Settings
from mandateguard.credentials import InProcessCredentials
from mandateguard.evidence import InMemoryEvidence
from mandateguard.gemini_checks import FakeGeminiClient, GeminiChecks
from mandateguard.models import Actor, AP2Bundle, DecisionRequest, PageExcerpt, PlanBody, TraceEvent
from mandateguard.pipeline import DEV_AGENT, Pipeline
from mandateguard.registry import AgentRegistry, ApproverRegistry, MerchantRegistry
from mandateguard.rules.engine import PackStore
from mandateguard.screener import CombinedScreener, HeuristicScreener
from mandateguard.stores import InMemoryStores

CLEAN = Merchant(id="merchant_clean", name="SoundHub", website="https://soundhub.example")
IMPOSTOR = Merchant(id="merchant_impostor", name="SoundHub Official", website="https://soundhub-deals.example")
INSTRUMENT = PaymentInstrument(id="stub", type="card", description="Card ••••4242")
SKU = "WH1000XM5-BLK"
HOME = "12 Orchard Road, #05-01, Singapore 238826"
ORIGIN = "https://mandateguard.test"
INTENT = "Buy 1x Sony WH-1000XM5 black from SoundHub if the price is between $200 and $300 in the next 7 days"


def new_key(kid: str | None = None) -> JWK:
    k = JWK.from_pyca(ec.generate_private_key(ec.SECP256R1()))
    if kid:
        d = json.loads(k.export())
        d["kid"] = kid
        k = JWK.from_json(json.dumps(d))
    return k


def public(k: JWK) -> dict:
    return json.loads(k.export_public())


class World:
    def __init__(self, gemini: FakeGeminiClient | None = None, now: float | None = None, packs_dir: str | None = None):
        self.surface_key = new_key("webapp-signing-1")
        self.agent_key = new_key()
        self.other_agent_key = new_key()
        self.merchant_key = new_key("soundhub-2026-10")
        self.impostor_key = new_key("soundhub-official-1")
        self.approver_key = new_key("risk-approver-1")
        self.address_salt = new_salt()
        self.web: dict[str, str] = {}
        self.approvers = ApproverRegistry()
        self.last_registration: dict = {}
        self.stores = InMemoryStores()
        self.registry = MerchantRegistry()
        self.agents = AgentRegistry()
        self.signer = audit.LocalEcSigner()
        self.processor = audit.LocalEcSigner()
        self.credentials = InProcessCredentials(self.signer.verify, processor_signer=self.processor)
        self.evidence = InMemoryEvidence()
        self.gemini = gemini or FakeGeminiClient()
        self.settings = Settings(backend="memory", stage2="fake", allowed_tools=["search_products", "read_page", "assemble_cart", "create_checkout"],
                                 hnp_txn_cap_minor=100_000, hnp_velocity_cap_minor=200_000, public_url=ORIGIN,
                                 **({"packs_dir": packs_dir} if packs_dir else {}))
        self._now = now
        self.pipeline = Pipeline(settings=self.settings, stores=self.stores, registry=self.registry, agents=self.agents,
                                 packs=PackStore(self.settings.packs_dir), screener=CombinedScreener([HeuristicScreener()]),
                                 gemini=GeminiChecks(self.gemini, "fake", None), chain=audit.InMemoryChain(), signer=self.signer,
                                 credentials=self.credentials, evidence=self.evidence,
                                 processor_keys={self.processor.kid: audit.PemVerifier(self.processor.public_pem(), self.processor.kid)},
                                 clock=self.clock, approvers=self.approvers, page_fetcher=self.fetch_page)
        self.operator = Actor(principal="ops@bank.test", role="operator", verified_by="test")
        self.surface = Actor(principal="webapp@bank.test", role="trusted_surface", verified_by="test")
        self.processor_actor = Actor(principal="processor@bank.test", role="processor", verified_by="test")
        self.pipeline.register_merchant_key({"id": CLEAN.id, "name": CLEAN.name, "website": CLEAN.website, "rating": 4.6,
                                             "rating_source": "test registry", "kid": self.merchant_key.kid, "public_jwk": public(self.merchant_key)},
                                            self.operator)
        self.pipeline.register_agent({"agent_id": "shopper-agent", "principals": ["dev"], "key_thumbprints": [self.agent_key.thumbprint()],
                                      "operator": "hackathon team"}, self.operator)

    def clock(self) -> float:
        return self._now if self._now is not None else time.time()

    def fetch_page(self, url: str) -> str:
        if url not in self.web:
            raise ConnectionError("unreachable")
        return self.web[url]

    @property
    def records(self) -> list[dict]:
        return self.pipeline.chain.all()

    def of_type(self, t: str) -> list[dict]:
        return [r for r in self.records if r.get("type") == t]

    # ---- the trusted surface: the user approves a summary, the web app signs and registers ------------------
    def sign_mandate(self, *, skus=(SKU,), qty=1, min_minor=20_000, max_minor=30_000, merchants=(CLEAN,), ttl=3600, titles=None,
                     intent_text=INTENT, summary_text=None, conditions: bool = True, ship_to=HOME, deliver_by="2026-10-24",
                     item_condition="new", min_seller_rating=4.0, agent_key: JWK | None = None, user_id="user_1",
                     tamper=None, passkey_consent: bool = False, instruction: dict | None = None) -> str:
        titles = titles or {}
        now = int(self.clock())
        agent_pub = JWK.from_json((agent_key or self.agent_key).export_public())
        cnf = {"jwk": json.loads(agent_pub.export_public())}
        salt = new_salt()
        summary_text = summary_text or f"{intent_text}. Delivered to your home address."
        conds = build_conditions(intent_text=intent_text, summary_text=summary_text, salt=salt, ship_to=ship_to, address_salt=self.address_salt,
                                 deliver_by=deliver_by, item_condition=item_condition, min_seller_rating=min_seller_rating) if conditions else None
        oc = GuardedOpenCheckoutMandate(constraints=[
            LineItems(items=[LineItemRequirements(id="line_1", acceptable_items=[Item(id=s, title=titles.get(s, s)) for s in skus], quantity=qty)]),
            AllowedMerchants(allowed=list(merchants)),
        ], cnf=cnf, iat=now, exp=now + ttl, mg_conditions=conds)
        oc_sdjwt = MandateClient().create(payloads=[oc], issuer_key=self.surface_key)
        oc_hash = compute_sd_hash(parse_token(oc_sdjwt))
        op = OpenPaymentMandate(constraints=[AmountRange(currency="USD", min=min_minor, max=max_minor), AllowedPayees(allowed=list(merchants)),
                                             PaymentReference(conditional_transaction_id=oc_hash)], cnf=cnf, iat=now, exp=now + ttl)
        op_sdjwt = MandateClient().create(payloads=[op], issuer_key=self.surface_key)
        mandate_id = "mnd_" + uuid.uuid4().hex[:10]
        body = {"mandate_id": mandate_id, "user_id": user_id, "intent_text": intent_text, "intent_salt": salt, "summary_text": summary_text,
                "open_checkout_mandate": oc_sdjwt, "open_payment_mandate": op_sdjwt, "user_public_jwk": public(self.surface_key),
                "linked_channels": {"telegram": "tg_123"},
                "consent": {"method": "passkey", "verified_by": "web app", "at": now}}
        if passkey_consent:
            body["passkey_consent"] = True
        if instruction:
            body["instruction"] = instruction
        if tamper:
            tamper(body)
        self.last_mandate_body = body
        self.last_registration = self.pipeline.register_mandate(body, self.surface)
        return mandate_id

    # ---- the agent commits its plan before browsing --------------------------------------------------------------
    def commit_plan(self, mandate_id: str, items=((SKU, 1),), payee_id: str = CLEAN.id, caller: Actor | None = None) -> str:
        body = PlanBody(mandate_id=mandate_id, items=[{"sku": s, "qty": q} for s, q in items], payee_id=payee_id)
        return self.pipeline.commit_plan(body, caller or DEV_AGENT)["plan_id"]

    # ---- the merchant reports shipping and delivery ------------------------------------------------------------------
    def delivery_jwt(self, checkout_hash: str, *, kind: str = "order.delivered", items=((SKU, 1, "new"),), ship_to: str | None = HOME,
                     at: str | None = None, eta: str | None = None, key: JWK | None = None, extra: dict | None = None) -> str:
        now = int(self.clock())
        claims = {"type": kind, "checkout_hash": checkout_hash, "order_id": "ord_1", "iat": now, "carrier": "SingPost", "tracking_ref": "SG123",
                  "items": [{"sku": s, "qty": q, "condition": c} for s, q, c in items]}
        if ship_to:
            claims["ship_to_sha256"] = commit(normalize_address(ship_to), self.address_salt)
        claims["delivered_at" if kind == "order.delivered" else "shipped_at"] = at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
        if eta:
            claims["estimated_delivery"] = eta
        claims.update(extra or {})
        key = key or self.merchant_key
        return create_jwt(header={"alg": "ES256", "typ": "JWT", "kid": key.kid}, payload=claims, private_key=key)

    # ---- the merchant signs a checkout ---------------------------------------------------------------------
    def checkout_jwt(self, items, *, merchant: Merchant = CLEAN, key: JWK | None = None, extra_total: int = 0, shipping_hash: str | None = None,
                     ship_to: str | None = HOME, promised_by: str | None = "2026-10-18", conditions: dict | None = None) -> str:
        key = key or self.merchant_key
        line_items, subtotal = [], 0
        for i, (sku, title, unit, qty) in enumerate(items):
            line = unit * qty
            subtotal += line
            line_items.append(LineItem(id=f"li_{i}", item=CItem(id=sku, title=title, price=unit), quantity=qty,
                                       totals=[Total(type="subtotal", amount=line), Total(type="total", amount=line)]))
        checkout = Checkout(id="chk_" + uuid.uuid4().hex[:8], merchant=merchant, line_items=line_items, status=Status.incomplete, currency="USD",
                            totals=[Total(type="subtotal", amount=subtotal), Total(type="total", amount=subtotal + extra_total)], links=[])
        payload = checkout.model_dump(mode="json", exclude_none=True)
        ful = {}
        if ship_to:
            ful["ship_to_sha256"] = commit(normalize_address(ship_to), self.address_salt)
        if promised_by:
            ful["promised_by"] = promised_by
        if ful:
            payload["fulfillment"] = ful
        payload["item_facts"] = {sku: {"condition": (conditions or {}).get(sku, "new")} for sku, *_ in items}
        if shipping_hash:
            payload["buyer"] = {"address_hash": shipping_hash}
        return create_jwt(header={"alg": "ES256", "typ": "JWT", "kid": key.kid}, payload=payload, private_key=key)

    # ---- the agent signs closed mandates ------------------------------------------------------------------------
    def payment_chain(self, mandate_id: str, checkout_jwt: str, amount_minor: int, *, payee: Merchant = CLEAN, nonce: str | None = None,
                      transaction_id: str | None = None, agent_key: JWK | None = None) -> tuple[str, str]:
        rec = self.stores.get_mandate(mandate_id)
        nonce = nonce or uuid.uuid4().hex
        pm = PaymentMandate(transaction_id=transaction_id or compute_sha256_b64url(checkout_jwt), payee=payee,
                            payment_amount=Amount(amount=amount_minor, currency="USD"), payment_instrument=INSTRUMENT)
        chain = MandateClient().present(holder_key=agent_key or self.agent_key, mandate_token=rec.open_payment_mandate, payloads=[pm],
                                        nonce=nonce, aud="credential-provider")
        return chain, nonce

    def checkout_chain(self, mandate_id: str, checkout_jwt: str, *, nonce: str | None = None, agent_key: JWK | None = None) -> tuple[str, str]:
        rec = self.stores.get_mandate(mandate_id)
        nonce = nonce or uuid.uuid4().hex
        cm = CheckoutMandate(checkout_jwt=checkout_jwt, checkout_hash=compute_sha256_b64url(checkout_jwt))
        chain = MandateClient().present(holder_key=agent_key or self.agent_key, mandate_token=rec.open_checkout_mandate, payloads=[cm],
                                        nonce=nonce, aud="merchant")
        return chain, nonce

    def request(self, mandate_id: str, *, items=((SKU, "Sony WH-1000XM5 Black", 27_999, 1),), merchant: Merchant = CLEAN, merchant_key: JWK | None = None,
                amount_minor: int | None = None, payee: Merchant | None = None, pages: list[PageExcerpt] | None = None, trace: list[TraceEvent] | None = None,
                with_checkout_chain: bool = True, payment_nonce: str | None = None, checkout_jwt: str | None = None, transaction_id: str | None = None,
                extra_total: int = 0, shipping_hash: str | None = None, ship_to: str | None = HOME, promised_by: str | None = "2026-10-18",
                conditions: dict | None = None, user_id: str | None = "user_1", agent_id: str | None = "shopper-agent",
                agent_key: JWK | None = None, plan_id: str | None = None) -> DecisionRequest:
        cj = checkout_jwt or self.checkout_jwt(items, merchant=merchant, key=merchant_key, extra_total=extra_total, shipping_hash=shipping_hash,
                                               ship_to=ship_to, promised_by=promised_by, conditions=conditions)
        total = sum(u * q for _, _, u, q in items) + extra_total
        pchain, pnonce = self.payment_chain(mandate_id, cj, amount_minor if amount_minor is not None else total, payee=payee or merchant,
                                            nonce=payment_nonce, transaction_id=transaction_id, agent_key=agent_key)
        cchain, cnonce = self.checkout_chain(mandate_id, cj, agent_key=agent_key) if with_checkout_chain else (None, None)
        if trace is None:
            trace = default_trace([s for s, *_ in items][:1], merchant.id)
        return DecisionRequest(mandate_id=mandate_id, user_id=user_id, agent_id=agent_id, plan_id=plan_id,
                               ap2=AP2Bundle(checkout_jwt=cj, payment_mandate_chain=pchain, payment_nonce=pnonce, checkout_mandate_chain=cchain,
                                             checkout_nonce=cnonce),
                               trace=trace, pages=pages or [])


def default_trace(plan_skus, payee_id, shipping_hash="addr_home") -> list[TraceEvent]:
    return [
        TraceEvent(seq=1, kind="plan", summary="buy headphones if in range", data={"items": [{"sku": s, "qty": 1} for s in plan_skus], "payee_id": payee_id, "shipping_address_hash": shipping_hash}),
        TraceEvent(seq=2, kind="tool_call", tool="read_page", summary="read product page", data={"url": "https://soundhub.example/p/wh1000xm5"}),
        TraceEvent(seq=3, kind="page_read", summary="product page", data={"url": "https://soundhub.example/p/wh1000xm5", "content_sha256": "abc"}),
        TraceEvent(seq=4, kind="tool_call", tool="assemble_cart", summary="cart", data={"items": [{"sku": s, "qty": 1} for s in plan_skus]}),
        TraceEvent(seq=5, kind="tool_call", tool="create_checkout", summary="checkout", data={}),
    ]


@pytest.fixture
def world() -> World:
    return World()
