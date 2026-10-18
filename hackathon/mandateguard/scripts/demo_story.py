"""The demo story against the deployed services. Every role acts as its own identity.

  bash scripts/demo.sh --enroll        one-time link and QR code to create the demo user's passkey
  bash scripts/demo.sh                 six purchases; the allowed ones are charged, shipped and delivered
  bash scripts/demo.sh --consent       the user first signs the mandates for purchases 1 and 6 with their passkey
  bash scripts/demo.sh --refund        also refunds the first purchase at the end
  bash scripts/demo.sh --misdeliver    SoundHub reports purchase 1 delivered to a different address
  bash scripts/demo.sh --only 1,6      run only some purchases

Who plays which role:
  operator         mandateguard-ops-sa registers SoundHub's key, the shopping agent and the policy approver
  trusted surface  trusted-surface-sa registers each signed mandate with the user's own message, and issues passkey links
  user             the phone creates the passkey, signs mandates and approves the held purchase
  agent            shopping-agent-sa commits its plan, reads SoundHub's live pages, asks MandateGuard and collects tokens
  channel          mandateguard-ops-sa fetches the approval link to deliver it
  processor        the credentials service charges the token and reports a signed receipt
  merchant         SoundHub's signing key, held by this script, signs checkouts and delivery events

1. Sony WH-1000XM5 at $279.99                        Allowed, charged, receipt reconciled, delivered
2. Bose earbuds; the page hides a gift-card order    Blocked: item not signed, hidden instructions quoted, drift located
3. AirPods from a look-alike store                   Blocked: unregistered key, merchant not authorized
4. Sony headset promised too late                    Blocked: delivery date after the signed deadline
5. Merchant signs "new" but its listing says renewed Blocked by Gemini: the listing contradicts the merchant's signed facts
6. JBL speaker in the same hour                      Held: hourly unattended limit; approved with a passkey, charged, delivered
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ap2.sdk.generated.types.merchant import Merchant  # noqa: E402
from jwcrypto.jwk import JWK  # noqa: E402
from tests.conftest import CLEAN, HOME, World, public  # noqa: E402

from mandateguard.models import PageExcerpt, TraceEvent  # noqa: E402

IMPOSTOR = Merchant(id="soundhub-official", name="SoundHub Official", website="https://soundhub-official-store.example")
KEYS = ROOT / ".demo" / "keys.json"
DAY = 86400
ELSEWHERE = "41 Harbor Road, Unit 9, Singapore 098765"


def qr(link: str) -> str:
    """The link as a terminal QR code, so a phone camera can open it. Empty if qrcode is not installed."""
    try:
        import io

        import qrcode
    except ImportError:
        return ""
    q = qrcode.QRCode(border=2)
    q.add_data(link)
    q.make(fit=True)
    out = io.StringIO()
    q.print_ascii(out=out, invert=True)
    return out.getvalue()


def human(iso: str) -> str:
    t = time.strptime(iso, "%Y-%m-%d")
    return f"{t.tm_mday} {time.strftime('%b %Y', t)}"


def day(offset: int) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(time.time() + offset * DAY))


def load_keys(w: World) -> None:
    """Stable demo identities: the merchant's, agent's and approver's keys must not change between runs."""
    k = json.loads(KEYS.read_text()) if KEYS.exists() else {}
    if "surface" in k:
        w.surface_key, w.agent_key = JWK.from_json(k["surface"]), JWK.from_json(k["agent"])
        w.merchant_key, w.impostor_key = JWK.from_json(k["merchant"]), JWK.from_json(k["impostor"])
        w.address_salt = k["address_salt"]
    else:
        k.update({"surface": w.surface_key.export(), "agent": w.agent_key.export(), "merchant": w.merchant_key.export(),
                  "impostor": w.impostor_key.export(), "address_salt": w.address_salt})
    if "approver" in k:
        w.approver_key = JWK.from_json(k["approver"])
    else:
        k["approver"] = w.approver_key.export()
    KEYS.parent.mkdir(exist_ok=True)
    KEYS.write_text(json.dumps(k))


def trace(sku: str, title: str, url: str, cart_skus: list[str], payee_id: str) -> list[TraceEvent]:
    return [
        TraceEvent(seq=1, kind="plan", summary=f"Price alert: {title} within the signed range",
                   data={"items": [{"sku": sku, "qty": 1}], "payee_id": payee_id}),
        TraceEvent(seq=2, kind="tool_call", tool="read_page", summary=f"Read product page: {title}", data={"url": url}),
        TraceEvent(seq=3, kind="page_read", summary="Product page retrieved", data={"url": url, "content_sha256": "-"}),
        TraceEvent(seq=4, kind="tool_call", tool="assemble_cart", summary="Assemble cart", data={"items": [{"sku": s, "qty": 1} for s in cart_skus]}),
        TraceEvent(seq=5, kind="tool_call", tool="create_checkout", summary="Request signed checkout", data={}),
    ]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mg", required=True)
    ap.add_argument("--cs", default="", help="credentials service; without it, tokens are issued but nothing is charged")
    ap.add_argument("--store", default="https://soundhub-55485752139.us-central1.run.app", help="SoundHub's storefront")
    ap.add_argument("--agent-token", required=True)
    ap.add_argument("--surface-token", required=True)
    ap.add_argument("--ops-token", required=True)
    ap.add_argument("--refund-token", default="")
    ap.add_argument("--agent-principal", required=True)
    ap.add_argument("--user", default="cus_4H7Q2M")
    ap.add_argument("--wait", type=int, default=300, help="seconds to wait for each answer from the phone")
    ap.add_argument("--enroll", action="store_true")
    ap.add_argument("--consent", action="store_true", help="the user signs the mandates for purchases 1 and 6 with their passkey")
    ap.add_argument("--refund", action="store_true")
    ap.add_argument("--misdeliver", action="store_true")
    ap.add_argument("--only", default="", help="comma list of scenario numbers, e.g. 1,6")
    a = ap.parse_args()
    mg, cs, store = a.mg.rstrip("/"), a.cs.rstrip("/"), a.store.rstrip("/")
    chosen = {int(x) for x in a.only.split(",") if x.strip()}
    auth = {k: {"Authorization": f"Bearer {v}"} for k, v in (("agent", a.agent_token), ("surface", a.surface_token), ("ops", a.ops_token))}
    shop = Merchant(id=CLEAN.id, name="SoundHub", website=store)

    def want(n: int) -> bool:
        return not chosen or n in chosen

    def call(method: str, url: str, role: str | None = None, **kw) -> dict:
        r = httpx.request(method, url, headers=auth.get(role, {}), timeout=180, **kw)
        if r.status_code >= 400:
            raise RuntimeError(f"{method} {url} -> {r.status_code} {r.text[:300]}")
        return r.json()

    if a.enroll:
        out = call("POST", f"{mg}/v1/admin/users/{a.user}/passkey-enrollments", "surface")
        print(f"Open on the phone within 15 minutes to create the passkey for {a.user}:\n  {out['link']}\n{qr(out['link'])}")
        return

    w = World()
    load_keys(w)
    print("operator: SoundHub's key, the shopping agent, the policy approver")
    print("  merchant:", call("POST", f"{mg}/v1/admin/merchants", "ops", json={"id": shop.id, "name": shop.name, "website": shop.website,
          "rating": 4.6, "rating_source": "demo merchant registry", "kid": w.merchant_key.kid, "public_jwk": public(w.merchant_key)}))
    print("  agent:", call("POST", f"{mg}/v1/admin/agents", "ops", json={"agent_id": "shopper-agent", "principals": [a.agent_principal],
          "key_thumbprints": [w.agent_key.thumbprint()], "operator": "AP2 Ordering Bot team", "description": "Price-watching shopping agent (ADK)"}))
    print("  approver:", call("POST", f"{mg}/v1/admin/policy-approvers", "ops", json={"approver_id": "head-of-payments-risk",
          "name": "Head of payments risk", "public_jwk": public(w.approver_key)}))

    def mandate(intent: str, message: str, sku: str, title: str, lo: int, hi: int, deliver_by: str, consent: bool = False) -> str | None:
        ins = {"channel": "telegram", "message_id": str(random.randint(10_000, 99_999)), "received_at": int(time.time()), "text": message}
        mid = w.sign_mandate(skus=(sku,), titles={sku: title}, merchants=(shop,), min_minor=lo, max_minor=hi, intent_text=intent, ttl=7 * DAY,
                             user_id=a.user, deliver_by=deliver_by, instruction=ins,
                             summary_text=f"{intent} Deliver to your home address by {human(deliver_by)}. New items only. Seller rated 4.0 or better.")
        body = dict(w.last_mandate_body)
        if consent:
            body["passkey_consent"] = True
        try:
            out = call("POST", f"{mg}/v1/admin/mandates", "surface", json=body)
        except RuntimeError as e:
            if "no passkey" in str(e):
                print("  the user has no passkey yet: run `bash scripts/demo.sh --enroll` first")
                return None
            raise
        if not out.get("consent_link"):
            return mid
        print(f"\n  The user signs this mandate on the phone (link expires in 15 minutes):\n  {out['consent_link']}\n{qr(out['consent_link'])}")
        until = time.time() + a.wait
        while time.time() < until:
            st = call("GET", f"{mg}/v1/admin/mandates/{mid}/consent", "surface")["status"]
            if st != "awaiting":
                print(f"  mandate {st}")
                return mid if st == "signed" else None
            time.sleep(3)
        print("  not signed in time; the agent can't use this mandate")
        return None

    def page(slug: str) -> tuple[str, PageExcerpt]:
        url = f"{store}/p/{slug}"
        return url, PageExcerpt(url=url, content=httpx.get(url, timeout=20).text)   # the agent reads the live page

    def plan(mid: str, sku: str, payee_id: str = CLEAN.id) -> str:
        out = call("POST", f"{mg}/v1/plans", "agent", json={"mandate_id": mid, "items": [{"sku": sku, "qty": 1}], "payee_id": payee_id})
        return out["plan_id"]

    def decide(req) -> dict:
        req.user_id, req.agent_id = a.user, "shopper-agent"
        out = call("POST", f"{mg}/v1/decisions", "agent", json=json.loads(req.model_dump_json()))
        print(f"  -> {out['verdict']:8} {out['rationale'][:160]}")
        return out

    def charge(out: dict, token: str, amount: int) -> dict | None:
        if not cs:
            print("     token issued; no processor configured, so nothing was charged")
            return None
        try:
            res = call("POST", f"{cs}/v1/charge", json={"payment_token": token, "checkout_hash": out["hashes"]["checkout"], "amount_minor": amount,
                                                        "currency": "USD", "payee_id": CLEAN.id, "order_id": "ord_" + out["decision_id"][-8:]})
        except RuntimeError as e:
            print(f"     charge failed: {e}")
            return None
        rep = res.get("report", {})
        mg_view = rep.get("mandateguard") if isinstance(rep.get("mandateguard"), dict) else {}
        print(f"     charged {res['payment_id']} · receipt reported: {rep.get('reported')} · record {mg_view.get('record_seq')}"
              f" · reconciled: {mg_view.get('reconciled')}" + (f" · {rep}" if not rep.get("reported") else ""))
        return res

    def deliver(out: dict, sku: str, eta: str, elsewhere: bool = False) -> None:
        """SoundHub reports shipping and delivery, signed with its registered key."""
        for kind in ("order.shipped", "order.delivered"):
            tok = w.delivery_jwt(out["hashes"]["checkout"], kind=kind, items=((sku, 1, "new"),), eta=eta if kind == "order.shipped" else None,
                                 ship_to=ELSEWHERE if (elsewhere and kind == "order.delivered") else HOME)
            r = httpx.post(f"{mg}/v1/fulfillment", json={"event_jwt": tok}, timeout=60)
            body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {"detail": r.text[:200]}
            print(f"     {kind.split('.')[1]}: " + (f"record {body.get('record_seq')} · matches what was signed: {body.get('reconciled')}"
                                                     + (f" · {[m['field'] for m in body.get('mismatches', [])]}" if body.get("mismatches") else "")
                                                     if r.status_code == 200 else f"{r.status_code} {body.get('detail')}"))

    def settle(out: dict, amount: int, sku: str, eta: str, elsewhere: bool = False) -> dict | None:
        """Allowed: charge and deliver. Held: send the approval link to the phone, wait, then charge and deliver."""
        token = out.get("payment_token")
        if not token and out.get("approval"):
            aid = out["approval"]["approval_id"]
            links = [p["link"] for p in call("GET", f"{mg}/v1/approvals/pending", "ops", params={"user_id": a.user}) if p["approval_id"] == aid]
            print(f"\n  Approval link for the phone (expires {out['approval']['expires_at']}):\n  {links[0] if links else '(not found)'}\n")
            if links:
                print(qr(links[0]))
            until = time.time() + a.wait
            while time.time() < until:
                st = call("GET", f"{mg}/v1/approvals/{aid}", "agent")
                if st["status"] not in ("issued", "approving"):
                    print(f"  approval: {st['status']}" + (f" ({st['error']})" if st.get("error") else ""))
                    token = st.get("payment_token")
                    break
                time.sleep(3)
            else:
                print("  no answer yet; the agent skips this match when the window closes")
        if not token:
            return None
        res = charge(out, token, amount)
        if res:
            deliver(out, sku, eta, elsewhere=elsewhere)
        return res

    promise, deadline = day(3), day(7)
    pay1 = None
    if want(1):
        print("1. Sony WH-1000XM5 drops to $279.99")
        m1 = mandate("Buy 1 Sony WH-1000XM5 in black from SoundHub if the price is between $200 and $300 in the next 7 days.",
                     "can you grab the sony xm5 headphones in black if they go under $300 this week", "WH1000XM5-BLK", "Sony WH-1000XM5, Black",
                     20_000, 30_000, deadline, consent=a.consent)
        if m1:
            p1 = plan(m1, "WH1000XM5-BLK")
            url1, pg1 = page("sony-wh-1000xm5-black")
            out1 = decide(w.request(m1, items=(("WH1000XM5-BLK", "Sony WH-1000XM5, Black", 27_999, 1),), merchant=shop, promised_by=promise, plan_id=p1,
                                    pages=[pg1], trace=trace("WH1000XM5-BLK", "Sony WH-1000XM5", url1, ["WH1000XM5-BLK"], shop.id)))
            pay1 = settle(out1, 27_999, "WH1000XM5-BLK", promise, elsewhere=a.misdeliver)

    if want(2):
        print("2. Bose earbuds; the product page hides an order for a gift card")
        m2 = mandate("Buy 1 Bose QuietComfort Ultra Earbuds from SoundHub for $180 to $250 within 7 days.",
                     "bose qc ultra earbuds from soundhub, max 250", "QCU-EARBUDS-BLK", "Bose QuietComfort Ultra Earbuds", 18_000, 25_000, deadline)
        url2, pg2 = page("bose-qc-ultra-earbuds")
        decide(w.request(m2, items=(("QCU-EARBUDS-BLK", "Bose QuietComfort Ultra Earbuds", 22_900, 1), ("GIFT-500", "SoundHub gift card", 50_000, 1)),
                         merchant=shop, promised_by=promise, pages=[pg2], plan_id=plan(m2, "QCU-EARBUDS-BLK"),
                         trace=trace("QCU-EARBUDS-BLK", "Bose QuietComfort Ultra Earbuds", url2, ["QCU-EARBUDS-BLK", "GIFT-500"], shop.id)))

    if want(3):
        print("3. AirPods found at a look-alike store")
        m3 = mandate("Buy 1 Apple AirPods Pro 2 from SoundHub if the price is between $180 and $230 within 5 days.",
                     "airpods pro 2 from soundhub if under 230", "AIRPODS-PRO-2", "Apple AirPods Pro 2", 18_000, 23_000, deadline)
        url3 = "https://soundhub-official-store.example/airpods-pro-2"
        decide(w.request(m3, items=(("AIRPODS-PRO-2", "Apple AirPods Pro 2", 18_900, 1),), merchant=IMPOSTOR, merchant_key=w.impostor_key, promised_by=promise,
                         pages=[PageExcerpt(url=url3, content="<h1>SoundHub Official · Apple AirPods Pro 2</h1><p>$189.00. Limited stock. Authorized reseller.</p>")],
                         plan_id=plan(m3, "AIRPODS-PRO-2"), trace=trace("AIRPODS-PRO-2", "Apple AirPods Pro 2", url3, ["AIRPODS-PRO-2"], shop.id)))

    if want(4):
        print("4. Sony WH-1000XM5 in silver, but delivery is too late")
        m4 = mandate("Buy 1 Sony WH-1000XM5 in silver from SoundHub between $200 and $300, delivered within 5 days.",
                     "the silver xm5 as well, but only if it arrives within 5 days", "WH1000XM5-SLV", "Sony WH-1000XM5, Silver", 20_000, 30_000, day(5))
        url4, pg4 = page("sony-wh-1000xm5-silver")
        decide(w.request(m4, items=(("WH1000XM5-SLV", "Sony WH-1000XM5, Silver", 26_900, 1),), merchant=shop, promised_by=day(11), pages=[pg4],
                         plan_id=plan(m4, "WH1000XM5-SLV"), trace=trace("WH1000XM5-SLV", "Sony WH-1000XM5 Silver", url4, ["WH1000XM5-SLV"], shop.id)))

    if want(5):
        print("5. Merchant signs 'new', but its own listing says renewed")
        m5 = mandate("Buy 1 new Sony WF-1000XM5 earbuds from SoundHub between $200 and $300 within 7 days.",
                     "new sony wf-1000xm5 earbuds please, under 300", "WF1000XM5-BLK", "Sony WF-1000XM5 Earbuds, Black", 20_000, 30_000, deadline)
        url5, pg5 = page("sony-wf-1000xm5-renewed")
        decide(w.request(m5, items=(("WF1000XM5-BLK", "Sony WF-1000XM5 Earbuds, Black (Renewed)", 21_400, 1),), merchant=shop, promised_by=promise,
                         pages=[pg5], plan_id=plan(m5, "WF1000XM5-BLK"), trace=trace("WF1000XM5-BLK", "Sony WF-1000XM5", url5, ["WF1000XM5-BLK"], shop.id)))

    if want(6):
        print("6. JBL speaker in the same hour as the headphones")
        m6 = mandate("Buy 1 JBL Charge 5 speaker from SoundHub for $200 to $260 within 7 days.", "jbl charge 5 in blue, up to 260",
                     "JBL-CHARGE5-BLU", "JBL Charge 5, Blue", 20_000, 26_000, deadline, consent=a.consent)
        if m6:
            url6, pg6 = page("jbl-charge-5-blue")
            out6 = decide(w.request(m6, items=(("JBL-CHARGE5-BLU", "JBL Charge 5, Blue", 24_999, 1),), merchant=shop, promised_by=promise, pages=[pg6],
                                    plan_id=plan(m6, "JBL-CHARGE5-BLU"), trace=trace("JBL-CHARGE5-BLU", "JBL Charge 5", url6, ["JBL-CHARGE5-BLU"], shop.id)))
            settle(out6, 24_999, "JBL-CHARGE5-BLU", promise)

    if a.refund and pay1:
        r = httpx.post(f"{cs}/v1/refund", json={"payment_id": pay1["payment_id"], "reason": "Customer cancelled before shipping"},
                       headers={"Authorization": f"Bearer {a.refund_token}"}, timeout=60)
        print("refund:", r.status_code, r.json().get("report", {}).get("reported") if r.status_code == 200 else r.text[:200])
    print(f"\nConsole: {mg}/console")


if __name__ == "__main__":
    main()
