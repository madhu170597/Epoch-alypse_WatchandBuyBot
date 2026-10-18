import { h, money, dateTime, day } from "./ui.js";
import { signWithPasskey, supported } from "./webauthn.js";

// The one-time key lives in the URL fragment, which browsers never send to servers or put in Referer headers.
const id = location.pathname.split("/").filter(Boolean).pop();
const key = new URLSearchParams(location.hash.slice(1)).get("k") || "";
const app = document.getElementById("app");
let timer = null;

const brand = () => h("div", { class: "who" }, "MandateGuard");

function finished(cls, title, body) {
  clearInterval(timer);
  app.replaceChildren(brand(), h("h1", {}, title), h("div", { class: `done ${cls}` }, body));
}

async function api(path, init = {}) {
  const r = await fetch(`/v1/mandates/${encodeURIComponent(id)}/consent${path}`, {
    ...init, headers: { "Content-Type": "application/json", "X-Consent-Key": key, ...(init.headers || {}) },
  });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw Object.assign(new Error(body.detail || `HTTP ${r.status}`), { status: r.status });
  return body;
}

function countdown(el, expiresAt, serverNow) {
  const skew = Date.now() / 1000 - serverNow;
  const tick = () => {
    const left = Math.max(0, Math.round(expiresAt - (Date.now() / 1000 - skew)));
    el.textContent = left > 0 ? `Expires in ${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}` : "Expired";
    if (left <= 0) {
      clearInterval(timer);
      app.querySelectorAll("button").forEach((b) => (b.disabled = true));
    }
  };
  tick();
  timer = setInterval(tick, 1000);
}

async function respond(action, buttons, note) {
  buttons.forEach((b) => (b.disabled = true));
  note.textContent = "";
  try {
    let assertion;
    if (action === "sign") {
      const options = await api("/passkey-options", { method: "POST" });
      note.textContent = "Confirm with your passkey.";
      assertion = await signWithPasskey(options);
    }
    const res = await api("/respond", { method: "POST", body: JSON.stringify({ action, assertion }) });
    if (res.status === "signed") {
      finished("ok", "Mandate signed", `Passkey signature recorded as audit record #${res.record_seq}.`);
    } else {
      finished("plain", "Mandate declined", "No purchases will be made under this mandate.");
    }
  } catch (e) {
    if (e.name === "NotAllowedError" || e.name === "AbortError") {
      note.textContent = "Passkey prompt dismissed. Nothing was signed.";
      buttons.forEach((b) => (b.disabled = false));
      return;
    }
    finished("bad", "Signing failed", e.message);
  }
}

function row(label, value) {
  return value ? h("div", { class: "item" }, h("span", { class: "muted" }, label), h("span", {}, value)) : null;
}

function render(v) {
  if (v.status !== "awaiting") {
    const msg = {
      signed: ["Signed", "This mandate has been signed."],
      declined: ["Declined", "This mandate was declined."],
      expired: ["Expired", "Signing request expired. Request a new link."],
    }[v.status] || ["Unavailable", "This mandate is no longer open for signing."];
    return finished("plain", msg[0], msg[1]);
  }
  const d = v.display || {}, c = d.conditions || {};
  const ccy = d.currency || "USD";
  const timerEl = h("p", { class: "timer" });
  const note = h("p", { class: "timer", role: "status" });
  const sign = h("button", { class: "btn primary", type: "button" }, "Sign with passkey");
  const decline = h("button", { class: "btn", type: "button" }, "Decline");
  if (!supported()) {
    sign.disabled = true;
    note.textContent = "Passkeys are unavailable in this browser. Open the link on the registered device.";
  }
  sign.addEventListener("click", () => respond("sign", [sign, decline], note));
  decline.addEventListener("click", () => respond("decline", [sign, decline], note));
  const items = (d.items || []).map((i) => `${i.quantity || 1}× ${i.title || i.id}`).join(", ");
  const stores = (d.merchants || []).map((m) => `${m.name}${m.website ? ` · ${String(m.website).replace(/^https?:\/\//, "")}` : ""}`).join(", ");
  app.replaceChildren(...[
    brand(),
    h("h1", {}, "Authorize purchase mandate"),
    ...(d.instruction_text ? [h("h2", {}, "Your request"), h("p", { class: "signed", style: "margin:0 0 12px" }, `“${d.instruction_text}”`)] : []),
    h("div", { class: "card" },
      row("Items", items),
      row("Merchant", stores),
      row("Amount", `${money(d.min_minor, ccy)} to ${money(d.max_minor, ccy)}`),
      row("Delivery", c.deliver_by ? `By ${day(c.deliver_by)}` : null),
      row("Condition", c.item_condition ? `${c.item_condition[0].toUpperCase()}${c.item_condition.slice(1)} only` : null),
      row("Seller rating", c.min_seller_rating ? `${Number(c.min_seller_rating).toFixed(1)} minimum` : null),
      row("Ship to", c.ship_to_sha256 ? "Registered address" : null),
      row("Valid until", dateTime(d.expires_at))),
    h("p", { class: "signed", style: "margin:14px 0 0" }, "Signing authorizes purchases within these limits only."),
    h("div", { class: "actions" }, sign, decline),
    note, timerEl].filter(Boolean));
  countdown(timerEl, v.expires_at, v.now);
}

(async () => {
  if (!id || !key) return finished("bad", "Invalid link", "Use the link exactly as received.");
  try {
    render(await api("/view"));
  } catch (e) {
    finished("bad", e.status === 403 ? "Invalid link" : "Unable to load mandate", e.status === 403 ? "Use the link exactly as received." : e.message);
  }
})();
