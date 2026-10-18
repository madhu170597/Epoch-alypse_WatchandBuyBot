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
  const r = await fetch(`/v1/approvals/${encodeURIComponent(id)}${path}`, {
    ...init, headers: { "Content-Type": "application/json", "X-Approval-Key": key, ...(init.headers || {}) },
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

async function respond(action, buttons, note, usePasskey) {
  buttons.forEach((b) => (b.disabled = true));
  note.textContent = "";
  try {
    let assertion;
    if (action === "approve" && usePasskey) {
      const options = await api("/passkey-options", { method: "POST" });
      note.textContent = "Confirm with your passkey.";
      assertion = await signWithPasskey(options);
    }
    const res = await api("/respond", { method: "POST", body: JSON.stringify({ action, assertion }) });
    if (res.verdict === "ALLOW") {
      finished("ok", "Approved", usePasskey ? "Purchase approved. Passkey signature recorded." : "Purchase approved.");
    } else if (action === "decline") {
      finished("plain", "Declined", "Purchase declined. No payment will be made.");
    } else {
      finished("bad", "Not approved", res.message || "Approval not completed.");
    }
  } catch (e) {
    if (e.name === "NotAllowedError" || e.name === "AbortError") {
      note.textContent = "Passkey prompt dismissed. No approval recorded.";
      buttons.forEach((b) => (b.disabled = false));
      return;
    }
    finished("bad", "Approval failed", `${e.message} No payment was made.`);
  }
}

function render(v) {
  if (v.status !== "issued") {
    const msg = {
      approved: ["Approved", "This purchase has been approved."],
      rejected: ["Declined", "This purchase was declined."],
      expired: ["Expired", "Request expired. No payment was made."],
    }[v.status] || ["Unavailable", "This request is no longer open."];
    return finished("plain", msg[0], msg[1]);
  }
  const at = v.attempted || {}, au = v.authorized || {}, c = au.conditions || {};
  const ccy = at.currency || au.currency || "USD";
  const usePasskey = !!v.passkey?.required;
  const timerEl = h("p", { class: "timer" });
  const note = h("p", { class: "timer", role: "status" });
  const approve = h("button", { class: "btn primary", type: "button" }, usePasskey ? "Approve with passkey" : "Approve purchase");
  const decline = h("button", { class: "btn", type: "button" }, "Decline");
  if (usePasskey && !supported()) {
    approve.disabled = true;
    note.textContent = "Passkeys are unavailable in this browser. Open the link on the registered device.";
  }
  approve.addEventListener("click", () => respond("approve", [approve, decline], note, usePasskey));
  decline.addEventListener("click", () => respond("decline", [approve, decline], note, false));
  const conds = [
    c.deliver_by ? `delivery by ${day(c.deliver_by)}` : null,
    c.item_condition ? `${c.item_condition} only` : null,
    c.min_seller_rating ? `seller rating ${Number(c.min_seller_rating).toFixed(1)} minimum` : null,
    c.ship_to_sha256 ? "registered address" : null,
  ].filter(Boolean);
  app.replaceChildren(...[
    brand(),
    h("h1", {}, "Purchase approval required"),
    h("div", { class: "card" },
      (at.items || []).map((i) => h("div", { class: "item" }, h("span", {}, `${i.qty}× ${i.title || i.sku}`), h("span", { class: "num muted" }, money(i.line_minor, ccy)))),
      h("div", { class: "muted", style: "margin-top:8px" }, `${at.merchant?.name || ""} · ${(at.merchant?.website || "").replace(/^https?:\/\//, "")}`),
      h("div", { class: "total num" }, money(at.total_minor, ccy))),
    h("h2", {}, "Reason for review"),
    h("ul", { class: "why" }, (v.reasons || []).map((r) => h("li", {}, r.detail))),
    h("h2", {}, "Your mandate"),
    au.intent_text ? h("p", { class: "signed", style: "margin:0 0 6px" }, `“${au.intent_text}”`) : null,
    h("p", { class: "signed num", style: "margin:0" },
      [`${money(au.min_minor, ccy)} to ${money(au.max_minor, ccy)}`, (au.merchants || []).map((m) => m.name).join(", "), ...conds, `valid until ${dateTime(au.expires_at)}`].join(" · ")),
    usePasskey ? h("p", { class: "signed", style: "margin:14px 0 0" },
      `Approval signs: ${money(v.statement?.amount_minor, ccy)} to ${at.merchant?.name || v.statement?.payee_id} · decision ${String(v.statement?.decision_id || "").slice(0, 16)}…`) : null,
    h("div", { class: "actions" }, approve, decline),
    note, timerEl].filter(Boolean));
  countdown(timerEl, v.expires_at, v.now);
}

(async () => {
  if (!id || !key) return finished("bad", "Invalid link", "Use the link exactly as received.");
  try {
    render(await api("/view"));
  } catch (e) {
    finished("bad", e.status === 403 ? "Invalid link" : "Unable to load request", e.status === 403 ? "Use the link exactly as received." : e.message);
  }
})();
