// Small DOM and formatting helpers. All text goes through textContent: decision records contain
// merchant-supplied page text, so nothing here ever parses strings as HTML.

export function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

const SYM = { USD: "$", EUR: "€", GBP: "£", INR: "₹" };
export function money(minor, ccy = "USD") {
  if (minor === null || minor === undefined || Number.isNaN(Number(minor))) return "—";
  const n = Number(minor);
  const body = (Math.abs(n) / 100).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  return (n < 0 ? "-" : "") + (SYM[ccy] ? SYM[ccy] + body : `${ccy} ${body}`);
}

const sameDay = (a, b) => a.toDateString() === b.toDateString();
export function when(ms) {
  const d = new Date(ms);
  const t = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
  return sameDay(d, new Date()) ? t : `${d.toLocaleDateString([], { day: "numeric", month: "short" })} ${t}`;
}
export function dateTime(sec) {
  if (!sec) return "—";
  return new Date(sec * 1000).toLocaleString([], { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit", hour12: false });
}
export const short = (s, n = 10) => (s ? `${s.slice(0, n)}…` : "—");
export function day(iso) {
  if (!iso || !/^\d{4}-\d{2}-\d{2}$/.test(iso)) return iso || "—";
  return new Date(`${iso}T00:00:00Z`).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });
}
export const host = (u) => String(u || "").replace(/^https?:\/\//, "").replace(/\/$/, "");

// How a decision is shown. Verdict codes stay in the record; people see words.
export function outcome(rec, followUp, approvalTtlS = 300) {
  if (rec.verdict === "ALLOW") return { label: "Allowed", cls: "ok" };
  if (rec.verdict === "DENY") return { label: "Blocked", cls: "bad" };
  if (rec.verdict === "ESCALATE") {
    if (followUp?.verdict === "ALLOW_BY_HUMAN") return { label: "Approved by user", cls: "ok" };
    if (followUp && followUp.human_override?.reply === "reject") return { label: "Declined by user", cls: "plain" };
    if (followUp && /expired/i.test(followUp.headline || "")) return { label: "Expired, skipped", cls: "plain" };
    if (Date.now() > rec.ts_ms + approvalTtlS * 1000) return { label: "Expired, skipped", cls: "plain" };
    return { label: "Waiting for user", cls: "hold" };
  }
  return { label: rec.verdict, cls: "plain" };
}

export async function copy(text, btn) {
  try { await navigator.clipboard.writeText(text); if (btn) { const o = btn.textContent; btn.textContent = "Copied"; setTimeout(() => (btn.textContent = o), 1200); } }
  catch { /* clipboard refused: the value is visible and selectable */ }
}
