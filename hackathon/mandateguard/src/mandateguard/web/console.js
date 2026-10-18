import { h, money, when, dateTime, short, copy, day, host } from "./ui.js";
import { importPublicKey, verifyChain, verifyRecord, verifyStatement, verifyPasskey, verifyJws, jwkThumbprint, verifyStatementJwk, GENESIS } from "./verify.js";

// MandateGuard operator console. Two views: decisions, and the audit log they are recorded in.
// Every value shown comes from a signed record; every signature can be checked in this browser.

const state = { records: [], bySeq: new Map(), followUps: new Map(), attempts: new Map(),
  view: "decisions", filter: "all", q: "", selected: null, tab: "summary", open: new Set(),
  key: null, keyInfo: null, procKeys: new Map(), merchantKeys: new Map(), approverKeys: new Map(),
  meta: null, lastSeq: -1, chain: null, verified: new Map(), texts: new Map() };
const $ = (id) => document.getElementById(id);
const isDecision = (r) => r.type === "decision";
const sa = (p) => (/^https?:/.test(String(p || "")) ? host(p) : String(p || "").replace(/@.*$/, ""));
const cap = (s) => (s ? s[0].toUpperCase() + s.slice(1) : s);
const ms = (v) => (v === undefined || v === null ? "—" : v >= 1000 ? `${(v / 1000).toFixed(2)} s` : `${v} ms`);
const TYPE = { "decision": "Decision", "approval": "Customer response", "mandate.registered": "Mandate registered", "mandate.rejected": "Mandate refused",
  "mandate.consented": "Mandate signed", "mandate.consent_declined": "Mandate declined", "mandate.consent_refused": "Signature refused",
  "agent.registered": "Agent registered", "agent.revoked": "Agent revoked", "client.registered": "Client registered",
  "client.revoked": "Client revoked", "merchant.key_registered": "Merchant key registered", "merchant.profile_updated": "Merchant updated",
  "policy.loaded": "Policy loaded", "policy.approver_registered": "Policy approver registered", "user.passkey_enrolled": "Passkey registered",
  "plan.committed": "Plan committed", "approval.link_issued": "Approval link issued", "approval.link_sent": "Approval link sent",
  "credential.released": "Token issued", "payment.executed": "Payment", "payment.refunded": "Refund", "payment.receipt_rejected": "Receipt refused",
  "fulfillment.shipped": "Shipment", "fulfillment.delivered": "Delivery", "fulfillment.rejected": "Delivery event refused" };
const GROUPS = { all: () => true, mandates: (t) => t.startsWith("mandate.") || t === "plan.committed",
  decisions: (t) => t === "decision" || t === "approval" || t.startsWith("approval."),
  money: (t) => t.startsWith("credential.") || t.startsWith("payment."), fulfilment: (t) => t.startsWith("fulfillment."),
  registry: (t) => t.startsWith("agent.") || t.startsWith("client.") || t.startsWith("merchant.") || t.startsWith("policy.") || t === "user.passkey_enrolled" };
const FILTERS = { decisions: [["all", "All"], ["ok", "Allowed"], ["hold", "Held"], ["bad", "Blocked"]],
  ledger: [["all", "All"], ["mandates", "Mandates"], ["decisions", "Decisions"], ["money", "Payments"], ["fulfilment", "Fulfilment"], ["registry", "Registry"]] };
const STATUS = { proven: ["Signed", "line"], verified: ["Verified", "ok"], attested: ["Attested", "hold"], failed: ["Failed", "bad"],
  waiting: ["Pending", "plain"], na: ["—", "plain"] };
const CHECK = { semantic_fit: "Request match", trace_drift: "Plan drift", counterparty_identity: "Merchant identity", page_screen: "Page content", intent_fidelity: "Request fidelity" };

async function getJSON(url) {
  const r = await fetch(url, { headers: { Accept: "application/json" } });
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  return r.json();
}
const first = (pred) => state.records.find(pred) || null;
function last(pred) { for (let i = state.records.length - 1; i >= 0; i--) if (pred(state.records[i])) return state.records[i]; return null; }

function ingest(recs) {
  const fresh = [];
  for (const r of recs) {
    if (state.bySeq.has(r.seq)) continue;
    state.bySeq.set(r.seq, r);
    state.records.push(r);
    if (r.type === "approval" && r.original_decision_id) {
      if (r.human_override?.accepted) state.followUps.set(r.original_decision_id, r);
      else state.attempts.set(r.original_decision_id, [...(state.attempts.get(r.original_decision_id) || []), r]);
    }
    state.lastSeq = Math.max(state.lastSeq, r.seq);
    fresh.push(r);
  }
  state.records.sort((a, b) => a.seq - b.seq);
  return fresh;
}

// ======================================================================== outcome
function outcomeOf(r) {
  const f = state.followUps.get(r.decision_id);
  const ttl = state.meta?.limits?.approval_ttl_s ?? 300;
  if (r.verdict === "ALLOW") return { label: "Allowed", cls: "ok", group: "ok" };
  if (r.verdict === "DENY") return { label: "Blocked", cls: "bad", group: "bad" };
  if (f?.verdict === "ALLOW_BY_HUMAN") return { label: "Approved", cls: "ok", group: "hold" };
  if (f && f.human_override?.reply === "reject") return { label: "Declined", cls: "plain", group: "hold" };
  if (Date.now() > r.ts_ms + ttl * 1000) return { label: "Expired", cls: "plain", group: "hold" };
  return { label: "Pending approval", short: "Held", cls: "hold", group: "hold" };
}
const reasonTitle = (r) => (r.verdict === "ALLOW" ? "Within mandate" : (r.evidence || [])[0]?.title || "");
const merchantOf = (r) => r.attempted?.merchant || {};
const itemsOf = (r) => (r.attempted?.items || []).map((i) => `${i.qty > 1 ? i.qty + "× " : ""}${i.title || i.sku}`).join(", ");
function payerOf(dec) {
  const f = state.followUps.get(dec.decision_id);
  return dec.verdict === "ALLOW" ? dec : (f?.verdict === "ALLOW_BY_HUMAN" ? f : null);
}
function related(dec) {
  const p = payerOf(dec);
  const byPayer = (t) => (p ? state.records.filter((r) => r.type === t && r.for_decision_id === p.decision_id) : []);
  return {
    reg: first((r) => r.type === "mandate.registered" && r.mandate_id === dec.mandate_id),
    consent: first((r) => r.type === "mandate.consented" && r.mandate_id === dec.mandate_id),
    declined: first((r) => r.type === "mandate.consent_declined" && r.mandate_id === dec.mandate_id),
    agentReg: dec.agent_id ? last((r) => r.type === "agent.registered" && r.agent_id === dec.agent_id && r.seq < dec.seq) : null,
    merchReg: dec.identity?.merchant_kid ? last((r) => r.type === "merchant.key_registered" && r.kid === dec.identity.merchant_kid) : null,
    policy: last((r) => r.type === "policy.loaded" && r.packs_hash === dec.hashes?.packs),
    plan: dec.trace?.witnessed_plan ? first((r) => r.type === "plan.committed" && r.plan_id === dec.trace.witnessed_plan.plan_id) : null,
    follow: state.followUps.get(dec.decision_id) || null,
    links: state.records.filter((r) => (r.type === "approval.link_issued" || r.type === "approval.link_sent") && r.original_decision_id === dec.decision_id),
    payer: p, release: byPayer("credential.released")[0] || null, paid: byPayer("payment.executed")[0] || null,
    refund: byPayer("payment.refunded")[0] || null, shipped: byPayer("fulfillment.shipped").at(-1) || null,
    delivered: byPayer("fulfillment.delivered").at(-1) || null,
  };
}
const enrolledKey = (uid, cred) => last((r) => r.type === "user.passkey_enrolled" && r.user_id === uid && r.credential_id_sha256 === cred);
const merchantName = (id, dec) => (dec?.attempted?.merchant?.id === id ? dec.attempted.merchant.name
  : (last((r) => r.type === "merchant.key_registered" && r.merchant?.id === id)?.merchant?.name || id));

// ======================================================================== list
function renderStats() {
  const el = $("stats");
  if (state.view === "ledger") {
    el.replaceChildren(h("span", {}, h("b", {}, state.records.length.toLocaleString()), " records"),
      h("span", {}, "latest ", h("b", {}, `#${state.lastSeq}`)));
    return;
  }
  const since = Date.now() - 86_400_000;
  const decs = state.records.filter((r) => isDecision(r) && r.ts_ms >= since);
  const n = (g) => decs.filter((r) => outcomeOf(r).group === g).length;
  const lat = decs.map((r) => r.latency_ms || 0).sort((a, b) => a - b);
  const pct = (q) => (lat.length ? lat[Math.min(lat.length - 1, Math.floor(q * lat.length))] : null);
  el.replaceChildren(h("span", {}, "Last 24 h"), h("span", {}, h("b", {}, decs.length), " decisions"), h("span", {}, h("b", {}, n("ok")), " allowed"),
    h("span", {}, h("b", {}, n("hold")), " held"), h("span", {}, h("b", {}, n("bad")), " blocked"),
    lat.length ? h("span", {}, "decision time p50 ", h("b", {}, ms(pct(0.5))), " · p95 ", h("b", {}, ms(pct(0.95)))) : null);
}

function renderFilters() {
  const el = $("filters");
  el.replaceChildren(...FILTERS[state.view].map(([k, label]) => h("button", { type: "button", "aria-pressed": state.filter === k ? "true" : "false",
    onclick: () => { state.filter = k; renderFilters(); renderList(); } }, label)));
}

function renderList(fresh = new Set()) {
  const tbody = $("rows"), head = $("head-row");
  const q = state.q.trim().toLowerCase();
  tbody.replaceChildren();
  if (state.view === "ledger") {
    head.replaceChildren(h("th", { class: "c-time" }, "Time"), h("th", { class: "c-type" }, "Event"), h("th", {}, "Subject"), h("th", { class: "c-cus" }, "Actor"), h("th", { class: "c-seq seq" }, "Record"));
    const rows = state.records.slice().reverse().filter((r) => GROUPS[state.filter](r.type))
      .filter((r) => !q || JSON.stringify([r.type, r.headline, r.actor?.principal, r.mandate_id, r.decision_id, r.user_id, r.seq]).toLowerCase().includes(q));
    for (const r of rows.slice(0, 400)) {
      const key = `seq:${r.seq}`;
      tbody.append(h("tr", { class: "row" + (fresh.has(r.seq) ? " fresh" : ""), tabindex: 0, "aria-selected": state.selected === key ? "true" : "false",
        onclick: () => select(key), onkeydown: (e) => { if (e.key === "Enter") select(key); } },
        h("td", { class: "when num" }, when(r.ts_ms)),
        h("td", {}, h("div", { class: "line1" }, TYPE[r.type] || r.type)),
        h("td", {}, h("div", { class: "line1" }, r.headline || ""), h("div", { class: "line2 mono" }, r.decision_id || r.for_decision_id || r.mandate_id || r.user_id || "")),
        h("td", { class: "cus" }, h("div", { class: "line1 mono" }, sa(r.actor?.principal))),
        h("td", { class: "seq mono" }, `#${r.seq}`)));
    }
    $("empty").hidden = rows.length > 0;
    return;
  }
  head.replaceChildren(h("th", { class: "c-time" }, "Time"), h("th", { class: "c-out" }, "Outcome"), h("th", { class: "c-cus" }, "Customer"),
    h("th", {}, "Purchase"), h("th", { class: "c-amt amt" }, "Amount"));
  const rows = state.records.filter(isDecision).slice().reverse().filter((r) => {
    const o = outcomeOf(r);
    if (state.filter !== "all" && o.group !== state.filter) return false;
    return !q || [merchantOf(r).name, itemsOf(r), r.mandate_id, r.decision_id, r.user_id, r.agent_id, reasonTitle(r)].join(" ").toLowerCase().includes(q);
  });
  for (const r of rows.slice(0, 400)) {
    const o = outcomeOf(r);
    tbody.append(h("tr", { class: "row" + (fresh.has(r.seq) ? " fresh" : ""), tabindex: 0, "aria-selected": state.selected === r.decision_id ? "true" : "false",
      onclick: () => select(r.decision_id), onkeydown: (e) => { if (e.key === "Enter") select(r.decision_id); } },
      h("td", { class: "when num" }, when(r.ts_ms)),
      h("td", { class: "out" }, h("div", { class: `line1 st ${o.cls}` }, o.short || o.label), h("div", { class: "line2" }, reasonTitle(r))),
      h("td", { class: "cus" }, h("div", { class: "line1 mono" }, r.user_id || "—")),
      h("td", {}, h("div", { class: "line1", style: "font-weight:500" }, merchantOf(r).name || "—"), h("div", { class: "line2" }, itemsOf(r))),
      h("td", { class: "amt num" }, r.attempted ? money(r.attempted.total_minor, r.attempted.currency) : "—")));
  }
  $("empty").hidden = rows.length > 0;
}

// ======================================================================== authorization chain
function chainRows(dec) {
  const x = related(dec), id = dec.identity || {}, at = dec.attempted || {}, ev = dec.evidence || [];
  const idFail = ev.filter((e) => e.id.startsWith("identity.") && !e.id.startsWith("identity.consent"));
  const planFail = ev.filter((e) => e.id.startsWith("plan.") || e.id === "fraud.plan_rewritten");
  const rows = [];
  const reg = x.reg, ins = reg?.instruction, ir = reg?.intent_review;
  // customer
  if (x.consent) {
    rows.push({ step: "Customer", party: x.consent.user_id, proof: "Passkey signature over the mandate", t: x.consent.ts_ms, status: "proven",
      recs: [x.consent], passkey: x.consent, details: [["Method", "WebAuthn passkey, user verification"], ["Credential", short(x.consent.human?.credential_id_sha256, 16)],
        ["Statement", `mandate ${x.consent.mandate_id} · registration record #${x.consent.registration_seq}`]] });
  } else if (x.declined) {
    rows.push({ step: "Customer", party: x.declined.user_id, proof: "Mandate declined", t: x.declined.ts_ms, status: "failed", recs: [x.declined], details: [] });
  } else {
    const m = reg?.consent?.method;
    rows.push({ step: "Customer", party: reg?.user_id || dec.user_id, proof: reg?.consent?.passkey_required ? "Awaiting passkey signature" : m && m !== "not recorded" ? `Consent attested by ${sa(reg.actor?.principal)}` : "No consent record",
      t: reg?.ts_ms, status: reg?.consent?.passkey_required ? "waiting" : m && m !== "not recorded" ? "attested" : "failed", recs: [reg],
      details: [["Method", m || "—"], ["Attested by", reg?.actor?.principal || "—"]] });
  }
  // request
  rows.push({ step: "Request", party: ins ? `${cap(ins.channel)} message ${ins.message_id}` : "Request text", t: ins?.received_at ? ins.received_at * 1000 : reg?.ts_ms,
    proof: ir ? `Fidelity check: ${ir.verdict === "NONE" ? "match" : ir.verdict.toLowerCase()}` : reg?.intent_commitment_verified ? "Hash committed in mandate" : "Not committed",
    status: !reg ? "failed" : ir ? (ir.verdict === "NONE" ? "proven" : "failed") : reg.intent_commitment_verified ? "attested" : "failed", recs: [reg],
    details: [["Commitment", reg?.conditions?.intent_sha256 ? short(reg.conditions.intent_sha256, 16) : "—"], ["Fidelity check", ir ? `${ir.model}: ${ir.verdict}${ir.findings?.length ? ` (${ir.findings[0]})` : ""}` : "—"],
      ["Message evidence", ins ? short(ins.sha256, 16) : "—"]], textSha: ins?.sha256 });
  // mandate
  const nConds = Object.keys(reg?.conditions || {}).filter((k) => k !== "v" && !k.startsWith("intent") && !k.startsWith("summary")).length;
  rows.push({ step: "Mandate", party: reg ? `Key ${short(reg.signer_thumbprint, 12)}` : "—", proof: reg ? `AP2 open mandates · ${nConds} signed conditions` : "Not registered",
    t: reg?.ts_ms, status: reg && id.signer_thumbprint === reg.signer_thumbprint ? "proven" : "failed", recs: [reg], mandateSig: reg,
    details: [["Mandate", dec.mandate_id], ["Registered by", reg?.actor?.principal || "—"], ["Signing key", reg?.signer_thumbprint || "—"],
      ["Delegated agent key", reg?.delegated_key_thumbprint || "—"], ["Valid until", dateTime(reg?.constraints?.expires_at)]] });
  // agent
  rows.push({ step: "Agent", party: dec.agent_id || sa(id.agent?.principal) || "Unregistered", proof: idFail.length ? idFail[0].title : `Delegated key ${short(id.delegated_key_thumbprint, 10)}`,
    t: dec.ts_ms, status: idFail.length ? "failed" : String(id.agent?.verified_by || "").startsWith("Google") ? "proven" : "attested", recs: [x.agentReg],
    details: [["Caller", id.agent?.principal || "—"], ["Identified by", id.agent?.verified_by || "—"], ["Registered by", x.agentReg?.actor?.principal || "—"],
      ...idFail.map((e) => ["Finding", e.detail])] });
  // plan
  const wp = dec.trace?.witnessed_plan;
  if (wp) {
    const extra = dec.trace?.items_not_in_plan || [];
    const broke = planFail.length || wp.matches_trace === false || extra.length;
    rows.push({ step: "Plan", party: dec.agent_id, proof: `${(wp.plan?.items || []).map((i) => `${i.qty}× ${i.sku}`).join(", ")} · ${broke ? "cart deviates" : "cart matches"}`,
      t: wp.committed_at * 1000, status: broke ? "failed" : "proven", recs: [x.plan],
      details: [["Plan", wp.plan_id], ["Payee", merchantName(wp.plan?.payee_id, dec)], ["Items outside plan", extra.join(", ") || "None"], ...planFail.map((e) => ["Finding", e.detail])] });
  } else {
    const traced = (dec.trace?.plan_seq ?? -1) >= 0;
    rows.push({ step: "Plan", party: dec.agent_id || "—", proof: traced ? "Reported in agent trace only" : "None", t: null, status: traced ? "attested" : "na", recs: [], details: [] });
  }
  // merchant
  rows.push({ step: "Merchant", party: at.merchant?.name || "—", proof: at.merchant_registered ? `Checkout signed · key ${id.merchant_kid}` : `Unregistered key ${id.merchant_kid}`,
    t: dec.ts_ms, status: at.merchant_registered ? "proven" : "failed", recs: [x.merchReg],
    checkoutSig: at.merchant_registered ? { sha: dec.envelope?.sha256, kid: id.merchant_kid } : null,
    details: [["Merchant", `${at.merchant?.name || "—"} · ${host(at.merchant?.website)}`], ["Key", `${id.merchant_kid} (${id.merchant_key_status || "unregistered"})`],
      ["Key registered by", x.merchReg?.actor?.principal || "—"]] });
  // policy
  const nOk = x.policy?.approvals_verified ?? 0, nAll = x.policy?.approvals_total ?? 0;
  const approvers = [...new Set((x.policy?.packs || []).map((p) => p.approval?.approved_by).filter(Boolean))].join(", ");
  rows.push({ step: "Policy", party: `${(dec.checks?.policy?.packs || []).length} packs`, proof: nAll && nOk === nAll ? `Approved by ${approvers}` : `Approvals ${nOk} of ${nAll}`,
    t: x.policy?.ts_ms, status: x.policy ? (nAll && nOk === nAll ? "proven" : "attested") : "failed", recs: [x.policy],
    approvals: nAll && nOk === nAll ? x.policy.packs.map((p) => p.approval) : null,
    details: (x.policy?.packs || []).map((p) => [`${p.name} v${p.version}`, `${p.approval?.verified ? `approved by ${p.approval.approved_by} on ${p.approval.approved_at}` : p.approval?.problem || "no approval"} · owner ${p.owner}`]) });
  // decision
  const prov = dec.provenance || {};
  rows.push({ step: "Decision", party: "MandateGuard", proof: `${dec.disposition || dec.verdict} · ${dec.signer_kid?.replace(/^kms:/, "")}`, t: dec.ts_ms, status: "proven", recs: [dec],
    details: [["Revision", prov.revision || "—"], ["Model", prov.model_version ? `${prov.model} · prompts ${prov.prompt_version}` : "Not used"], ["Policy hash", short(prov.packs_hash, 16)]] });
  // approval
  if (dec.verdict === "ESCALATE") {
    const ttl = state.meta?.limits?.approval_ttl_s ?? 300;
    const linkDetails = x.links.map((l) => [l.type === "approval.link_sent" ? "Link sent" : "Link issued", `${l.type === "approval.link_sent" ? l.channel : sa(l.to)} · ${when(l.ts_ms)}`]);
    if (!x.follow) {
      const expired = Date.now() > dec.ts_ms + ttl * 1000;
      rows.push({ step: "Approval", party: dec.user_id, proof: expired ? "No response; expired" : "Awaiting response", t: null, status: expired ? "na" : "waiting", recs: x.links, details: linkDetails });
    } else if (x.follow.verdict === "ALLOW_BY_HUMAN") {
      const pk = x.follow.human?.method === "passkey";
      rows.push({ step: "Approval", party: x.follow.user_id, proof: pk ? "Passkey signature over amount, payee and decision" : `Approved via ${x.follow.human?.method || x.follow.channel}`,
        t: x.follow.ts_ms, status: pk ? "proven" : "attested", recs: [...x.links, x.follow], passkey: pk ? x.follow : null,
        details: [...linkDetails, ["Statement", pk ? `${money(x.follow.human?.statement?.amount_minor, x.follow.human?.statement?.currency)} to ${x.follow.human?.statement?.payee_id}` : "—"]] });
    } else {
      rows.push({ step: "Approval", party: x.follow.user_id, proof: "Declined", t: x.follow.ts_ms, status: "na", recs: [...x.links, x.follow], details: linkDetails });
    }
  }
  if (!x.payer) return rows;
  rows.push({ step: "Token", party: "Credentials service", proof: x.release ? `Single-use · ${money(x.release.bound_to?.amount_minor, x.release.bound_to?.currency)}` : "Not issued",
    t: x.release?.ts_ms, status: x.release ? "proven" : "failed", recs: [x.release],
    details: [["Issuer", host(x.release?.actor?.principal)], ["Token hash", short(x.release?.token_sha256, 16)], ["Bound to", x.release ? `${x.release.bound_to?.payee_id} · checkout ${short(x.release.bound_to?.checkout_hash, 12)}` : "—"]] });
  const p = x.paid;
  rows.push({ step: "Payment", party: p ? "Processor" : "—", proof: p ? `${p.receipt?.payment_id} · ${p.reconciliation?.matches ? "reconciled" : "mismatch"}` : "Not reported",
    t: p?.ts_ms, status: p ? (p.reconciliation?.matches ? "proven" : "failed") : "waiting", recs: [p], receipt: p,
    details: p ? [["Receipt key", p.receipt_kid], ["PSP reference", p.receipt?.psp_confirmation_id || "—"], ["Mismatches", (p.reconciliation?.mismatches || []).map((m) => m.field).join(", ") || "None"]] : [] });
  if (p) {
    if (x.shipped) {
      const e = x.shipped.event || {};
      rows.push({ step: "Shipment", party: x.shipped.merchant?.name, proof: [e.carrier, e.estimated_delivery ? `ETA ${day(e.estimated_delivery)}` : null].filter(Boolean).join(" · ") || "Shipped",
        t: x.shipped.ts_ms, status: x.shipped.reconciliation?.matches ? "proven" : "failed", recs: [x.shipped], jws: { token: x.shipped.event_jwt, kid: x.shipped.kid },
        details: [["Tracking", e.tracking_ref || "—"], ["Signing key", x.shipped.kid], ["Exceptions", (x.shipped.reconciliation?.mismatches || []).map((m) => m.field).join(", ") || "None"]] });
    }
    if (x.delivered) {
      const e = x.delivered.event || {}, mm = x.delivered.reconciliation?.mismatches || [];
      rows.push({ step: "Delivery", party: x.delivered.merchant?.name, proof: `${day(String(e.delivered_at || "").slice(0, 10))} · ${mm.length ? "exceptions" : "as signed"}`,
        t: x.delivered.ts_ms, status: mm.length ? "failed" : "proven", recs: [x.delivered], jws: { token: x.delivered.event_jwt, kid: x.delivered.kid },
        details: [["Signing key", x.delivered.kid], ["Exceptions", mm.map((m) => m.field).join(", ") || "None"]] });
    } else if (!x.refund) {
      rows.push({ step: "Delivery", party: at.merchant?.name, proof: at.fulfillment?.promised_by ? `Promised ${day(at.fulfillment.promised_by)}` : "Not reported", t: null, status: "waiting", recs: [], details: [] });
    }
  }
  if (x.refund) rows.push({ step: "Refund", party: sa(x.refund.receipt?.requested_by), proof: money(x.refund.receipt?.amount_minor, x.refund.receipt?.currency),
    t: x.refund.ts_ms, status: "proven", recs: [x.refund], receipt: x.refund, details: [["Reason", x.refund.receipt?.reason || "—"]] });
  return rows;
}

async function keyFor(map, kid) {
  if (!map.has(kid)) await loadKeys();
  return map.get(kid) || null;
}

// Every signature behind one row, checked with its signer's published key. Returns {good, total, notes, kinds}.
async function verifyRow(row) {
  const out = { good: 0, total: 0, notes: [], kinds: new Set() };
  const count = (ok, kind, note) => { out.total++; out.kinds.add(kind); if (ok) out.good++; else out.notes.push(note); };
  for (const r of row.recs.filter(Boolean)) {
    const v = await verifyRecord(r, state.key);
    count(v.hashMatches && v.signatureValid, "MandateGuard", `record #${r.seq}`);
  }
  if (row.receipt) {
    const key = state.procKeys.get(row.receipt.receipt_kid);
    count(key ? await verifyStatement(row.receipt.receipt, row.receipt.receipt_signature, key) : false, "Processor", "processor receipt");
  }
  if (row.passkey) {
    const enr = enrolledKey(row.passkey.user_id, row.passkey.human?.credential_id_sha256);
    const v = enr ? await verifyPasskey(row.passkey.human, enr.public_jwk) : { challengeMatches: false, signatureValid: false };
    count(v.challengeMatches && v.signatureValid, "Customer passkey", "passkey");
  }
  if (row.mandateSig?.evidence?.sha256) {
    try {
      const body = await getJSON(`/v1/evidence/${row.mandateSig.evidence.sha256}`);
      const sameKey = (await jwkThumbprint(body.user_public_jwk)) === row.mandateSig.signer_thumbprint;
      for (const tok of [body.open_checkout_mandate, body.open_payment_mandate]) {
        count(sameKey && await verifyJws(String(tok).split("~")[0], body.user_public_jwk), "Mandate issuer", "mandate signature");
      }
    } catch { out.notes.push("mandate evidence unavailable"); }
  }
  if (row.checkoutSig?.sha) {
    try {
      const env = await getJSON(`/v1/evidence/${row.checkoutSig.sha}`);
      count(await verifyJws(env.ap2?.checkout_jwt, await keyFor(state.merchantKeys, row.checkoutSig.kid)), "Merchant", "checkout signature");
    } catch { out.notes.push("checkout evidence unavailable"); }
  }
  for (const a of row.approvals || []) {
    const jwk = await keyFor(state.approverKeys, a?.approved_by);
    count(jwk ? await verifyStatementJwk(a.statement, a.signature, jwk) : false, "Policy approver", `approval of ${a?.statement?.pack}`);
  }
  if (row.jws) count(await verifyJws(row.jws.token, await keyFor(state.merchantKeys, row.jws.kid)), "Merchant", "merchant event signature");
  return out;
}

function authorizationTab(dec) {
  const rows = chainRows(dec);
  const res = state.verified.get(dec.decision_id);
  const line = h("div", { class: "vline num" });
  const btn = h("button", { class: "btn sm", type: "button" }, "Verify signatures");
  const body = h("tbody");
  const draw = () => {
    body.replaceChildren();
    rows.forEach((row, i) => {
      const r = res?.rows?.[i];
      let st = row.status;
      if (st === "proven" && r) st = r.notes.length ? "failed" : "verified";
      const [label, cls] = STATUS[st];
      const key = `${dec.decision_id}:${i}`;
      const open = state.open.has(key);
      body.append(h("tr", { class: `click${open ? " open" : ""}${st === "failed" ? " failed" : ""}`, onclick: () => { open ? state.open.delete(key) : state.open.add(key); draw(); } },
        h("td", { class: "k" }, row.step), h("td", {}, row.party || "—"), h("td", {}, row.proof || "—"),
        h("td", { class: "t-time num faint", style: "white-space:nowrap" }, row.t ? when(row.t) : "—"), h("td", {}, h("span", { class: `pill ${cls}` }, label))));
      if (open) {
        const recs = row.recs.filter(Boolean).map((x) => `#${x.seq}`).join(" ") || "—";
        const notes = r?.notes?.length ? [["Verification", `Failed: ${r.notes.join(", ")}`]] : r ? [["Verification", `${r.good} of ${r.total} signatures valid`]] : [];
        body.append(h("tr", { class: "more" }, h("td", { colspan: 5 }, h("dl", { class: "kv" },
          [...row.details, ["Records", recs], ...notes].flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)])))));
      }
    });
  };
  const showResult = () => {
    if (!res) { line.replaceChildren(); return; }
    const parties = [...res.kinds];
    line.replaceChildren(h("span", { class: `pill ${res.good === res.total ? "ok" : "bad"}` }, `${res.good} of ${res.total} signatures valid`),
      h("span", { class: "faint" }, `  Verified locally · ${parties.length} signing parties: ${parties.join(", ")}`));
  };
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    line.replaceChildren(h("span", { class: "faint" }, "Verifying"));
    const out = { rows: [], good: 0, total: 0, kinds: new Set() };
    for (const row of rows) {
      const r = await verifyRow(row);
      out.rows.push(r); out.good += r.good; out.total += r.total; r.kinds.forEach((k) => out.kinds.add(k));
    }
    state.verified.set(dec.decision_id, out);
    btn.disabled = false;
    renderDetail();
  });
  draw(); showResult();
  return [h("div", { class: "block" }, h("h4", {}, "Authorization chain", btn),
    h("table", { class: "t chain-t" }, h("thead", {}, h("tr", {}, h("th", { style: "width:92px" }, "Step"), h("th", {}, "Party"), h("th", {}, "Proof"),
      h("th", { class: "c-time-col", style: "width:88px" }, "Time"), h("th", { style: "width:92px" }, "Status"))), body), line)];
}

// ======================================================================== summary
function kv(pairs) {
  return h("dl", { class: "kv" }, pairs.filter(Boolean).flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v ?? "—")]));
}

function summaryTab(dec) {
  const x = related(dec), o = outcomeOf(dec), prov = dec.provenance || {}, tm = prov.timings_ms || {}, s2 = dec.stage2 || {};
  const reasons = (dec.evidence || []).map((e) => h("li", {}, h("div", { class: `st ${e.outcome === "DENY" ? "bad" : "hold"}` }, e.title), h("div", { class: "muted" }, e.detail)));
  const model = s2.fast_path ? "Not required: all checks proven by code"
    : s2.ran ? `${s2.label || prov.model} · ${Object.keys(s2.checks || {}).length} checks · ${ms(s2.ms)}`
    : dec.verdict === "DENY" ? "Not required: blocked by policy" : "Not run";
  const pol = dec.checks?.policy || {};
  const settle = [];
  if (x.release) settle.push(["Token", `Issued ${when(x.release.ts_ms)} · ${money(x.release.bound_to?.amount_minor, x.release.bound_to?.currency)}`]);
  if (x.paid) settle.push(["Payment", `${x.paid.receipt?.payment_id} · ${x.paid.reconciliation?.matches ? "reconciled" : "mismatch"} · ${when(x.paid.ts_ms)}`]);
  if (x.shipped) settle.push(["Shipment", `${x.shipped.event?.carrier || "Shipped"} · ${x.shipped.event?.tracking_ref || ""} · ${when(x.shipped.ts_ms)}`]);
  if (x.delivered) settle.push(["Delivery", `${day(String(x.delivered.event?.delivered_at || "").slice(0, 10))} · ${(x.delivered.reconciliation?.mismatches || []).length ? "exceptions" : "as signed"}`]);
  if (x.refund) settle.push(["Refund", `${money(x.refund.receipt?.amount_minor, x.refund.receipt?.currency)} · ${when(x.refund.ts_ms)}`]);
  return [
    h("div", { class: "block" }, h("h4", {}, "Decision"), kv([
      ["Outcome", h("span", { class: `st ${o.cls}` }, o.label)],
      ["Disposition", dec.disposition || dec.verdict],
      ["Reasons", reasons.length ? h("ul", {}, reasons) : "Within mandate"],
      x.follow ? ["Customer response", `${x.follow.verdict === "ALLOW_BY_HUMAN" ? "Approved" : "Declined"} · ${x.follow.human?.method || x.follow.channel} · ${when(x.follow.ts_ms)}`] : null,
      ["Model review", model],
      ["Decision time", h("span", { class: "num" }, ms(dec.latency_ms), h("span", { class: "faint" }, `  identity ${ms(tm.identity_and_input)} · policy ${ms(tm.policy)} · model ${ms(tm.model_review)}`))],
      ["Policy", `${(pol.packs || []).map((p) => `${p.name} v${p.version}`).join(", ")} · ${pol.passed}/${pol.evaluated} rules clear`],
      ["Decided", `${dateTime(dec.ts_ms / 1000)} · record #${dec.seq}`],
    ])),
    h("div", { class: "block" }, h("h4", {}, "Parties"), kv([
      ["Customer", h("span", { class: "mono" }, dec.user_id)],
      ["Agent", h("span", {}, dec.agent_id || "—", h("span", { class: "faint" }, `  ${dec.identity?.agent?.principal || ""}`))],
      ["Merchant", h("span", {}, merchantOf(dec).name || "—", h("span", { class: "faint" }, `  ${host(merchantOf(dec).website)} · key ${dec.identity?.merchant_kid || "—"}`))],
      ["Mandate", h("span", { class: "mono" }, dec.mandate_id)],
    ])),
    settle.length ? h("div", { class: "block" }, h("h4", {}, "Settlement"), kv(settle)) : null,
  ];
}

// ======================================================================== mandate vs cart
function mandateTab(dec) {
  const au = dec.authorized, at = dec.attempted, x = related(dec);
  if (!au || !at) return [h("p", { class: "faint" }, "Not available for this record format.")];
  const ccy = at.currency || au.currency, c = au.conditions || {}, chk = dec.conditions?.checked || {};
  const d = x.delivered || x.shipped, ev = d?.event || {}, mm = new Map((d?.reconciliation?.mismatches || []).map((m) => [m.field, m]));
  const mark = (ok) => h("span", { class: ok ? "mark-ok" : "mark-bad" }, ok ? "✓ " : "✕ ");
  const cell = (ok, text) => h("td", { class: ok === false ? "diff" : "" }, ok === null || ok === undefined ? "" : mark(ok), text);
  const allowedSkus = new Set((au.items || []).map((i) => i.id));
  const extra = (at.items || []).filter((i) => !allowedSkus.has(i.sku));
  const inRange = at.total_minor >= au.min_minor && at.total_minor <= au.max_minor;
  const okMerchant = (au.merchants || []).some((m) => m.id === at.merchant?.id) && at.merchant_registered;
  const okPayee = (au.payee_ids || []).includes(at.payee?.id);
  const rows = [
    ["Merchant", (au.merchants || []).map((m) => m.name).join(", "), cell(okMerchant, `${at.merchant?.name || "—"}${at.merchant_registered ? "" : " (unregistered key)"}`), d ? h("td") : null],
    ["Items", (au.items || []).map((i) => `${i.quantity}× ${i.title || i.id}`).join(", "), cell(extra.length === 0, itemsOf(dec)),
      d ? cell(!mm.has("items"), (ev.items || []).map((i) => `${i.qty}× ${i.sku}`).join(", ")) : null],
    ["Amount", `${money(au.min_minor, ccy)} to ${money(au.max_minor, ccy)}`, cell(inRange, money(at.total_minor, ccy)), d ? h("td") : null],
    ["Payee", (au.merchants || []).filter((m) => (au.payee_ids || []).includes(m.id)).map((m) => m.name).join(", ") || (au.payee_ids || []).join(", "), cell(okPayee, at.payee?.name || at.payee?.id), d ? h("td") : null],
  ];
  if (c.ship_to_sha256) rows.push(["Ship to", "Registered address (salted hash)", cell(!!chk.ship_to_matches, chk.ship_to_stated ? (chk.ship_to_matches ? "Same address" : "Different address") : "Not stated"),
    d ? cell(!mm.has("ship_to"), mm.has("ship_to") ? "Different address" : "Same address") : null]);
  if (c.deliver_by) {
    const ok = !!chk.promised_by && chk.promised_by <= c.deliver_by;
    rows.push(["Delivery", `By ${day(c.deliver_by)}`, cell(ok, chk.promised_by ? `Promised ${day(chk.promised_by)}` : "No date"),
      d ? cell(!(mm.has("deliver_by") || mm.has("promised_by")), ev.delivered_at ? `Delivered ${day(ev.delivered_at.slice(0, 10))}` : `ETA ${day(ev.estimated_delivery || "")}`) : null]);
  }
  if (c.item_condition) {
    const bad = chk.bad_condition_items || [];
    rows.push(["Condition", `${cap(c.item_condition)} only`, cell(bad.length === 0, bad.length ? bad.map((b) => b.condition).join(", ") : cap(c.item_condition)),
      d ? cell(!mm.has("condition"), [...new Set((ev.items || []).map((i) => cap(String(i.condition || "unstated"))))].join(", ")) : null]);
  }
  if (c.min_seller_rating) rows.push(["Seller rating", `${Number(c.min_seller_rating).toFixed(1)} minimum`,
    cell(chk.seller_rating >= c.min_seller_rating, chk.seller_rating >= 0 ? `${Number(chk.seller_rating).toFixed(1)} (registry)` : "Not on file"), d ? h("td") : null]);
  rows.push(["Validity", `Until ${dateTime(au.expires_at)}`, cell(!au.expires_at || dec.ts_ms / 1000 <= au.expires_at, `Attempted ${dateTime(dec.ts_ms / 1000)}`), d ? h("td") : null]);
  const ins = x.reg?.instruction;
  const reqBlock = h("div", { class: "block" }, h("h4", {}, "Customer request"));
  if (ins?.sha256) {
    const q = h("blockquote", { class: "req" }, state.texts.get(ins.sha256) || "…", h("span", { class: "src" }, `${cap(ins.channel)} message ${ins.message_id} · ${dateTime(ins.received_at)}`));
    reqBlock.append(q);
    if (!state.texts.has(ins.sha256)) getJSON(`/v1/evidence/${ins.sha256}`).then((m) => { state.texts.set(ins.sha256, m.text || ""); q.firstChild.textContent = m.text || ""; }).catch(() => {});
  }
  reqBlock.append(h("blockquote", { class: "req" }, au.intent_text || "—", h("span", { class: "src" }, `Signed request · mandate ${dec.mandate_id}`)));
  return [reqBlock, h("div", { class: "block" }, h("h4", {}, "Signed versus checkout" + (d ? " versus delivery" : "")),
    h("table", { class: "t" }, h("thead", {}, h("tr", {}, h("th", { style: "width:110px" }, "Term"), h("th", {}, "Signed by customer"), h("th", {}, `Checkout · ${at.merchant?.name || ""}`),
      d ? h("th", {}, `Reported · record #${d.seq}`) : null)),
      h("tbody", {}, rows.map(([k, signed, chkCell, dCell]) => h("tr", {}, h("td", { class: "k" }, k), h("td", {}, signed), chkCell, dCell)))))];
}

// ======================================================================== evidence
function evidenceTab(dec) {
  const s2 = dec.stage2 || {}, ev = dec.evidence || [], pages = dec.checks?.pages || [], t = dec.trace || {};
  const out = [];
  out.push(h("div", { class: "block" }, h("h4", {}, "Findings"), ev.length ? h("table", { class: "t" },
    h("thead", {}, h("tr", {}, h("th", { style: "width:80px" }, "Result"), h("th", {}, "Finding"), h("th", { style: "width:160px" }, "Source"))),
    h("tbody", {}, ev.map((e) => h("tr", {}, h("td", {}, h("span", { class: `pill ${e.outcome === "DENY" ? "bad" : "hold"}` }, e.outcome === "DENY" ? "Block" : "Hold")),
      h("td", {}, h("div", { style: "font-weight:500" }, e.title), h("div", { class: "muted" }, e.detail),
        (e.data?.excerpts || []).map((q) => h("div", { class: "quote" }, h("span", { class: "where" }, `${q.where}${q.url ? " · " + q.url : ""}`), q.text))),
      h("td", { class: "faint" }, e.source || "")))))
    : h("p", { class: "faint", style: "margin:0" }, "None")));
  if (pages.length) out.push(h("div", { class: "block" }, h("h4", {}, "Pages"), h("table", { class: "t" },
    h("thead", {}, h("tr", {}, h("th", {}, "URL"), h("th", { style: "width:180px" }, "MandateGuard copy"), h("th", { style: "width:120px" }, "Result"))),
    h("tbody", {}, pages.map((p) => h("tr", {}, h("td", { class: "mono" }, p.url),
      h("td", {}, p.fetched_evidence_sha256 ? h("a", { href: `/v1/evidence/${p.fetched_evidence_sha256}`, target: "_blank", rel: "noopener", class: "mono" }, short(p.fetched_evidence_sha256, 12)) : h("span", { class: "faint" }, p.reason || "—")),
      h("td", {}, p.fetched ? h("span", { class: `pill ${p.matches ? "ok" : "bad"}` }, p.matches ? "Identical" : "Differs") : h("span", { class: "pill plain" }, "Not fetched"))))))));
  const checks = Object.entries(s2.checks || {});
  out.push(h("div", { class: "block" }, h("h4", {}, "Model review"), s2.fast_path
    ? kv([["Status", "Not required"], ["Proven by code", h("ul", {}, (s2.proven || []).map((p) => h("li", {}, p)))]])
    : checks.length ? h("table", { class: "t" }, h("thead", {}, h("tr", {}, h("th", {}, "Check"), h("th", {}, "Result"), h("th", { class: "amt" }, "Time"), h("th", { class: "amt" }, "Tokens"))),
      h("tbody", {}, checks.map(([n, c]) => h("tr", {}, h("td", {}, CHECK[n] || n, (c.attempts || 1) > 1 ? h("span", { class: "faint" }, "  hedged") : null),
        h("td", {}, c.verdict === "NONE" ? h("span", { class: "pill ok" }, "Clear") : h("span", { class: `pill ${c.verdict === "DENY" ? "bad" : "hold"}` }, c.verdict === "DENY" ? "Block" : "Hold"),
          c.verdict !== "NONE" && c.findings?.[0] ? h("div", { class: "muted", style: "margin-top:2px" }, c.findings[0]) : null),
        h("td", { class: "amt num" }, ms(c.ms)), h("td", { class: "amt num" }, c.tokens ? c.tokens.toLocaleString() : "—")))),
      (Object.keys(s2.skipped || {}).length || (s2.stopped_after_block || []).length) ? h("tfoot", {}, h("tr", {}, h("td", { colspan: 4, class: "faint" },
        [Object.keys(s2.skipped || {}).length ? `Not asked, proven by code: ${Object.keys(s2.skipped).map((n) => CHECK[n] || n).join(", ")}` : null,
         (s2.stopped_after_block || []).length ? `Not awaited after a block: ${s2.stopped_after_block.map((n) => CHECK[n] || n).join(", ")}` : null].filter(Boolean).join(" · ")))) : null)
    : h("p", { class: "faint", style: "margin:0" }, dec.verdict === "DENY" ? "Not required: blocked by policy" : "Not run")));
  if (t.steps?.length) {
    const wp = t.witnessed_plan;
    out.push(h("div", { class: "block" }, h("h4", {}, "Agent trace"), h("table", { class: "t" },
      h("thead", {}, h("tr", {}, h("th", { style: "width:44px" }, "Step"), h("th", { style: "width:150px" }, "Action"), h("th", {}, "Detail"))),
      h("tbody", {}, [
        wp ? h("tr", {}, h("td", { class: "faint" }, "—"), h("td", {}, "Plan committed"),
          h("td", {}, `${(wp.plan?.items || []).map((i) => `${i.qty}× ${i.sku}`).join(", ")} · payee ${merchantName(wp.plan?.payee_id, dec)}`, h("span", { class: "faint" }, `  record #${wp.record_seq}`))) : null,
        ...t.steps.map((s) => h("tr", { class: s.seq === t.first_unplanned_seq ? "failed" : "" }, h("td", { class: "num faint" }, s.seq),
          h("td", {}, s.kind === "plan" ? "Plan (reported)" : s.kind === "page_read" ? "Page read" : s.kind === "tool_call" ? h("span", { class: "mono" }, s.tool) : s.kind),
          h("td", {}, s.summary || "", s.url ? h("div", { class: "faint mono" }, s.url) : null,
            s.seq === t.first_unplanned_seq ? h("div", { class: "mark-bad" }, `Outside plan: ${(t.items_not_in_plan || []).join(", ")}`) : null))),
      ]))));
  }
  return out;
}

// ======================================================================== record
function recordTab(r) {
  const prev = state.bySeq.get(r.seq - 1);
  const out = h("div", { class: "vline" });
  const btn = h("button", { class: "btn sm", type: "button", onclick: async () => {
    const v = await verifyRecord(r, state.key);
    const link = r.seq === 0 ? r.prev_hash === GENESIS : prev ? prev.hash === r.prev_hash : null;
    out.replaceChildren(h("span", { class: `pill ${v.hashMatches && v.signatureValid && link !== false ? "ok" : "bad"}` },
      v.hashMatches && v.signatureValid ? "Signature valid" : "Signature invalid"),
      h("span", { class: "faint" }, `  hash ${v.hashMatches ? "matches" : "differs"} · ${link === null ? "previous record not loaded" : link ? `linked to #${r.seq - 1}` : "chain link broken"}`));
  } }, "Verify record");
  const re = isDecision(r) ? h("button", { class: "btn sm", type: "button", onclick: async () => {
    rep.replaceChildren(h("span", { class: "faint" }, "Re-verifying from stored evidence"));
    try {
      const x = await getJSON(`/v1/decisions/${r.decision_id}/reverify`);
      rep.replaceChildren(h("table", { class: "t" }, h("tbody", {}, x.checks.map((c) => h("tr", {}, h("td", {}, c.label, c.detail ? h("div", { class: "faint" }, c.detail) : null),
        h("td", { style: "width:90px" }, h("span", { class: `pill ${c.ok ? "ok" : "bad"}` }, c.ok ? "Pass" : "Fail")))))));
    } catch (e) { rep.replaceChildren(h("span", { class: "pill bad" }, e.message)); }
  } }, "Re-verify from evidence") : null;
  const rep = h("div", { class: "block" });
  const dl = h("button", { class: "btn sm", type: "button", onclick: () => download(`record-${r.seq}.json`, r) }, "Download JSON");
  return [h("div", { class: "block" }, h("h4", {}, "Signed record"), kv([
      ["Record", `#${r.seq} · ${new Date(r.ts_ms).toISOString().replace("T", " ").slice(0, 19)} UTC`],
      ["Type", TYPE[r.type] || r.type], ["Actor", `${r.actor?.principal || "—"} · ${r.actor?.role || ""}`], ["Identified by", r.actor?.verified_by || "—"],
      ["Service", `${r.by_service?.service || "—"} · ${r.by_service?.revision || "—"}`],
      ["Hash", h("span", { class: "mono" }, r.hash)], ["Previous", h("span", { class: "mono" }, r.prev_hash)], ["Signed by", h("span", { class: "mono" }, r.signer_kid || "unsigned")],
      r.envelope?.sha256 ? ["Request evidence", h("a", { href: `/v1/evidence/${r.envelope.sha256}`, target: "_blank", rel: "noopener", class: "mono" }, short(r.envelope.sha256, 16))] : null,
    ]), h("div", { style: "display:flex;gap:8px;flex-wrap:wrap;margin-top:12px" }, btn, re, dl), out), rep];
}

function download(name, obj) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" }));
  const a = h("a", { href: url, download: name });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

async function exportEvidence(dec, btn) {
  btn.disabled = true;
  try {
    const recs = new Map();
    const add = (r) => r && recs.set(r.seq, r);
    const x = related(dec);
    [dec, x.reg, x.consent, x.declined, x.agentReg, x.merchReg, x.policy, x.plan, x.follow, x.release, x.paid, x.refund, x.shipped, x.delivered, ...x.links,
      ...(state.attempts.get(dec.decision_id) || [])].forEach(add);
    if (x.consent) add(enrolledKey(x.consent.user_id, x.consent.human?.credential_id_sha256));
    if (x.follow?.human) add(enrolledKey(x.follow.user_id, x.follow.human.credential_id_sha256));
    const evidence = {};
    for (const sha of [dec.envelope?.sha256, x.reg?.evidence?.sha256, x.reg?.instruction?.sha256].filter(Boolean)) {
      try { evidence[sha] = await getJSON(`/v1/evidence/${sha}`); } catch { /* evidence may be private */ }
    }
    download(`mandateguard-evidence-${dec.decision_id}.json`, { format: "mandateguard.evidence.v1", exported_at: new Date().toISOString(),
      decision_id: dec.decision_id, records: [...recs.values()].sort((a, b) => a.seq - b.seq), evidence, keys: await getJSON("/v1/audit/keys"),
      verification: "Each record: sha256 over RFC 8785 JSON without hash, signature and signer_kid; ECDSA P-256 signature with keys.mandateguard." });
  } finally { btn.disabled = false; }
}

// ======================================================================== detail frame
const TABS = [["summary", "Summary"], ["authorization", "Authorization"], ["mandate", "Mandate vs. cart"], ["evidence", "Evidence"], ["record", "Record"]];

function renderDecision(dec) {
  const o = outcomeOf(dec), at = dec.attempted;
  const link = h("button", { class: "btn sm", type: "button", onclick: (e) => copy(`${location.origin}/console#${dec.decision_id}`, e.currentTarget) }, "Copy link");
  const exp = h("button", { class: "btn sm", type: "button" }, "Export evidence");
  exp.addEventListener("click", () => exportEvidence(dec, exp));
  const tabs = h("div", { class: "tabs", role: "tablist" }, TABS.map(([k, label]) => h("button", { type: "button", role: "tab", "aria-selected": state.tab === k ? "true" : "false",
    onclick: () => { state.tab = k; renderDetail(); } }, label)));
  const body = { summary: summaryTab, authorization: authorizationTab, mandate: mandateTab, evidence: evidenceTab, record: recordTab }[state.tab](dec);
  return [h("div", { class: "dhead" }, h("span", { class: `pill ${o.cls}` }, o.label), h("span", { class: "amount num" }, at ? money(at.total_minor, at.currency) : "—"),
      h("span", { class: "what" }, `${merchantOf(dec).name || ""} · ${itemsOf(dec)}`)),
    h("div", { class: "dsub" }, h("span", { class: "mono" }, dec.decision_id), h("span", { class: "mono" }, dec.user_id), h("span", {}, dateTime(dec.ts_ms / 1000)),
      h("span", { class: "acts" }, link, exp)),
    tabs, ...body];
}

function renderEvent(r) {
  const body = { ...r };
  for (const k of ["seq", "prev_hash", "ts_ms", "hash", "signature", "signer_kid", "actor", "by_service", "headline", "type"]) delete body[k];
  const dec = r.decision_id || r.for_decision_id || r.original_decision_id;
  return [h("div", { class: "dhead" }, h("span", { class: "pill plain" }, TYPE[r.type] || r.type), h("span", { class: "what" }, r.headline || "")),
    h("div", { class: "dsub" }, h("span", { class: "mono" }, `#${r.seq}`), h("span", {}, dateTime(r.ts_ms / 1000)),
      dec && state.records.some((x) => isDecision(x) && x.decision_id === dec) ? h("span", { class: "acts" }, h("button", { class: "btn sm", type: "button", onclick: () => { state.view = "decisions"; state.filter = "all"; syncView(); select(dec); } }, "Open decision")) : null),
    ...recordTab(r), h("div", { class: "block" }, h("h4", {}, "Content"), h("pre", { class: "quote" }, JSON.stringify(body, null, 2)))];
}

function renderDetail() {
  const d = $("detail");
  let r = null;
  if (state.selected?.startsWith("seq:")) r = state.bySeq.get(Number(state.selected.slice(4)));
  else r = state.records.find((x) => x.decision_id === state.selected && isDecision(x));
  if (!r) { d.replaceChildren(window.matchMedia("(max-width: 1000px)").matches ? "" : h("div", { class: "empty" }, h("h2", {}, "No record selected"))); return; }
  d.replaceChildren(...(isDecision(r) ? renderDecision(r) : renderEvent(r)).filter(Boolean));
}

function select(id, { scroll = true } = {}) {
  state.selected = id;
  const tag = id.replace(":", "-");
  if (location.hash !== "#" + tag) history.replaceState(null, "", "#" + tag);
  renderList();
  renderDetail();
  if (scroll && window.matchMedia("(max-width: 1000px)").matches) $("detail").scrollIntoView({ behavior: "smooth", block: "start" });
}

function syncView() {
  document.querySelectorAll(".views button").forEach((b) => (b.dataset.view === state.view ? b.setAttribute("aria-current", "page") : b.removeAttribute("aria-current")));
  renderFilters(); renderStats(); renderList();
}

// ======================================================================== ledger status and keys
async function loadKeys() {
  const keys = await getJSON("/v1/audit/keys");
  state.keyInfo = keys.mandateguard;
  state.key = await importPublicKey(keys.mandateguard.pem);
  for (const p of keys.processors || []) state.procKeys.set(p.kid, await importPublicKey(p.pem));
  for (const k of keys.merchants || []) state.merchantKeys.set(k.kid, k.public_jwk);
  for (const a of keys.approvers || []) state.approverKeys.set(a.approver_id, a.public_jwk);
  return keys;
}

async function checkChain() {
  const el = $("chain");
  if (!state.key) return;
  const res = await verifyChain(state.records, state.key);
  state.chain = res;
  el.className = "";
  el.replaceChildren(res.ok ? h("span", { class: "st ok" }, "Ledger verified") : h("span", { class: "st bad" }, `Ledger broken at #${res.problems[0].seq}`),
    h("span", { class: "faint num" }, res.ok ? `  ${res.count.toLocaleString()} records` : `  ${res.problems[0].problem}`));
}

async function poll() {
  try {
    const fresh = ingest(await getJSON(`/v1/audit/records?after=${state.lastSeq}`));
    $("live").className = "live"; $("live").textContent = "Live";
    if (fresh.length) {
      renderStats(); renderList(new Set(fresh.map((r) => r.seq)));
      const sel = state.selected;
      const touches = fresh.some((r) => [r.decision_id, r.for_decision_id, r.original_decision_id].includes(sel) || (sel && r.mandate_id && state.records.some((d) => d.decision_id === sel && d.mandate_id === r.mandate_id)));
      if (touches) renderDetail();
      await checkChain();
    }
  } catch { $("live").className = "live stale"; $("live").textContent = "Reconnecting"; }
}

function fromHash() {
  const tag = location.hash.slice(1).replace("seq-", "seq:");
  if (!tag) return;
  if (tag.startsWith("seq:")) { state.view = "ledger"; state.filter = "all"; syncView(); select(tag, { scroll: false }); }
  else if (state.records.some((r) => r.decision_id === tag)) { state.view = "decisions"; syncView(); select(tag, { scroll: false }); }
}

async function main() {
  document.querySelectorAll(".views button").forEach((b) => b.addEventListener("click", () => {
    state.view = b.dataset.view; state.filter = "all"; syncView();
  }));
  $("q").addEventListener("input", (e) => { state.q = e.target.value; renderList(); });
  $("verify").addEventListener("click", async (e) => {
    const b = e.currentTarget; b.disabled = true;
    await checkChain();
    try {
      const s = await getJSON("/v1/audit/verify");
      const a = s.anchoring || {};
      $("chain").append(h("span", { class: "faint" }, ` · server ${s.ok === state.chain?.ok ? "concurs" : "disagrees"} · ${a.checkpoints ?? 0} checkpoints${a.mismatched_seqs?.length ? `, ${a.mismatched_seqs.length} mismatched` : ""}`));
    } catch { /* the local result stands */ }
    b.disabled = false;
  });
  window.addEventListener("hashchange", fromHash);
  const [meta, , recs] = await Promise.all([getJSON("/v1/console/meta"), loadKeys(), getJSON("/v1/audit/records?limit=500")]);
  state.meta = meta;
  $("env").textContent = [meta.environment, meta.region].filter(Boolean).join(" · ");
  $("env").title = [meta.project, meta.model, meta.packs.map((p) => `${p.name} v${p.version}`).join(", ")].filter(Boolean).join(" · ");
  ingest(recs);
  syncView();
  if (location.hash) fromHash();
  else {
    const latest = [...state.records].reverse().find(isDecision);
    if (latest && window.matchMedia("(min-width: 1001px)").matches) select(latest.decision_id, { scroll: false });
  }
  await checkChain();
  setInterval(poll, 4000);
}

main().catch((e) => { $("chain").replaceChildren(h("span", { class: "st bad" }, "Unavailable"), h("span", { class: "faint" }, `  ${e.message}`)); });
