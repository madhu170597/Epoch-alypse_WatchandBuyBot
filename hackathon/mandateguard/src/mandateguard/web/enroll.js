import { h } from "./ui.js";
import { createPasskey, supported } from "./webauthn.js";

const id = location.pathname.split("/").filter(Boolean).pop();
const key = new URLSearchParams(location.hash.slice(1)).get("k") || "";
const app = document.getElementById("app");
const brand = () => h("div", { class: "who" }, "MandateGuard");

function done(cls, title, body) {
  app.replaceChildren(brand(), h("h1", {}, title), h("div", { class: `done ${cls}` }, body));
}

async function post(path, body) {
  const r = await fetch(`/v1/passkeys/enrollments/${encodeURIComponent(id)}${path}`, {
    method: "POST", headers: { "Content-Type": "application/json", "X-Enroll-Key": key }, body: body ? JSON.stringify(body) : undefined });
  const out = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(out.detail || `HTTP ${r.status}`);
  return out;
}

function render() {
  if (!id || !key) return done("bad", "Invalid link", "Use the link exactly as received.");
  const note = h("p", { class: "timer", role: "status" });
  const btn = h("button", { class: "btn primary", type: "button" }, "Create passkey");
  if (!supported()) { btn.disabled = true; note.textContent = "Passkeys are unavailable in this browser."; }
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    note.textContent = "Follow the device prompt.";
    try {
      const options = await post("/options");
      const credential = await createPasskey(options);
      const res = await post("/finish", { credential });
      done("ok", "Passkey registered", `Recorded as audit record #${res.record_seq}.`);
    } catch (e) {
      btn.disabled = false;
      note.textContent = e.name === "NotAllowedError" ? "Prompt dismissed. No passkey was created." : e.message;
    }
  });
  app.replaceChildren(brand(), h("h1", {}, "Register a passkey"),
    h("p", { class: "signed" }, "The passkey signs your purchase mandates and approvals. The private key remains on this device; MandateGuard stores only the public key."),
    h("div", { class: "actions" }, btn), note);
}

render();
