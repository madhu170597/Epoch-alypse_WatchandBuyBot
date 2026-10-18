// Independent verification of MandateGuard decision records, in the browser (or Node 20+).
// Recomputes each record's hash over RFC 8785 canonical JSON and checks its ECDSA P-256 signature
// with the published public key. Nothing here trusts the server's own "verified" answer.

const enc = new TextEncoder();
const EXCLUDED = new Set(["hash", "signature", "signer_kid"]);
export const GENESIS = "0".repeat(64);

// RFC 8785 (JCS). Number and string serialization in JCS are defined as ECMAScript's, so JSON.stringify is exact.
export function canonical(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort(); // UTF-16 code-unit order, as JCS requires
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
}

export function signedBody(rec) {
  const out = {};
  for (const k of Object.keys(rec)) if (!EXCLUDED.has(k)) out[k] = rec[k];
  return out;
}

export async function sha256hex(text) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(text)));
  return Array.from(d, (b) => b.toString(16).padStart(2, "0")).join("");
}

function b64urlBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

// Cloud KMS returns DER-encoded ECDSA signatures; WebCrypto wants raw r||s (IEEE P1363).
function derToRaw(der) {
  let i = 0;
  if (der[i++] !== 0x30) throw new Error("signature is not DER");
  if (der[i] & 0x80) i += 1 + (der[i] & 0x7f); else i += 1;
  const int = () => {
    if (der[i++] !== 0x02) throw new Error("bad DER integer");
    const len = der[i++];
    let v = der.slice(i, i + len);
    i += len;
    while (v.length > 32 && v[0] === 0) v = v.slice(1);
    const out = new Uint8Array(32);
    out.set(v, 32 - v.length);
    return out;
  };
  const raw = new Uint8Array(64);
  raw.set(int(), 0);
  raw.set(int(), 32);
  return raw;
}

export async function importPublicKey(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey("spki", der, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
}

export async function verifyRecord(rec, key) {
  const text = canonical(signedBody(rec));
  const computed = await sha256hex(text);
  let signatureValid = false;
  if (rec.signature && key) {
    try {
      signatureValid = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, derToRaw(b64urlBytes(rec.signature)), enc.encode(text));
    } catch { signatureValid = false; }
  }
  return { hashMatches: computed === rec.hash, signatureValid, computed };
}

// Verifies a contiguous window of records. If the window starts after record 0, its first link is reported as unchecked.
export async function verifyChain(records, key) {
  const recs = [...records].sort((a, b) => a.seq - b.seq);
  const problems = [];
  let prev = null;
  for (const r of recs) {
    const v = await verifyRecord(r, key);
    if (!v.hashMatches) problems.push({ seq: r.seq, problem: "content does not match its hash" });
    if (!v.signatureValid) problems.push({ seq: r.seq, problem: "signature does not verify" });
    if (prev) {
      if (r.seq !== prev.seq + 1) problems.push({ seq: r.seq, problem: `gap after #${prev.seq}` });
      if (r.prev_hash !== prev.hash) problems.push({ seq: r.seq, problem: "does not link to the previous record" });
    } else if (r.seq === 0 && r.prev_hash !== GENESIS) {
      problems.push({ seq: 0, problem: "first record does not start the chain" });
    }
    prev = r;
  }
  return { ok: problems.length === 0, count: recs.length, from: recs[0]?.seq ?? null, to: prev?.seq ?? null, head: prev?.hash ?? null, problems };
}

// ---- statements signed by other parties ------------------------------------------------------------------

// A processor receipt (or any statement) signed the way MandateGuard signs records: ECDSA P-256 over RFC 8785 JSON.
export async function verifyStatement(obj, signatureB64, key) {
  try {
    return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, derToRaw(b64urlBytes(signatureB64)), enc.encode(canonical(obj)));
  } catch { return false; }
}

export async function importJwk(jwk) {
  if (jwk.kty === "EC") return crypto.subtle.importKey("jwk", { kty: "EC", crv: jwk.crv, x: jwk.x, y: jwk.y }, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  if (jwk.kty === "RSA") return crypto.subtle.importKey("jwk", { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256" }, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  throw new Error("unsupported key type");
}

// The user's passkey signature over a purchase statement. WebAuthn signs authenticatorData || sha256(clientDataJSON),
// and clientDataJSON carries the challenge, which must be sha256 of the statement the record says the user approved.
export async function verifyPasskey(human, jwk) {
  const out = { challengeMatches: false, signatureValid: false };
  try {
    const client = b64urlBytes(human.assertion.client_data_json);
    const clientData = JSON.parse(new TextDecoder().decode(client));
    const expected = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(canonical(human.statement))));
    let s = ""; for (const b of expected) s += String.fromCharCode(b);
    out.challengeMatches = clientData.challenge === btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "") && clientData.type === "webauthn.get";
    const auth = b64urlBytes(human.assertion.authenticator_data);
    const clientHash = new Uint8Array(await crypto.subtle.digest("SHA-256", client));
    const data = new Uint8Array(auth.length + clientHash.length); data.set(auth, 0); data.set(clientHash, auth.length);
    const key = await importJwk(jwk);
    const sig = b64urlBytes(human.assertion.signature);
    out.signatureValid = jwk.kty === "EC"
      ? await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, derToRaw(sig), data)
      : await crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, key, sig, data);
  } catch { /* leave as false */ }
  return out;
}

// A compact JWS made with a JWK (ES256 or RS256): a merchant's checkout or delivery event, the web app's signature on a mandate.
export async function verifyJws(token, jwk) {
  try {
    const [h, p, sig] = String(token).split(".");
    if (!h || !p || !sig || !jwk) return false;
    const key = await importJwk(jwk);
    const data = enc.encode(`${h}.${p}`);
    return jwk.kty === "EC"
      ? await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, b64urlBytes(sig), data)
      : await crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, key, b64urlBytes(sig), data);
  } catch { return false; }
}

// RFC 7638 thumbprint, the form MandateGuard records for the key that signed a mandate.
export async function jwkThumbprint(jwk) {
  const members = jwk.kty === "EC" ? { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y } : { e: jwk.e, kty: jwk.kty, n: jwk.n };
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(canonical(members))));
  let s = ""; for (const b of d) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// A statement signed like a receipt (ECDSA P-256, DER, over RFC 8785 JSON), with the signer's JWK: policy approvals.
export async function verifyStatementJwk(obj, signatureB64, jwk) {
  try {
    return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, await importJwk(jwk), derToRaw(b64urlBytes(signatureB64)), enc.encode(canonical(obj)));
  } catch { return false; }
}
