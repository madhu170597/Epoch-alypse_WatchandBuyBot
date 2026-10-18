// WebAuthn in the browser, with the base64url JSON that py_webauthn speaks. No libraries.

export function b64uEncode(buf) {
  const bytes = new Uint8Array(buf instanceof ArrayBuffer ? buf : buf.buffer || buf);
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64uDecode(str) {
  let s = str.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

export const supported = () => typeof window !== "undefined" && !!window.PublicKeyCredential && !!navigator.credentials;

function creationOptions(o) {
  return { ...o, challenge: b64uDecode(o.challenge), user: { ...o.user, id: b64uDecode(o.user.id) },
    excludeCredentials: (o.excludeCredentials || []).map((c) => ({ ...c, id: b64uDecode(c.id) })) };
}

function requestOptions(o) {
  return { ...o, challenge: b64uDecode(o.challenge), allowCredentials: (o.allowCredentials || []).map((c) => ({ ...c, id: b64uDecode(c.id) })) };
}

export async function createPasskey(optionsJson) {
  const cred = await navigator.credentials.create({ publicKey: creationOptions(optionsJson) });
  return {
    id: cred.id, rawId: b64uEncode(cred.rawId), type: cred.type, authenticatorAttachment: cred.authenticatorAttachment || undefined,
    response: { clientDataJSON: b64uEncode(cred.response.clientDataJSON), attestationObject: b64uEncode(cred.response.attestationObject),
      transports: cred.response.getTransports ? cred.response.getTransports() : [] },
    clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
  };
}

export async function signWithPasskey(optionsJson) {
  const cred = await navigator.credentials.get({ publicKey: requestOptions(optionsJson) });
  const r = cred.response;
  const out = { id: cred.id, rawId: b64uEncode(cred.rawId), type: cred.type,
    response: { clientDataJSON: b64uEncode(r.clientDataJSON), authenticatorData: b64uEncode(r.authenticatorData), signature: b64uEncode(r.signature) },
    clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {} };
  if (r.userHandle) out.response.userHandle = b64uEncode(r.userHandle);
  return out;
}
