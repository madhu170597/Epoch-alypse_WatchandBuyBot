// Calls to the identity service: WebAuthn passkey ceremonies and Telegram linking.
import {startAuthentication, startRegistration} from '@simplewebauthn/browser';

import {auth} from '../firebase';
import {IDENTITY_URL} from '../config';

const base = IDENTITY_URL.replace(/\/$/, '');

async function authHeader(): Promise<Record<string, string>> {
  const user = auth!.currentUser;
  if (!user) throw new Error('not signed in');
  const token = await user.getIdToken();
  return {Authorization: `Bearer ${token}`};
}

/** Register a new passkey against the signed-in Firebase user. */
export async function registerPasskey(): Promise<void> {
  const headers = await authHeader();
  const optRes = await fetch(`${base}/passkey/register/options`, {
    method: 'POST',
    headers,
  });
  if (!optRes.ok) throw new Error(`register options failed: ${optRes.status}`);
  const optionsJSON = await optRes.json();
  const attResp = await startRegistration({optionsJSON});
  const verRes = await fetch(`${base}/passkey/register/verify`, {
    method: 'POST',
    headers: {...headers, 'Content-Type': 'application/json'},
    body: JSON.stringify({credential: attResp}),
  });
  if (!verRes.ok) throw new Error(`register verify failed: ${await verRes.text()}`);
}

/** Usernameless passkey login. Returns a Firebase custom token. */
export async function passkeyLogin(): Promise<string> {
  const optRes = await fetch(`${base}/passkey/login/options`, {method: 'POST'});
  if (!optRes.ok) throw new Error(`login options failed: ${optRes.status}`);
  const {handle, options} = await optRes.json();
  const authResp = await startAuthentication({optionsJSON: options});
  const verRes = await fetch(`${base}/passkey/login/verify`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({handle, credential: authResp}),
  });
  if (!verRes.ok) throw new Error(`login verify failed: ${await verRes.text()}`);
  const {custom_token} = await verRes.json();
  return custom_token as string;
}

/** Issue a one-time code to link a Telegram account. */
export async function startTelegramLink(): Promise<{code: string; expires_in: number}> {
  const headers = await authHeader();
  const res = await fetch(`${base}/telegram/link/start`, {method: 'POST', headers});
  if (!res.ok) throw new Error(`telegram link failed: ${res.status}`);
  return res.json();
}

// ── Wallet: dummy cards + addresses (demo only; PAN never leaves the browser) ──
export interface Card {
  id: string;
  brand: string;
  last4: string;
  exp_month: number;
  exp_year: number;
  holder: string;
}
export interface Address {
  id: string;
  name: string;
  line1: string;
  line2?: string;
  city: string;
  region?: string;
  postal?: string;
  country: string;
}

async function jsonHeaders(): Promise<Record<string, string>> {
  return {...(await authHeader()), 'Content-Type': 'application/json'};
}

export async function listCards(): Promise<Card[]> {
  const res = await fetch(`${base}/wallet/cards`, {headers: await authHeader()});
  if (!res.ok) throw new Error(`list cards failed: ${res.status}`);
  return (await res.json()).cards ?? [];
}

export async function addCard(body: {
  number: string;
  exp_month: number;
  exp_year: number;
  holder: string;
}): Promise<void> {
  const res = await fetch(`${base}/wallet/cards`, {
    method: 'POST',
    headers: await jsonHeaders(),
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`add card failed: ${await res.text()}`);
}

export async function deleteCard(id: string): Promise<void> {
  const res = await fetch(`${base}/wallet/cards/${id}`, {
    method: 'DELETE',
    headers: await authHeader(),
  });
  if (!res.ok) throw new Error(`delete card failed: ${res.status}`);
}

export async function listAddresses(): Promise<Address[]> {
  const res = await fetch(`${base}/wallet/addresses`, {headers: await authHeader()});
  if (!res.ok) throw new Error(`list addresses failed: ${res.status}`);
  return (await res.json()).addresses ?? [];
}

export async function addAddress(body: Omit<Address, 'id'>): Promise<void> {
  const res = await fetch(`${base}/wallet/addresses`, {
    method: 'POST',
    headers: await jsonHeaders(),
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`add address failed: ${await res.text()}`);
}

export async function deleteAddress(id: string): Promise<void> {
  const res = await fetch(`${base}/wallet/addresses/${id}`, {
    method: 'DELETE',
    headers: await authHeader(),
  });
  if (!res.ok) throw new Error(`delete address failed: ${res.status}`);
}
