"""Firestore accessors.

Collections:
  users/{uid}                         -> {email, telegram_chat_id}
  users/{uid}/passkeys/{cred_id}      -> {public_key_b64, sign_count, transports}
  users/{uid}/cards/{card_id}         -> {brand, last4, exp_month, exp_year, holder, instrument_id, default}
  users/{uid}/addresses/{addr_id}     -> {name, line1, line2, city, region, postal, country, default}
  passkey_index/{cred_id}             -> {uid}            (reverse lookup for login)
  telegram_index/{chat_id}            -> {uid}            (reverse lookup for the bot)
  webauthn_challenges/{handle}        -> {challenge_b64, kind, expires_at}
  link_codes/{code}                   -> {uid, expires_at}
"""

import time

from app import firebase


def _now() -> int:
    return int(time.time())


# ── users ────────────────────────────────────────────────────────────────

def upsert_user(uid: str, email: str | None) -> None:
    doc = firebase.get_db().collection("users").document(uid)
    data = {"email": email} if email else {}
    doc.set(data, merge=True)


def set_telegram_chat_id(uid: str, telegram_chat_id: str) -> None:
    db = firebase.get_db()
    db.collection("users").document(uid).set(
        {"telegram_chat_id": telegram_chat_id}, merge=True
    )
    db.collection("telegram_index").document(str(telegram_chat_id)).set({"uid": uid})


def uid_by_chat(telegram_chat_id: str) -> str | None:
    """Reverse lookup: linked Firebase uid for a Telegram chat, or None."""
    snap = (
        firebase.get_db()
        .collection("telegram_index")
        .document(str(telegram_chat_id))
        .get()
    )
    return snap.to_dict().get("uid") if snap.exists else None


# ── wallet: dummy cards + addresses (demo only, never a real PAN) ───────────

def add_card(uid: str, card: dict) -> None:
    db = firebase.get_db()
    col = db.collection("users").document(uid).collection("cards")
    card["default"] = not any(True for _ in col.limit(1).stream())
    col.document(card["instrument_id"]).set(card)


def list_cards(uid: str) -> list[dict]:
    col = firebase.get_db().collection("users").document(uid).collection("cards")
    return [{"id": d.id, **d.to_dict()} for d in col.stream()]


def delete_card(uid: str, card_id: str) -> None:
    firebase.get_db().collection("users").document(uid).collection("cards").document(
        card_id
    ).delete()


def add_address(uid: str, addr: dict) -> str:
    db = firebase.get_db()
    col = db.collection("users").document(uid).collection("addresses")
    addr["default"] = not any(True for _ in col.limit(1).stream())
    ref = col.document()
    ref.set(addr)
    return ref.id


def list_addresses(uid: str) -> list[dict]:
    col = firebase.get_db().collection("users").document(uid).collection("addresses")
    return [{"id": d.id, **d.to_dict()} for d in col.stream()]


def delete_address(uid: str, addr_id: str) -> None:
    firebase.get_db().collection("users").document(uid).collection(
        "addresses"
    ).document(addr_id).delete()


# ── webauthn challenges ──────────────────────────────────────────────────

def put_challenge(handle: str, challenge_b64: str, kind: str, ttl: int) -> None:
    firebase.get_db().collection("webauthn_challenges").document(handle).set(
        {"challenge_b64": challenge_b64, "kind": kind, "expires_at": _now() + ttl}
    )


def take_challenge(handle: str, kind: str) -> str | None:
    """Return and delete a non-expired challenge of the given kind."""
    ref = firebase.get_db().collection("webauthn_challenges").document(handle)
    snap = ref.get()
    if not snap.exists:
        return None
    data = snap.to_dict()
    ref.delete()
    if data.get("kind") != kind or data.get("expires_at", 0) < _now():
        return None
    return data.get("challenge_b64")


# ── passkey credentials ──────────────────────────────────────────────────

def save_credential(
    uid: str, cred_id: str, public_key_b64: str, sign_count: int, transports: list[str]
) -> None:
    db = firebase.get_db()
    db.collection("users").document(uid).collection("passkeys").document(cred_id).set(
        {
            "public_key_b64": public_key_b64,
            "sign_count": sign_count,
            "transports": transports,
        }
    )
    db.collection("passkey_index").document(cred_id).set({"uid": uid})


def list_credential_ids(uid: str) -> list[str]:
    col = firebase.get_db().collection("users").document(uid).collection("passkeys")
    return [d.id for d in col.stream()]


def get_credential(cred_id: str) -> dict | None:
    """Resolve a credential id to {uid, public_key_b64, sign_count, transports}."""
    db = firebase.get_db()
    idx = db.collection("passkey_index").document(cred_id).get()
    if not idx.exists:
        return None
    uid = idx.to_dict().get("uid")
    snap = (
        db.collection("users").document(uid).collection("passkeys").document(cred_id).get()
    )
    if not snap.exists:
        return None
    return {"uid": uid, **snap.to_dict()}


def update_sign_count(uid: str, cred_id: str, sign_count: int) -> None:
    firebase.get_db().collection("users").document(uid).collection("passkeys").document(
        cred_id
    ).set({"sign_count": sign_count}, merge=True)


# ── telegram link codes ──────────────────────────────────────────────────

def put_link_code(code: str, uid: str, ttl: int) -> None:
    firebase.get_db().collection("link_codes").document(code).set(
        {"uid": uid, "expires_at": _now() + ttl}
    )


def take_link_code(code: str) -> str | None:
    """Return and delete the uid for a non-expired code."""
    ref = firebase.get_db().collection("link_codes").document(code)
    snap = ref.get()
    if not snap.exists:
        return None
    data = snap.to_dict()
    ref.delete()
    if data.get("expires_at", 0) < _now():
        return None
    return data.get("uid")
