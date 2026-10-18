"""WebAuthn passkey registration and login.

Registration binds a passkey to an existing Firebase user (the caller must be
signed in with a valid ID token). Login is usernameless: a resident passkey
proves the user, and on success we mint a Firebase custom token the client
exchanges for an ID token.
"""

import json
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from app import firebase, store
from app.auth import require_user
from app.config import settings

router = APIRouter(prefix="/passkey", tags=["passkey"])

_REG = "registration"
_AUTH = "authentication"


class CredentialBody(BaseModel):
    credential: dict


class LoginVerifyBody(BaseModel):
    handle: str
    credential: dict


@router.post("/register/options")
def register_options(user: dict = Depends(require_user)) -> dict:
    uid = user["uid"]
    email = user.get("email")
    store.upsert_user(uid, email)
    exclude = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(cid))
        for cid in store.list_credential_ids(uid)
    ]
    options = generate_registration_options(
        rp_id=settings.rp_id,
        rp_name=settings.rp_name,
        user_id=uid.encode("utf-8"),
        user_name=email or uid,
        user_display_name=email or uid,
        exclude_credentials=exclude,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )
    store.put_challenge(
        uid, bytes_to_base64url(options.challenge), _REG, settings.challenge_ttl_seconds
    )
    return json.loads(options_to_json(options))


@router.post("/register/verify")
def register_verify(body: CredentialBody, user: dict = Depends(require_user)) -> dict:
    uid = user["uid"]
    challenge_b64 = store.take_challenge(uid, _REG)
    if not challenge_b64:
        raise HTTPException(status_code=400, detail="no_or_expired_challenge")
    try:
        verified = verify_registration_response(
            credential=json.dumps(body.credential),
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_rp_id=settings.rp_id,
            expected_origin=settings.expected_origin,
            require_user_verification=True,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"verification_failed: {e}") from e

    cred_id = bytes_to_base64url(verified.credential_id)
    transports = body.credential.get("response", {}).get("transports", []) or []
    store.save_credential(
        uid,
        cred_id,
        bytes_to_base64url(verified.credential_public_key),
        verified.sign_count,
        transports,
    )
    return {"status": "ok", "credential_id": cred_id}


@router.post("/login/options")
def login_options() -> dict:
    handle = uuid.uuid4().hex
    options = generate_authentication_options(
        rp_id=settings.rp_id,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    store.put_challenge(
        handle, bytes_to_base64url(options.challenge), _AUTH, settings.challenge_ttl_seconds
    )
    return {"handle": handle, "options": json.loads(options_to_json(options))}


@router.post("/login/verify")
def login_verify(body: LoginVerifyBody) -> dict:
    challenge_b64 = store.take_challenge(body.handle, _AUTH)
    if not challenge_b64:
        raise HTTPException(status_code=400, detail="no_or_expired_challenge")

    cred_id = body.credential.get("id")
    if not cred_id:
        raise HTTPException(status_code=400, detail="missing_credential_id")
    record = store.get_credential(cred_id)
    if not record:
        raise HTTPException(status_code=400, detail="unknown_credential")

    try:
        verified = verify_authentication_response(
            credential=json.dumps(body.credential),
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_rp_id=settings.rp_id,
            expected_origin=settings.expected_origin,
            credential_public_key=base64url_to_bytes(record["public_key_b64"]),
            credential_current_sign_count=record.get("sign_count", 0),
            require_user_verification=True,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"verification_failed: {e}") from e

    store.update_sign_count(record["uid"], cred_id, verified.new_sign_count)
    custom_token = firebase.create_custom_token(record["uid"])
    return {"custom_token": custom_token}
