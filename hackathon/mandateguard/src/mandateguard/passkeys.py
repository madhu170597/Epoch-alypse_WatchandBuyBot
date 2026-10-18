"""Passkeys for step-up approval (WebAuthn, via py_webauthn).

Enrollment: the user's trusted surface (the web app, after login) asks MandateGuard for a one-time
enrollment link; the user opens it and creates a passkey for MandateGuard's origin. The public key is
kept and published in a chained `user.passkey_enrolled` record.

Approval: the challenge is the sha256 of a statement naming the exact purchase (decision record hash,
merchant, payee, amount, checkout hash). The resulting assertion is the user's own signature over that
statement; it is stored in the approval record and anyone can verify it with the enrolled public key.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import time
from typing import Any
from urllib.parse import urlparse

from webauthn import generate_authentication_options, generate_registration_options, options_to_json, verify_authentication_response, verify_registration_response
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url, decode_credential_public_key
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor, ResidentKeyRequirement,
                                      UserVerificationRequirement)

ENROLLMENT_TTL_S = 15 * 60


class PasskeyError(Exception):
    pass


def cose_to_jwk(cose: bytes) -> dict[str, Any]:
    key = decode_credential_public_key(cose)
    if hasattr(key, "x") and hasattr(key, "y"):
        return {"kty": "EC", "crv": "P-256", "x": bytes_to_base64url(key.x), "y": bytes_to_base64url(key.y), "alg": "ES256"}
    if hasattr(key, "n") and hasattr(key, "e"):
        return {"kty": "RSA", "n": bytes_to_base64url(key.n), "e": bytes_to_base64url(key.e), "alg": "RS256"}
    raise PasskeyError("unsupported passkey algorithm")


class Passkeys:
    def __init__(self, public_url: str, stores: Any):
        u = urlparse(public_url or "http://localhost")
        self.rp_id = u.hostname or "localhost"
        self.origin = f"{u.scheme}://{u.netloc}" if u.netloc else "http://localhost"
        self.stores = stores

    # ---- enrollment ------------------------------------------------------------------------------
    def start_enrollment(self, user_id: str, created_by: str) -> dict[str, Any]:
        enr = {"enrollment_id": "enr_" + secrets.token_hex(12), "user_id": user_id, "key": secrets.token_urlsafe(24),
               "status": "issued", "created_by": created_by, "created_at": time.time(), "expires_at": time.time() + ENROLLMENT_TTL_S}
        self.stores.put_enrollment(enr)
        return enr

    def _open_enrollment(self, enrollment_id: str, key: str) -> dict[str, Any]:
        enr = self.stores.get_enrollment(enrollment_id)
        if not enr or not secrets.compare_digest(str(enr.get("key", "")), str(key or "")):
            raise PasskeyError("This enrollment link is not valid.")
        if enr["status"] != "issued":
            raise PasskeyError("This enrollment link was already used.")
        if time.time() > enr["expires_at"]:
            raise PasskeyError("This enrollment link has expired. Ask for a new one.")
        return enr

    def registration_options(self, enrollment_id: str, key: str) -> str:
        enr = self._open_enrollment(enrollment_id, key)
        challenge = os.urandom(32)
        self.stores.update_enrollment(enrollment_id, {"challenge": bytes_to_base64url(challenge)})
        existing = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(p["credential_id"])) for p in self.stores.passkeys_for(enr["user_id"])]
        opts = generate_registration_options(
            rp_id=self.rp_id, rp_name="MandateGuard", user_name=enr["user_id"], user_display_name=enr["user_id"],
            user_id=hashlib.sha256(enr["user_id"].encode()).digest()[:16], challenge=challenge, exclude_credentials=existing,
            authenticator_selection=AuthenticatorSelectionCriteria(resident_key=ResidentKeyRequirement.PREFERRED,
                                                                   user_verification=UserVerificationRequirement.REQUIRED),
            supported_pub_key_algs=[COSEAlgorithmIdentifier.ECDSA_SHA_256, COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256],
        )
        return options_to_json(opts)

    def finish_enrollment(self, enrollment_id: str, key: str, credential: dict[str, Any]) -> dict[str, Any]:
        enr = self._open_enrollment(enrollment_id, key)
        if not enr.get("challenge"):
            raise PasskeyError("Start the enrollment first.")
        try:
            v = verify_registration_response(credential=credential, expected_challenge=base64url_to_bytes(enr["challenge"]),
                                             expected_rp_id=self.rp_id, expected_origin=self.origin, require_user_verification=True)
        except Exception as e:  # noqa: BLE001
            raise PasskeyError(f"The passkey could not be verified: {e}") from e
        cred_id = bytes_to_base64url(v.credential_id)
        pk = {"credential_id": cred_id, "credential_id_sha256": hashlib.sha256(v.credential_id).hexdigest(), "user_id": enr["user_id"],
              "public_key_cose": bytes_to_base64url(v.credential_public_key), "public_jwk": cose_to_jwk(v.credential_public_key),
              "sign_count": v.sign_count, "aaguid": str(v.aaguid), "device_type": str(getattr(v.credential_device_type, "value", v.credential_device_type)),
              "backed_up": bool(v.credential_backed_up), "created_at": time.time(), "enrollment_id": enrollment_id,
              "enrollment_created_by": enr["created_by"], "rp_id": self.rp_id}
        self.stores.put_passkey(pk)
        self.stores.update_enrollment(enrollment_id, {"status": "used", "used_at": time.time()})
        return pk

    # ---- assertions ------------------------------------------------------------------------------------
    @staticmethod
    def statement_challenge(statement: dict[str, Any]) -> bytes:
        import rfc8785

        return hashlib.sha256(rfc8785.dumps(statement)).digest()

    def has_passkey(self, user_id: str) -> bool:
        return bool(self.stores.passkeys_for(user_id))

    def assertion_options(self, user_id: str, challenge: bytes) -> str:
        creds = self.stores.passkeys_for(user_id)
        if not creds:
            raise PasskeyError("This user has no passkey enrolled.")
        opts = generate_authentication_options(rp_id=self.rp_id, challenge=challenge, user_verification=UserVerificationRequirement.REQUIRED,
                                               allow_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(p["credential_id"])) for p in creds])
        return options_to_json(opts)

    def verify_assertion(self, user_id: str, credential: dict[str, Any], challenge: bytes) -> dict[str, Any]:
        cred_id = str(credential.get("rawId") or credential.get("id") or "")
        pk = next((p for p in self.stores.passkeys_for(user_id) if p["credential_id"] == cred_id), None)
        if pk is None:
            raise PasskeyError("That passkey is not enrolled for this user.")
        try:
            v = verify_authentication_response(credential=credential, expected_challenge=challenge, expected_rp_id=self.rp_id,
                                               expected_origin=self.origin, credential_public_key=base64url_to_bytes(pk["public_key_cose"]),
                                               credential_current_sign_count=int(pk.get("sign_count", 0)), require_user_verification=True)
        except Exception as e:  # noqa: BLE001
            raise PasskeyError(f"The passkey signature did not verify: {e}") from e
        self.stores.update_passkey(cred_id, {"sign_count": v.new_sign_count, "last_used_at": time.time()})
        resp = credential.get("response", {})
        return {"method": "passkey", "credential_id_sha256": pk["credential_id_sha256"], "user_verified": True,
                "public_jwk": pk["public_jwk"], "rp_id": self.rp_id, "origin": self.origin,
                "assertion": {"client_data_json": resp.get("clientDataJSON"), "authenticator_data": resp.get("authenticatorData"),
                              "signature": resp.get("signature")},
                "challenge": bytes_to_base64url(challenge)}
