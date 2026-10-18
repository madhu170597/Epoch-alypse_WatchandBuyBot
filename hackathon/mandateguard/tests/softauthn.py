"""A software WebAuthn authenticator (ES256, "none" attestation) so passkey flows can be tested without a browser."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class SoftAuthenticator:
    def __init__(self, origin: str):
        self.origin = origin
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = os.urandom(16)
        self.counter = 0

    def _cose(self) -> bytes:
        n = self.key.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})

    def create(self, options_json: str) -> dict:
        o = json.loads(options_json)
        client = json.dumps({"type": "webauthn.create", "challenge": o["challenge"], "origin": self.origin, "crossOrigin": False}).encode()
        auth = (hashlib.sha256(o["rp"]["id"].encode()).digest() + bytes([0x01 | 0x04 | 0x40]) + struct.pack(">I", self.counter)
                + b"\x00" * 16 + struct.pack(">H", len(self.cred_id)) + self.cred_id + self._cose())
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth})
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(client), "attestationObject": b64u(att)}, "clientExtensionResults": {}}

    def get(self, options_json: str, *, challenge_override: str | None = None) -> dict:
        o = json.loads(options_json)
        self.counter += 1
        client = json.dumps({"type": "webauthn.get", "challenge": challenge_override or o["challenge"], "origin": self.origin,
                             "crossOrigin": False}).encode()
        auth = hashlib.sha256(o["rpId"].encode()).digest() + bytes([0x01 | 0x04]) + struct.pack(">I", self.counter)
        sig = self.key.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(client), "authenticatorData": b64u(auth), "signature": b64u(sig)},
                "clientExtensionResults": {}}
