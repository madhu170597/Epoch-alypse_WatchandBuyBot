"""Evidence and checkpoints, kept outside the decision record.

Evidence: every request as submitted, every mandate registration and every policy file is stored by the
sha256 of its exact bytes. Records carry the hash, so anyone holding the evidence can re-verify a decision
later without trusting MandateGuard's summary of it. Objects are created once and never overwritten.

Checkpoints: after each record is appended, its seq, hash and signature are written to the same store, under the
ledger's own prefix, so a new ledger never collides with the sequence numbers of an earlier one.
In Cloud Storage with a retention policy, nobody (MandateGuard's own service account included) can delete
or rewrite a checkpoint before the retention period ends, so truncating or re-signing the chain shows up
as a mismatch against the checkpoints.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any, Protocol

log = logging.getLogger("mandateguard.evidence")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class EvidenceStore(Protocol):
    def put(self, data: bytes, content_type: str = "application/json") -> str: ...
    def get(self, sha256: str) -> bytes | None: ...
    def uri(self, sha256: str) -> str: ...
    def anchor(self, record: dict[str, Any]) -> None: ...
    def checkpoints(self, limit: int = 50) -> list[dict[str, Any]]: ...
    def describe(self) -> dict[str, Any]: ...


def _checkpoint(record: dict[str, Any]) -> dict[str, Any]:
    return {"seq": record["seq"], "hash": record["hash"], "prev_hash": record["prev_hash"], "ts_ms": record.get("ts_ms"),
            "signature": record.get("signature"), "signer_kid": record.get("signer_kid")}


class InMemoryEvidence:
    def __init__(self):
        self.objects: dict[str, bytes] = {}
        self._checkpoints: dict[int, dict[str, Any]] = {}

    def put(self, data: bytes, content_type: str = "application/json") -> str:
        h = sha256_hex(data)
        self.objects.setdefault(h, data)
        return h

    def get(self, sha256: str) -> bytes | None:
        return self.objects.get(sha256)

    def uri(self, sha256: str) -> str:
        return f"memory://evidence/{sha256}"

    def anchor(self, record: dict[str, Any]) -> None:
        self._checkpoints.setdefault(record["seq"], _checkpoint(record))  # write-once, like a retention-locked object

    def checkpoints(self, limit: int = 50) -> list[dict[str, Any]]:
        return [self._checkpoints[k] for k in sorted(self._checkpoints)[-limit:]]

    def describe(self) -> dict[str, Any]:
        return {"kind": "memory", "location": "process memory", "retention": "none"}


class GcsEvidence:
    """Cloud Storage bucket. Objects: evidence/<sha256> (shared), checkpoints/<ledger>/<seq>.json. Create-only writes."""

    def __init__(self, bucket: str, project: str | None = None, ledger: str = "ledger"):
        from google.cloud import storage

        self.client = storage.Client(project=project or None)
        self.bucket_name = bucket
        self.bucket = self.client.bucket(bucket)
        self.prefix = f"checkpoints/{ledger}/"
        self._retention: str | None = None

    def put(self, data: bytes, content_type: str = "application/json") -> str:
        from google.api_core import exceptions as gexc

        h = sha256_hex(data)
        blob = self.bucket.blob(f"evidence/{h}")
        try:
            blob.upload_from_string(data, content_type=content_type, if_generation_match=0)
        except gexc.PreconditionFailed:
            pass  # same bytes already stored under the same hash
        return h

    def get(self, sha256: str) -> bytes | None:
        from google.api_core import exceptions as gexc

        try:
            return self.bucket.blob(f"evidence/{sha256}").download_as_bytes()
        except gexc.NotFound:
            return None

    def uri(self, sha256: str) -> str:
        return f"gs://{self.bucket_name}/evidence/{sha256}"

    def anchor(self, record: dict[str, Any]) -> None:
        from google.api_core import exceptions as gexc

        blob = self.bucket.blob(f"{self.prefix}{record['seq']:012d}.json")
        try:
            blob.upload_from_string(json.dumps(_checkpoint(record), sort_keys=True), content_type="application/json", if_generation_match=0)
        except gexc.PreconditionFailed:
            log.warning("checkpoint %s already exists; not overwritten", record["seq"])

    def checkpoints(self, limit: int = 50) -> list[dict[str, Any]]:
        blobs = list(self.client.list_blobs(self.bucket_name, prefix=self.prefix))
        blobs.sort(key=lambda b: b.name)
        return [json.loads(b.download_as_bytes()) for b in blobs[-limit:]]

    def describe(self) -> dict[str, Any]:
        if self._retention is None:
            try:
                self.bucket.reload()
                secs = self.bucket.retention_period
                locked = self.bucket.retention_policy_locked
                self._retention = f"{int(secs) // 86400} days{' (locked)' if locked else ''}" if secs else "none"
            except Exception as e:  # noqa: BLE001
                self._retention = f"unknown ({type(e).__name__})"
        return {"kind": "gcs", "location": f"gs://{self.bucket_name}", "retention": self._retention}
