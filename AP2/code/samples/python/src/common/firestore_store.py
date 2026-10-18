# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tiny key-value store with a Firestore backend and an in-memory fallback.

When roles run as separate Cloud Run services they can no longer share a local
process dict or filesystem, so cross-service state (merchant carts, issued
credential tokens) lives in Firestore. For local dev and tests the store falls
back to an in-memory dict, so no credentials are needed unless
FIRESTORE_ENABLED=true.

Values may be any JSON-serializable object; non-dict values are wrapped so the
Firestore document is always a mapping.
"""

import logging
import os
import threading
from typing import Any

_logger = logging.getLogger("ap2.firestore_store")

_FIRESTORE_ENABLED = os.environ.get("FIRESTORE_ENABLED", "").lower() == "true"
_WRAP_KEY = "_v"

_lock = threading.Lock()
_client = None  # lazy Firestore client
_mem: dict[str, dict[str, Any]] = {}  # collection -> {doc_id -> value}


def _wrap(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {_WRAP_KEY: value}


def _unwrap(doc: dict[str, Any] | None) -> Any:
    if doc is None:
        return None
    if set(doc.keys()) == {_WRAP_KEY}:
        return doc[_WRAP_KEY]
    return doc


def _get_client():
    """Lazily create a Firestore client; fall back to memory on any failure."""
    global _client, _FIRESTORE_ENABLED
    if not _FIRESTORE_ENABLED:
        return None
    if _client is None:
        with _lock:
            if _client is None:
                try:
                    from google.cloud import firestore

                    _client = firestore.Client()
                except Exception as e:  # missing creds/project, etc.
                    _logger.warning(
                        "Firestore unavailable, using in-memory store: %s", e
                    )
                    _FIRESTORE_ENABLED = False
                    return None
    return _client


class KVStore:
    """A named view over one logical collection."""

    def __init__(self, collection: str):
        self.collection = collection

    def get(self, doc_id: str) -> Any:
        client = _get_client()
        if client is None:
            return _mem.get(self.collection, {}).get(doc_id)
        snap = client.collection(self.collection).document(doc_id).get()
        return _unwrap(snap.to_dict()) if snap.exists else None

    def set(self, doc_id: str, value: Any) -> None:
        client = _get_client()
        if client is None:
            _mem.setdefault(self.collection, {})[doc_id] = value
            return
        client.collection(self.collection).document(doc_id).set(_wrap(value))

    def delete(self, doc_id: str) -> None:
        client = _get_client()
        if client is None:
            _mem.get(self.collection, {}).pop(doc_id, None)
            return
        client.collection(self.collection).document(doc_id).delete()

    def items(self) -> list[tuple[str, Any]]:
        """Return (doc_id, value) pairs. Used for scans over small collections."""
        client = _get_client()
        if client is None:
            return list(_mem.get(self.collection, {}).items())
        return [
            (d.id, _unwrap(d.to_dict()))
            for d in client.collection(self.collection).stream()
        ]
