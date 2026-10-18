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

"""Shared single-use payment-credential token store.

The credentials provider issues tokens here; the merchant consumes them at
checkout completion. In the A2A (separate-service) topology these run in
different processes, so the store is Firestore-backed (with an in-memory
fallback for local dev) rather than a shared file.

Keys:
  <token>            -> token_data dict
  <reference>        -> token_data dict (same object, looked up by receipt ref)
  mandate:<hash>     -> <token> string  (one purchase per mandate / idempotency)
"""

from typing import Any

from common.firestore_store import KVStore

_store = KVStore("ap2_tokens")


def get(key: str) -> Any:
    return _store.get(key)


def put(key: str, value: Any) -> None:
    _store.set(key, value)


def delete(key: str) -> None:
    _store.delete(key)
