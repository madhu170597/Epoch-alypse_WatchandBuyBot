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

"""Storage for cart data and risk data.

Cart data (merchant-signed JWTs) is persisted between interactions between the
shopper and merchant agents. Backed by Firestore (shared across service
instances) with an in-memory fallback for local dev — see
``common.firestore_store``.
"""

from typing import Any

from common.firestore_store import KVStore

_carts = KVStore("merchant_carts")
_risk = KVStore("merchant_risk")


def get_cart_data(cart_id: str) -> dict[str, Any] | None:
  """Get cart data (jwt, hash, item info) by cart ID."""
  return _carts.get(cart_id)


def set_cart_data(cart_id: str, data: dict[str, Any]) -> None:
  """Set cart data by cart ID."""
  _carts.set(cart_id, data)


def set_risk_data(context_id: str, risk_data: str) -> None:
  """Set risk data by context ID."""
  _risk.set(context_id, risk_data)


def get_risk_data(context_id: str) -> str | None:
  """Get risk data by context ID."""
  return _risk.get(context_id)
