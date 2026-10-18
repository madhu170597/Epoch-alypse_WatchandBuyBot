"""Who MandateGuard recognises: merchants (with a key history) and shopping agents.

Merchants: a profile (id, name, website, rating) and any number of signing keys. A key id is bound to one
key forever; rotating means registering a new key id. Retired keys stay on file so past decisions can be
re-verified; only active keys are accepted for new checkouts.

Agents: SAFR's first runtime component. An agent is registered with the service accounts it runs as and
the public keys users may delegate mandates to. A decision request is only evaluated if the verified caller
is a registered agent and the mandate delegates to one of that agent's keys.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from jwcrypto.jwk import JWK


class KeyConflict(Exception):
    pass


def thumbprint(jwk: dict[str, Any] | JWK) -> str:
    k = jwk if isinstance(jwk, JWK) else JWK.from_json(json.dumps(jwk))
    return k.thumbprint()


PROFILE_FIELDS = ("name", "website", "rating", "rating_source")


# ------------------------------------------------------------------------------------------- merchants
class MerchantRegistry:
    """In-memory registry. `profiles[id]`, `keys[kid]`."""

    def __init__(self):
        self.profiles: dict[str, dict[str, Any]] = {}
        self.keys: dict[str, dict[str, Any]] = {}

    # writes ---------------------------------------------------------------------
    def register_key(self, entry: dict[str, Any], *, by: str, retire_previous: bool = True) -> dict[str, Any] | None:
        """Returns a change summary, or None when the exact key is already registered (idempotent)."""
        mid, kid = entry["id"], entry["kid"]
        tp = thumbprint(entry["public_jwk"])
        existing = self._get_key(kid)
        if existing is not None:
            if existing["thumbprint"] != tp or existing["merchant_id"] != mid:
                raise KeyConflict(f"key id {kid!r} is already registered to a different key; register a new key id to rotate")
            before = dict(self._get_profile(mid) or {})
            changed = {f: {"from": before.get(f), "to": entry[f]} for f in PROFILE_FIELDS if f in entry and before.get(f) != entry[f]}
            if not changed:
                return None
            # profile fields may still change, e.g. rating or website; that change is itself a recorded event
            return {"profile": self._put_profile(mid, entry, by), "profile_changed": changed}
        now = time.time()
        retired = []
        if retire_previous:
            for k in self._keys_of(mid):
                if k["status"] == "active":
                    k.update({"status": "retired", "retired_at": now, "retired_by": by})
                    self._put_key(k)
                    retired.append(k["kid"])
        key = {"kid": kid, "merchant_id": mid, "public_jwk": entry["public_jwk"], "thumbprint": tp, "status": "active",
               "registered_by": by, "registered_at": now}
        self._put_key(key)
        profile = self._put_profile(mid, entry, by)
        return {"profile": profile, "key": {k: key[k] for k in ("kid", "thumbprint", "status", "public_jwk")}, "retired_kids": retired}

    def _put_profile(self, mid: str, entry: dict[str, Any], by: str) -> dict[str, Any]:
        prof = dict(self._get_profile(mid) or {"id": mid, "registered_by": by, "registered_at": time.time()})
        for f in PROFILE_FIELDS:
            if f in entry:
                prof[f] = entry[f]
        prof["updated_by"] = by
        prof["updated_at"] = time.time()
        self._save_profile(prof)
        return prof

    # reads ----------------------------------------------------------------------
    def lookup_key(self, kid: str | None, *, include_retired: bool = False) -> tuple[dict[str, Any], dict[str, Any]] | None:
        if not kid:
            return None
        key = self._get_key(kid)
        if key is None or (key["status"] != "active" and not include_retired):
            return None
        prof = self._get_profile(key["merchant_id"]) or {"id": key["merchant_id"]}
        return key, prof

    def lookup(self, *, kid: str | None, include_retired: bool = False) -> dict[str, Any] | None:
        """Flattened entry for the AP2 verifier: id, name, website, rating, kid, public_jwk, status."""
        found = self.lookup_key(kid, include_retired=include_retired)
        if found is None:
            return None
        key, prof = found
        return {**prof, "kid": key["kid"], "public_jwk": key["public_jwk"], "status": key["status"], "thumbprint": key["thumbprint"],
                "key_registered_by": key["registered_by"], "key_registered_at": key["registered_at"]}

    def all(self) -> list[dict[str, Any]]:
        return [dict(p) for p in self._all_profiles()]

    def public_keys(self) -> list[dict[str, Any]]:
        return [{k: v for k, v in key.items()} for key in self._all_keys()]

    # storage primitives (overridden by the Firestore registry) -------------------------------------
    def _get_key(self, kid): return self.keys.get(kid)
    def _put_key(self, key): self.keys[key["kid"]] = key
    def _keys_of(self, mid): return [k for k in self.keys.values() if k["merchant_id"] == mid]
    def _all_keys(self): return list(self.keys.values())
    def _get_profile(self, mid): return self.profiles.get(mid)
    def _save_profile(self, prof): self.profiles[prof["id"]] = prof
    def _all_profiles(self): return list(self.profiles.values())


class FirestoreMerchantRegistry(MerchantRegistry):
    def __init__(self, db: Any, ttl_s: int = 15):
        super().__init__()
        self.db = db
        self.ttl = ttl_s
        self._loaded = 0.0

    def _refresh(self, force: bool = False) -> None:
        if force or time.time() - self._loaded > self.ttl:
            self.profiles = {d.id: d.to_dict() for d in self.db.collection("mg_merchant_profiles").stream()}
            self.keys = {d.id: d.to_dict() for d in self.db.collection("mg_merchant_keys").stream()}
            self._loaded = time.time()

    def _get_key(self, kid):
        self._refresh()
        if kid not in self.keys:  # a key registered by another instance moments ago
            snap = self.db.collection("mg_merchant_keys").document(kid).get()
            if snap.exists:
                self.keys[kid] = snap.to_dict()
        return self.keys.get(kid)

    def _put_key(self, key):
        self.db.collection("mg_merchant_keys").document(key["kid"]).set(key)
        self.keys[key["kid"]] = key

    def _keys_of(self, mid):
        self._refresh(force=True)
        return super()._keys_of(mid)

    def _all_keys(self):
        self._refresh()
        return super()._all_keys()

    def _get_profile(self, mid):
        self._refresh()
        return self.profiles.get(mid)

    def _save_profile(self, prof):
        self.db.collection("mg_merchant_profiles").document(prof["id"]).set(prof)
        self.profiles[prof["id"]] = prof

    def _all_profiles(self):
        self._refresh()
        return super()._all_profiles()


# ------------------------------------------------------------------------------------------- agents
@dataclass
class AgentEntry:
    agent_id: str
    principals: list[str]                 # service accounts the agent runs as (Google ID token email)
    key_thumbprints: list[str]            # JWK thumbprints of keys users may delegate mandates to
    operator: str = ""                    # who runs the agent
    description: str = ""
    webhook_url: str = ""                 # https endpoint for approval.answered events; empty means the agent polls
    registered_by: str = ""
    registered_at: float = field(default_factory=time.time)
    status: str = "active"


class AgentRegistry:
    def __init__(self):
        self.agents: dict[str, AgentEntry] = {}

    def register(self, entry: AgentEntry) -> AgentEntry | None:
        prev = self.get(entry.agent_id)
        self._save(entry)
        return prev

    def revoke(self, agent_id: str) -> AgentEntry | None:
        entry = self.get(agent_id)
        if entry is not None and entry.status == "active":
            entry.status = "revoked"
            self._save(entry)
        return entry

    def get(self, agent_id: str) -> AgentEntry | None:
        return self.agents.get(agent_id)

    def by_principal(self, principal: str) -> AgentEntry | None:
        return next((a for a in self._all() if a.status == "active" and principal in a.principals), None)

    def by_key(self, key_thumbprint: str) -> AgentEntry | None:
        return next((a for a in self._all() if a.status == "active" and key_thumbprint in a.key_thumbprints), None)

    def all(self) -> list[AgentEntry]:
        return self._all()

    def _save(self, entry: AgentEntry) -> None:
        self.agents[entry.agent_id] = entry

    def _all(self) -> list[AgentEntry]:
        return list(self.agents.values())


class FirestoreAgentRegistry(AgentRegistry):
    def __init__(self, db: Any, ttl_s: int = 15):
        super().__init__()
        self.db = db
        self.ttl = ttl_s
        self._loaded = 0.0

    def _all(self) -> list[AgentEntry]:
        if time.time() - self._loaded > self.ttl:
            self.agents = {d.id: AgentEntry(**d.to_dict()) for d in self.db.collection("mg_agents").stream()}
            self._loaded = time.time()
        return list(self.agents.values())

    def get(self, agent_id: str) -> AgentEntry | None:
        snap = self.db.collection("mg_agents").document(agent_id).get()
        return AgentEntry(**snap.to_dict()) if snap.exists else None

    def _save(self, entry: AgentEntry) -> None:
        self.db.collection("mg_agents").document(entry.agent_id).set(asdict(entry))
        self.agents[entry.agent_id] = entry
        self._loaded = 0.0


# ------------------------------------------------------------------------------------------- policy approvers
@dataclass
class ApproverEntry:
    """A person or role whose signature a policy pack needs before it counts as approved."""

    approver_id: str
    public_jwk: dict[str, Any]
    thumbprint: str
    name: str = ""
    registered_by: str = ""
    registered_at: float = field(default_factory=time.time)
    status: str = "active"


class ApproverRegistry:
    def __init__(self):
        self.approvers: dict[str, ApproverEntry] = {}

    def register(self, entry: ApproverEntry) -> ApproverEntry | None:
        prev = self.get(entry.approver_id)
        self._save(entry)
        return prev

    def get(self, approver_id: str) -> ApproverEntry | None:
        return self.approvers.get(approver_id)

    def all(self) -> list[ApproverEntry]:
        return list(self.approvers.values())

    def _save(self, entry: ApproverEntry) -> None:
        self.approvers[entry.approver_id] = entry


class FirestoreApproverRegistry(ApproverRegistry):
    def __init__(self, db: Any):
        super().__init__()
        self.db = db

    def get(self, approver_id: str) -> ApproverEntry | None:
        snap = self.db.collection("mg_policy_approvers").document(approver_id).get()
        return ApproverEntry(**snap.to_dict()) if snap.exists else None

    def all(self) -> list[ApproverEntry]:
        return [ApproverEntry(**d.to_dict()) for d in self.db.collection("mg_policy_approvers").stream()]

    def _save(self, entry: ApproverEntry) -> None:
        self.db.collection("mg_policy_approvers").document(entry.approver_id).set(asdict(entry))
