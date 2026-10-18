"""Registered API clients: which identity may call MandateGuard in which role, and where its events are sent.

The operator registers each client with POST /v1/admin/clients; every registration and revocation is a chained
record, so who was allowed to call, and from when, is part of the audit trail. The MG_*_CALLERS environment lists
still work and are meant for bootstrapping the first operator. Shopping agents are not clients here: registering an
agent (POST /v1/admin/agents) already names the service accounts it runs as, and that grants the agent role.

Roles: channel (delivers approval links), trusted_surface (registers mandates for its users), operator (registers
agents, merchants, approvers and clients), processor (reports receipts).
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any

ROLES = ("channel", "trusted_surface", "operator", "processor")


@dataclass
class ClientEntry:
    client_id: str
    role: str
    principals: list[str]                 # Google ID token emails (or subjects) the client calls as
    webhook_url: str = ""                 # https endpoint for this role's events; empty means the client polls
    description: str = ""
    registered_by: str = ""
    registered_at: float = field(default_factory=time.time)
    status: str = "active"


class ClientRegistry:
    def __init__(self):
        self.clients: dict[str, ClientEntry] = {}

    def register(self, entry: ClientEntry) -> ClientEntry | None:
        prev = self.get(entry.client_id)
        self._save(entry)
        return prev

    def revoke(self, client_id: str) -> ClientEntry | None:
        entry = self.get(client_id)
        if entry is not None and entry.status == "active":
            entry.status = "revoked"
            self._save(entry)
        return entry

    def get(self, client_id: str) -> ClientEntry | None:
        return self.clients.get(client_id)

    def all(self) -> list[ClientEntry]:
        return self._all()

    def active(self, role: str) -> list[ClientEntry]:
        return [c for c in self._all() if c.role == role and c.status == "active"]

    def allows(self, role: str, principal: str) -> ClientEntry | None:
        return next((c for c in self.active(role) if principal in c.principals), None)

    def _save(self, entry: ClientEntry) -> None:
        self.clients[entry.client_id] = entry

    def _all(self) -> list[ClientEntry]:
        return list(self.clients.values())


class FirestoreClientRegistry(ClientRegistry):
    """Collection mg_clients. Read through a short cache so a caller check adds no round trip; an unknown principal
    refreshes it at most every two seconds, so a new registration works at once on every instance. A revocation is
    immediate on the instance that made it and takes up to `ttl_s` on the others."""

    def __init__(self, db: Any, ttl_s: int = 15):
        super().__init__()
        self.db = db
        self.ttl = ttl_s
        self._loaded = 0.0

    def _refresh(self, force: bool = False) -> None:
        if force or time.time() - self._loaded > self.ttl:
            self.clients = {d.id: ClientEntry(**d.to_dict()) for d in self.db.collection("mg_clients").stream()}
            self._loaded = time.time()

    def _all(self) -> list[ClientEntry]:
        self._refresh()
        return list(self.clients.values())

    def get(self, client_id: str) -> ClientEntry | None:
        snap = self.db.collection("mg_clients").document(client_id).get()
        return ClientEntry(**snap.to_dict()) if snap.exists else None

    def allows(self, role: str, principal: str) -> ClientEntry | None:
        found = super().allows(role, principal)
        if found is None and time.time() - self._loaded > 2:
            self._refresh(force=True)
            found = super().allows(role, principal)
        return found

    def _save(self, entry: ClientEntry) -> None:
        self.db.collection("mg_clients").document(entry.client_id).set(asdict(entry))
        self.clients[entry.client_id] = entry
