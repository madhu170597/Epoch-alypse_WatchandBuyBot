"""Lazy firebase-admin initialization and thin helpers.

Init is deferred so the module imports without credentials (unit tests, CI). The
first call that needs Firebase triggers init via Application Default Credentials
or GOOGLE_APPLICATION_CREDENTIALS.
"""

import threading

import firebase_admin
from firebase_admin import auth, credentials, firestore

from app.config import settings

_lock = threading.Lock()
_app: firebase_admin.App | None = None
_db = None


def _ensure_app() -> firebase_admin.App:
    global _app
    if _app is None:
        with _lock:
            if _app is None:
                options = {}
                if settings.firebase_project_id:
                    options["projectId"] = settings.firebase_project_id
                _app = firebase_admin.initialize_app(
                    credentials.ApplicationDefault(), options or None
                )
    return _app


def get_db():
    global _db
    if _db is None:
        _db = firestore.client(_ensure_app())
    return _db


def verify_id_token(id_token: str) -> dict:
    """Verify a Firebase ID token; raises on invalid/expired."""
    return auth.verify_id_token(id_token, app=_ensure_app())


def create_custom_token(uid: str) -> str:
    """Mint a Firebase custom token the client exchanges for an ID token."""
    token = auth.create_custom_token(uid, app=_ensure_app())
    return token.decode("utf-8") if isinstance(token, bytes) else token
