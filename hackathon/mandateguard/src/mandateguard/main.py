"""`uvicorn mandateguard.main:app` entry point (Cloud Run uses $PORT)."""

from .app import create_app

app = create_app()
