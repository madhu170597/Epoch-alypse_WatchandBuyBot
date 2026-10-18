"""Identity service entrypoint."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import internal, passkey, telegram_link, wallet

app = FastAPI(title="Identity Service", version="0.2.0")

# The web app calls this service cross-origin with a Bearer token (no cookies),
# so a permissive CORS policy without credentials is safe for the demo.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(passkey.router)
app.include_router(telegram_link.router)
app.include_router(wallet.router)
app.include_router(internal.router)


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}
