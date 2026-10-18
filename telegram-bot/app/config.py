"""Telegram bot configuration from environment."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Telegram Bot API token (from @BotFather).
    bot_token: str = ""
    # Secret path segment for the webhook URL: /webhook/<webhook_secret>.
    webhook_secret: str = ""
    # Public base URL of THIS bot service (Cloud Run / tunnel). Used as the
    # webhook_url registered with MandateGuard for approval events.
    public_base_url: str = ""

    # Identity service (account linking) + the shared secret it expects.
    identity_url: str = "http://localhost:8090"
    telegram_bot_secret: str = ""
    # Shared secret for identity /internal/* calls (falls back to bot secret).
    service_secret: str = ""
    # Require the chat to be linked to a signed-in user before ordering.
    enforce_link: bool = False

    # Shopping agent A2A endpoint (JSON-RPC message/stream).
    agent_url: str = "http://localhost:8080/a2a/shopping_agent"
    agent_timeout_seconds: float = 300.0

    # Web app URL for deep links (passkey re-sign for order-widening).
    web_app_url: str = "http://localhost:5173"

    # Secret for the internal /notify endpoint other services call.
    notify_secret: str = ""

    # ── MandateGuard (channel role) ────────────────────────────────────────
    # Base URL of the deployed MandateGuard; empty disables channel features.
    mandate_guard_url: str = ""
    # Path to the bot's channel service-account key JSON (mints the ID token
    # for GET /v1/approvals/pending and POST /v1/approvals/{id}/redeem).
    mg_channel_sa_key: str = ""
    # Optional: MandateGuard decision-signer public key PEM for verifying
    # approval webhook events. Fetched from the service when empty.
    mg_event_public_pem: str = ""
    # Seconds the autonomous monitoring loop polls the agent before giving up.
    monitor_poll_seconds: float = 12.0
    monitor_max_seconds: float = 600.0


settings = Settings()
