"""Service configuration from environment."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Firebase project id. Optional locally — firebase-admin infers it from ADC
    # or GOOGLE_APPLICATION_CREDENTIALS. Required in deploy.
    firebase_project_id: str = ""

    # WebAuthn relying party. rp_id is the registrable domain (no scheme/port):
    # "localhost" for local dev, your web app's domain in prod. expected_origin
    # is the full origin the browser reports.
    rp_id: str = "localhost"
    rp_name: str = "Agentic Ordering Bot"
    expected_origin: str = "http://localhost:5173"

    # TTLs (seconds).
    challenge_ttl_seconds: int = 300
    link_code_ttl_seconds: int = 600

    # Shared secret the Telegram bot presents to the link/verify endpoint.
    telegram_bot_secret: str = ""

    # Shared secret for /internal/* service-to-service calls (bot + agent).
    # Falls back to telegram_bot_secret when empty.
    service_secret: str = ""

    # Require a second factor (MFA) on protected endpoints.
    require_mfa: bool = False


settings = Settings()
