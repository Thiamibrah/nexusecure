from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

# config.py -> app/ -> backend/ -> project root, where the real .env lives. A relative
# "env_file=.env" is resolved against the CWD at import time, which broke local dev
# (uvicorn is run from backend/, no .env there) while working by accident under Docker
# and pytest (Compose injects real env vars; env_file just wasn't providing anything
# extra there either). Anchoring to this file's location makes it CWD-independent.
_ENV_FILE = Path(__file__).resolve().parent.parent.parent / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=_ENV_FILE, extra="ignore")

    APP_NAME: str = "NexusSecure"
    APP_ENV: str = "development"
    SECRET_KEY: str = "changeme"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    DATABASE_URL: str = "sqlite:///./nexussecure.db"

    FIRST_ADMIN_EMAIL: str = "admin@nexussecure.local"
    # If unset, a random password is generated at first startup and logged once.
    FIRST_ADMIN_PASSWORD: str | None = None

    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "app/logs/nexussecure.log"

    # Email (optionnel)
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = ""


settings = Settings()
