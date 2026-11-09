"""Settings, read from environment variables at start-up."""
import os
from dataclasses import dataclass

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEV_AUDIT_KEY = "dev-only-change-me"


@dataclass
class Settings:
    env: str = os.environ.get("TV_ENV", "dev")
    db_path: str = os.environ.get("TV_DB", os.path.join(BASE, "data", "trustvault.db"))
    storage_dir: str = os.environ.get("TV_STORAGE", os.path.join(BASE, "data", "files"))
    audit_key: bytes = os.environ.get("TV_AUDIT_KEY", DEV_AUDIT_KEY).encode()
    max_upload_bytes: int = int(os.environ.get("TV_MAX_UPLOAD", 10 * 1024 * 1024))
    session_hours: int = int(os.environ.get("TV_SESSION_HOURS", 8))
    trust_proxy: bool = os.environ.get("TV_TRUST_PROXY", "0") == "1"
    seed_password: str = os.environ.get("TV_SEED_PASSWORD", "ChangeMe-Demo-2026!")
    lockout_attempts: int = 5
    lockout_minutes: int = 5


settings = Settings()
