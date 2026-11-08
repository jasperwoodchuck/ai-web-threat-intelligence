"""Application environment loading for local backend configuration."""

import os
from pathlib import Path

from dotenv import load_dotenv

BACKEND_ENV_FILE = Path(__file__).resolve().parents[1] / ".env"


def load_environment(env_file: Path = BACKEND_ENV_FILE) -> None:
    """Load backend .env values without overriding explicitly set environment values."""
    load_dotenv(dotenv_path=env_file, override=False)


def frontend_origins() -> list[str]:
    """Return local development origins plus configured production origins."""
    origins = {"http://localhost:5173", "http://127.0.0.1:5173"}
    configured = os.getenv("FRONTEND_ORIGIN", "")
    origins.update(origin.strip().rstrip("/") for origin in configured.split(",") if origin.strip())
    return sorted(origins)
