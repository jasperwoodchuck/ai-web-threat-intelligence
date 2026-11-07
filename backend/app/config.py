"""Application environment loading for local backend configuration."""

from pathlib import Path

from dotenv import load_dotenv

BACKEND_ENV_FILE = Path(__file__).resolve().parents[1] / ".env"


def load_environment(env_file: Path = BACKEND_ENV_FILE) -> None:
    """Load backend .env values without overriding explicitly set environment values."""
    load_dotenv(dotenv_path=env_file, override=False)
