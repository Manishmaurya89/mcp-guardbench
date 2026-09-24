"""Application settings, loaded from ``GUARDBENCH_*`` environment variables.

Defaults are secure: dev mode is OFF, so the API refuses requests until an API key
is configured. ``.env.example`` turns dev mode on for the local lab.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration. Never holds real credentials in the lab."""

    model_config = SettingsConfigDict(
        env_prefix="GUARDBENCH_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    dev_mode: bool = False
    log_level: str = "INFO"
    log_json: bool = True

    database_url: str = "sqlite:///./data/guardbench.db"

    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8000, ge=1, le=65535)
    api_key: SecretStr | None = None
    api_url: str = "http://127.0.0.1:8000"
    dashboard_port: int = Field(default=8501, ge=1, le=65535)

    test_cases_dir: Path = Path("test_cases")
    reports_dir: Path = Path("reports")
    policy_path: Path | None = None
    alembic_ini: Path | None = None

    max_response_bytes: int = Field(default=4096, ge=256, le=1_000_000)
    max_calls_per_trace: int = Field(default=10, ge=1, le=1000)

    @field_validator("log_level")
    @classmethod
    def _valid_level(cls, value: str) -> str:
        level = value.upper()
        if level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("log_level must be DEBUG, INFO, WARNING, ERROR, or CRITICAL")
        return level

    @property
    def is_sqlite(self) -> bool:
        """True when the configured database is SQLite."""
        return self.database_url.startswith("sqlite")

    @property
    def api_key_value(self) -> str | None:
        """The configured API key, or ``None``. Callers must never log this."""
        return self.api_key.get_secret_value() if self.api_key and self.api_key.get_secret_value() else None


def load_settings() -> Settings:
    """Build settings from the environment (a fresh instance each call, no global cache)."""
    return Settings()
