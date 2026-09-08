"""Configuration management and platform data directory resolution."""

import os
import sys
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def get_default_data_dir() -> Path:
    """Resolve platform-specific local application data directory."""
    env_data_dir = os.environ.get("AGENTSHIELD_DATA_DIR")
    if env_data_dir:
        return Path(env_data_dir).expanduser().resolve()

    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "AgentShield"
    if sys.platform == "win32":
        app_data = os.environ.get("APPDATA")
        if app_data:
            return Path(app_data) / "AgentShield"
        return Path.home() / "AppData" / "Roaming" / "AgentShield"
    # Linux and other POSIX
    xdg_data = os.environ.get("XDG_DATA_HOME")
    if xdg_data:
        return Path(xdg_data) / "agentshield"
    return Path.home() / ".local" / "share" / "agentshield"


def ensure_secure_dir(path: Path) -> Path:
    """Ensure directory exists with 0700 permissions on POSIX systems."""
    if not path.exists():
        path.mkdir(parents=True, exist_ok=True)
        if hasattr(os, "chmod") and sys.platform != "win32":
            path.chmod(0o700)
    return path


class Settings(BaseSettings):
    """AgentShield application settings."""

    model_config = SettingsConfigDict(
        env_prefix="AGENTSHIELD_",
        case_sensitive=False,
        extra="ignore",
    )

    host: str = "127.0.0.1"
    port: int = 8765
    data_dir: Path = Field(default_factory=get_default_data_dir)
    profile: Literal["audit", "balanced", "strict"] = "balanced"
    dev_mode: bool = False
    log_level: str = "INFO"

    # CORS and Host verification
    allowed_hosts: list[str] = Field(
        default_factory=lambda: [
            "127.0.0.1",
            "localhost",
        ]
    )
    cors_allowed_origins: list[str] = Field(
        default_factory=lambda: [
            "http://127.0.0.1:8765",
            "http://localhost:8765",
            "http://127.0.0.1:5173",
            "http://localhost:5173",
        ]
    )

    # Persistence overrides
    database_url: str | None = None
    admin_token_path: Path | None = None
    proxy_token_path: Path | None = None
    frontend_dist_dir: Path | None = None

    # Proxy upstream configuration
    openai_upstream_base_url: str = "https://api.openai.com"
    anthropic_upstream_base_url: str = "https://api.anthropic.com"
    proxy_connect_timeout_seconds: float = 10.0
    proxy_read_timeout_seconds: float = 120.0
    proxy_write_timeout_seconds: float = 30.0
    proxy_max_body_bytes: int = 10 * 1024 * 1024
    proxy_max_response_bytes: int = 10 * 1024 * 1024

    @property
    def effective_database_url(self) -> str:
        """Get the active SQLite database URL."""
        if self.database_url:
            return self.database_url
        db_path = self.data_dir / "agentshield.db"
        return f"sqlite:///{db_path}"

    @property
    def effective_admin_token_path(self) -> Path:
        """Get the admin token file path."""
        if self.admin_token_path:
            return self.admin_token_path
        return self.data_dir / "admin.token"

    @property
    def effective_proxy_token_path(self) -> Path:
        """Get the proxy token file path."""
        if self.proxy_token_path:
            return self.proxy_token_path
        return self.data_dir / "proxy.token"

    @property
    def effective_frontend_dist_dir(self) -> Path:
        """Get frontend static build output directory."""
        if self.frontend_dist_dir:
            return self.frontend_dist_dir
        # Standard repository structure:
        # backend/src/agentshield/core/config.py -> ../../../../frontend/dist
        current_file = Path(__file__).resolve()
        repo_root = current_file.parent.parent.parent.parent.parent
        return repo_root / "frontend" / "dist"


_settings_instance: Settings | None = None


def get_settings() -> Settings:
    """Retrieve the application settings instance."""
    global _settings_instance
    if _settings_instance is None:
        _settings_instance = Settings()
    return _settings_instance


def reset_settings(new_settings: Settings | None = None) -> Settings:
    """Reset the application settings instance (primarily for tests)."""
    global _settings_instance
    _settings_instance = new_settings
    return get_settings()
