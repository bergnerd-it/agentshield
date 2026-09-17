"""Configuration management and platform data directory resolution."""

import os
import re
import sys
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
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


class CustomTermSettings(BaseModel):
    """Validated configuration boundary for one project-specific term rule."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    id: str
    pattern: str
    match_kind: Literal["exact", "regex"] = "exact"
    case_sensitive: bool = True
    word_boundaries: bool = False
    data_class: str = "project_term"
    default_action: Literal["ALLOW", "WARN", "REDACT", "REQUIRE_APPROVAL", "BLOCK"] = "WARN"
    excluded_path_prefixes: list[list[str | int]] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_domain_rule(self) -> Self:
        """Apply the same safe-regex and identifier validation as the detector."""
        from agentshield.filtering.detectors.custom_terms import CustomTermRule, MatchKind
        from agentshield.policies.models import PolicyAction

        CustomTermRule(
            id=self.id,
            pattern=self.pattern,
            match_kind=MatchKind(self.match_kind),
            case_sensitive=self.case_sensitive,
            word_boundaries=self.word_boundaries,
            data_class=self.data_class,
            default_action=PolicyAction[self.default_action],
            excluded_path_prefixes=tuple(tuple(path) for path in self.excluded_path_prefixes),
        )
        return self


class Settings(BaseSettings):
    """AgentShield application settings."""

    model_config = SettingsConfigDict(
        env_prefix="AGENTSHIELD_",
        case_sensitive=False,
        extra="ignore",
        hide_input_in_errors=True,
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
    fingerprint_key_path: Path | None = None
    frontend_dist_dir: Path | None = None

    # Proxy upstream configuration
    openai_upstream_base_url: str = "https://api.openai.com"
    anthropic_upstream_base_url: str = "https://api.anthropic.com"
    proxy_connect_timeout_seconds: float = 10.0
    proxy_read_timeout_seconds: float = 120.0
    proxy_write_timeout_seconds: float = 30.0
    proxy_max_body_bytes: int = 10 * 1024 * 1024
    proxy_max_response_bytes: int = 10 * 1024 * 1024
    sse_max_event_bytes: int = 64 * 1024
    pseudonym_ttl_seconds: int = 3600
    approval_timeout_seconds: float = Field(default=60.0, gt=0.0, le=3600.0)

    # Milestone 3 detector configuration
    detector_timeout_seconds: float = Field(default=5.0, gt=0.0, le=60.0)
    secret_excluded_fingerprints: list[str] = Field(default_factory=list)
    presidio_enabled: bool = True
    pii_languages: list[Literal["en", "de"]] = Field(default_factory=lambda: ["en", "de"])
    pii_entity_types: list[Literal["PERSON", "ORGANIZATION"]] = Field(
        default_factory=lambda: ["PERSON", "ORGANIZATION"]
    )
    presidio_model_names: dict[str, str] = Field(
        default_factory=lambda: {
            "en": "en_core_web_lg",
            "de": "de_core_news_lg",
        }
    )
    pii_minimum_confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    pii_detect_ip_addresses: bool = False
    custom_terms: list[CustomTermSettings] = Field(default_factory=list)

    @field_validator("secret_excluded_fingerprints")
    @classmethod
    def validate_secret_fingerprints(cls, values: list[str]) -> list[str]:
        if any(
            len(value) != 64 or any(char not in "0123456789abcdef" for char in value)
            for value in values
        ):
            raise ValueError("secret exclusions must be lower-case SHA-256 keyed fingerprints")
        return values

    @model_validator(mode="after")
    def validate_detector_configuration(self) -> Self:
        rule_ids = [rule.id for rule in self.custom_terms]
        if len(set(rule_ids)) != len(rule_ids):
            raise ValueError("custom term rule ids must be unique")
        if set(self.presidio_model_names) != set(self.pii_languages) or any(
            not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name)
            for name in self.presidio_model_names.values()
        ):
            raise ValueError("Presidio requires one safe local model name per language")
        return self

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
    def effective_fingerprint_key_path(self) -> Path:
        """Get the protected local key path for non-reversible finding fingerprints."""
        if self.fingerprint_key_path:
            return self.fingerprint_key_path
        return self.data_dir / "fingerprint.key"

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
