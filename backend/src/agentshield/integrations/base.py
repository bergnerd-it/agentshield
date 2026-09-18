"""Base protocols, dataclasses, and abstract adapter for coding-agent integrations."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class IntegrationStatus:
    """Current detection and configuration status of an agent integration."""

    agent_type: str
    configured: bool
    config_path: str
    proxy_url: str
    has_token: bool
    last_backup_path: str | None = None
    updated_at: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class ConfigDiff:
    """Structured unified diff preview of configuration changes."""

    agent_type: str
    config_path: str
    original_content: str
    modified_content: str
    unified_diff: str
    has_changes: bool


class BaseIntegrationAdapter(ABC):
    """Abstract base class for coding agent configuration adapters."""

    agent_type: str
    default_config_path: Path
    proxy_url: str

    @abstractmethod
    def detect(self, config_path: Path | None = None) -> IntegrationStatus:
        """Detect whether the local agent configuration points to AgentShield."""
        ...

    @abstractmethod
    def preview(self, token: str, config_path: Path | None = None) -> ConfigDiff:
        """Generate a unified diff preview of proposed configuration changes."""
        ...

    @abstractmethod
    def render_config(self, token: str, existing_content: str | None) -> str:
        """Render new configuration content preserving existing unrelated settings."""
        ...
