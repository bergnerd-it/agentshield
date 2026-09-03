"""SQLAlchemy 2 declarative models for AgentShield persistence."""

import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(UTC)


class Base(DeclarativeBase):
    """Base declarative class for all persistence models."""

    pass


class AppSetting(Base):
    """Key-value application settings overrides."""

    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value_json: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    def get_value(self) -> Any:
        return json.loads(self.value_json)

    def set_value(self, val: Any) -> None:
        self.value_json = json.dumps(val)


class SecurityPolicy(Base):
    """Versioned security policy configuration."""

    __tablename__ = "security_policies"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    profile: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    rules_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class IntegrationConfig(Base):
    """Coding-agent integration metadata and configuration backups."""

    __tablename__ = "integration_configs"

    agent_type: Mapped[str] = mapped_column(String(64), primary_key=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="not_configured")
    last_backup_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    config_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class AuditEvent(Base):
    """Privacy-preserving audit log events."""

    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True, nullable=False
    )
    request_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    session_id: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    agent: Mapped[str | None] = mapped_column(String(64), nullable=True)
    project: Mapped[str | None] = mapped_column(String(128), nullable=True)
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    endpoint: Mapped[str] = mapped_column(String(128), nullable=False)
    direction: Mapped[str] = mapped_column(String(16), nullable=False)  # REQUEST / RESPONSE
    action: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # ALLOW, WARN, REDACT, REQUIRE_APPROVAL, BLOCK
    rule_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    finding_counts_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
