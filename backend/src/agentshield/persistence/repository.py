"""Repository data access objects isolating SQLAlchemy models from API handlers."""

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agentshield.persistence.models import AppSetting, AuditEvent, IntegrationConfig, SecurityPolicy


class SettingsRepository:
    """Data access repository for application settings."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def get_setting(self, key: str) -> Any | None:
        setting = self.session.get(AppSetting, key)
        return setting.get_value() if setting else None

    def set_setting(self, key: str, value: Any) -> AppSetting:
        setting = self.session.get(AppSetting, key)
        if not setting:
            setting = AppSetting(key=key)
            self.session.add(setting)
        setting.set_value(value)
        self.session.flush()
        return setting

    def list_all(self) -> dict[str, Any]:
        stmt = select(AppSetting)
        settings = self.session.scalars(stmt).all()
        return {s.key: s.get_value() for s in settings}


class PolicyRepository:
    """Data access repository for security policies."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def get_policy(self, policy_id: str) -> SecurityPolicy | None:
        return self.session.get(SecurityPolicy, policy_id)

    def get_active_policy_by_profile(self, profile: str) -> SecurityPolicy | None:
        stmt = select(SecurityPolicy).where(
            SecurityPolicy.profile == profile,
            SecurityPolicy.is_active.is_(True),
        )
        return self.session.scalars(stmt).first()

    def list_policies(self, profile: str | None = None) -> list[SecurityPolicy]:
        stmt = select(SecurityPolicy)
        if profile:
            stmt = stmt.where(SecurityPolicy.profile == profile)
        return list(self.session.scalars(stmt).all())

    def save_policy(self, policy: SecurityPolicy) -> SecurityPolicy:
        self.session.add(policy)
        self.session.flush()
        return policy


class IntegrationRepository:
    """Data access repository for coding-agent integrations."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def get_integration(self, agent_type: str) -> IntegrationConfig | None:
        return self.session.get(IntegrationConfig, agent_type)

    def list_integrations(self) -> list[IntegrationConfig]:
        stmt = select(IntegrationConfig)
        return list(self.session.scalars(stmt).all())

    def save_integration(self, integration: IntegrationConfig) -> IntegrationConfig:
        self.session.add(integration)
        self.session.flush()
        return integration


class AuditRepository:
    """Data access repository for privacy-preserving audit events."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def record_event(self, event: AuditEvent) -> AuditEvent:
        self.session.add(event)
        self.session.flush()
        return event

    def get_event(self, event_id: str) -> AuditEvent | None:
        return self.session.get(AuditEvent, event_id)

    def count_events(
        self,
        action: str | None = None,
        provider: str | None = None,
        agent: str | None = None,
        project: str | None = None,
    ) -> int:
        stmt = select(func.count()).select_from(AuditEvent)
        if action:
            stmt = stmt.where(AuditEvent.action == action)
        if provider:
            stmt = stmt.where(AuditEvent.provider == provider)
        if agent:
            stmt = stmt.where(AuditEvent.agent == agent)
        if project:
            stmt = stmt.where(AuditEvent.project == project)
        count = self.session.scalar(stmt)
        return int(count or 0)

    def list_events(
        self,
        limit: int = 50,
        offset: int = 0,
        action: str | None = None,
        provider: str | None = None,
        agent: str | None = None,
        project: str | None = None,
    ) -> list[AuditEvent]:
        stmt = select(AuditEvent).order_by(AuditEvent.timestamp.desc())
        if action:
            stmt = stmt.where(AuditEvent.action == action)
        if provider:
            stmt = stmt.where(AuditEvent.provider == provider)
        if agent:
            stmt = stmt.where(AuditEvent.agent == agent)
        if project:
            stmt = stmt.where(AuditEvent.project == project)
        stmt = stmt.offset(offset).limit(limit)
        return list(self.session.scalars(stmt).all())
