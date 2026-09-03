"""Tests for SQLite persistence, WAL configuration, Alembic migrations, and repositories."""

import os
import sys
from pathlib import Path

from sqlalchemy import text

from agentshield.persistence.db import create_db_engine, get_db_session, run_migrations
from agentshield.persistence.models import AuditEvent, IntegrationConfig, SecurityPolicy
from agentshield.persistence.repository import (
    AuditRepository,
    IntegrationRepository,
    PolicyRepository,
    SettingsRepository,
)


def test_sqlite_wal_mode_and_pragmas(temp_data_dir: Path) -> None:
    """Verify SQLite initializes with WAL mode, foreign keys, and busy timeout."""
    db_url = f"sqlite:///{temp_data_dir / 'test_wal.db'}"
    run_migrations(db_url)
    engine = create_db_engine(db_url)

    with engine.connect() as conn:
        wal = conn.execute(text("PRAGMA journal_mode")).scalar()
        fk = conn.execute(text("PRAGMA foreign_keys")).scalar()
        busy = conn.execute(text("PRAGMA busy_timeout")).scalar()

        assert str(wal).lower() == "wal"
        assert fk == 1
        assert busy == 5000

    # Test file permission 0600 on POSIX
    db_file = temp_data_dir / "test_wal.db"
    if sys.platform != "win32" and hasattr(os, "stat"):
        mode = oct(db_file.stat().st_mode)[-3:]
        assert mode == "600"


def test_settings_repository_crud() -> None:
    """Verify SettingsRepository sets, gets, and lists configuration key-values."""
    with get_db_session() as session:
        repo = SettingsRepository(session)
        repo.set_setting("max_request_size_bytes", 10485760)
        repo.set_setting("features_enabled", {"mock_server": True, "strict_mode": False})

        val1 = repo.get_setting("max_request_size_bytes")
        val2 = repo.get_setting("features_enabled")

        assert val1 == 10485760
        assert val2 == {"mock_server": True, "strict_mode": False}

        all_settings = repo.list_all()
        assert "max_request_size_bytes" in all_settings


def test_policy_and_integration_repositories() -> None:
    """Verify PolicyRepository and IntegrationRepository operate properly."""
    with get_db_session() as session:
        # Policy
        pol_repo = PolicyRepository(session)
        pol = SecurityPolicy(
            id="pol_balanced_01",
            name="Default Balanced Policy",
            profile="balanced",
            is_active=True,
            version="1.0.0",
            rules_json="[]",
        )
        pol_repo.save_policy(pol)

        loaded = pol_repo.get_active_policy_by_profile("balanced")
        assert loaded is not None
        assert loaded.id == "pol_balanced_01"

        # Integration
        integ_repo = IntegrationRepository(session)
        integ = IntegrationConfig(
            agent_type="codex",
            status="configured",
            last_backup_path="/path/to/backup.toml",
            config_json='{"endpoint": "http://127.0.0.1:8765"}',
        )
        integ_repo.save_integration(integ)

        loaded_integ = integ_repo.get_integration("codex")
        assert loaded_integ is not None
        assert loaded_integ.status == "configured"


def test_audit_repository_logging() -> None:
    """Verify AuditRepository records privacy-preserving metadata events."""
    with get_db_session() as session:
        audit_repo = AuditRepository(session)
        event = AuditEvent(
            id="evt-1234-uuid-test",
            request_id="req-9876",
            session_id="sess-001",
            agent="codex",
            provider="openai",
            model="gpt-4o",
            endpoint="/v1/chat/completions",
            direction="REQUEST",
            action="BLOCK",
            rule_id="rule-block-synthetic-keys",
            finding_counts_json='{"secret": 1}',
            metadata_json='{"content_fingerprint": "a1b2c3d4"}',
        )
        audit_repo.record_event(event)

        events = audit_repo.list_events(action="BLOCK")
        assert len(events) >= 1
        assert events[0].request_id == "req-9876"
        assert events[0].action == "BLOCK"
