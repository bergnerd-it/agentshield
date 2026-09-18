"""Tests for privacy-preserving audit query, serialization, and export in JSON and HTML."""

import json
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from sqlalchemy.orm import Session

from agentshield.api.app import create_app
from agentshield.audit.service import AuditExportService
from agentshield.core.auth import get_or_create_admin_token
from agentshield.core.config import Settings
from agentshield.persistence.db import get_session_factory
from agentshield.persistence.models import AuditEvent
from agentshield.persistence.repository import AuditRepository


@pytest.fixture
def audit_db(temp_data_dir: Path, test_settings: Settings) -> Generator[Session]:
    """Create a temporary database session populated with diverse audit events."""
    factory = get_session_factory()
    session = factory()
    repo = AuditRepository(session)

    base_time = datetime(2026, 9, 15, 10, 0, 0, tzinfo=UTC)

    # 1. Allowed request
    repo.record_event(
        AuditEvent(
            id=uuid4().hex,
            timestamp=base_time,
            request_id="req-allow-1",
            session_id="sess-1",
            agent="codex",
            project="backend-api",
            provider="openai",
            model="gpt-4o",
            endpoint="/v1/chat/completions",
            direction="REQUEST",
            action="ALLOW",
            rule_id=None,
            finding_counts_json=json.dumps({}),
            metadata_json=json.dumps(
                {
                    "duration_ms": 120.5,
                    "status_code": 200,
                    "request_size": 350,
                    "response_size": 520,
                    "proxy_overhead_ms": 3.2,
                    "sha256_fingerprint": "a" * 64,
                }
            ),
        )
    )

    # 2. Blocked request with secret detector finding
    repo.record_event(
        AuditEvent(
            id=uuid4().hex,
            timestamp=base_time + timedelta(hours=1),
            request_id="req-block-1",
            session_id="sess-2",
            agent="claude-code",
            project="frontend-ui",
            provider="anthropic",
            model="claude-3-5-sonnet",
            endpoint="/v1/messages",
            direction="REQUEST",
            action="BLOCK",
            rule_id="builtin-secret-block",
            finding_counts_json=json.dumps({"SECRET_OPENAI_KEY": 1}),
            metadata_json=json.dumps(
                {
                    "duration_ms": 15.0,
                    "status_code": 403,
                    "request_size": 280,
                    "response_size": 0,
                    "proxy_overhead_ms": 14.5,
                    "sha256_fingerprint": "b" * 64,
                    "detectors": [
                        {
                            "detector_id": "secret-detector",
                            "confidence": 1.0,
                            "category": "SECRET_OPENAI_KEY",
                        }
                    ],
                    "error_class": "ContentBlockedError",
                    # Deliberately include an unsafe key to verify it is stripped
                    "raw_prompt": "UNSAFE_PROMPT_DO_NOT_LEAK",
                }
            ),
        )
    )

    # 3. Redacted request
    repo.record_event(
        AuditEvent(
            id=uuid4().hex,
            timestamp=base_time + timedelta(hours=2),
            request_id="req-redact-1",
            session_id="sess-3",
            agent="codex",
            project="backend-api",
            provider="openai",
            model="gpt-4o",
            endpoint="/v1/chat/completions",
            direction="REQUEST",
            action="REDACT",
            rule_id="pii-redact-rule",
            finding_counts_json=json.dumps({"PII_EMAIL": 2}),
            metadata_json=json.dumps(
                {
                    "duration_ms": 250.0,
                    "status_code": 200,
                    "request_size": 410,
                    "response_size": 390,
                    "proxy_overhead_ms": 8.0,
                    "sha256_fingerprint": "c" * 64,
                }
            ),
        )
    )

    # 4. Manual approval request
    repo.record_event(
        AuditEvent(
            id=uuid4().hex,
            timestamp=base_time + timedelta(hours=3),
            request_id="req-approval-1",
            session_id="sess-4",
            agent="custom-agent",
            project="infra",
            provider="openai",
            model="gpt-4o",
            endpoint="/v1/chat/completions",
            direction="REQUEST",
            action="REQUIRE_APPROVAL",
            rule_id="approval-term-rule",
            finding_counts_json=json.dumps({"CUSTOM_TERM": 1}),
            metadata_json=json.dumps(
                {
                    "duration_ms": 1500.0,
                    "status_code": 200,
                    "request_size": 180,
                    "response_size": 220,
                    "proxy_overhead_ms": 5.0,
                    "approval_status": "approved",
                }
            ),
        )
    )

    session.commit()
    yield session
    session.close()


def test_audit_repository_date_and_attribute_filtering(audit_db: Session) -> None:
    """Verify repository filtering by timestamp range, action, provider, and agent."""
    repo = AuditRepository(audit_db)

    # Total count
    assert repo.count_events() == 4

    # Filter by action
    assert repo.count_events(action="BLOCK") == 1
    assert repo.count_events(action="ALLOW") == 1

    # Filter by agent
    assert repo.count_events(agent="codex") == 2
    assert repo.count_events(agent="claude-code") == 1

    # Filter by date range
    t_start = datetime(2026, 9, 15, 10, 30, 0, tzinfo=UTC)
    t_end = datetime(2026, 9, 15, 12, 30, 0, tzinfo=UTC)
    events_in_range = repo.list_events(start_time=t_start, end_time=t_end)
    assert len(events_in_range) == 2
    assert {e.action for e in events_in_range} == {"BLOCK", "REDACT"}


def test_audit_export_service_json_serialization_and_allowlist(audit_db: Session) -> None:
    """Verify JSON export adheres to strict metadata allowlist and strips prohibited keys."""
    repo = AuditRepository(audit_db)
    service = AuditExportService(repo)

    content, filename, media_type = service.export(export_format="json")

    assert filename.startswith("agentshield-audit-")
    assert filename.endswith(".json")
    assert media_type == "application/json; charset=utf-8"

    data = json.loads(content)
    assert "export_metadata" in data
    assert data["export_metadata"]["total_events"] == 4
    assert "notice" in data["export_metadata"]

    events = data["events"]
    assert len(events) == 4

    # Find the blocked event and assert prohibited key 'raw_prompt' was stripped
    blocked_ev = next(e for e in events if e["action"] == "BLOCK")
    assert "raw_prompt" not in blocked_ev["metadata"]
    assert "UNSAFE_PROMPT_DO_NOT_LEAK" not in content
    assert blocked_ev["metadata"]["status_code"] == 403
    assert blocked_ev["finding_counts"] == {"SECRET_OPENAI_KEY": 1}


def test_audit_export_service_html_standalone_generation(audit_db: Session) -> None:
    """Verify HTML export produces self-contained report with metrics and no CDNs."""
    repo = AuditRepository(audit_db)
    service = AuditExportService(repo)

    content, filename, media_type = service.export(export_format="html", agent="codex")

    assert filename.startswith("agentshield-audit-")
    assert filename.endswith(".html")
    assert media_type == "text/html; charset=utf-8"

    # Verify self-contained structure and styling
    assert "<!DOCTYPE html>" in content
    assert "🛡️ AgentShield Audit Report" in content
    assert "Privacy-Preserving Audit Guarantee" in content
    assert "Total Events" in content
    assert "Blocked" in content
    assert "Redacted" in content

    # Verify no external CDN links or unpinned scripts
    assert "cdn." not in content
    assert "http://" not in content or "http://www.w3.org" in content or "127.0.0.1" in content
    assert "https://" not in content  # Zero external https CDN or font imports

    # Filtered events check (only codex events: 2)
    assert "req-allow-1" in content
    assert "req-redact-1" in content
    assert "req-block-1" not in content  # Claude-code was filtered out


@pytest.mark.asyncio
async def test_audit_export_api_endpoint(test_settings: Settings, audit_db: Session) -> None:
    """Verify POST /api/v1/audit/export returns proper attachments with authentication."""
    app = create_app(test_settings)
    admin_token = get_or_create_admin_token(test_settings.effective_admin_token_path)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),  # pyright: ignore[reportArgumentType]
        base_url="http://127.0.0.1:8765",
    ) as client:
        # 1. Unauthenticated request rejected
        resp_unauth = await client.post("/api/v1/audit/export", json={"format": "json"})
        assert resp_unauth.status_code == 401

        # 2. Authenticated JSON export
        resp_json = await client.post(
            "/api/v1/audit/export",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"format": "json", "action": "BLOCK"},
        )
        assert resp_json.status_code == 200
        assert "application/json" in resp_json.headers["content-type"]
        disposition = resp_json.headers["content-disposition"]
        assert 'attachment; filename="agentshield-audit-' in disposition
        data = resp_json.json()
        assert data["export_metadata"]["total_events"] == 1
        assert data["events"][0]["action"] == "BLOCK"

        # 3. Authenticated HTML export
        resp_html = await client.post(
            "/api/v1/audit/export",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"format": "html"},
        )
        assert resp_html.status_code == 200
        assert "text/html" in resp_html.headers["content-type"]
        disposition_html = resp_html.headers["content-disposition"]
        assert 'attachment; filename="agentshield-audit-' in disposition_html
        assert "<!DOCTYPE html>" in resp_html.text
