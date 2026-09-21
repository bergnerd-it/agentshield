"""Privacy-preserving audit export service and data serialization."""

import contextlib
import json
from datetime import UTC, datetime
from typing import Any, Literal

from agentshield.audit.exporters.html_exporter import export_html
from agentshield.audit.exporters.json_exporter import export_json
from agentshield.persistence.models import AuditEvent
from agentshield.persistence.repository import AuditRepository

# Strict allowlist of safe metadata keys
SAFE_METADATA_KEYS = frozenset(
    {
        "duration_ms",
        "request_size",
        "response_size",
        "proxy_overhead_ms",
        "status_code",
        "sha256_fingerprint",
        "detectors",
        "policy_version",
        "error_class",
        "approval_status",
        "reason",
        "streaming",
    }
)


class AuditExportService:
    """Service coordinates querying, sanitization, and exporting of audit records."""

    def __init__(self, repo: AuditRepository) -> None:
        self.repo = repo

    @staticmethod
    def sanitize_event(event: AuditEvent) -> dict[str, Any]:
        """Convert an AuditEvent model to an allowlisted sanitized dictionary."""
        finding_counts: dict[str, int] = {}
        if event.finding_counts_json:
            with contextlib.suppress(Exception):
                finding_counts = json.loads(event.finding_counts_json)

        raw_metadata: dict[str, Any] = {}
        if event.metadata_json:
            with contextlib.suppress(Exception):
                raw_metadata = json.loads(event.metadata_json)

        # Allowlist filter metadata strictly
        sanitized_metadata: dict[str, Any] = {
            k: v for k, v in raw_metadata.items() if k in SAFE_METADATA_KEYS
        }

        return {
            "id": event.id,
            "timestamp": event.timestamp.isoformat(),
            "request_id": event.request_id,
            "session_id": event.session_id,
            "agent": event.agent,
            "project": event.project,
            "provider": event.provider,
            "model": event.model,
            "endpoint": event.endpoint,
            "direction": event.direction,
            "action": event.action,
            "rule_id": event.rule_id,
            "finding_counts": finding_counts,
            "metadata": sanitized_metadata,
        }

    def export(
        self,
        export_format: Literal["json", "html"] = "json",
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        agent: str | None = None,
        provider: str | None = None,
        action: str | None = None,
        project: str | None = None,
        limit: int = 10000,
    ) -> tuple[str, str, str]:
        """Query audit records and render exported artifact.

        Returns:
            tuple of (rendered_content, filename, media_type)
        """
        events = self.repo.list_events(
            limit=limit,
            offset=0,
            action=action,
            provider=provider,
            agent=agent,
            project=project,
            start_time=start_time,
            end_time=end_time,
        )
        sanitized_events = [self.sanitize_event(e) for e in events]

        filters: dict[str, Any] = {
            "start_time": start_time.isoformat() if start_time else None,
            "end_time": end_time.isoformat() if end_time else None,
            "agent": agent,
            "provider": provider,
            "action": action,
            "project": project,
        }

        timestamp_str = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        if export_format == "html":
            content = export_html(sanitized_events, filters=filters)
            filename = f"agentshield-audit-{timestamp_str}.html"
            media_type = "text/html; charset=utf-8"
        elif export_format == "json":
            content = export_json(sanitized_events, filters=filters)
            filename = f"agentshield-audit-{timestamp_str}.json"
            media_type = "application/json; charset=utf-8"
        else:
            raise ValueError(f"Unsupported export format: {export_format}")

        return content, filename, media_type
