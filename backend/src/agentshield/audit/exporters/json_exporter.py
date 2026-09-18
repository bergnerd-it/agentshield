"""Sanitized JSON export formatter for privacy-preserving audit events."""

import json
from datetime import UTC, datetime
from typing import Any

from agentshield import __version__


def export_json(
    events: list[dict[str, Any]],
    filters: dict[str, Any] | None = None,
) -> str:
    """Format sanitized audit events into a structured JSON export document."""
    now = datetime.now(UTC).isoformat()
    envelope = {
        "export_metadata": {
            "generated_at": now,
            "agentshield_version": __version__,
            "filters": {k: v for k, v in (filters or {}).items() if v is not None},
            "total_events": len(events),
            "notice": (
                "Privacy-Preserving Audit Report - Raw prompts, LLM responses, "
                "and detected secrets are strictly excluded by design."
            ),
        },
        "events": events,
    }
    return json.dumps(envelope, indent=2, ensure_ascii=False)
