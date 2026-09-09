"""Offset-safe, non-reversible Milestone 3 redaction tests."""

from agentshield.filtering.models import Finding, FindingCategory, FindingLocation, Severity
from agentshield.filtering.redaction.service import redact_payload


def _finding(
    *, start: int, end: int, category: FindingCategory, severity: Severity, replacement: str
) -> Finding:
    text = "abcdefghij"[start:end]
    return Finding.create(
        category=category,
        severity=severity,
        detector_id=f"detector-{category.value}",
        detector_version="1.0.0",
        location=FindingLocation(path=("input",), start=start, end=end),
        confidence=1.0,
        fingerprint_key=b"test-fingerprint-key",
        detected_text=text,
        suggested_replacement=replacement,
    )


def test_redaction_replaces_from_end_and_handles_adjacent_findings() -> None:
    payload = {"input": "abcdefghij", "model": "unchanged", "unknown": 42}
    findings = (
        _finding(
            start=0,
            end=3,
            category=FindingCategory.PII_EMAIL,
            severity=Severity.HIGH,
            replacement="[EMAIL]",
        ),
        _finding(
            start=3,
            end=6,
            category=FindingCategory.CUSTOM_TERM,
            severity=Severity.MEDIUM,
            replacement="[TERM]",
        ),
    )

    redacted = redact_payload(payload, findings)

    assert redacted == {"input": "[EMAIL][TERM]ghij", "model": "unchanged", "unknown": 42}


def test_overlapping_findings_choose_severity_then_category_deterministically() -> None:
    payload = {"input": "abcdefghij"}
    findings = (
        _finding(
            start=1,
            end=7,
            category=FindingCategory.CUSTOM_TERM,
            severity=Severity.MEDIUM,
            replacement="[TERM]",
        ),
        _finding(
            start=3,
            end=8,
            category=FindingCategory.PII_EMAIL,
            severity=Severity.HIGH,
            replacement="[EMAIL]",
        ),
    )

    assert redact_payload(payload, findings)["input"] == "abc[EMAIL]ij"
