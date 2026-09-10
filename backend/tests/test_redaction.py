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


def test_redaction_with_pseudonym_vault_registers_and_replaces() -> None:
    from agentshield.pseudonyms.vault import InMemoryPseudonymVault

    vault = InMemoryPseudonymVault()
    payload = {"input": "alice and alice and bob"}
    findings = (
        Finding.create(
            category=FindingCategory.PII_PERSON,
            severity=Severity.HIGH,
            detector_id="pii-person",
            detector_version="1.0.0",
            location=FindingLocation(path=("input",), start=0, end=5),
            confidence=0.9,
            fingerprint_key=b"k" * 32,
            detected_text="alice",
            suggested_replacement="[PERSON]",
        ),
        Finding.create(
            category=FindingCategory.PII_PERSON,
            severity=Severity.HIGH,
            detector_id="pii-person",
            detector_version="1.0.0",
            location=FindingLocation(path=("input",), start=10, end=15),
            confidence=0.9,
            fingerprint_key=b"k" * 32,
            detected_text="alice",
            suggested_replacement="[PERSON]",
        ),
        Finding.create(
            category=FindingCategory.PII_PERSON,
            severity=Severity.HIGH,
            detector_id="pii-person",
            detector_version="1.0.0",
            location=FindingLocation(path=("input",), start=20, end=23),
            confidence=0.9,
            fingerprint_key=b"k" * 32,
            detected_text="bob",
            suggested_replacement="[PERSON]",
        ),
    )

    redacted = redact_payload(payload, findings, vault=vault, session_id="sess_test")
    text = redacted["input"]
    assert "alice" not in text
    assert "bob" not in text
    # Both "alice" occurrences should have the same placeholder
    ph_alice = vault.get_or_create(
        session_id="sess_test", original_value="alice", category=FindingCategory.PII_PERSON
    )
    ph_bob = vault.get_or_create(
        session_id="sess_test", original_value="bob", category=FindingCategory.PII_PERSON
    )
    assert ph_alice != ph_bob
    assert text == f"{ph_alice} and {ph_alice} and {ph_bob}"
