"""Security invariants for provider-independent filtering models."""

from dataclasses import FrozenInstanceError

import pytest

from agentshield.filtering.models import (
    Finding,
    FindingCategory,
    FindingLocation,
    Severity,
)


def test_finding_validates_offsets_and_hides_content() -> None:
    location = FindingLocation(path=("messages", 0, "content"), start=4, end=12)
    finding = Finding.create(
        category=FindingCategory.SECRET_API_KEY,
        severity=Severity.CRITICAL,
        detector_id="secret-patterns",
        detector_version="1.0.0",
        location=location,
        confidence=1.0,
        fingerprint_key=b"test-fingerprint-key",
        detected_text="synth-sensitive-marker",
        metadata={"pattern": "provider-api-key"},
    )

    representation = repr(finding)
    assert "synth-sensitive-marker" not in representation
    assert finding.fingerprint != "synth-sensitive-marker"
    assert len(finding.fingerprint) == 64
    with pytest.raises(FrozenInstanceError):
        finding.confidence = 0.5  # type: ignore[misc]


@pytest.mark.parametrize(
    ("start", "end"),
    [(-1, 2), (2, 2), (3, 2), (None, 2), (2, None)],
)
def test_location_rejects_invalid_offset_pairs(start: int | None, end: int | None) -> None:
    with pytest.raises(ValueError, match="offset"):
        FindingLocation(path=("input",), start=start, end=end)


def test_finding_rejects_out_of_range_confidence_without_echoing_content() -> None:
    with pytest.raises(ValueError, match="confidence") as exc_info:
        Finding.create(
            category=FindingCategory.PII_EMAIL,
            severity=Severity.HIGH,
            detector_id="structured-pii",
            detector_version="1.0.0",
            location=FindingLocation(path=("input",), start=0, end=5),
            confidence=1.1,
            fingerprint_key=b"test-fingerprint-key",
            detected_text="unique-sensitive-value",
        )

    assert "unique-sensitive-value" not in str(exc_info.value)
