"""Structured PII and Presidio normalization tests without model downloads."""

import importlib.util
from dataclasses import dataclass
from typing import cast

import pytest

from agentshield.filtering.detectors.pii import (
    PresidioAnalyzer,
    PresidioDetector,
    PresidioDetectorConfig,
    StructuredPiiDetector,
    StructuredPiiDetectorConfig,
)
from agentshield.filtering.engine import DetectorEngine
from agentshield.filtering.models import FindingCategory, ScanContext, ScanDirection, ScanTarget


def _context(text: str) -> ScanContext:
    return ScanContext(
        provider="anthropic",
        endpoint="/v1/messages",
        direction=ScanDirection.REQUEST,
        targets=(ScanTarget(path=("messages", 0, "content"), text=text),),
    )


@pytest.mark.asyncio
async def test_structured_pii_positive_unicode_and_configurable_ip() -> None:
    text = (
        "Kontakt: fictional.person@example.invalid, +49 30 00000000, "
        "DE36 0000 0000 0000 0000 00, 192.0.2.42 - Grüße"
    )
    detector = StructuredPiiDetector(
        fingerprint_key=b"test-key",
        config=StructuredPiiDetectorConfig(detect_ip_addresses=True),
    )

    findings = await detector.detect(_context(text))

    assert {finding.category for finding in findings} == {
        FindingCategory.PII_EMAIL,
        FindingCategory.PII_PHONE,
        FindingCategory.PII_IBAN,
        FindingCategory.PII_IP_ADDRESS,
    }
    assert text not in repr(findings)


@pytest.mark.asyncio
async def test_structured_pii_false_positives_and_ip_default() -> None:
    text = "not-an-email, 999999, DE00 0000 0000 0000 0000 00, 192.0.2.42"
    findings = await StructuredPiiDetector(fingerprint_key=b"test-key").detect(_context(text))

    assert findings == ()


@dataclass(frozen=True)
class _Result:
    entity_type: str
    start: int
    end: int
    score: float


class _FakeAnalyzer:
    def __init__(self) -> None:
        self.calls: list[tuple[tuple[str, ...], str]] = []

    def analyze(self, *, text: str, entities: list[str], language: str) -> list[_Result]:
        self.calls.append((tuple(entities), language))
        if language == "en":
            return [_Result("PERSON", 0, 14, 0.88)]
        return [_Result("ORGANIZATION", 19, 33, 0.77)]


class _UnavailableAnalyzer:
    def analyze(self, *, text: str, entities: list[str], language: str) -> list[_Result]:
        del text, entities, language
        raise RuntimeError("SyntheticConfidentialDetectorDetail")


@pytest.mark.asyncio
async def test_presidio_results_normalize_for_english_and_german() -> None:
    analyzer = _FakeAnalyzer()
    detector = PresidioDetector(
        fingerprint_key=b"test-key",
        analyzer=cast(PresidioAnalyzer, analyzer),
        config=PresidioDetectorConfig(languages=("en", "de")),
    )
    text = "Fictional Name at Beispiel Gruppe"

    findings = await detector.detect(_context(text))

    assert [finding.category for finding in findings] == [
        FindingCategory.PII_PERSON,
        FindingCategory.PII_ORGANIZATION,
    ]
    assert analyzer.calls == [
        (("PERSON", "ORGANIZATION"), "en"),
        (("PERSON", "ORGANIZATION"), "de"),
    ]
    assert all(finding.detector_id == "presidio-pii" for finding in findings)
    assert text not in repr(findings)


@pytest.mark.asyncio
async def test_unavailable_presidio_is_an_explicit_sanitized_failure() -> None:
    detector = PresidioDetector(
        fingerprint_key=b"test-key",
        analyzer=cast(PresidioAnalyzer, _UnavailableAnalyzer()),
    )

    report = await DetectorEngine((detector,), timeout_seconds=0.5).scan(
        _context("SyntheticConfidentialDetectorDetail")
    )

    assert report.findings == ()
    assert report.failures[0].code == "unavailable"
    assert "SyntheticConfidentialDetectorDetail" not in repr(report.failures)


@pytest.mark.asyncio
async def test_missing_local_models_fail_without_invoking_runtime_download(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested_models: list[str] = []

    def _missing_model(name: str, package: str | None = None) -> None:
        del package
        requested_models.append(name)

    monkeypatch.setattr(importlib.util, "find_spec", _missing_model)
    detector = PresidioDetector(fingerprint_key=b"test-key")

    report = await DetectorEngine((detector,), timeout_seconds=0.5).scan(_context("clean text"))

    assert requested_models == ["en_core_web_lg"]
    assert report.findings == ()
    assert report.failures[0].code == "unavailable"
