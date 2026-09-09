"""Detector ordering, failure, and timeout behavior."""

import asyncio

import pytest

from agentshield.filtering.engine import DetectorEngine
from agentshield.filtering.models import Finding, ScanContext, ScanDirection


class _Detector:
    detector_version = "1.0.0"
    required = True

    def __init__(self, detector_id: str, calls: list[str], *, delay: float = 0) -> None:
        self.detector_id = detector_id
        self.calls = calls
        self.delay = delay

    async def detect(self, context: ScanContext) -> tuple[Finding, ...]:
        del context
        self.calls.append(self.detector_id)
        if self.delay:
            await asyncio.sleep(self.delay)
        return ()


class _UnavailableDetector(_Detector):
    async def detect(self, context: ScanContext) -> tuple[Finding, ...]:
        del context
        self.calls.append(self.detector_id)
        raise RuntimeError("synthetic confidential error detail")


@pytest.mark.asyncio
async def test_detectors_run_in_declared_order_and_failures_are_sanitized() -> None:
    calls: list[str] = []
    engine = DetectorEngine(
        detectors=(
            _Detector("secret-patterns", calls),
            _UnavailableDetector("presidio-pii", calls),
            _Detector("custom-terms", calls),
        ),
        timeout_seconds=0.1,
    )
    context = ScanContext(
        provider="openai", endpoint="/v1/responses", direction=ScanDirection.REQUEST, targets=()
    )

    report = await engine.scan(context)

    assert calls == ["secret-patterns", "presidio-pii", "custom-terms"]
    assert len(report.failures) == 1
    assert report.failures[0].code == "unavailable"
    assert "confidential" not in repr(report.failures)


@pytest.mark.asyncio
async def test_detector_timeout_is_explicit() -> None:
    calls: list[str] = []
    engine = DetectorEngine((_Detector("presidio-pii", calls, delay=0.1),), timeout_seconds=0.001)
    context = ScanContext(
        provider="openai", endpoint="/v1/responses", direction=ScanDirection.REQUEST, targets=()
    )

    report = await engine.scan(context)

    assert report.failures[0].code == "timeout"
