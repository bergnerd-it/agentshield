"""Ordered detector execution with explicit sanitized failure results."""

import asyncio
from collections.abc import Iterable

from agentshield.filtering.models import (
    DetectionReport,
    Detector,
    DetectorFailure,
    Finding,
    ScanContext,
)


class DetectorEngine:
    """Run detectors in declaration order and never convert errors to clean scans."""

    def __init__(self, detectors: Iterable[Detector], timeout_seconds: float) -> None:
        if timeout_seconds <= 0:
            raise ValueError("detector timeout must be positive")
        self.detectors = tuple(detectors)
        self.timeout_seconds = timeout_seconds

    async def scan(self, context: ScanContext) -> DetectionReport:
        findings: list[Finding] = []
        failures: list[DetectorFailure] = []
        for detector in self.detectors:
            try:
                result = await asyncio.wait_for(
                    detector.detect(context), timeout=self.timeout_seconds
                )
                findings.extend(result)
            except TimeoutError:
                failures.append(
                    DetectorFailure(
                        detector_id=detector.detector_id,
                        detector_version=detector.detector_version,
                        required=detector.required,
                        code="timeout",
                    )
                )
            except Exception:  # Detector adapter boundary; details may contain inspected data.
                failures.append(
                    DetectorFailure(
                        detector_id=detector.detector_id,
                        detector_version=detector.detector_version,
                        required=detector.required,
                        code="unavailable",
                    )
                )
        return DetectionReport(findings=tuple(findings), failures=tuple(failures))
