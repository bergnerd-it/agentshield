"""Provider-neutral request inspection orchestration before credential access."""

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from agentshield.filtering.detectors.secrets import SecretDetector
from agentshield.filtering.engine import DetectorEngine
from agentshield.filtering.models import (
    DetectionReport,
    DetectorFailure,
    ScanContext,
    ScanDirection,
    ScanTarget,
)
from agentshield.filtering.redaction import redact_payload
from agentshield.policies.engine import PolicyEngine
from agentshield.policies.models import PolicyAction, PolicyDecision
from agentshield.proxy.scanning import build_request_scan_context
from agentshield.proxy.types import LOCAL_AUTH_HEADERS, Provider

_SAFE_HEADER_NAMES = frozenset(
    {
        "accept",
        "accept-encoding",
        "connection",
        "content-encoding",
        "content-length",
        "content-type",
        "host",
        "user-agent",
        "anthropic-beta",
        "anthropic-version",
        "openai-organization",
        "openai-project",
        "x-agentshield-loop-detection",
    }
)


@dataclass(frozen=True, slots=True)
class InspectionResult:
    payload: dict[str, Any]
    report: DetectionReport
    decision: PolicyDecision


class RequestInspectionPipeline:
    """Normalize, detect, decide, and irreversibly redact supported request text."""

    def __init__(
        self,
        *,
        detector_engine: DetectorEngine,
        policy_engine: PolicyEngine,
        header_secret_detector: SecretDetector,
    ) -> None:
        self.detector_engine = detector_engine
        self.policy_engine = policy_engine
        self.header_secret_detector = header_secret_detector

    @staticmethod
    def _header_context(
        provider: Provider,
        endpoint: str,
        headers: Mapping[str, str],
    ) -> ScanContext:
        targets = tuple(
            ScanTarget(path=("$headers", key.casefold()), text=value)
            for key, value in sorted(headers.items(), key=lambda item: item[0].casefold())
            if key.casefold() not in LOCAL_AUTH_HEADERS and key.casefold() not in _SAFE_HEADER_NAMES
        )
        return ScanContext(
            provider=provider.value,
            endpoint=endpoint,
            direction=ScanDirection.REQUEST,
            targets=targets,
        )

    async def _scan_headers(
        self,
        provider: Provider,
        endpoint: str,
        headers: Mapping[str, str],
    ) -> DetectionReport:
        try:
            findings = await asyncio.wait_for(
                self.header_secret_detector.detect(
                    self._header_context(provider, endpoint, headers)
                ),
                timeout=self.detector_engine.timeout_seconds,
            )
            return DetectionReport(findings=findings)
        except TimeoutError:
            code = "timeout"
        except Exception:  # Secret-detector boundary; never retain exception text.
            code = "unavailable"
        return DetectionReport(
            failures=(
                DetectorFailure(
                    detector_id=self.header_secret_detector.detector_id,
                    detector_version=self.header_secret_detector.detector_version,
                    required=True,
                    code=code,
                ),
            )
        )

    async def inspect(
        self,
        *,
        provider: Provider,
        endpoint: str,
        payload: dict[str, Any],
        headers: Mapping[str, str],
    ) -> InspectionResult:
        context = build_request_scan_context(provider, endpoint, payload)
        header_report = await self._scan_headers(provider, endpoint, headers)
        payload_report = await self.detector_engine.scan(context)
        report = DetectionReport(
            findings=header_report.findings + payload_report.findings,
            failures=header_report.failures + payload_report.failures,
        )
        decision = self.policy_engine.evaluate(context, report)
        transformed = payload
        if decision.action is PolicyAction.REDACT:
            redactions = tuple(
                item.finding
                for item in decision.finding_actions
                if item.action is PolicyAction.REDACT
                and item.finding.location.path[:1] != ("$headers",)
            )
            transformed = redact_payload(payload, redactions)
        return InspectionResult(payload=transformed, report=report, decision=decision)
