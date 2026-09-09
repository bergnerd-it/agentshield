"""Unsupported binary and multimodal payload detector."""

from agentshield.filtering.models import (
    Finding,
    FindingCategory,
    FindingLocation,
    ScanContext,
    Severity,
)


class UnsupportedContentDetector:
    detector_id = "unsupported-content"
    detector_version = "1.0.0"
    required = True

    def __init__(self, *, fingerprint_key: bytes) -> None:
        self.fingerprint_key = fingerprint_key

    async def detect(self, context: ScanContext) -> tuple[Finding, ...]:
        return tuple(
            Finding.create(
                category=FindingCategory.UNSUPPORTED_CONTENT,
                severity=Severity.HIGH,
                detector_id=self.detector_id,
                detector_version=self.detector_version,
                location=FindingLocation(path=item.path),
                confidence=1.0,
                fingerprint_key=self.fingerprint_key,
                detected_text=item.content_type,
                metadata={"content_type": item.content_type},
            )
            for item in context.unsupported_content
        )
