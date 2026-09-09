"""Strongly typed, framework-independent detector domain models."""

import hashlib
import hmac
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from types import MappingProxyType
from typing import Protocol, Self
from uuid import UUID


class FindingCategory(StrEnum):
    """Stable finding categories used by policy and safe observability."""

    SECRET_API_KEY = "secret_api_key"
    SECRET_AWS_ACCESS_KEY = "secret_aws_access_key"
    SECRET_AWS_SECRET = "secret_aws_secret"
    SECRET_GITHUB_TOKEN = "secret_github_token"
    SECRET_BEARER_TOKEN = "secret_bearer_token"
    SECRET_JWT = "secret_jwt"
    SECRET_PRIVATE_KEY = "secret_private_key"
    SECRET_PASSWORD = "secret_password"
    SECRET_HIGH_ENTROPY = "secret_high_entropy"
    PII_EMAIL = "pii_email"
    PII_PHONE = "pii_phone"
    PII_IBAN = "pii_iban"
    PII_IP_ADDRESS = "pii_ip_address"
    PII_PERSON = "pii_person"
    PII_ORGANIZATION = "pii_organization"
    CUSTOM_TERM = "custom_term"
    UNSUPPORTED_CONTENT = "unsupported_content"

    @property
    def is_secret(self) -> bool:
        return self.value.startswith("secret_")

    @property
    def is_pii(self) -> bool:
        return self.value.startswith("pii_")


class Severity(IntEnum):
    """Ordered severity levels."""

    LOW = 10
    MEDIUM = 20
    HIGH = 30
    CRITICAL = 40


class ScanDirection(StrEnum):
    REQUEST = "REQUEST"
    RESPONSE = "RESPONSE"


PathPart = str | int


@dataclass(frozen=True, slots=True)
class FindingLocation:
    """JSON location plus half-open offsets into exactly one string value."""

    path: tuple[PathPart, ...]
    start: int | None = None
    end: int | None = None

    def __post_init__(self) -> None:
        if not self.path:
            raise ValueError("finding location path must not be empty")
        if (self.start is None) != (self.end is None):
            raise ValueError("finding offsets must either both be present or both be absent")
        if (
            self.start is not None
            and self.end is not None
            and (self.start < 0 or self.end <= self.start)
        ):
            raise ValueError("finding offsets must form a non-empty half-open range")


@dataclass(frozen=True, slots=True)
class ScanTarget:
    """One explicitly supported textual value selected from a provider payload."""

    path: tuple[PathPart, ...]
    text: str = field(repr=False)

    def __post_init__(self) -> None:
        if not self.path:
            raise ValueError("scan target path must not be empty")


@dataclass(frozen=True, slots=True)
class UnsupportedContent:
    """Safe description of a payload node AgentShield cannot inspect."""

    path: tuple[PathPart, ...]
    content_type: str


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Provider-neutral context passed to every detector."""

    provider: str
    endpoint: str
    direction: ScanDirection
    targets: tuple[ScanTarget, ...]
    model: str | None = None
    unsupported_content: tuple[UnsupportedContent, ...] = ()
    agent: str | None = None
    project: str | None = None


def _safe_metadata(metadata: Mapping[str, str] | None) -> Mapping[str, str]:
    if metadata is None:
        return MappingProxyType({})
    safe: dict[str, str] = {}
    for key, value in metadata.items():
        if not key or len(key) > 64 or len(value) > 128 or "\n" in key or "\n" in value:
            raise ValueError("finding metadata must use short, single-line display values")
        safe[str(key)] = str(value)
    return MappingProxyType(safe)


@dataclass(frozen=True, slots=True)
class Finding:
    """Normalized finding that deliberately never retains detected content."""

    id: UUID
    category: FindingCategory
    severity: Severity
    detector_id: str
    detector_version: str
    location: FindingLocation
    confidence: float
    fingerprint: str
    suggested_replacement: str | None = None
    metadata: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("finding confidence must be between zero and one")
        if not self.detector_id or not self.detector_version:
            raise ValueError("finding detector identity must not be empty")
        if len(self.fingerprint) != 64:
            raise ValueError("finding fingerprint must be a 64-character digest")
        object.__setattr__(self, "metadata", _safe_metadata(self.metadata))

    @classmethod
    def create(
        cls,
        *,
        category: FindingCategory,
        severity: Severity,
        detector_id: str,
        detector_version: str,
        location: FindingLocation,
        confidence: float,
        fingerprint_key: bytes,
        detected_text: str,
        suggested_replacement: str | None = None,
        metadata: Mapping[str, str] | None = None,
    ) -> Self:
        """Create a finding using a keyed, non-reversible content fingerprint."""
        digest = hmac.new(
            fingerprint_key,
            detected_text.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        finding_id = UUID(bytes=bytes.fromhex(digest[:32]))
        return cls(
            id=finding_id,
            category=category,
            severity=severity,
            detector_id=detector_id,
            detector_version=detector_version,
            location=location,
            confidence=confidence,
            fingerprint=digest,
            suggested_replacement=suggested_replacement,
            metadata=_safe_metadata(metadata),
        )


@dataclass(frozen=True, slots=True)
class DetectorFailure:
    """Sanitized detector failure supplied explicitly to policy evaluation."""

    detector_id: str
    detector_version: str
    required: bool
    code: str


@dataclass(frozen=True, slots=True)
class DetectionReport:
    findings: tuple[Finding, ...] = ()
    failures: tuple[DetectorFailure, ...] = ()


class Detector(Protocol):
    """Asynchronous provider-independent detector contract."""

    detector_id: str
    detector_version: str
    required: bool

    async def detect(self, context: ScanContext) -> tuple[Finding, ...]: ...
