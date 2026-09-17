"""Domain models for manual approval workflows."""

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    CANCELLED = "cancelled"

    @property
    def is_terminal(self) -> bool:
        return self != ApprovalStatus.PENDING


@dataclass(frozen=True, slots=True)
class FindingSummary:
    """Safe, masked summary of a protected content finding for operator display."""

    category: str
    severity: str
    detector_id: str
    message: str
    path: tuple[str | int, ...]
    start_offset: int | None
    end_offset: int | None
    fingerprint: str


@dataclass(slots=True)
class ApprovalRequest:
    """One in-flight or decided manual approval request."""

    id: str
    request_fingerprint: str
    policy_version: str
    provider: str
    model: str | None
    endpoint: str
    direction: str
    agent: str | None
    project: str | None
    session_id: str | None
    findings: tuple[FindingSummary, ...]
    created_at: datetime
    expires_at: datetime
    status: ApprovalStatus = ApprovalStatus.PENDING
    decided_at: datetime | None = None
    decision_reason: str | None = None
    raw_payload_masked: dict[str, Any] | None = None
    redacted_payload: dict[str, Any] | None = None

    @property
    def remaining_seconds(self) -> float:
        now = datetime.now(UTC)
        if self.status.is_terminal or now >= self.expires_at:
            return 0.0
        return max(0.0, (self.expires_at - now).total_seconds())

    def clear_payloads(self) -> None:
        """Clear sensitive payload bodies from memory upon resolution or eviction."""
        self.raw_payload_masked = None
        self.redacted_payload = None
