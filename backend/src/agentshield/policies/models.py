"""Policy inputs and explainable decision models."""

from dataclasses import dataclass
from enum import IntEnum, StrEnum

from agentshield.filtering.models import Finding, FindingCategory, ScanContext, Severity


class PolicyAction(IntEnum):
    ALLOW = 10
    WARN = 20
    REDACT = 30
    REQUIRE_APPROVAL = 40
    BLOCK = 50


class PolicyProfile(StrEnum):
    AUDIT = "audit"
    BALANCED = "balanced"
    STRICT = "strict"


@dataclass(frozen=True, slots=True)
class PolicyRule:
    """One immutable rule; unset selectors match every value."""

    id: str
    action: PolicyAction
    priority: int = 0
    category: FindingCategory | None = None
    minimum_severity: Severity | None = None
    detector_id: str | None = None
    provider: str | None = None
    model: str | None = None
    endpoint: str | None = None
    direction: str | None = None
    agent: str | None = None
    project: str | None = None

    def matches(self, context: ScanContext, finding: Finding) -> bool:
        return all(
            (
                self.category is None or self.category is finding.category,
                self.minimum_severity is None or finding.severity >= self.minimum_severity,
                self.detector_id is None or self.detector_id == finding.detector_id,
                self.provider is None or self.provider == context.provider,
                self.model is None or self.model == context.model,
                self.endpoint is None or self.endpoint == context.endpoint,
                self.direction is None or self.direction == context.direction.value,
                self.agent is None or self.agent == context.agent,
                self.project is None or self.project == context.project,
            )
        )


@dataclass(frozen=True, slots=True)
class FindingAction:
    finding: Finding
    action: PolicyAction
    matched_rule_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    action: PolicyAction
    findings: tuple[Finding, ...]
    finding_actions: tuple[FindingAction, ...]
    matched_rule_ids: tuple[str, ...]
    reason: str
    policy_version: str
    hypothetical_action: PolicyAction | None = None
