"""Deterministic profile and immutable-rule policy evaluation."""

from collections.abc import Iterable

from agentshield.filtering.models import DetectionReport, DetectorFailure, Finding, ScanContext
from agentshield.policies.models import (
    FindingAction,
    PolicyAction,
    PolicyDecision,
    PolicyProfile,
    PolicyRule,
)


class PolicyEngine:
    """Evaluate findings only; detectors never make authorization decisions."""

    def __init__(
        self,
        profile: PolicyProfile,
        rules: Iterable[PolicyRule] = (),
        policy_version: str = "milestone-3/default-v1",
    ) -> None:
        self.profile = profile
        self.rules = tuple(rules)
        self.policy_version = policy_version

    @staticmethod
    def _configured_custom_action(finding: Finding) -> PolicyAction | None:
        value = finding.metadata.get("default_action")
        if value is None:
            return None
        try:
            return PolicyAction[value]
        except KeyError:
            return None

    def _balanced_default(self, finding: Finding) -> PolicyAction:
        if finding.category.is_secret:
            return PolicyAction.BLOCK
        if finding.category.is_pii:
            return PolicyAction.REDACT
        if finding.category.value == "custom_term":
            return self._configured_custom_action(finding) or PolicyAction.WARN
        return PolicyAction.WARN

    def _profile_default(self, finding: Finding) -> PolicyAction:
        if finding.category.is_secret:
            return PolicyAction.BLOCK
        if self.profile is PolicyProfile.AUDIT:
            return PolicyAction.ALLOW
        if self.profile is PolicyProfile.STRICT:
            if finding.category.is_pii:
                return PolicyAction.REDACT
            return PolicyAction.BLOCK
        return self._balanced_default(finding)

    @staticmethod
    def _failure_action(profile: PolicyProfile, failure: DetectorFailure) -> PolicyAction:
        if failure.detector_id == "secret-patterns":
            return PolicyAction.BLOCK
        if profile is PolicyProfile.STRICT and failure.required:
            return PolicyAction.BLOCK
        if profile is PolicyProfile.BALANCED:
            return PolicyAction.WARN
        return PolicyAction.ALLOW

    def _action_for_finding(
        self, context: ScanContext, finding: Finding
    ) -> tuple[PolicyAction, tuple[str, ...]]:
        matches = [rule for rule in self.rules if rule.matches(context, finding)]
        matches.sort(key=lambda rule: (-int(rule.action), -rule.priority, rule.id))
        if finding.category.is_secret:
            return PolicyAction.BLOCK, tuple(rule.id for rule in matches)
        if not matches:
            return self._profile_default(finding), ()
        action = max((rule.action for rule in matches), key=int)
        return action, tuple(rule.id for rule in matches)

    def evaluate(self, context: ScanContext, report: DetectionReport) -> PolicyDecision:
        dispositions: list[FindingAction] = []
        matched_ids: set[str] = set()
        for finding in report.findings:
            action, rule_ids = self._action_for_finding(context, finding)
            matched_ids.update(rule_ids)
            dispositions.append(
                FindingAction(finding=finding, action=action, matched_rule_ids=rule_ids)
            )

        candidate_actions = [item.action for item in dispositions]
        candidate_actions.extend(
            self._failure_action(self.profile, item) for item in report.failures
        )
        action = max(candidate_actions, key=int, default=PolicyAction.ALLOW)

        hypothetical: PolicyAction | None = None
        if self.profile is PolicyProfile.AUDIT:
            balanced_actions = [self._balanced_default(item) for item in report.findings]
            hypothetical = max(balanced_actions, key=int, default=PolicyAction.ALLOW)
            if action is not PolicyAction.BLOCK:
                action = PolicyAction.ALLOW

        ordered_rule_ids = tuple(
            rule.id
            for rule in sorted(
                (rule for rule in self.rules if rule.id in matched_ids),
                key=lambda rule: (-int(rule.action), -rule.priority, rule.id),
            )
        )
        reason = (
            f"profile={self.profile.value}; findings={len(report.findings)}; "
            f"detector_failures={len(report.failures)}; action={action.name}"
        )
        return PolicyDecision(
            action=action,
            findings=report.findings,
            finding_actions=tuple(dispositions),
            matched_rule_ids=ordered_rule_ids,
            reason=reason,
            policy_version=self.policy_version,
            hypothetical_action=hypothetical,
        )
