"""Deterministic policy profile, rule, and failure behavior."""

from agentshield.filtering.models import (
    DetectionReport,
    DetectorFailure,
    Finding,
    FindingCategory,
    FindingLocation,
    ScanContext,
    ScanDirection,
    Severity,
)
from agentshield.policies.engine import PolicyEngine
from agentshield.policies.models import PolicyAction, PolicyProfile, PolicyRule
from agentshield.proxy.types import Provider


def _context() -> ScanContext:
    return ScanContext(
        provider=Provider.OPENAI.value,
        endpoint="/v1/responses",
        direction=ScanDirection.REQUEST,
        targets=(),
    )


def _finding(category: FindingCategory, severity: Severity = Severity.HIGH) -> Finding:
    return Finding.create(
        category=category,
        severity=severity,
        detector_id="synthetic-detector",
        detector_version="1.0.0",
        location=FindingLocation(path=("input",), start=0, end=5),
        confidence=0.9,
        fingerprint_key=b"test-fingerprint-key",
        detected_text="value",
        suggested_replacement=f"[REDACTED:{category.value}]",
    )


def test_action_precedence_is_deterministic() -> None:
    findings = (
        _finding(FindingCategory.PII_EMAIL),
        _finding(FindingCategory.CUSTOM_TERM, Severity.MEDIUM),
        _finding(FindingCategory.SECRET_API_KEY, Severity.CRITICAL),
    )
    rules = (
        PolicyRule(id="warn-email", action=PolicyAction.WARN, category=FindingCategory.PII_EMAIL),
        PolicyRule(
            id="redact-email", action=PolicyAction.REDACT, category=FindingCategory.PII_EMAIL
        ),
    )

    decision = PolicyEngine(profile=PolicyProfile.BALANCED, rules=rules).evaluate(
        _context(), DetectionReport(findings=findings)
    )

    assert decision.action is PolicyAction.BLOCK
    assert decision.matched_rule_ids == ("redact-email", "warn-email")
    assert [item.finding.id for item in decision.finding_actions] == [f.id for f in findings]


def test_profile_defaults_cover_all_milestone_three_actions() -> None:
    email = DetectionReport(findings=(_finding(FindingCategory.PII_EMAIL),))
    custom = DetectionReport(findings=(_finding(FindingCategory.CUSTOM_TERM),))
    empty = DetectionReport()

    assert (
        PolicyEngine(PolicyProfile.BALANCED).evaluate(_context(), empty).action
        is PolicyAction.ALLOW
    )
    assert (
        PolicyEngine(PolicyProfile.BALANCED).evaluate(_context(), custom).action
        is PolicyAction.WARN
    )
    assert (
        PolicyEngine(PolicyProfile.BALANCED).evaluate(_context(), email).action
        is PolicyAction.REDACT
    )
    assert (
        PolicyEngine(PolicyProfile.STRICT).evaluate(_context(), custom).action is PolicyAction.BLOCK
    )


def test_audit_observes_nonsecrets_but_security_invariant_blocks_secrets() -> None:
    email = DetectionReport(findings=(_finding(FindingCategory.PII_EMAIL),))
    secret = DetectionReport(findings=(_finding(FindingCategory.SECRET_API_KEY),))

    audit_email = PolicyEngine(PolicyProfile.AUDIT).evaluate(_context(), email)
    audit_secret = PolicyEngine(PolicyProfile.AUDIT).evaluate(_context(), secret)

    assert audit_email.action is PolicyAction.ALLOW
    assert audit_email.hypothetical_action is PolicyAction.REDACT
    assert audit_secret.action is PolicyAction.BLOCK


def test_explicit_allow_rule_cannot_override_secret_fail_closed_invariant() -> None:
    secret = DetectionReport(findings=(_finding(FindingCategory.SECRET_API_KEY),))
    rule = PolicyRule(
        id="unsafe-secret-allow",
        action=PolicyAction.ALLOW,
        category=FindingCategory.SECRET_API_KEY,
    )

    decision = PolicyEngine(PolicyProfile.AUDIT, rules=(rule,)).evaluate(_context(), secret)

    assert decision.action is PolicyAction.BLOCK
    assert decision.matched_rule_ids == ("unsafe-secret-allow",)


def test_detector_failures_are_never_silent() -> None:
    pii_failure = DetectorFailure(
        detector_id="presidio-pii", detector_version="1.0.0", required=True, code="unavailable"
    )
    secret_failure = DetectorFailure(
        detector_id="secret-patterns", detector_version="1.0.0", required=True, code="timeout"
    )

    balanced = PolicyEngine(PolicyProfile.BALANCED).evaluate(
        _context(), DetectionReport(failures=(pii_failure,))
    )
    strict = PolicyEngine(PolicyProfile.STRICT).evaluate(
        _context(), DetectionReport(failures=(pii_failure,))
    )
    failed_secret = PolicyEngine(PolicyProfile.AUDIT).evaluate(
        _context(), DetectionReport(failures=(secret_failure,))
    )

    assert balanced.action is PolicyAction.WARN
    assert strict.action is PolicyAction.BLOCK
    assert failed_secret.action is PolicyAction.BLOCK
