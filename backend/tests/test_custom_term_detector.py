"""Validated custom-term matching behavior."""

import pytest

from agentshield.filtering.detectors.custom_terms import (
    CustomTermDetector,
    CustomTermRule,
    MatchKind,
)
from agentshield.filtering.models import ScanContext, ScanDirection, ScanTarget
from agentshield.policies.models import PolicyAction


def _context(text: str, path: tuple[str | int, ...] = ("input",)) -> ScanContext:
    return ScanContext(
        provider="openai",
        endpoint="/v1/responses",
        direction=ScanDirection.REQUEST,
        targets=(ScanTarget(path=path, text=text),),
    )


@pytest.mark.asyncio
async def test_exact_case_boundary_repetition_and_default_action() -> None:
    detector = CustomTermDetector(
        fingerprint_key=b"test-key",
        rules=(
            CustomTermRule(
                id="fictional-class",
                pattern="FictionalWidget",
                match_kind=MatchKind.EXACT,
                case_sensitive=False,
                word_boundaries=True,
                data_class="internal_class",
                default_action=PolicyAction.REDACT,
            ),
        ),
    )

    findings = await detector.detect(
        _context("fictionalwidget FictionalWidgetExtra FICTIONALWIDGET fictionalwidget")
    )

    assert len(findings) == 3
    assert all(item.metadata["rule_id"] == "fictional-class" for item in findings)
    assert all(item.metadata["default_action"] == "REDACT" for item in findings)


@pytest.mark.asyncio
async def test_safe_regex_and_path_exclusion() -> None:
    rule = CustomTermRule(
        id="fictional-package",
        pattern=r"fictional\.[a-z]+\.internal",
        match_kind=MatchKind.REGEX,
        excluded_path_prefixes=(("tools",),),
    )
    detector = CustomTermDetector(fingerprint_key=b"test-key", rules=(rule,))

    assert len(await detector.detect(_context("fictional.alpha.internal"))) == 1
    assert await detector.detect(_context("fictional.alpha.internal", ("tools", 0, "name"))) == ()


@pytest.mark.parametrize("pattern", ["(a+)+", r"(secret)", r"value\1", "x" * 257])
def test_unsafe_or_unbounded_regex_configuration_is_rejected(pattern: str) -> None:
    with pytest.raises(ValueError, match="regex"):
        CustomTermRule(id="unsafe", pattern=pattern, match_kind=MatchKind.REGEX)
