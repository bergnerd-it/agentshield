"""Safe YAML import/export for custom terms and policy rules."""

import pytest

from agentshield.filtering.detectors.custom_terms import CustomTermRule, MatchKind
from agentshield.filtering.models import FindingCategory, Severity
from agentshield.policies.models import PolicyAction, PolicyRule
from agentshield.policies.yaml_io import (
    dump_custom_terms_yaml,
    dump_policy_yaml,
    load_custom_terms_yaml,
    load_policy_yaml,
)


def test_custom_term_yaml_round_trip_preserves_explicit_matching_behavior() -> None:
    rules = (
        CustomTermRule(
            id="fictional-package",
            pattern=r"fictional\.[a-z]+\.internal",
            match_kind=MatchKind.REGEX,
            case_sensitive=False,
            word_boundaries=True,
            data_class="package_name",
            default_action=PolicyAction.BLOCK,
            excluded_path_prefixes=(("tools",),),
        ),
    )

    serialized = dump_custom_terms_yaml(rules)
    loaded = load_custom_terms_yaml(serialized)

    assert loaded == rules
    assert "schema_version: 1" in serialized


def test_policy_yaml_round_trip_preserves_version_and_selectors() -> None:
    rules = (
        PolicyRule(
            id="redact-emails",
            action=PolicyAction.REDACT,
            priority=10,
            category=FindingCategory.PII_EMAIL,
            minimum_severity=Severity.MEDIUM,
            provider="openai",
            direction="REQUEST",
        ),
    )

    serialized = dump_policy_yaml("policy-v7", rules)

    assert load_policy_yaml(serialized) == ("policy-v7", rules)


@pytest.mark.parametrize(
    "loader",
    [load_custom_terms_yaml, load_policy_yaml],
)
def test_yaml_import_uses_safe_loader_and_hides_confidential_input(loader: object) -> None:
    malicious = "!!python/object/apply:os.system ['SyntheticConfidentialCommand']"

    with pytest.raises(ValueError) as exc_info:
        loader(malicious)  # type: ignore[operator]

    assert "SyntheticConfidentialCommand" not in str(exc_info.value)
