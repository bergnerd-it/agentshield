"""Bounded safe-YAML import and export for Milestone 3 detector and policy rules."""

from collections.abc import Mapping
from typing import Any, cast

import yaml

from agentshield.filtering.detectors.custom_terms import (
    CustomTermRule,
    MatchKind,
)
from agentshield.filtering.models import FindingCategory, Severity
from agentshield.policies.models import PolicyAction, PolicyRule

_MAX_YAML_BYTES = 256 * 1024


def _load_mapping(text: str) -> dict[str, Any]:
    if len(text.encode("utf-8")) > _MAX_YAML_BYTES:
        raise ValueError("YAML configuration exceeds the size limit")
    try:
        loaded = yaml.safe_load(text)
    except yaml.YAMLError:
        raise ValueError("YAML configuration is invalid") from None
    if not isinstance(loaded, dict):
        raise ValueError("YAML configuration must contain a mapping")
    return cast(dict[str, Any], loaded)


def _only_keys(value: Mapping[str, Any], allowed: frozenset[str], label: str) -> None:
    if any(key not in allowed for key in value):
        raise ValueError(f"{label} contains unsupported fields")


def _required_string(value: Mapping[str, Any], key: str, label: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise ValueError(f"{label} requires a non-empty {key}")
    return item


def _optional_string(value: Mapping[str, Any], key: str) -> str | None:
    item = value.get(key)
    if item is None:
        return None
    if not isinstance(item, str):
        raise ValueError(f"policy rule {key} must be a string")
    return item


def _boolean(value: Mapping[str, Any], key: str, default: bool) -> bool:
    item = value.get(key, default)
    if not isinstance(item, bool):
        raise ValueError(f"custom-term rule {key} must be a boolean")
    return item


def _rule_mappings(root: Mapping[str, Any], key: str) -> list[dict[str, Any]]:
    raw = root.get(key)
    if not isinstance(raw, list):
        raise ValueError(f"YAML configuration requires a {key} list")
    result: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError(f"every {key} entry must be a mapping")
        result.append(cast(dict[str, Any], item))
    return result


def dump_custom_terms_yaml(rules: tuple[CustomTermRule, ...]) -> str:
    document = {
        "schema_version": 1,
        "terms": [
            {
                "id": rule.id,
                "pattern": rule.pattern,
                "match_kind": rule.match_kind.value,
                "case_sensitive": rule.case_sensitive,
                "word_boundaries": rule.word_boundaries,
                "data_class": rule.data_class,
                "default_action": rule.default_action.name,
                "excluded_path_prefixes": [list(path) for path in rule.excluded_path_prefixes],
            }
            for rule in rules
        ],
    }
    return yaml.safe_dump(document, sort_keys=False, allow_unicode=True)


def load_custom_terms_yaml(text: str) -> tuple[CustomTermRule, ...]:
    root = _load_mapping(text)
    _only_keys(root, frozenset({"schema_version", "terms"}), "custom-term document")
    if root.get("schema_version") != 1:
        raise ValueError("custom-term YAML schema_version must be 1")
    allowed = frozenset(
        {
            "id",
            "pattern",
            "match_kind",
            "case_sensitive",
            "word_boundaries",
            "data_class",
            "default_action",
            "excluded_path_prefixes",
        }
    )
    rules: list[CustomTermRule] = []
    for item in _rule_mappings(root, "terms"):
        _only_keys(item, allowed, "custom-term rule")
        excluded = item.get("excluded_path_prefixes", [])
        if not isinstance(excluded, list) or any(not isinstance(path, list) for path in excluded):
            raise ValueError("custom-term excluded paths must be lists")
        paths: list[tuple[str | int, ...]] = []
        for path in excluded:
            typed_path = cast(list[object], path)
            if any(
                not isinstance(part, (str, int)) or isinstance(part, bool) for part in typed_path
            ):
                raise ValueError("custom-term excluded path values must be strings or integers")
            paths.append(tuple(cast(list[str | int], typed_path)))
        try:
            rules.append(
                CustomTermRule(
                    id=_required_string(item, "id", "custom-term rule"),
                    pattern=_required_string(item, "pattern", "custom-term rule"),
                    match_kind=MatchKind(item.get("match_kind", "exact")),
                    case_sensitive=_boolean(item, "case_sensitive", True),
                    word_boundaries=_boolean(item, "word_boundaries", False),
                    data_class=_required_string(
                        {"data_class": item.get("data_class", "project_term")},
                        "data_class",
                        "custom-term rule",
                    ),
                    default_action=PolicyAction[item.get("default_action", "WARN")],
                    excluded_path_prefixes=tuple(paths),
                )
            )
        except KeyError, TypeError, ValueError:
            raise ValueError("custom-term YAML contains an invalid rule") from None
    if len({rule.id for rule in rules}) != len(rules):
        raise ValueError("custom-term YAML rule ids must be unique")
    return tuple(rules)


def dump_policy_yaml(policy_version: str, rules: tuple[PolicyRule, ...]) -> str:
    if not policy_version:
        raise ValueError("policy version must not be empty")
    document = {
        "schema_version": 1,
        "policy_version": policy_version,
        "rules": [
            {
                key: value
                for key, value in {
                    "id": rule.id,
                    "action": rule.action.name,
                    "priority": rule.priority,
                    "category": rule.category.value if rule.category else None,
                    "minimum_severity": rule.minimum_severity.name
                    if rule.minimum_severity
                    else None,
                    "detector_id": rule.detector_id,
                    "provider": rule.provider,
                    "model": rule.model,
                    "endpoint": rule.endpoint,
                    "direction": rule.direction,
                    "agent": rule.agent,
                    "project": rule.project,
                }.items()
                if value is not None
            }
            for rule in rules
        ],
    }
    return yaml.safe_dump(document, sort_keys=False, allow_unicode=True)


def load_policy_yaml(text: str) -> tuple[str, tuple[PolicyRule, ...]]:
    root = _load_mapping(text)
    _only_keys(
        root,
        frozenset({"schema_version", "policy_version", "rules"}),
        "policy document",
    )
    if root.get("schema_version") != 1:
        raise ValueError("policy YAML schema_version must be 1")
    policy_version = _required_string(root, "policy_version", "policy document")
    allowed = frozenset(
        {
            "id",
            "action",
            "priority",
            "category",
            "minimum_severity",
            "detector_id",
            "provider",
            "model",
            "endpoint",
            "direction",
            "agent",
            "project",
        }
    )
    rules: list[PolicyRule] = []
    for item in _rule_mappings(root, "rules"):
        _only_keys(item, allowed, "policy rule")
        priority = item.get("priority", 0)
        if not isinstance(priority, int) or isinstance(priority, bool):
            raise ValueError("policy rule priority must be an integer")
        try:
            category_value = _optional_string(item, "category")
            severity_value = _optional_string(item, "minimum_severity")
            rules.append(
                PolicyRule(
                    id=_required_string(item, "id", "policy rule"),
                    action=PolicyAction[_required_string(item, "action", "policy rule")],
                    priority=priority,
                    category=FindingCategory(category_value) if category_value else None,
                    minimum_severity=Severity[severity_value] if severity_value else None,
                    detector_id=_optional_string(item, "detector_id"),
                    provider=_optional_string(item, "provider"),
                    model=_optional_string(item, "model"),
                    endpoint=_optional_string(item, "endpoint"),
                    direction=_optional_string(item, "direction"),
                    agent=_optional_string(item, "agent"),
                    project=_optional_string(item, "project"),
                )
            )
        except KeyError, TypeError, ValueError:
            raise ValueError("policy YAML contains an invalid rule") from None
    if len({rule.id for rule in rules}) != len(rules):
        raise ValueError("policy YAML rule ids must be unique")
    return policy_version, tuple(rules)
