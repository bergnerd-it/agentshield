"""Offset-safe JSON string replacement without reversible mappings."""

from copy import deepcopy
from typing import Any, cast

from agentshield.filtering.models import Finding, FindingCategory, PathPart

_CATEGORY_PRIORITY: dict[FindingCategory, int] = {
    category: (300 if category.is_secret else 200 if category.is_pii else 100)
    for category in FindingCategory
}


def _get_value(payload: object, path: tuple[PathPart, ...]) -> object:
    current = payload
    for part in path:
        if isinstance(part, int):
            if not isinstance(current, list) or not 0 <= part < len(current):
                raise ValueError("redaction location does not exist")
            current = current[part]
        else:
            if not isinstance(current, dict) or part not in current:
                raise ValueError("redaction location does not exist")
            current = cast(dict[str, Any], current)[part]
    return current


def _set_value(payload: object, path: tuple[PathPart, ...], value: str) -> None:
    if not path:
        raise ValueError("redaction location does not exist")
    *parent_parts, final = path
    parent = _get_value(payload, tuple(parent_parts)) if parent_parts else payload
    if isinstance(final, int):
        if not isinstance(parent, list) or not 0 <= final < len(parent):
            raise ValueError("redaction location does not exist")
        parent[final] = value
    else:
        if not isinstance(parent, dict) or final not in parent:
            raise ValueError("redaction location does not exist")
        cast(dict[str, Any], parent)[final] = value


def _rank(finding: Finding) -> tuple[int, int, float, str, str]:
    return (
        int(finding.severity),
        _CATEGORY_PRIORITY[finding.category],
        finding.confidence,
        finding.detector_id,
        str(finding.id),
    )


def _select_non_overlapping(findings: list[Finding]) -> list[Finding]:
    selected: list[Finding] = []
    for finding in sorted(findings, key=_rank, reverse=True):
        start = finding.location.start
        end = finding.location.end
        if start is None or end is None or finding.suggested_replacement is None:
            continue
        if all(
            end <= existing.location.start or start >= existing.location.end
            for existing in selected
            if existing.location.start is not None and existing.location.end is not None
        ):
            selected.append(finding)
    return selected


def redact_payload(payload: dict[str, Any], findings: tuple[Finding, ...]) -> dict[str, Any]:
    """Return a copied payload with deterministic, right-to-left replacements."""
    transformed = deepcopy(payload)
    by_path: dict[tuple[PathPart, ...], list[Finding]] = {}
    for finding in findings:
        by_path.setdefault(finding.location.path, []).append(finding)

    for path, candidates in by_path.items():
        original = _get_value(transformed, path)
        if not isinstance(original, str):
            raise ValueError("redaction location must identify a string")
        selected = _select_non_overlapping(candidates)
        value = original
        for finding in sorted(
            selected,
            key=lambda item: cast(int, item.location.start),
            reverse=True,
        ):
            start = finding.location.start
            end = finding.location.end
            replacement = finding.suggested_replacement
            if start is None or end is None or replacement is None or end > len(original):
                raise ValueError("redaction offsets are outside the selected string")
            value = f"{value[:start]}{replacement}{value[end:]}"
        _set_value(transformed, path, value)

    return transformed
