"""Validated custom exact-term and restricted-regex detection."""

import asyncio
import re
from dataclasses import dataclass
from enum import StrEnum

from agentshield.filtering.models import (
    Finding,
    FindingCategory,
    FindingLocation,
    ScanContext,
    Severity,
)
from agentshield.policies.models import PolicyAction


class MatchKind(StrEnum):
    EXACT = "exact"
    REGEX = "regex"


def _validate_regex(pattern: str) -> re.Pattern[str]:
    if not pattern or len(pattern) > 256:
        raise ValueError("custom regex must contain between 1 and 256 characters")
    if re.search(r"(?<!\\)\(", pattern) or re.search(r"\\[1-9]", pattern):
        raise ValueError("custom regex groups and backreferences are not permitted")
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise ValueError("custom regex is invalid") from exc


@dataclass(frozen=True, slots=True)
class CustomTermRule:
    id: str
    pattern: str
    match_kind: MatchKind = MatchKind.EXACT
    case_sensitive: bool = True
    word_boundaries: bool = False
    data_class: str = "project_term"
    default_action: PolicyAction = PolicyAction.WARN
    excluded_path_prefixes: tuple[tuple[str | int, ...], ...] = ()

    def __post_init__(self) -> None:
        if not self.id or len(self.id) > 64:
            raise ValueError("custom term rule id must contain at most 64 characters")
        if self.match_kind is MatchKind.EXACT and (not self.pattern or len(self.pattern) > 256):
            raise ValueError("custom term pattern must contain between 1 and 256 characters")
        if not self.data_class or len(self.data_class) > 64:
            raise ValueError("custom term data class must contain at most 64 characters")
        if self.match_kind is MatchKind.REGEX:
            _validate_regex(self.pattern)


class CustomTermDetector:
    detector_id = "custom-terms"
    detector_version = "1.0.0"
    required = True

    def __init__(
        self,
        *,
        fingerprint_key: bytes,
        rules: tuple[CustomTermRule, ...] = (),
    ) -> None:
        if len({rule.id for rule in rules}) != len(rules):
            raise ValueError("custom term rule ids must be unique")
        self.fingerprint_key = fingerprint_key
        self.rules = rules

    @staticmethod
    def _excluded(path: tuple[str | int, ...], rule: CustomTermRule) -> bool:
        return any(path[: len(prefix)] == prefix for prefix in rule.excluded_path_prefixes)

    @staticmethod
    def _compiled(rule: CustomTermRule) -> re.Pattern[str]:
        expression = rule.pattern if rule.match_kind is MatchKind.REGEX else re.escape(rule.pattern)
        if rule.word_boundaries:
            expression = rf"(?<!\w)(?:{expression})(?!\w)"
        flags = 0 if rule.case_sensitive else re.IGNORECASE
        return re.compile(expression, flags)

    def _detect_sync(self, context: ScanContext) -> tuple[Finding, ...]:
        findings: list[Finding] = []
        for target in context.targets:
            for rule in self.rules:
                if self._excluded(target.path, rule):
                    continue
                for match in self._compiled(rule).finditer(target.text):
                    findings.append(
                        Finding.create(
                            category=FindingCategory.CUSTOM_TERM,
                            severity=Severity.HIGH,
                            detector_id=self.detector_id,
                            detector_version=self.detector_version,
                            location=FindingLocation(
                                path=target.path, start=match.start(), end=match.end()
                            ),
                            confidence=1.0,
                            fingerprint_key=self.fingerprint_key,
                            detected_text=target.text[match.start() : match.end()],
                            suggested_replacement=f"[REDACTED:{rule.data_class.upper()}]",
                            metadata={
                                "rule_id": rule.id,
                                "data_class": rule.data_class,
                                "default_action": rule.default_action.name,
                                "match_kind": rule.match_kind.value,
                            },
                        )
                    )
        findings.sort(
            key=lambda item: (
                tuple(str(part) for part in item.location.path),
                item.location.start or 0,
                item.metadata.get("rule_id", ""),
            )
        )
        return tuple(findings)

    async def detect(self, context: ScanContext) -> tuple[Finding, ...]:
        return await asyncio.to_thread(self._detect_sync, context)
