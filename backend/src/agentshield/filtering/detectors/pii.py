"""Structured PII detection and Microsoft Presidio result normalization."""

import asyncio
import ipaddress
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, cast

from agentshield.filtering.models import (
    Finding,
    FindingCategory,
    FindingLocation,
    ScanContext,
    Severity,
)

_EMAIL = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?![\w.-])"
)
_PHONE = re.compile(r"(?<!\w)(?:\+\d{1,3}[ .-]?)?(?:\(?\d{2,4}\)?[ .-]?){2,5}\d{3,4}(?!\w)")
_IBAN = re.compile(r"(?<![A-Z0-9])[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}(?![A-Z0-9])")
_IP = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f:.]{3,45})(?![\w:])")


@dataclass(frozen=True, slots=True)
class StructuredPiiDetectorConfig:
    detect_ip_addresses: bool = False


def _valid_phone(value: str) -> bool:
    digits = "".join(char for char in value if char.isdigit())
    return 8 <= len(digits) <= 15 and len(set(digits)) > 1


def _valid_iban(value: str) -> bool:
    compact = value.replace(" ", "").upper()
    if not 15 <= len(compact) <= 34 or not compact[:2].isalpha() or not compact[2:4].isdigit():
        return False
    rearranged = compact[4:] + compact[:4]
    numeric = "".join(str(ord(char) - 55) if char.isalpha() else char for char in rearranged)
    return int(numeric) % 97 == 1


class StructuredPiiDetector:
    detector_id = "structured-pii"
    detector_version = "1.0.0"
    required = True

    def __init__(
        self,
        *,
        fingerprint_key: bytes,
        config: StructuredPiiDetectorConfig | None = None,
    ) -> None:
        self.fingerprint_key = fingerprint_key
        self.config = config or StructuredPiiDetectorConfig()

    def _create(
        self,
        *,
        category: FindingCategory,
        path: tuple[str | int, ...],
        text: str,
        start: int,
        end: int,
        confidence: float,
    ) -> Finding:
        return Finding.create(
            category=category,
            severity=Severity.HIGH,
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            location=FindingLocation(path=path, start=start, end=end),
            confidence=confidence,
            fingerprint_key=self.fingerprint_key,
            detected_text=text[start:end],
            suggested_replacement=f"[REDACTED:{category.value.upper()}]",
            metadata={"entity_type": category.value},
        )

    async def detect(self, context: ScanContext) -> tuple[Finding, ...]:
        findings: list[Finding] = []
        for target in context.targets:
            for match in _EMAIL.finditer(target.text):
                findings.append(
                    self._create(
                        category=FindingCategory.PII_EMAIL,
                        path=target.path,
                        text=target.text,
                        start=match.start(),
                        end=match.end(),
                        confidence=0.99,
                    )
                )
            for match in _PHONE.finditer(target.text):
                if _valid_phone(match.group(0)):
                    findings.append(
                        self._create(
                            category=FindingCategory.PII_PHONE,
                            path=target.path,
                            text=target.text,
                            start=match.start(),
                            end=match.end(),
                            confidence=0.9,
                        )
                    )
            for match in _IBAN.finditer(target.text.upper()):
                if _valid_iban(match.group(0)):
                    findings.append(
                        self._create(
                            category=FindingCategory.PII_IBAN,
                            path=target.path,
                            text=target.text,
                            start=match.start(),
                            end=match.end(),
                            confidence=0.99,
                        )
                    )
            if self.config.detect_ip_addresses:
                for match in _IP.finditer(target.text):
                    try:
                        ipaddress.ip_address(match.group(0))
                    except ValueError:
                        continue
                    findings.append(
                        self._create(
                            category=FindingCategory.PII_IP_ADDRESS,
                            path=target.path,
                            text=target.text,
                            start=match.start(),
                            end=match.end(),
                            confidence=0.99,
                        )
                    )
        findings.sort(
            key=lambda item: (
                tuple(str(part) for part in item.location.path),
                item.location.start or 0,
                item.category.value,
            )
        )
        return tuple(findings)


class PresidioResult(Protocol):
    entity_type: str
    start: int
    end: int
    score: float


class PresidioAnalyzer(Protocol):
    def analyze(
        self, *, text: str, entities: list[str], language: str
    ) -> Sequence[PresidioResult]: ...


@dataclass(frozen=True, slots=True)
class PresidioDetectorConfig:
    languages: tuple[str, ...] = ("en", "de")
    entity_types: tuple[str, ...] = ("PERSON", "ORGANIZATION")
    model_names: tuple[tuple[str, str], ...] = (
        ("en", "en_core_web_lg"),
        ("de", "de_core_news_lg"),
    )
    minimum_confidence: float = 0.5

    def __post_init__(self) -> None:
        if not self.languages or any(language not in {"en", "de"} for language in self.languages):
            raise ValueError("Presidio languages must be configured from en and de")
        if not self.entity_types or any(
            entity not in {"PERSON", "ORGANIZATION"} for entity in self.entity_types
        ):
            raise ValueError("Presidio entity types must be PERSON or ORGANIZATION")
        configured_models = dict(self.model_names)
        if set(configured_models) != set(self.languages) or any(
            not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name) for name in configured_models.values()
        ):
            raise ValueError("Presidio requires one safe local model name per language")
        if not 0.0 <= self.minimum_confidence <= 1.0:
            raise ValueError("Presidio confidence threshold must be between zero and one")


class PresidioDetector:
    detector_id = "presidio-pii"
    detector_version = "1.0.0"
    required = True

    def __init__(
        self,
        *,
        fingerprint_key: bytes,
        analyzer: PresidioAnalyzer | None = None,
        config: PresidioDetectorConfig | None = None,
    ) -> None:
        self.fingerprint_key = fingerprint_key
        self._analyzer = analyzer
        self.config = config or PresidioDetectorConfig()

    def _get_analyzer(self) -> PresidioAnalyzer:
        if self._analyzer is None:
            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import NlpEngineProvider

            configured_models = dict(self.config.model_names)
            provider = NlpEngineProvider(
                nlp_configuration={
                    "nlp_engine_name": "spacy",
                    "models": [
                        {"lang_code": language, "model_name": configured_models[language]}
                        for language in self.config.languages
                    ],
                }
            )
            self._analyzer = cast(
                PresidioAnalyzer,
                AnalyzerEngine(
                    nlp_engine=provider.create_engine(),
                    supported_languages=list(self.config.languages),
                ),
            )
        return self._analyzer

    async def detect(self, context: ScanContext) -> tuple[Finding, ...]:
        analyzer = await asyncio.to_thread(self._get_analyzer)
        findings: list[Finding] = []
        seen: set[tuple[tuple[str | int, ...], str, int, int]] = set()
        categories = {
            "PERSON": FindingCategory.PII_PERSON,
            "ORGANIZATION": FindingCategory.PII_ORGANIZATION,
        }
        for target in context.targets:
            for language in self.config.languages:
                results = await asyncio.to_thread(
                    analyzer.analyze,
                    text=target.text,
                    entities=list(self.config.entity_types),
                    language=language,
                )
                for result in results:
                    if (
                        result.entity_type not in categories
                        or result.score < self.config.minimum_confidence
                    ):
                        continue
                    if not 0 <= result.start < result.end <= len(target.text):
                        raise ValueError("Presidio returned invalid finding offsets")
                    key = (target.path, result.entity_type, result.start, result.end)
                    if key in seen:
                        continue
                    seen.add(key)
                    category = categories[result.entity_type]
                    findings.append(
                        Finding.create(
                            category=category,
                            severity=Severity.MEDIUM,
                            detector_id=self.detector_id,
                            detector_version=self.detector_version,
                            location=FindingLocation(
                                path=target.path, start=result.start, end=result.end
                            ),
                            confidence=result.score,
                            fingerprint_key=self.fingerprint_key,
                            detected_text=target.text[result.start : result.end],
                            suggested_replacement=f"[REDACTED:{category.value.upper()}]",
                            metadata={"entity_type": result.entity_type, "language": language},
                        )
                    )
        findings.sort(
            key=lambda item: (
                tuple(str(part) for part in item.location.path),
                item.location.start or 0,
                item.category.value,
            )
        )
        return tuple(findings)
