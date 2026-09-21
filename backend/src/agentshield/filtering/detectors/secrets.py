"""Deterministic contextual secret detection with bounded normalization passes."""

import base64
import binascii
import math
import re
from array import array
from collections import Counter
from dataclasses import dataclass

from agentshield.filtering.models import (
    Finding,
    FindingCategory,
    FindingLocation,
    ScanContext,
    Severity,
)

_ZERO_WIDTH = frozenset({"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"})
_COMMON_EXAMPLE_VALUES = frozenset(
    {"example", "changeme", "password", "test", "testing", "placeholder", "your-password"}
)


@dataclass(frozen=True, slots=True)
class SecretDetectorConfig:
    excluded_fingerprints: frozenset[str] = frozenset()
    minimum_entropy: float = 3.5
    maximum_base64_candidates: int = 32


@dataclass(frozen=True, slots=True)
class _Candidate:
    category: FindingCategory
    start: int
    end: int
    confidence: float
    pattern: str


@dataclass(frozen=True, slots=True)
class _MappedText:
    text: str
    starts: array[int] | None = None
    ends: array[int] | None = None

    def original_range(self, start: int, end: int) -> tuple[int, int]:
        if self.starts is None or self.ends is None:
            return start, end
        return self.starts[start], self.ends[end - 1]


def _identity(text: str) -> _MappedText:
    # Identity passes do not need per-character offset maps. Keeping two tuples of
    # Python integers here amplified a 10 MiB request into hundreds of MiB.
    return _MappedText(text)


def _without_zero_width(text: str) -> _MappedText:
    chars: list[str] = []
    starts = array("I")
    ends = array("I")
    for index, char in enumerate(text):
        if char in _ZERO_WIDTH:
            continue
        chars.append(char)
        starts.append(index)
        ends.append(index + 1)
    return _MappedText("".join(chars), starts, ends)


def _url_decode_ascii(text: str) -> _MappedText:
    chars: list[str] = []
    starts = array("I")
    ends = array("I")
    index = 0
    while index < len(text):
        if index + 2 < len(text) and text[index] == "%":
            pair = text[index + 1 : index + 3]
            try:
                value = int(pair, 16)
            except ValueError:
                value = -1
            if 0 <= value < 128:
                chars.append(chr(value))
                starts.append(index)
                ends.append(index + 3)
                index += 3
                continue
        chars.append(text[index])
        starts.append(index)
        ends.append(index + 1)
        index += 1
    return _MappedText("".join(chars), starts, ends)


_HOMOGLYPH_MAP: dict[str, str] = {
    "\u0430": "a",  # Cyrillic small letter a
    "\u0435": "e",  # Cyrillic small letter ie
    "\u043e": "o",  # Cyrillic small letter o
    "\u0440": "p",  # Cyrillic small letter er
    "\u0441": "c",  # Cyrillic small letter es
    "\u0443": "y",  # Cyrillic small letter u
    "\u0445": "x",  # Cyrillic small letter ha
    "\u0456": "i",  # Cyrillic small letter byelorussian-ukrainian i
    "\u0458": "j",  # Cyrillic small letter je
    "\u0410": "A",  # Cyrillic capital letter A
    "\u0412": "B",  # Cyrillic capital letter Ve
    "\u0415": "E",  # Cyrillic capital letter Ie
    "\u041a": "K",  # Cyrillic capital letter Ka
    "\u041c": "M",  # Cyrillic capital letter Em
    "\u041d": "H",  # Cyrillic capital letter En
    "\u041e": "O",  # Cyrillic capital letter O
    "\u0420": "P",  # Cyrillic capital letter Er
    "\u0421": "C",  # Cyrillic capital letter Es
    "\u0422": "T",  # Cyrillic capital letter Te
    "\u0425": "X",  # Cyrillic capital letter Ha
}
_HOMOGLYPH_TRANSLATION = str.maketrans(_HOMOGLYPH_MAP)


def _normalize_homoglyphs(text: str) -> _MappedText:
    # Every configured replacement is one code point, so offsets are unchanged.
    return _MappedText(text.translate(_HOMOGLYPH_TRANSLATION))


_PATTERNS: tuple[tuple[FindingCategory, str, re.Pattern[str], float], ...] = (
    (
        FindingCategory.SECRET_PRIVATE_KEY,
        "pem-private-key",
        re.compile(
            r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]{1,16384}?"
            r"-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"
        ),
        1.0,
    ),
    (
        FindingCategory.SECRET_API_KEY,
        "anthropic-api-key",
        re.compile(r"(?<![\w])sk-ant-[A-Za-z0-9_-]{20,}(?![\w])", re.IGNORECASE),
        0.99,
    ),
    (
        FindingCategory.SECRET_API_KEY,
        "openai-api-key",
        re.compile(r"(?<![\w])sk-(?!ant-)[A-Za-z0-9_-]{20,}(?![\w])", re.IGNORECASE),
        0.99,
    ),
    (
        FindingCategory.SECRET_AWS_ACCESS_KEY,
        "aws-access-key-id",
        re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
        0.99,
    ),
    (
        FindingCategory.SECRET_GITHUB_TOKEN,
        "github-token",
        re.compile(r"(?<![\w])(?:gh[opsu]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{22,})(?![\w])"),
        0.99,
    ),
    (
        FindingCategory.SECRET_JWT,
        "jwt",
        re.compile(
            r"(?<![\w-])[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?![\w-])"
        ),
        0.97,
    ),
    (
        FindingCategory.SECRET_BEARER_TOKEN,
        "bearer-token",
        re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{16,})"),
        0.98,
    ),
    (
        FindingCategory.SECRET_AWS_SECRET,
        "aws-secret-assignment",
        re.compile(
            r"(?i)\b(?:aws_secret_access_key|aws_secret_key)\b\s*[:=]\s*[\"']?"
            r"([A-Za-z0-9/+=_-]{20,})"
        ),
        0.98,
    ),
    (
        FindingCategory.SECRET_PASSWORD,
        "password-assignment",
        re.compile(
            r"(?i)\b(?:[a-z0-9_]*[_-])?(?:password|passwd|pwd)\b\s*[:=]\s*[\"']?([^\s\"',;]{8,})"
        ),
        0.95,
    ),
)

_CONTEXTUAL_VALUE = re.compile(
    r"(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|secret|token)\b"
    r"\s*[:=]\s*[\"']?([A-Za-z0-9/+=_-]{20,})"
)
_BASE64_CONTEXT = re.compile(
    r"(?i)\b(?:base64|encoded|credential_base64)\b\s*[:=]\s*[\"']?"
    r"([A-Za-z0-9+/]{24,}={0,2})"
)


def _capture_range(pattern_name: str, match: re.Match[str]) -> tuple[int, int]:
    if pattern_name in {
        "bearer-token",
        "aws-secret-assignment",
        "password-assignment",
    }:
        return match.span(1)
    return match.span(0)


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _plain_candidates(text: str, minimum_entropy: float) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    for category, name, pattern, confidence in _PATTERNS:
        for match in pattern.finditer(text):
            start, end = _capture_range(name, match)
            value = text[start:end]
            if (
                category is FindingCategory.SECRET_PASSWORD
                and value.casefold() in _COMMON_EXAMPLE_VALUES
            ):
                continue
            candidates.append(_Candidate(category, start, end, confidence, name))

    for match in _CONTEXTUAL_VALUE.finditer(text):
        start, end = match.span(1)
        value = text[start:end]
        if value.casefold() in _COMMON_EXAMPLE_VALUES or _entropy(value) < minimum_entropy:
            continue
        candidates.append(
            _Candidate(
                FindingCategory.SECRET_HIGH_ENTROPY,
                start,
                end,
                0.8,
                "contextual-high-entropy",
            )
        )
    return candidates


class SecretDetector:
    detector_id = "secret-patterns"
    detector_version = "1.0.0"
    required = True

    def __init__(
        self,
        *,
        fingerprint_key: bytes,
        config: SecretDetectorConfig | None = None,
    ) -> None:
        self.fingerprint_key = fingerprint_key
        self.config = config or SecretDetectorConfig()

    def _finding(
        self,
        *,
        target_path: tuple[str | int, ...],
        original_text: str,
        candidate: _Candidate,
        start: int,
        end: int,
        encoding: str,
    ) -> Finding | None:
        finding = Finding.create(
            category=candidate.category,
            severity=Severity.CRITICAL,
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            location=FindingLocation(path=target_path, start=start, end=end),
            confidence=candidate.confidence,
            fingerprint_key=self.fingerprint_key,
            detected_text=original_text[start:end],
            metadata={"pattern": candidate.pattern, "encoding": encoding},
        )
        if finding.fingerprint in self.config.excluded_fingerprints:
            return None
        return finding

    @staticmethod
    def _normalization_passes(text: str) -> tuple[tuple[_MappedText, str], ...]:
        passes: list[tuple[_MappedText, str]] = [(_identity(text), "plain")]
        if any(char in text for char in _ZERO_WIDTH):
            passes.append((_without_zero_width(text), "zero-width"))
        if re.search(r"%[0-9A-Fa-f]{2}", text):
            passes.append((_url_decode_ascii(text), "url"))
        if any(char in _HOMOGLYPH_MAP for char in text):
            passes.append((_normalize_homoglyphs(text), "homoglyph"))
        return tuple(passes)

    def _append_candidate(
        self,
        *,
        target_path: tuple[str | int, ...],
        original_text: str,
        candidate: _Candidate,
        start: int,
        end: int,
        encoding: str,
        seen: set[tuple[FindingCategory, tuple[str | int, ...], int, int]],
        findings: list[Finding],
    ) -> None:
        key = (candidate.category, target_path, start, end)
        if key in seen:
            return
        seen.add(key)
        finding = self._finding(
            target_path=target_path,
            original_text=original_text,
            candidate=candidate,
            start=start,
            end=end,
            encoding=encoding,
        )
        if finding is not None:
            findings.append(finding)

    def _scan_mapped_passes(
        self,
        *,
        path: tuple[str | int, ...],
        text: str,
        seen: set[tuple[FindingCategory, tuple[str | int, ...], int, int]],
        findings: list[Finding],
    ) -> None:
        for mapped, encoding in self._normalization_passes(text):
            for candidate in _plain_candidates(mapped.text, self.config.minimum_entropy):
                start, end = mapped.original_range(candidate.start, candidate.end)
                self._append_candidate(
                    target_path=path,
                    original_text=text,
                    candidate=candidate,
                    start=start,
                    end=end,
                    encoding=encoding,
                    seen=seen,
                    findings=findings,
                )

    def _scan_base64(
        self,
        *,
        path: tuple[str | int, ...],
        text: str,
        seen: set[tuple[FindingCategory, tuple[str | int, ...], int, int]],
        findings: list[Finding],
    ) -> None:
        for index, match in enumerate(_BASE64_CONTEXT.finditer(text)):
            if index >= self.config.maximum_base64_candidates:
                return
            try:
                decoded = base64.b64decode(match.group(1), validate=True).decode("utf-8")
            except binascii.Error, UnicodeDecodeError:
                continue
            decoded_candidates = _plain_candidates(decoded, self.config.minimum_entropy)
            if not decoded_candidates:
                continue
            start, end = match.span(1)
            self._append_candidate(
                target_path=path,
                original_text=text,
                candidate=decoded_candidates[0],
                start=start,
                end=end,
                encoding="base64",
                seen=seen,
                findings=findings,
            )

    async def detect(self, context: ScanContext) -> tuple[Finding, ...]:
        findings: list[Finding] = []
        seen: set[tuple[FindingCategory, tuple[str | int, ...], int, int]] = set()
        for target in context.targets:
            self._scan_mapped_passes(
                path=target.path,
                text=target.text,
                seen=seen,
                findings=findings,
            )
            self._scan_base64(
                path=target.path,
                text=target.text,
                seen=seen,
                findings=findings,
            )

        findings.sort(
            key=lambda item: (
                tuple(str(part) for part in item.location.path),
                item.location.start or 0,
                item.category.value,
            )
        )
        return tuple(findings)
