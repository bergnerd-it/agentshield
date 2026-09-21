"""Positive, negative, boundary, and encoding cases for secret detection."""

import base64
import gc
import tracemalloc

import pytest

from agentshield.filtering.detectors.secrets import SecretDetector, SecretDetectorConfig
from agentshield.filtering.models import FindingCategory, ScanContext, ScanDirection, ScanTarget


def _context(text: str) -> ScanContext:
    return ScanContext(
        provider="openai",
        endpoint="/v1/responses",
        direction=ScanDirection.REQUEST,
        targets=(ScanTarget(path=("input",), text=text),),
    )


@pytest.mark.asyncio
async def test_plain_normalization_has_bounded_memory_amplification() -> None:
    """Large ordinary payloads must not allocate per-character Python offset objects."""
    text = "a" * 1024 * 1024
    detector = SecretDetector(fingerprint_key=b"test-key")
    gc.collect()
    tracemalloc.start()
    try:
        findings = await detector.detect(_context(text))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert findings == ()
    assert peak < 32 * 1024 * 1024


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("text", "category"),
    [
        ("key=sk-synth_openai_1234567890abcdef", FindingCategory.SECRET_API_KEY),
        ("key=sk-ant-synth_anthropic_1234567890", FindingCategory.SECRET_API_KEY),
        ("aws_access_key_id=AKIA0000000000000000", FindingCategory.SECRET_AWS_ACCESS_KEY),
        (
            "aws_secret_access_key=SYNTHETIC_AWS_SECRET_VALUE_000000000",
            FindingCategory.SECRET_AWS_SECRET,
        ),
        ("token=ghp_SYNTHETIC012345678901234567890123", FindingCategory.SECRET_GITHUB_TOKEN),
        (
            "Authorization: Bearer SYNTHETIC_BEARER_TOKEN_0123456789",
            FindingCategory.SECRET_BEARER_TOKEN,
        ),
        (
            "jwt=eyJzeW50aCI6dHJ1ZX0.eyJzdWIiOiJmaWN0aW9uYWwifQ.c3ludGhldGljc2lnbmF0dXJl",
            FindingCategory.SECRET_JWT,
        ),
        (
            "-----BEGIN PRIVATE KEY-----\nSYNTHETIC-NOT-A-REAL-KEY\n-----END PRIVATE KEY-----",
            FindingCategory.SECRET_PRIVATE_KEY,
        ),
        ("password = 'synthetic-password-value-1234'", FindingCategory.SECRET_PASSWORD),
        (
            "api_key = 'u7F3aQ9vL2mX8pR4tN6kC1zB'",
            FindingCategory.SECRET_HIGH_ENTROPY,
        ),
    ],
)
async def test_required_secret_families(text: str, category: FindingCategory) -> None:
    findings = await SecretDetector(fingerprint_key=b"test-key").detect(_context(text))

    assert category in {finding.category for finding in findings}
    assert text not in repr(findings)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "text",
    [
        "uuid=123e4567-e89b-12d3-a456-426614174000",
        "sha256=" + "a" * 64,
        "Bearer token",
        "password = example",
        "task_sk-synth_openai_1234567890abcdef_suffix",
    ],
)
async def test_secret_false_positive_corpus(text: str) -> None:
    findings = await SecretDetector(fingerprint_key=b"test-key").detect(_context(text))

    assert findings == ()


@pytest.mark.asyncio
async def test_url_encoding_zero_width_and_contextual_base64_are_bounded() -> None:
    encoded_bearer = base64.b64encode(b"Bearer SYNTHETIC_BEARER_TOKEN_ABCDEFGHIJKL").decode()
    text = (
        "api_key%3Dsk-synth_urlencoded_1234567890abcd "
        "ghp_SYNTHETIC0123\u200b45678901234567890123 "
        f"credential_base64={encoded_bearer}"
    )

    findings = await SecretDetector(fingerprint_key=b"test-key").detect(_context(text))

    encodings = {finding.metadata.get("encoding") for finding in findings}
    assert {"url", "zero-width", "base64"} <= encodings
    assert all(
        finding.location.end is not None and finding.location.end <= len(text)
        for finding in findings
    )


@pytest.mark.asyncio
async def test_fingerprint_allowlist_excludes_without_retaining_plaintext() -> None:
    detector = SecretDetector(fingerprint_key=b"test-key")
    text = "key=sk-synth_allowlisted_1234567890abcdef"
    initial = await detector.detect(_context(text))
    assert initial

    allowlisted = SecretDetector(
        fingerprint_key=b"test-key",
        config=SecretDetectorConfig(excluded_fingerprints=frozenset({initial[0].fingerprint})),
    )
    assert await allowlisted.detect(_context(text)) == ()
