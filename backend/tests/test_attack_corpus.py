"""Synthetic attack corpus and multi-sink zero-leak verification suite.

Verifies that:
1. Every corpus vector is accurately detected by the detector engine.
2. The policy engine applies the expected actions across security profiles.
3. Blocked synthetic secrets never cross into any of the 5 sinks:
   - Upstream mock provider captures
   - Application and access logs
   - SQLite database content
   - JSON and HTML audit exports
   - HTTP response bodies and error details
"""

import json
import logging
import sqlite3
from collections.abc import Generator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar, cast

import httpx
import pytest
from fastapi.testclient import TestClient

from agentshield.api.app import create_app
from agentshield.api.dependencies import (
    get_credential_store,
    get_forward_client,
    get_inspection_pipeline,
)
from agentshield.core.auth import get_or_create_admin_token, get_or_create_proxy_token
from agentshield.core.config import Settings
from agentshield.core.credentials import InMemoryCredentialStore
from agentshield.filtering.detectors.custom_terms import CustomTermDetector, CustomTermRule
from agentshield.filtering.detectors.pii import (
    PresidioAnalyzer,
    PresidioDetector,
    PresidioDetectorConfig,
    StructuredPiiDetector,
    StructuredPiiDetectorConfig,
)
from agentshield.filtering.detectors.secrets import SecretDetector
from agentshield.filtering.detectors.unsupported import UnsupportedContentDetector
from agentshield.filtering.engine import DetectorEngine
from agentshield.filtering.models import (
    ScanContext,
    ScanDirection,
    ScanTarget,
)
from agentshield.policies.engine import PolicyEngine
from agentshield.policies.models import PolicyAction, PolicyProfile
from agentshield.proxy.client import ProxyForwardClient
from agentshield.proxy.inspection import RequestInspectionPipeline
from tests.mock_providers import MockOpenAIServer

CORPUS_DIR = Path(__file__).parent / "corpus"


def _load_corpus_file(filename: str) -> list[dict[str, Any]]:
    path = CORPUS_DIR / filename
    with path.open(encoding="utf-8") as f:
        return cast(list[dict[str, Any]], json.load(f))


@dataclass(frozen=True)
class _PresidioMatch:
    entity_type: str
    start: int
    end: int
    score: float


class _InjectedPresidioAnalyzer:
    """Mock Presidio analyzer that recognizes specific names and organizations deterministically."""

    KNOWN_ENTITIES: ClassVar[dict[str, str]] = {
        "Erika Mustermann": "PERSON",
        "John Doe": "PERSON",
        "Alpine Example GmbH": "ORGANIZATION",
    }

    def analyze(self, *, text: str, entities: list[str], language: str) -> list[_PresidioMatch]:
        del entities, language
        results: list[_PresidioMatch] = []
        for term, entity_type in self.KNOWN_ENTITIES.items():
            start = 0
            while True:
                idx = text.find(term, start)
                if idx == -1:
                    break
                results.append(_PresidioMatch(entity_type, idx, idx + len(term), 0.95))
                start = idx + len(term)
        return results


def _build_test_detector_engine(key: bytes = b"test-fingerprint-key-corpus") -> DetectorEngine:

    custom_rules = (
        CustomTermRule(
            id="rule-cust-1",
            pattern="GreenfieldGrantService",
            default_action=PolicyAction.REDACT,
        ),
        CustomTermRule(
            id="rule-cust-2",
            pattern="com.company.internal",
            default_action=PolicyAction.REDACT,
        ),
        CustomTermRule(
            id="rule-cust-3",
            pattern="PROJECT_NEBULA",
            default_action=PolicyAction.REDACT,
        ),
        CustomTermRule(
            id="rule-cust-4",
            pattern="prod_customers_v2",
            default_action=PolicyAction.REDACT,
        ),
    )
    return DetectorEngine(
        (
            SecretDetector(fingerprint_key=key),
            StructuredPiiDetector(
                fingerprint_key=key,
                config=StructuredPiiDetectorConfig(detect_ip_addresses=True),
            ),
            PresidioDetector(
                fingerprint_key=key,
                analyzer=cast(PresidioAnalyzer, _InjectedPresidioAnalyzer()),
                config=PresidioDetectorConfig(languages=("en", "de")),
            ),
            CustomTermDetector(fingerprint_key=key, rules=custom_rules),
            UnsupportedContentDetector(fingerprint_key=key),
        ),
        timeout_seconds=1.0,
    )


def _build_test_pipeline(
    profile: PolicyProfile = PolicyProfile.BALANCED,
) -> RequestInspectionPipeline:
    key = b"test-fingerprint-key-corpus"
    engine = _build_test_detector_engine(key)
    return RequestInspectionPipeline(
        detector_engine=engine,
        policy_engine=PolicyEngine(profile),
        header_secret_detector=SecretDetector(fingerprint_key=key),
    )


@pytest.fixture
def corpus_proxy_client(
    test_settings: Settings,
) -> Generator[tuple[TestClient, MockOpenAIServer, str, str]]:
    mock = MockOpenAIServer()
    upstream = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=mock.app),  # pyright: ignore[reportArgumentType]
        base_url=test_settings.openai_upstream_base_url,
    )
    forwarder = ProxyForwardClient(settings=test_settings, client=upstream)
    app = create_app(test_settings)
    app.dependency_overrides[get_forward_client] = lambda: forwarder
    app.dependency_overrides[get_credential_store] = lambda: InMemoryCredentialStore(
        initial_keys={"openai": "sk-synth-upstream-key-99999"}
    )
    app.dependency_overrides[get_inspection_pipeline] = lambda: _build_test_pipeline(
        PolicyProfile.BALANCED
    )

    admin_token = get_or_create_admin_token(test_settings.effective_admin_token_path)
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)

    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        yield client, mock, admin_token, proxy_token


# ---------------------------------------------------------------------------
# Test 1: Detector Unit Verification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "item",
    _load_corpus_file("secrets.json")
    + _load_corpus_file("pii.json")
    + _load_corpus_file("custom_terms.json")
    + _load_corpus_file("obfuscation.json"),
    ids=lambda item: item["id"],
)
@pytest.mark.asyncio
async def test_attack_corpus_positive_detection(item: dict[str, Any]) -> None:
    """Verify that every positive corpus item is correctly flagged by the DetectorEngine."""
    engine = _build_test_detector_engine()
    context = ScanContext(
        provider="openai",
        endpoint="/v1/chat/completions",
        direction=ScanDirection.REQUEST,
        targets=(ScanTarget(path=("input",), text=item["payload"]),),
    )

    report = await engine.scan(context)
    findings = report.findings
    assert len(findings) > 0, f"Expected detector finding for {item['id']}: {item['description']}"

    # Verify category matches or falls into the same family
    found_categories = {f.category.value for f in findings}
    expected_cat = item["category"]

    if expected_cat == "secret_api_key":
        assert any(c.startswith("secret_") for c in found_categories)
    else:
        assert expected_cat in found_categories, (
            f"Expected category {expected_cat} for {item['id']}, got {found_categories}"
        )


@pytest.mark.parametrize(
    "item",
    _load_corpus_file("false_positives.json"),
    ids=lambda item: item["id"],
)
@pytest.mark.asyncio
async def test_attack_corpus_false_positives_allow(item: dict[str, Any]) -> None:
    """Verify that benign false positive candidates produce zero findings."""
    engine = _build_test_detector_engine()
    context = ScanContext(
        provider="openai",
        endpoint="/v1/chat/completions",
        direction=ScanDirection.REQUEST,
        targets=(ScanTarget(path=("input",), text=item["payload"]),),
    )

    report = await engine.scan(context)
    findings = report.findings
    assert len(findings) == 0, (
        f"False positive triggered for {item['id']}: {[f.category for f in findings]}"
    )


# ---------------------------------------------------------------------------
# Test 2: Policy Enforcement Verification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "item",
    _load_corpus_file("secrets.json")
    + _load_corpus_file("pii.json")
    + _load_corpus_file("custom_terms.json")
    + _load_corpus_file("false_positives.json"),
    ids=lambda item: item["id"],
)
@pytest.mark.asyncio
async def test_attack_corpus_policy_actions(item: dict[str, Any]) -> None:
    """Verify that findings result in expected policy actions for balanced & strict profiles."""
    engine = _build_test_detector_engine()
    context = ScanContext(
        provider="openai",
        endpoint="/v1/chat/completions",
        direction=ScanDirection.REQUEST,
        targets=(ScanTarget(path=("input",), text=item["payload"]),),
    )
    report = await engine.scan(context)

    # Test Balanced Profile
    policy_balanced = PolicyEngine(PolicyProfile.BALANCED)
    dec_balanced = policy_balanced.evaluate(context, report)
    assert dec_balanced.action.name == item["expected_action_balanced"], (
        f"Item {item['id']} balanced action mismatch: expected "
        f"{item['expected_action_balanced']}, got {dec_balanced.action.name}"
    )

    # Test Strict Profile
    policy_strict = PolicyEngine(PolicyProfile.STRICT)
    dec_strict = policy_strict.evaluate(context, report)
    assert dec_strict.action.name == item["expected_action_strict"], (
        f"Item {item['id']} strict action mismatch: expected "
        f"{item['expected_action_strict']}, got {dec_strict.action.name}"
    )


# ---------------------------------------------------------------------------
# Test 3: Multi-Sink Zero-Leak Verification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "item",
    [
        item
        for item in (_load_corpus_file("secrets.json") + _load_corpus_file("obfuscation.json"))
        if item.get("must_not_leak")
    ],
    ids=lambda item: item["id"],
)
def test_attack_corpus_multi_sink_zero_leak(
    item: dict[str, Any],
    corpus_proxy_client: tuple[TestClient, MockOpenAIServer, str, str],
    test_settings: Settings,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Assert that detected synthetic secrets are absent from all 5 operational sinks."""
    client, mock_server, admin_token, proxy_token = corpus_proxy_client
    secret_payload: str = item["payload"]

    # Clear prior recorded requests
    mock_server.recorded_requests.clear()

    # Determine unique secret token to search for across sinks
    # If payload is an assignment like password = 'xyz', isolate the secret token
    search_token = secret_payload
    if "=" in secret_payload or ":" in secret_payload:
        for delimiter in ("=", ":"):
            if delimiter in secret_payload:
                val = secret_payload.split(delimiter, 1)[1].strip().strip("'\"")
                if len(val) >= 8:
                    search_token = val
                    break

    # Send proxy request with secret payload
    with caplog.at_level(logging.DEBUG):
        response = client.post(
            "/proxy/openai/v1/responses",
            headers={"Authorization": f"Bearer {proxy_token}"},
            json={
                "model": "gpt-4o",
                "input": f"Analyze this configuration: {secret_payload}",
            },
        )

    # Invariant: Secret payloads must trigger BLOCK (HTTP 403)
    assert response.status_code == 403, (
        f"Expected HTTP 403 for {item['id']}, got {response.status_code}: {response.text}"
    )

    # 1. Sink 1: Mock Upstream Provider Capture
    assert len(mock_server.recorded_requests) == 0, (
        f"Sink 1 Leak: Upstream mock provider received request for blocked {item['id']}"
    )
    for rec in mock_server.recorded_requests:
        assert search_token not in rec.body.decode("utf-8", errors="replace"), (
            "Sink 1 Leak in recorded body"
        )
        assert search_token not in str(rec.headers), "Sink 1 Leak in recorded headers"

    # 2. Sink 2: Application and HTTP Logs
    assert search_token not in caplog.text, f"Sink 2 Leak: Secret found in logs for {item['id']}"

    # 3. Sink 3: SQLite Database Tables
    with sqlite3.connect(test_settings.data_dir / "agentshield.db") as conn:
        db_dump = "\n".join(conn.iterdump())
    assert search_token not in db_dump, f"Sink 3 Leak: Secret found in SQLite for {item['id']}"

    # 4. Sink 4: Audit Export (JSON and HTML)
    resp_export_json = client.post(
        "/api/v1/audit/export",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"format": "json"},
    )
    assert resp_export_json.status_code == 200
    assert search_token not in resp_export_json.text, (
        f"Sink 4 Leak: Secret found in JSON export for {item['id']}"
    )

    resp_export_html = client.post(
        "/api/v1/audit/export",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"format": "html"},
    )
    assert resp_export_html.status_code == 200
    assert search_token not in resp_export_html.text, (
        f"Sink 4 Leak: Secret found in HTML export for {item['id']}"
    )

    # 5. Sink 5: HTTP Error Response Body & Headers
    assert search_token not in response.text, (
        f"Sink 5 Leak: Secret found in HTTP response body for {item['id']}"
    )
    assert search_token not in str(response.headers), (
        f"Sink 5 Leak: Secret found in HTTP response headers for {item['id']}"
    )
