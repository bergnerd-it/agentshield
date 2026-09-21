"""Automated pytest assertions for Specification §18.4 SLA and payload bounds."""

import time
from collections.abc import Generator

import httpx
import pytest
from fastapi.testclient import TestClient

from agentshield.api.app import create_app
from agentshield.api.dependencies import (
    get_credential_store,
    get_forward_client,
    get_inspection_pipeline,
)
from agentshield.core.auth import get_or_create_proxy_token
from agentshield.core.config import Settings
from agentshield.core.credentials import InMemoryCredentialStore
from agentshield.filtering.detectors.custom_terms import CustomTermDetector, CustomTermRule
from agentshield.filtering.detectors.pii import StructuredPiiDetector, StructuredPiiDetectorConfig
from agentshield.filtering.detectors.secrets import SecretDetector
from agentshield.filtering.detectors.unsupported import UnsupportedContentDetector
from agentshield.filtering.engine import DetectorEngine
from agentshield.policies.engine import PolicyEngine
from agentshield.policies.models import PolicyAction, PolicyProfile
from agentshield.proxy.client import ProxyForwardClient
from agentshield.proxy.inspection import RequestInspectionPipeline
from tests.mock_providers import MockOpenAIServer


@pytest.fixture
def performance_client(
    test_settings: Settings,
) -> Generator[tuple[TestClient, MockOpenAIServer, str]]:
    mock = MockOpenAIServer()
    upstream = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=mock.app),  # pyright: ignore[reportArgumentType]
        base_url=test_settings.openai_upstream_base_url,
    )
    forwarder = ProxyForwardClient(settings=test_settings, client=upstream)

    key = b"performance-test-key"
    rules = (
        CustomTermRule(
            id="rule-perf-1",
            pattern="GreenfieldGrantService",
            default_action=PolicyAction.REDACT,
        ),
    )
    engine = DetectorEngine(
        (
            SecretDetector(fingerprint_key=key),
            StructuredPiiDetector(
                fingerprint_key=key,
                config=StructuredPiiDetectorConfig(detect_ip_addresses=True),
            ),
            CustomTermDetector(fingerprint_key=key, rules=rules),
            UnsupportedContentDetector(fingerprint_key=key),
        ),
        timeout_seconds=2.0,
    )
    pipeline = RequestInspectionPipeline(
        detector_engine=engine,
        policy_engine=PolicyEngine(PolicyProfile.BALANCED),
        header_secret_detector=SecretDetector(fingerprint_key=key),
    )

    app = create_app(test_settings)
    app.dependency_overrides[get_forward_client] = lambda: forwarder
    app.dependency_overrides[get_credential_store] = lambda: InMemoryCredentialStore(
        initial_keys={"openai": "sk-synth-perf-key-12345"}
    )
    app.dependency_overrides[get_inspection_pipeline] = lambda: pipeline

    token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)

    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        yield client, mock, token


def test_median_proxy_overhead_under_30ms(
    performance_client: tuple[TestClient, MockOpenAIServer, str],
) -> None:
    """Specification §18.4: Verify median pre-request overhead for small text is under 30 ms."""
    client, _mock, token = performance_client
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "model": "gpt-4o",
        "input": "Write a python function to check if a string is a palindrome.",
    }

    # Warmup
    for _ in range(3):
        client.post("/proxy/openai/v1/responses", headers=headers, json=payload)

    overheads_ms: list[float] = []
    iterations = 25

    for _ in range(iterations):
        t0 = time.perf_counter()
        resp = client.post("/proxy/openai/v1/responses", headers=headers, json=payload)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        assert resp.status_code == 200
        overheads_ms.append(elapsed_ms)

    overheads_ms.sort()
    p50_latency = overheads_ms[len(overheads_ms) // 2]

    # Specification §18.4: Target median overhead < 30 ms
    assert p50_latency < 30.0, (
        f"Median overhead SLA violation: measured {p50_latency:.2f} ms (expected < 30.0 ms)"
    )


def test_payload_exceeding_10mib_rejected_with_413(
    performance_client: tuple[TestClient, MockOpenAIServer, str],
) -> None:
    """Verify that requests exceeding 10 MiB limit are rejected with HTTP 413."""
    client, mock, token = performance_client
    headers = {"Authorization": f"Bearer {token}"}

    # 10 MiB + 1024 bytes payload
    oversized_text = "x" * (10 * 1024 * 1024 + 1024)
    payload = {"model": "gpt-4o", "input": oversized_text}

    response = client.post("/proxy/openai/v1/responses", headers=headers, json=payload)

    assert response.status_code == 413
    problem = response.json()
    assert problem["type"] == "urn:agentshield:error:payload-too-large"
    assert len(mock.recorded_requests) == 0, (
        "Upstream mock server must not receive oversized payloads"
    )
