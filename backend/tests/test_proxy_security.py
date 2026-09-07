"""Security, authentication isolation, and loop detection tests for proxy routes."""

import logging
from collections.abc import Generator

import httpx
import pytest
from fastapi.testclient import TestClient

from agentshield.api.app import create_app
from agentshield.api.dependencies import (
    get_credential_store,
    get_forward_client,
)
from agentshield.core.auth import get_or_create_proxy_token
from agentshield.core.config import Settings
from agentshield.core.credentials import InMemoryCredentialStore
from agentshield.proxy.client import ProxyForwardClient
from tests.mock_providers import MockOpenAIServer


@pytest.fixture
def mock_openai() -> MockOpenAIServer:
    return MockOpenAIServer()


@pytest.fixture
def security_test_client(
    test_settings: Settings,
    mock_openai: MockOpenAIServer,
) -> Generator[TestClient]:
    """Create test client with mock upstream provider."""
    transport = httpx.ASGITransport(app=mock_openai.app)  # pyright: ignore[reportArgumentType]
    mock_http_client = httpx.AsyncClient(
        transport=transport,
        base_url=test_settings.openai_upstream_base_url,
    )
    forward_client = ProxyForwardClient(
        settings=test_settings,
        client=mock_http_client,
    )
    cred_store = InMemoryCredentialStore(
        initial_keys={"openai": "sk-synth-secret-upstream-key-xyz987"}
    )

    app = create_app(test_settings)
    app.dependency_overrides[get_forward_client] = lambda: forward_client
    app.dependency_overrides[get_credential_store] = lambda: cred_store

    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        yield client


def test_proxy_auth_missing_token_returns_401(
    security_test_client: TestClient,
) -> None:
    """Test that requests without local proxy token are rejected with 401 Problem Details."""
    response = security_test_client.post(
        "/proxy/openai/v1/responses",
        json={"model": "gpt-4o", "input": "Hello"},
    )

    assert response.status_code == 401
    problem = response.json()
    assert problem["type"] == "urn:agentshield:error:unauthorized"
    assert "proxy token" in problem["detail"]


def test_proxy_auth_invalid_token_returns_401(
    security_test_client: TestClient,
) -> None:
    """Test that requests with an invalid proxy token are rejected."""
    response = security_test_client.post(
        "/proxy/openai/v1/responses",
        headers={"Authorization": "Bearer invalid_proxy_token_here"},
        json={"model": "gpt-4o", "input": "Hello"},
    )

    assert response.status_code == 401
    problem = response.json()
    assert problem["type"] == "urn:agentshield:error:unauthorized"


def test_proxy_token_never_sent_upstream(
    security_test_client: TestClient,
    test_settings: Settings,
    mock_openai: MockOpenAIServer,
) -> None:
    """Test that local proxy tokens are stripped and never reach the upstream server."""
    local_proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)

    response = security_test_client.post(
        "/proxy/openai/v1/responses",
        headers={
            "Authorization": f"Bearer {local_proxy_token}",
            "X-API-Key": local_proxy_token,
            "X-AgentShield-Token": local_proxy_token,
        },
        json={"model": "gpt-4o", "input": "Hello"},
    )

    assert response.status_code == 200
    assert len(mock_openai.recorded_requests) == 1
    recorded = mock_openai.recorded_requests[0]

    # Verify no header contains the local proxy token
    for header_name, header_val in recorded.headers.items():
        assert local_proxy_token not in header_val, (
            f"Local proxy token leaked in header: {header_name}"
        )
    assert local_proxy_token.encode("utf-8") not in recorded.body


def test_provider_key_never_leaks_in_client_response(
    security_test_client: TestClient,
    test_settings: Settings,
) -> None:
    """Test that upstream provider secret keys are never returned to client."""
    local_proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)
    upstream_key = "sk-synth-secret-upstream-key-xyz987"

    response = security_test_client.post(
        "/proxy/openai/v1/responses",
        headers={"Authorization": f"Bearer {local_proxy_token}"},
        json={"model": "gpt-4o", "input": "Hello"},
    )

    assert response.status_code == 200
    assert upstream_key not in response.text
    for h_name, h_val in response.headers.items():
        assert upstream_key not in h_val, f"Upstream secret leaked in response header: {h_name}"


def test_loop_detection_rejects_incoming_marker(
    security_test_client: TestClient,
    test_settings: Settings,
) -> None:
    """Test that request with loop detection header is rejected."""
    local_proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)

    response = security_test_client.post(
        "/proxy/openai/v1/responses",
        headers={
            "Authorization": f"Bearer {local_proxy_token}",
            "X-AgentShield-Loop-Detection": "1",
        },
        json={"model": "gpt-4o", "input": "Loop test"},
    )

    assert response.status_code == 508
    problem = response.json()
    assert problem["type"] == "urn:agentshield:error:loop-detected"


def test_payload_size_limit(
    security_test_client: TestClient,
    test_settings: Settings,
) -> None:
    """Test that request exceeding max body bytes is rejected with 413."""
    local_proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)

    # Configure a small max size
    test_settings.proxy_max_body_bytes = 100

    response = security_test_client.post(
        "/proxy/openai/v1/responses",
        headers={"Authorization": f"Bearer {local_proxy_token}"},
        json={"model": "gpt-4o", "large_payload": "a" * 200},
    )

    assert response.status_code == 413
    problem = response.json()
    assert problem["type"] == "urn:agentshield:error:payload-too-large"


def test_secrets_absent_from_logs(
    security_test_client: TestClient,
    test_settings: Settings,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Assert that synthetic API keys and tokens never appear in application logs."""
    local_proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)
    upstream_key = "sk-synth-secret-upstream-key-xyz987"

    with caplog.at_level(logging.DEBUG):
        response = security_test_client.post(
            "/proxy/openai/v1/responses",
            headers={"Authorization": f"Bearer {local_proxy_token}"},
            json={"model": "gpt-4o", "input": "Testing secret log omission"},
        )
        assert response.status_code == 200

    for record in caplog.records:
        assert upstream_key not in record.message
        assert local_proxy_token not in record.message
