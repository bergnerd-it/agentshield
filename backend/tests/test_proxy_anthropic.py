"""Contract and integration tests for Anthropic reverse proxy endpoints."""

import gzip
import json
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
from tests.mock_providers import MockAnthropicServer


@pytest.fixture
def mock_anthropic() -> MockAnthropicServer:
    return MockAnthropicServer()


@pytest.fixture
def anthropic_test_app(
    test_settings: Settings,
    mock_anthropic: MockAnthropicServer,
) -> Generator[TestClient]:
    """Create test client with mock upstream Anthropic provider."""
    transport = httpx.ASGITransport(app=mock_anthropic.app)  # pyright: ignore[reportArgumentType]
    mock_http_client = httpx.AsyncClient(
        transport=transport,
        base_url=test_settings.anthropic_upstream_base_url,
    )
    forward_client = ProxyForwardClient(
        settings=test_settings,
        client=mock_http_client,
    )
    cred_store = InMemoryCredentialStore(
        initial_keys={"anthropic": "sk-ant-synth-real-upstream-key-88888"}
    )

    app = create_app(test_settings)
    app.dependency_overrides[get_forward_client] = lambda: forward_client
    app.dependency_overrides[get_credential_store] = lambda: cred_store

    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        yield client


def test_anthropic_messages_forwarding(
    anthropic_test_app: TestClient,
    test_settings: Settings,
    mock_anthropic: MockAnthropicServer,
) -> None:
    """Test successful forwarding of Anthropic Messages API request."""
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)

    response = anthropic_test_app.post(
        "/proxy/anthropic/v1/messages",
        headers={"x-api-key": proxy_token},
        json={
            "model": "claude-3-5-sonnet-20241022",
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": "Hello Claude"}],
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "msg_synth_001"
    assert data["role"] == "assistant"

    # Verify mock provider received the request with correct headers
    assert len(mock_anthropic.recorded_requests) == 1
    recorded = mock_anthropic.recorded_requests[0]
    assert recorded.path == "/v1/messages"
    assert recorded.headers["x-api-key"] == "sk-ant-synth-real-upstream-key-88888"
    assert proxy_token not in recorded.headers.values()
    assert recorded.headers["anthropic-version"] == "2023-06-01"
    assert recorded.headers["x-agentshield-loop-detection"] == "1"


def test_anthropic_custom_headers_and_unknown_fields(
    anthropic_test_app: TestClient,
    test_settings: Settings,
    mock_anthropic: MockAnthropicServer,
) -> None:
    """Test custom anthropic-version, anthropic-beta, and unknown payload fields."""
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)

    payload = {
        "model": "claude-3-5-sonnet-20241022",
        "max_tokens": 512,
        "messages": [{"role": "user", "content": "Hi"}],
        "custom_metadata_tag": {"project_id": "proj-123"},
        "experimental_feature": True,
    }

    response = anthropic_test_app.post(
        "/proxy/anthropic/v1/messages",
        headers={
            "Authorization": f"Bearer {proxy_token}",
            "anthropic-version": "2023-01-01",
            "anthropic-beta": "prompt-caching-2024-07-31",
        },
        json=payload,
    )

    assert response.status_code == 200
    assert len(mock_anthropic.recorded_requests) == 1
    recorded = mock_anthropic.recorded_requests[0]
    assert recorded.headers["anthropic-version"] == "2023-01-01"
    assert recorded.headers["anthropic-beta"] == "prompt-caching-2024-07-31"
    assert recorded.json is not None
    assert recorded.json["custom_metadata_tag"] == {"project_id": "proj-123"}
    assert recorded.json["experimental_feature"] is True


def test_anthropic_gzip_request_is_decoded_before_forwarding(
    anthropic_test_app: TestClient,
    test_settings: Settings,
    mock_anthropic: MockAnthropicServer,
) -> None:
    """Anthropic receives decoded JSON and no stale content-coding metadata."""
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)
    payload = {
        "model": "claude-3-5-sonnet-20241022",
        "max_tokens": 64,
        "messages": [{"role": "user", "content": "Synthetic compressed request"}],
    }
    decoded_body = json.dumps(payload, separators=(",", ":")).encode()

    response = anthropic_test_app.post(
        "/proxy/anthropic/v1/messages",
        headers={
            "x-api-key": proxy_token,
            "Content-Type": "application/json",
            "Content-Encoding": "gzip",
        },
        content=gzip.compress(decoded_body),
    )

    assert response.status_code == 200
    assert len(mock_anthropic.recorded_requests) == 1
    recorded = mock_anthropic.recorded_requests[0]
    assert recorded.body == decoded_body
    assert recorded.json == payload
    assert "content-encoding" not in recorded.headers
    assert int(recorded.headers["content-length"]) == len(decoded_body)


def test_anthropic_streaming_guard(
    anthropic_test_app: TestClient,
    test_settings: Settings,
    mock_anthropic: MockAnthropicServer,
) -> None:
    """Test that stream: true requests are rejected for Anthropic."""
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)

    response = anthropic_test_app.post(
        "/proxy/anthropic/v1/messages",
        headers={"x-api-key": proxy_token},
        json={
            "model": "claude-3-5-sonnet-20241022",
            "max_tokens": 100,
            "messages": [{"role": "user", "content": "Stream me"}],
            "stream": True,
        },
    )

    assert response.status_code == 400
    problem = response.json()
    assert problem["type"] == "urn:agentshield:error:streaming-not-supported"
    assert len(mock_anthropic.recorded_requests) == 0


@pytest.mark.parametrize(
    ("status_code", "error_payload"),
    [
        (
            400,
            {
                "type": "error",
                "error": {"type": "invalid_request_error", "message": "max_tokens: required"},
            },
        ),
        (
            401,
            {
                "type": "error",
                "error": {"type": "authentication_error", "message": "invalid x-api-key"},
            },
        ),
        (
            429,
            {
                "type": "error",
                "error": {"type": "rate_limit_error", "message": "Rate limit exceeded"},
            },
        ),
        (500, {"type": "error", "error": {"type": "api_error", "message": "Internal error"}}),
        (
            529,
            {
                "type": "error",
                "error": {"type": "overloaded_error", "message": "Anthropic is overloaded"},
            },
        ),
    ],
)
def test_anthropic_upstream_error_preservation(
    anthropic_test_app: TestClient,
    test_settings: Settings,
    mock_anthropic: MockAnthropicServer,
    status_code: int,
    error_payload: dict[str, object],
) -> None:
    """Test that Anthropic upstream errors are relayed faithfully."""
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)

    mock_anthropic.next_status_code = status_code
    mock_anthropic.next_response_body = error_payload

    response = anthropic_test_app.post(
        "/proxy/anthropic/v1/messages",
        headers={"x-api-key": proxy_token},
        json={
            "model": "claude-3-5-sonnet-20241022",
            "max_tokens": 100,
            "messages": [{"role": "user", "content": "Test"}],
        },
    )

    assert response.status_code == status_code
    assert response.json() == error_payload


def test_anthropic_missing_credentials_fails(
    test_settings: Settings,
    mock_anthropic: MockAnthropicServer,
) -> None:
    """Test that missing Anthropic API key in CredentialStore returns 500 Problem Details."""
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)

    empty_cred_store = InMemoryCredentialStore()

    transport = httpx.ASGITransport(app=mock_anthropic.app)  # pyright: ignore[reportArgumentType]
    mock_http_client = httpx.AsyncClient(
        transport=transport, base_url=test_settings.anthropic_upstream_base_url
    )
    forward_client = ProxyForwardClient(settings=test_settings, client=mock_http_client)

    app = create_app(test_settings)
    app.dependency_overrides[get_forward_client] = lambda: forward_client
    app.dependency_overrides[get_credential_store] = lambda: empty_cred_store

    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        response = client.post(
            "/proxy/anthropic/v1/messages",
            headers={"x-api-key": proxy_token},
            json={
                "model": "claude-3-5-sonnet-20241022",
                "max_tokens": 100,
                "messages": [{"role": "user", "content": "Test"}],
            },
        )

        assert response.status_code == 500
        problem = response.json()
        assert problem["type"] == "urn:agentshield:error:missing-credential"
        assert "anthropic" in problem["detail"]
