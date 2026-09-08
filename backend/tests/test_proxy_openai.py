"""Contract and integration tests for OpenAI reverse proxy endpoints."""

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
def openai_test_app(
    test_settings: Settings,
    mock_openai: MockOpenAIServer,
) -> Generator[TestClient]:
    """Create test client with mock upstream OpenAI provider."""
    # Custom AsyncClient with mock ASGI transport
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
        initial_keys={"openai": "sk-synth-real-upstream-key-99999"}
    )

    app = create_app(test_settings)
    app.dependency_overrides[get_forward_client] = lambda: forward_client
    app.dependency_overrides[get_credential_store] = lambda: cred_store

    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        yield client


def test_openai_responses_forwarding(
    openai_test_app: TestClient,
    test_settings: Settings,
    mock_openai: MockOpenAIServer,
) -> None:
    """Test successful forwarding of OpenAI Responses API request."""
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)

    response = openai_test_app.post(
        "/proxy/openai/v1/responses",
        headers={
            "Authorization": f"Bearer {proxy_token}",
            "OpenAI-Organization": "org-synth-12345",
        },
        json={
            "model": "gpt-4o",
            "input": "Explain unit testing.",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "resp-synth-001"
    assert data["model"] == "gpt-4o"

    # Verify mock provider received the request with correct headers
    assert len(mock_openai.recorded_requests) == 1
    recorded = mock_openai.recorded_requests[0]
    assert recorded.path == "/v1/responses"
    assert recorded.headers["authorization"] == "Bearer sk-synth-real-upstream-key-99999"
    assert proxy_token not in recorded.headers.values()
    assert recorded.headers["openai-organization"] == "org-synth-12345"
    assert recorded.headers["x-agentshield-loop-detection"] == "1"


def test_openai_chat_completions_unknown_fields_preserved(
    openai_test_app: TestClient,
    test_settings: Settings,
    mock_openai: MockOpenAIServer,
) -> None:
    """Test Chat Completions forwarding and unknown field preservation."""
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)

    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Hello world"}],
        "temperature": 0.7,
        "custom_vendor_param": {"nested_key": 42},
        "unknown_flag": True,
    }

    response = openai_test_app.post(
        "/proxy/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {proxy_token}"},
        json=payload,
    )

    assert response.status_code == 200
    assert len(mock_openai.recorded_requests) == 1
    recorded = mock_openai.recorded_requests[0]
    assert recorded.path == "/v1/chat/completions"
    assert recorded.json is not None
    assert recorded.json["custom_vendor_param"] == {"nested_key": 42}
    assert recorded.json["unknown_flag"] is True
    assert recorded.json["temperature"] == 0.7


def test_openai_streaming_guard(
    openai_test_app: TestClient,
    test_settings: Settings,
    mock_openai: MockOpenAIServer,
) -> None:
    """Test that stream: true requests are rejected in Milestone 2."""
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)

    response = openai_test_app.post(
        "/proxy/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {proxy_token}"},
        json={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hello"}],
            "stream": True,
        },
    )

    assert response.status_code == 400
    problem = response.json()
    assert problem["type"] == "urn:agentshield:error:streaming-not-supported"
    assert "Milestone 4" in problem["detail"]
    assert len(mock_openai.recorded_requests) == 0


@pytest.mark.parametrize(
    "body",
    [
        b'{"model":',
        b'{"model":"first","model":"second"}',
    ],
)
def test_openai_invalid_json_rejected_before_provider_contact(
    openai_test_app: TestClient,
    test_settings: Settings,
    mock_openai: MockOpenAIServer,
    body: bytes,
) -> None:
    """Malformed and duplicate-key JSON receive a safe client error locally."""
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)

    response = openai_test_app.post(
        "/proxy/openai/v1/responses",
        headers={
            "Authorization": f"Bearer {proxy_token}",
            "Content-Type": "application/json",
        },
        content=body,
    )

    assert response.status_code == 400
    assert response.json()["type"] == "urn:agentshield:error:invalid-proxy-payload"
    assert len(mock_openai.recorded_requests) == 0


@pytest.mark.parametrize(
    ("status_code", "error_payload"),
    [
        (400, {"error": {"message": "Invalid request", "type": "invalid_request_error"}}),
        (
            401,
            {"error": {"message": "Incorrect API key provided", "type": "invalid_request_error"}},
        ),
        (429, {"error": {"message": "Rate limit exceeded", "type": "requests"}}),
        (500, {"error": {"message": "The server had an error", "type": "server_error"}}),
        (529, {"error": {"message": "The server is overloaded", "type": "server_error"}}),
    ],
)
def test_openai_upstream_error_preservation(
    openai_test_app: TestClient,
    test_settings: Settings,
    mock_openai: MockOpenAIServer,
    status_code: int,
    error_payload: dict[str, object],
) -> None:
    """Test that upstream error status codes and provider JSON payloads are preserved verbatim."""
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)

    mock_openai.next_status_code = status_code
    mock_openai.next_response_body = error_payload

    response = openai_test_app.post(
        "/proxy/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {proxy_token}"},
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "Test"}]},
    )

    assert response.status_code == status_code
    assert response.json() == error_payload


def test_openai_missing_credentials_fails(
    test_settings: Settings,
    mock_openai: MockOpenAIServer,
) -> None:
    """Test that missing upstream OpenAI key results in 500 Problem Details."""
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)

    # Credential store with NO OpenAI key
    empty_cred_store = InMemoryCredentialStore()

    transport = httpx.ASGITransport(app=mock_openai.app)  # pyright: ignore[reportArgumentType]
    mock_http_client = httpx.AsyncClient(
        transport=transport, base_url=test_settings.openai_upstream_base_url
    )
    forward_client = ProxyForwardClient(settings=test_settings, client=mock_http_client)

    app = create_app(test_settings)
    app.dependency_overrides[get_forward_client] = lambda: forward_client
    app.dependency_overrides[get_credential_store] = lambda: empty_cred_store

    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        response = client.post(
            "/proxy/openai/v1/responses",
            headers={"Authorization": f"Bearer {proxy_token}"},
            json={"model": "gpt-4o", "input": "Hello"},
        )

        assert response.status_code == 500
        problem = response.json()
        assert problem["type"] == "urn:agentshield:error:missing-credential"
        assert "openai" in problem["detail"]
