"""Security, authentication isolation, and loop detection tests for proxy routes."""

import asyncio
import gzip
import logging
from collections.abc import Generator
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from agentshield.api.app import create_app
from agentshield.api.dependencies import (
    get_credential_store,
    get_current_settings,
    get_forward_client,
    require_admin_auth,
)
from agentshield.core.auth import (
    get_or_create_admin_token,
    get_or_create_proxy_token,
)
from agentshield.core.config import Settings
from agentshield.core.credentials import InMemoryCredentialStore
from agentshield.proxy.client import ProxyForwardClient
from agentshield.proxy.types import Provider, ProxyRequest
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
    temp_data_dir: Path,
    mock_openai: MockOpenAIServer,
) -> None:
    """Test request exceeding max body bytes is rejected with 413 without mutating singleton."""
    custom_settings = Settings(
        host="127.0.0.1",
        port=8765,
        data_dir=temp_data_dir,
        profile="balanced",
        dev_mode=True,
        log_level="DEBUG",
        proxy_max_body_bytes=100,
        cors_allowed_origins=[
            "http://127.0.0.1:8765",
            "http://localhost:8765",
            "http://127.0.0.1:5173",
        ],
    )
    local_proxy_token = get_or_create_proxy_token(custom_settings.effective_proxy_token_path)

    transport = httpx.ASGITransport(app=mock_openai.app)  # pyright: ignore[reportArgumentType]
    mock_http_client = httpx.AsyncClient(
        transport=transport,
        base_url=custom_settings.openai_upstream_base_url,
    )
    forward_client = ProxyForwardClient(
        settings=custom_settings,
        client=mock_http_client,
    )
    cred_store = InMemoryCredentialStore(
        initial_keys={"openai": "sk-synth-secret-upstream-key-xyz987"}
    )

    app = create_app(custom_settings)
    app.dependency_overrides[get_current_settings] = lambda: custom_settings
    app.dependency_overrides[get_forward_client] = lambda: forward_client
    app.dependency_overrides[get_credential_store] = lambda: cred_store

    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        response = client.post(
            "/proxy/openai/v1/responses",
            headers={"Authorization": f"Bearer {local_proxy_token}"},
            json={"model": "gpt-4o", "large_payload": "a" * 200},
        )

        assert response.status_code == 413
        problem = response.json()
        assert problem["type"] == "urn:agentshield:error:payload-too-large"


def test_early_content_length_header_rejection(
    temp_data_dir: Path,
    mock_openai: MockOpenAIServer,
) -> None:
    """Test that request with oversized Content-Length header is rejected early."""
    custom_settings = Settings(
        host="127.0.0.1",
        port=8765,
        data_dir=temp_data_dir,
        profile="balanced",
        dev_mode=True,
        log_level="DEBUG",
        proxy_max_body_bytes=50,
    )
    local_proxy_token = get_or_create_proxy_token(custom_settings.effective_proxy_token_path)

    transport = httpx.ASGITransport(app=mock_openai.app)  # pyright: ignore[reportArgumentType]
    mock_http_client = httpx.AsyncClient(
        transport=transport,
        base_url=custom_settings.openai_upstream_base_url,
    )
    forward_client = ProxyForwardClient(
        settings=custom_settings,
        client=mock_http_client,
    )
    cred_store = InMemoryCredentialStore(
        initial_keys={"openai": "sk-synth-secret-upstream-key-xyz987"}
    )

    app = create_app(custom_settings)
    app.dependency_overrides[get_current_settings] = lambda: custom_settings
    app.dependency_overrides[get_forward_client] = lambda: forward_client
    app.dependency_overrides[get_credential_store] = lambda: cred_store

    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        response = client.post(
            "/proxy/openai/v1/responses",
            headers={
                "Authorization": f"Bearer {local_proxy_token}",
                "Content-Length": "1000",
                "Content-Type": "application/json",
            },
            content=b'{"model": "gpt-4o"}',
        )

        assert response.status_code == 413
        problem = response.json()
        assert problem["type"] == "urn:agentshield:error:payload-too-large"
        assert "1000 bytes" in problem["detail"]


def test_proxy_auth_with_non_bearer_auth_and_valid_x_api_key(
    security_test_client: TestClient,
    test_settings: Settings,
) -> None:
    """Test that valid x-api-key is accepted when non-Bearer Authorization header is present."""
    local_proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)

    # 1. Non-Bearer Authorization header (e.g. Basic) alongside valid x-api-key
    response = security_test_client.post(
        "/proxy/openai/v1/responses",
        headers={
            "Authorization": "Basic dXNlcjpwYXNz",
            "x-api-key": local_proxy_token,
        },
        json={"model": "gpt-4o", "input": "Hello"},
    )
    assert response.status_code == 200

    # 2. Invalid Bearer Authorization alongside valid x-api-key
    response2 = security_test_client.post(
        "/proxy/openai/v1/responses",
        headers={
            "Authorization": "Bearer invalid_token",
            "x-api-key": local_proxy_token,
        },
        json={"model": "gpt-4o", "input": "Hello"},
    )
    assert response2.status_code == 200


@pytest.mark.asyncio
async def test_require_admin_auth_candidates(test_settings: Settings) -> None:
    """Test that require_admin_auth validates candidate headers properly."""
    admin_token = get_or_create_admin_token(test_settings.effective_admin_token_path)

    # Non-bearer auth with valid X-AgentShield-Token
    result = await require_admin_auth(
        settings=test_settings,
        authorization="Basic dXNlcjpwYXNz",
        x_agentshield_token=admin_token,
    )
    assert result == admin_token

    # Valid Bearer token
    result2 = await require_admin_auth(
        settings=test_settings,
        authorization=f"Bearer {admin_token}",
        x_agentshield_token=None,
    )
    assert result2 == admin_token


def test_content_encoding_header_not_relayed(
    security_test_client: TestClient,
    test_settings: Settings,
    mock_openai: MockOpenAIServer,
) -> None:
    """Test that upstream Content-Encoding is stripped from relayed response headers."""
    local_proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)

    gzipped_content = gzip.compress(
        b'{"id": "resp-synth-001", "object": "response", "model": "gpt-4o"}'
    )
    mock_openai.next_response_body = gzipped_content
    mock_openai.next_headers = {
        "content-encoding": "gzip",
        "content-type": "application/json",
    }

    response = security_test_client.post(
        "/proxy/openai/v1/responses",
        headers={"Authorization": f"Bearer {local_proxy_token}"},
        json={"model": "gpt-4o", "input": "Hello"},
    )

    assert response.status_code == 200
    assert "content-encoding" not in response.headers


@pytest.mark.asyncio
async def test_proxy_forward_client_connection_pooling(
    test_settings: Settings,
    mock_openai: MockOpenAIServer,
) -> None:
    """Test ProxyForwardClient reuses client connection and does not close it per forward call."""
    transport = httpx.ASGITransport(app=mock_openai.app)  # pyright: ignore[reportArgumentType]
    forward_client = ProxyForwardClient(
        settings=test_settings,
        transport=transport,
    )

    req = ProxyRequest(
        provider=Provider.OPENAI,
        url=f"{test_settings.openai_upstream_base_url}/v1/responses",
        method="POST",
        headers={"authorization": "Bearer synth-key", "content-type": "application/json"},
        body=b'{"model": "gpt-4o"}',
    )

    resp1 = await forward_client.forward(req)
    assert resp1.status_code == 200
    underlying_client = forward_client.client
    assert underlying_client is not None
    assert not underlying_client.is_closed

    resp2 = await forward_client.forward(req)
    assert resp2.status_code == 200
    assert forward_client.client is underlying_client
    assert not underlying_client.is_closed

    await forward_client.aclose()
    assert underlying_client.is_closed


@pytest.mark.asyncio
async def test_invalid_url_surfaces_as_500(test_settings: Settings) -> None:
    """Test that an invalid upstream URL raises httpx.InvalidURL and is not converted to 502."""
    forward_client = ProxyForwardClient(settings=test_settings)
    req = ProxyRequest(
        provider=Provider.OPENAI,
        url="ftp://invalid.endpoint/path",
        method="POST",
        headers={},
        body=b"",
    )
    with pytest.raises(httpx.UnsupportedProtocol):
        await forward_client.forward(req)
    await forward_client.aclose()


@pytest.mark.asyncio
async def test_client_disconnect_cancels_and_awaits_upstream(test_settings: Settings) -> None:
    """Test that client disconnect cancels upstream request and properly awaits cancellation."""

    class MockDisconnectRequest:
        async def is_disconnected(self) -> bool:
            return True

    upstream_cancelled = False

    async def slow_upstream(_request: httpx.Request) -> httpx.Response:
        nonlocal upstream_cancelled
        try:
            await asyncio.sleep(10)
            return httpx.Response(200, json={"result": "ok"})
        except asyncio.CancelledError:
            upstream_cancelled = True
            raise

    mock_http_client = httpx.AsyncClient(transport=httpx.MockTransport(slow_upstream))
    forward_client = ProxyForwardClient(settings=test_settings, client=mock_http_client)

    req = ProxyRequest(
        provider=Provider.OPENAI,
        url="http://localhost/test",
        method="POST",
        headers={},
        body=b"",
    )

    with pytest.raises(asyncio.CancelledError):
        await forward_client.forward(
            proxy_request=req,
            client_request=MockDisconnectRequest(),  # pyright: ignore[reportArgumentType]
        )

    assert upstream_cancelled is True
    await mock_http_client.aclose()
    await forward_client.aclose()


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
