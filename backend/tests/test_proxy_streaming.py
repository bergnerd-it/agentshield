"""Contract and integration tests for streaming proxy endpoints and rehydration."""

import json
from collections.abc import Generator

import httpx
import pytest
from fastapi.testclient import TestClient

from agentshield.api.app import create_app
from agentshield.api.dependencies import (
    get_credential_store,
    get_forward_client,
    get_inspection_pipeline,
    get_pseudonym_vault,
)
from agentshield.core.auth import get_or_create_proxy_token
from agentshield.core.config import Settings
from agentshield.core.credentials import InMemoryCredentialStore
from agentshield.filtering.detectors.pii import StructuredPiiDetector
from agentshield.filtering.detectors.secrets import SecretDetector
from agentshield.filtering.detectors.unsupported import UnsupportedContentDetector
from agentshield.filtering.engine import DetectorEngine
from agentshield.policies.engine import PolicyEngine
from agentshield.policies.models import PolicyProfile
from agentshield.proxy.client import ProxyForwardClient
from agentshield.proxy.inspection import RequestInspectionPipeline
from agentshield.pseudonyms.vault import InMemoryPseudonymVault
from tests.mock_providers import MockAnthropicServer, MockOpenAIServer

FINGERPRINT_KEY = b"test-fingerprint-key-milestone-4"
MOCK_OPENAI_KEY = "sk-synth-real-upstream-key-99999"
MOCK_ANTHROPIC_KEY = "sk-ant-synth-real-upstream-key-99999"


def _build_inspection_pipeline(
    profile: PolicyProfile = PolicyProfile.BALANCED,
) -> RequestInspectionPipeline:
    return RequestInspectionPipeline(
        detector_engine=DetectorEngine(
            (
                SecretDetector(fingerprint_key=FINGERPRINT_KEY),
                StructuredPiiDetector(fingerprint_key=FINGERPRINT_KEY),
                UnsupportedContentDetector(fingerprint_key=FINGERPRINT_KEY),
            ),
            timeout_seconds=0.5,
        ),
        policy_engine=PolicyEngine(profile),
        header_secret_detector=SecretDetector(fingerprint_key=FINGERPRINT_KEY),
    )


@pytest.fixture
def streaming_vault() -> InMemoryPseudonymVault:
    return InMemoryPseudonymVault(default_ttl_seconds=3600)


@pytest.fixture
def streaming_openai_client(
    test_settings: Settings,
    streaming_vault: InMemoryPseudonymVault,
) -> Generator[tuple[TestClient, MockOpenAIServer, InMemoryPseudonymVault]]:
    mock = MockOpenAIServer()
    transport = httpx.ASGITransport(app=mock.app)  # pyright: ignore[reportArgumentType]
    upstream = httpx.AsyncClient(
        transport=transport,
        base_url=test_settings.openai_upstream_base_url,
    )
    forwarder = ProxyForwardClient(settings=test_settings, client=upstream)
    cred_store = InMemoryCredentialStore(initial_keys={"openai": MOCK_OPENAI_KEY})
    pipeline = _build_inspection_pipeline(PolicyProfile.BALANCED)

    app = create_app(test_settings)
    app.dependency_overrides[get_forward_client] = lambda: forwarder
    app.dependency_overrides[get_credential_store] = lambda: cred_store
    app.dependency_overrides[get_inspection_pipeline] = lambda: pipeline
    app.dependency_overrides[get_pseudonym_vault] = lambda: streaming_vault

    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        yield client, mock, streaming_vault


@pytest.fixture
def streaming_anthropic_client(
    test_settings: Settings,
    streaming_vault: InMemoryPseudonymVault,
) -> Generator[tuple[TestClient, MockAnthropicServer, InMemoryPseudonymVault]]:
    mock = MockAnthropicServer()
    transport = httpx.ASGITransport(app=mock.app)  # pyright: ignore[reportArgumentType]
    upstream = httpx.AsyncClient(
        transport=transport,
        base_url=test_settings.anthropic_upstream_base_url,
    )
    forwarder = ProxyForwardClient(settings=test_settings, client=upstream)
    cred_store = InMemoryCredentialStore(initial_keys={"anthropic": MOCK_ANTHROPIC_KEY})
    pipeline = _build_inspection_pipeline(PolicyProfile.BALANCED)

    app = create_app(test_settings)
    app.dependency_overrides[get_forward_client] = lambda: forwarder
    app.dependency_overrides[get_credential_store] = lambda: cred_store
    app.dependency_overrides[get_inspection_pipeline] = lambda: pipeline
    app.dependency_overrides[get_pseudonym_vault] = lambda: streaming_vault

    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        yield client, mock, streaming_vault


def test_openai_responses_streaming(
    streaming_openai_client: tuple[TestClient, MockOpenAIServer, InMemoryPseudonymVault],
    test_settings: Settings,
) -> None:
    """Test OpenAI Responses endpoint streaming SSE events."""
    client, mock, _ = streaming_openai_client
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)

    response = client.post(
        "/proxy/openai/v1/responses",
        headers={"Authorization": f"Bearer {proxy_token}"},
        json={"model": "gpt-4o", "input": "Hello streaming world", "stream": True},
    )

    assert response.status_code == 200
    assert "text/event-stream" in response.headers.get("content-type", "")
    assert "response.text.delta" in response.text
    assert "[DONE]" in response.text
    assert len(mock.recorded_requests) == 1
    assert mock.recorded_requests[0].json is not None
    assert mock.recorded_requests[0].json["stream"] is True


def test_openai_chat_completions_streaming(
    streaming_openai_client: tuple[TestClient, MockOpenAIServer, InMemoryPseudonymVault],
    test_settings: Settings,
) -> None:
    """Test OpenAI Chat Completions endpoint streaming SSE events."""
    client, mock, _ = streaming_openai_client
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)

    response = client.post(
        "/proxy/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {proxy_token}"},
        json={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hello chat stream"}],
            "stream": True,
        },
    )

    assert response.status_code == 200
    assert "text/event-stream" in response.headers.get("content-type", "")
    assert "chat.completion.chunk" in response.text
    assert "Synthetic test chat completion." in response.text
    assert "[DONE]" in response.text
    assert len(mock.recorded_requests) == 1
    assert mock.recorded_requests[0].json is not None
    assert mock.recorded_requests[0].json["stream"] is True


def test_anthropic_messages_streaming(
    streaming_anthropic_client: tuple[TestClient, MockAnthropicServer, InMemoryPseudonymVault],
    test_settings: Settings,
) -> None:
    """Test Anthropic Messages endpoint streaming SSE events."""
    client, mock, _ = streaming_anthropic_client
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)

    response = client.post(
        "/proxy/anthropic/v1/messages",
        headers={"x-api-key": proxy_token},
        json={
            "model": "claude-3-5-sonnet-20241022",
            "max_tokens": 100,
            "messages": [{"role": "user", "content": "Hello Anthropic stream"}],
            "stream": True,
        },
    )

    assert response.status_code == 200
    assert "text/event-stream" in response.headers.get("content-type", "")
    assert "message_start" in response.text
    assert "content_block_delta" in response.text
    assert "Synthetic test Anthropic response." in response.text
    assert len(mock.recorded_requests) == 1
    assert mock.recorded_requests[0].json is not None
    assert mock.recorded_requests[0].json["stream"] is True


def test_openai_streaming_rehydration_roundtrip(
    streaming_openai_client: tuple[TestClient, MockOpenAIServer, InMemoryPseudonymVault],
    test_settings: Settings,
) -> None:
    """Test that pseudonymized PII in streaming response is rehydrated in the client stream."""
    client, mock, _ = streaming_openai_client
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)
    session_id = "test-stream-session-1"

    # Send request with PII (email address)
    original_email = "jane.doe@corp.example.com"
    req_body = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": f"Please verify {original_email}"}],
        "stream": True,
    }

    # Perform request
    response = client.post(
        "/proxy/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {proxy_token}", "x-session-id": session_id},
        json=req_body,
    )

    assert response.status_code == 200
    # Upstream must have received the pseudonymized email, not the raw email
    assert len(mock.recorded_requests) == 1
    recorded = mock.recorded_requests[0]
    assert recorded.json is not None
    prompt_sent_to_upstream = recorded.json["messages"][0]["content"]
    assert original_email not in prompt_sent_to_upstream
    assert "<AS:EMAIL:" in prompt_sent_to_upstream

    # Extract the placeholder issued
    placeholder = prompt_sent_to_upstream.split("Please verify ")[1].strip()

    # Now simulate an upstream response that echoes this exact placeholder
    chunks = [
        {
            "id": "chatcmpl-echo-001",
            "object": "chat.completion.chunk",
            "created": 1700000000,
            "model": "gpt-4o",
            "choices": [
                {
                    "index": 0,
                    "delta": {"content": f"The verified address is {placeholder}!"},
                    "finish_reason": None,
                }
            ],
        },
        {
            "id": "chatcmpl-echo-001",
            "object": "chat.completion.chunk",
            "created": 1700000000,
            "model": "gpt-4o",
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
        },
    ]
    mock.next_stream_events = [f"data: {json.dumps(c)}\n\n".encode() for c in chunks] + [
        b"data: [DONE]\n\n"
    ]

    # Re-issue request with same session_id so vault has the mapping
    stream_resp = client.post(
        "/proxy/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {proxy_token}", "x-session-id": session_id},
        json={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Echo placeholder"}],
            "stream": True,
        },
    )

    assert stream_resp.status_code == 200
    # Client stream must contain the original rehydrated email, NOT the placeholder
    assert original_email in stream_resp.text
    assert placeholder not in stream_resp.text


def test_openai_streaming_split_placeholder_rehydration(
    streaming_openai_client: tuple[TestClient, MockOpenAIServer, InMemoryPseudonymVault],
    test_settings: Settings,
) -> None:
    """Test rehydration when placeholder is fragmented across adjacent SSE delta chunks."""
    client, mock, _ = streaming_openai_client
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)
    session_id = "test-split-session-2"

    original_email = "split.test@corp.example.com"

    # Step 1: populate vault via initial inspection request
    client.post(
        "/proxy/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {proxy_token}", "x-session-id": session_id},
        json={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": f"Register {original_email}"}],
            "stream": True,
        },
    )

    recorded = mock.recorded_requests[-1]
    assert recorded.json is not None
    prompt = recorded.json["messages"][0]["content"]
    placeholder = prompt.split("Register ")[1].strip()
    assert placeholder.startswith("<AS:EMAIL:") and placeholder.endswith(">")

    # Split placeholder into 3 fragments across 3 delta chunks
    part1 = placeholder[:10]  # e.g. "<AS:EMAIL:"
    part2 = placeholder[10:18]  # middle session hash
    part3 = placeholder[18:]  # remainder including closing >

    split_chunks = [
        {
            "id": "chatcmpl-split-001",
            "object": "chat.completion.chunk",
            "created": 1700000000,
            "model": "gpt-4o",
            "choices": [
                {"index": 0, "delta": {"content": f"Account for {part1}"}, "finish_reason": None}
            ],
        },
        {
            "id": "chatcmpl-split-001",
            "object": "chat.completion.chunk",
            "created": 1700000000,
            "model": "gpt-4o",
            "choices": [{"index": 0, "delta": {"content": part2}, "finish_reason": None}],
        },
        {
            "id": "chatcmpl-split-001",
            "object": "chat.completion.chunk",
            "created": 1700000000,
            "model": "gpt-4o",
            "choices": [
                {"index": 0, "delta": {"content": f"{part3} is ready."}, "finish_reason": None}
            ],
        },
        {
            "id": "chatcmpl-split-001",
            "object": "chat.completion.chunk",
            "created": 1700000000,
            "model": "gpt-4o",
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
        },
    ]

    mock.next_stream_events = [f"data: {json.dumps(c)}\n\n".encode() for c in split_chunks] + [
        b"data: [DONE]\n\n"
    ]

    response = client.post(
        "/proxy/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {proxy_token}", "x-session-id": session_id},
        json={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Fetch"}],
            "stream": True,
        },
    )

    assert response.status_code == 200
    assert original_email in response.text
    assert placeholder not in response.text

    # Parse and concatenate deltas from SSE events as a downstream LLM client does
    deltas: list[str] = []
    for line in response.text.splitlines():
        if line.startswith("data: ") and not line.endswith("[DONE]"):
            data = json.loads(line[6:])
            deltas.append(data["choices"][0]["delta"].get("content", ""))
    full_message = "".join(deltas)
    assert full_message == f"Account for {original_email} is ready."


def test_anthropic_streaming_rehydration_roundtrip(
    streaming_anthropic_client: tuple[TestClient, MockAnthropicServer, InMemoryPseudonymVault],
    test_settings: Settings,
) -> None:
    """Test rehydration for Anthropic streaming response."""
    client, mock, _ = streaming_anthropic_client
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)
    session_id = "test-anthropic-session-3"

    original_email = "anthropic.user@corp.example.com"

    # Populate vault via request
    client.post(
        "/proxy/anthropic/v1/messages",
        headers={"x-api-key": proxy_token, "x-session-id": session_id},
        json={
            "model": "claude-3-5-sonnet-20241022",
            "max_tokens": 100,
            "messages": [{"role": "user", "content": f"Email is {original_email}"}],
            "stream": True,
        },
    )

    recorded = mock.recorded_requests[-1]
    assert recorded.json is not None
    prompt = recorded.json["messages"][0]["content"]
    placeholder = prompt.split("Email is ")[1].strip()
    assert placeholder.startswith("<AS:EMAIL:")

    # Configure mock Anthropic server to stream back the placeholder
    events = [
        (
            "message_start",
            {
                "type": "message_start",
                "message": {
                    "id": "msg-001",
                    "type": "message",
                    "role": "assistant",
                    "content": [],
                    "model": "claude-3-5-sonnet-20241022",
                },
            },
        ),
        (
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            },
        ),
        (
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": f"Found user with {placeholder}."},
            },
        ),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ("message_stop", {"type": "message_stop"}),
    ]
    mock.next_stream_events = [
        f"event: {ev}\ndata: {json.dumps(d)}\n\n".encode() for ev, d in events
    ]

    response = client.post(
        "/proxy/anthropic/v1/messages",
        headers={"x-api-key": proxy_token, "x-session-id": session_id},
        json={
            "model": "claude-3-5-sonnet-20241022",
            "max_tokens": 100,
            "messages": [{"role": "user", "content": "Echo"}],
            "stream": True,
        },
    )

    assert response.status_code == 200
    assert f"Found user with {original_email}." in response.text
    assert placeholder not in response.text


def test_non_streaming_rehydration_roundtrip(
    streaming_openai_client: tuple[TestClient, MockOpenAIServer, InMemoryPseudonymVault],
    test_settings: Settings,
) -> None:
    """Test that non-streaming JSON responses are also rehydrated."""
    client, mock, _ = streaming_openai_client
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)
    session_id = "test-non-streaming-session-4"

    original_email = "nonstreaming@corp.example.com"

    # Step 1: send request to get placeholder
    client.post(
        "/proxy/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {proxy_token}", "x-session-id": session_id},
        json={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": f"Query for {original_email}"}],
        },
    )

    recorded = mock.recorded_requests[-1]
    assert recorded.json is not None
    prompt = recorded.json["messages"][0]["content"]
    placeholder = prompt.split("Query for ")[1].strip()

    # Step 2: configure mock server to return non-streaming JSON echoing placeholder
    mock.next_response_body = {
        "id": "chatcmpl-ns-001",
        "object": "chat.completion",
        "created": 1700000000,
        "model": "gpt-4o",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": f"Result for {placeholder}"},
                "finish_reason": "stop",
            }
        ],
    }

    response = client.post(
        "/proxy/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {proxy_token}", "x-session-id": session_id},
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "Echo non-streaming"}]},
    )

    assert response.status_code == 200
    body = response.json()
    content = body["choices"][0]["message"]["content"]
    assert content == f"Result for {original_email}"
    assert placeholder not in content


def test_secrets_never_entered_in_vault_and_never_rehydrated(
    streaming_openai_client: tuple[TestClient, MockOpenAIServer, InMemoryPseudonymVault],
    test_settings: Settings,
) -> None:
    """Security Invariant: Secrets can NEVER enter PseudonymVault and are NEVER rehydrated."""
    client, _, vault = streaming_openai_client
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)
    session_id = "test-secret-vault-invariant"

    # Synthetic secret token
    secret_value = "sk-ant-api03-synth_marker_never_vault_1234567890abcdef"

    # Send request with secret
    response = client.post(
        "/proxy/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {proxy_token}", "x-session-id": session_id},
        json={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": f"My secret key is {secret_value}"}],
        },
    )

    # In balanced profile, secret is BLOCKED (403 ContentBlockedError)
    assert response.status_code == 403
    # Vault must not have recorded this session or any mapping for the secret
    assert not vault.has_session_mappings(session_id)
    assert vault.rehydrate(session_id=session_id, placeholder="<AS:SECRET:0001>") is None


def test_session_isolation_in_rehydration(
    streaming_openai_client: tuple[TestClient, MockOpenAIServer, InMemoryPseudonymVault],
    test_settings: Settings,
) -> None:
    """Session isolation: Session B cannot rehydrate placeholders belonging to Session A."""
    client, mock, _ = streaming_openai_client
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)

    # Session A registers email
    email_a = "alice@example.com"
    client.post(
        "/proxy/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {proxy_token}", "x-session-id": "session-A"},
        json={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": f"Hello {email_a}"}],
            "stream": True,
        },
    )
    last_req = mock.recorded_requests[-1]
    assert last_req.json is not None
    placeholder_a = last_req.json["messages"][0]["content"].split("Hello ")[1].strip()

    # Session B receives Session A's placeholder in an SSE stream
    chunks = [
        {
            "id": "chatcmpl-sess-001",
            "object": "chat.completion.chunk",
            "created": 1700000000,
            "model": "gpt-4o",
            "choices": [
                {
                    "index": 0,
                    "delta": {"content": f"Data: {placeholder_a}"},
                    "finish_reason": "stop",
                }
            ],
        }
    ]
    mock.next_stream_events = [f"data: {json.dumps(c)}\n\n".encode() for c in chunks] + [
        b"data: [DONE]\n\n"
    ]

    response = client.post(
        "/proxy/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {proxy_token}", "x-session-id": "session-B"},
        json={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Request"}],
            "stream": True,
        },
    )

    assert response.status_code == 200
    # Session B must NOT rehydrate Session A's email!
    assert email_a not in response.text
    # The placeholder remains untouched
    assert placeholder_a in response.text


def test_upstream_error_before_streaming(
    streaming_openai_client: tuple[TestClient, MockOpenAIServer, InMemoryPseudonymVault],
    test_settings: Settings,
) -> None:
    """Upstream 4xx/5xx returned before streaming starts is preserved faithfully."""
    client, mock, _ = streaming_openai_client
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)

    mock.next_status_code = 429
    mock.next_response_body = {
        "error": {
            "message": "Rate limit reached for requests",
            "type": "requests",
            "param": None,
            "code": "rate_limit_exceeded",
        }
    }

    response = client.post(
        "/proxy/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {proxy_token}"},
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "Hi"}], "stream": True},
    )

    assert response.status_code == 429
    assert response.headers.get("content-type") == "application/json"
    body = response.json()
    assert body["error"]["code"] == "rate_limit_exceeded"


def test_upstream_credential_leak_in_streaming_headers(
    streaming_openai_client: tuple[TestClient, MockOpenAIServer, InMemoryPseudonymVault],
    test_settings: Settings,
) -> None:
    """Upstream reflecting the provider API key in response headers is blocked."""
    client, mock, _ = streaming_openai_client
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)

    mock.next_headers = {
        "content-type": "text/event-stream",
        "x-reflected-key": MOCK_OPENAI_KEY,
    }
    mock.next_stream_events = [b"data: {}\n\n"]

    response = client.post(
        "/proxy/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {proxy_token}"},
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "Hi"}], "stream": True},
    )

    assert response.status_code == 502
    assert response.json()["type"] == "urn:agentshield:error:upstream-credential-leak"
    assert MOCK_OPENAI_KEY not in response.text


def test_upstream_credential_leak_in_streaming_chunks(
    streaming_openai_client: tuple[TestClient, MockOpenAIServer, InMemoryPseudonymVault],
    test_settings: Settings,
) -> None:
    """Upstream emitting the provider API key in an SSE chunk terminates stream immediately."""
    client, mock, _ = streaming_openai_client
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)

    leaked_chunk = {
        "id": "chatcmpl-leak-001",
        "object": "chat.completion.chunk",
        "choices": [{"index": 0, "delta": {"content": f"Leaking {MOCK_OPENAI_KEY}"}}],
    }

    mock.next_stream_events = [
        b'data: {"choices": [{"delta": {"content": "Safe prefix"}}]}\n\n',
        f"data: {json.dumps(leaked_chunk)}\n\n".encode(),
        b"data: [DONE]\n\n",
    ]

    response = client.post(
        "/proxy/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {proxy_token}"},
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "Hi"}], "stream": True},
    )

    assert response.status_code == 200
    # Stream was aborted when credential was detected: provider key MUST NOT be sent to client
    assert MOCK_OPENAI_KEY not in response.text
    assert "[DONE]" not in response.text


def test_upstream_secret_leak_in_stream_terminates(
    streaming_openai_client: tuple[TestClient, MockOpenAIServer, InMemoryPseudonymVault],
    test_settings: Settings,
) -> None:
    """Upstream emitting a detected secret mid-stream terminates the stream."""
    client, mock, _ = streaming_openai_client
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)

    # Synthetic secret pattern recognizable by SecretDetector
    synthetic_secret = "AKIAIOSFODNN7EXAMPLE"

    secret_chunk = {
        "id": "chatcmpl-sec-001",
        "object": "chat.completion.chunk",
        "choices": [{"index": 0, "delta": {"content": f"Here is key: {synthetic_secret}"}}],
    }

    mock.next_stream_events = [
        b'data: {"choices": [{"delta": {"content": "Beginning text: "}}]}\n\n',
        f"data: {json.dumps(secret_chunk)}\n\n".encode(),
        b'data: {"choices": [{"delta": {"content": "Trailing text"}}]}\n\n',
        b"data: [DONE]\n\n",
    ]

    response = client.post(
        "/proxy/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {proxy_token}"},
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "Hi"}], "stream": True},
    )

    assert response.status_code == 200
    # SecretDetector stops the stream; secret must not appear in client output
    assert synthetic_secret not in response.text
    assert "Trailing text" not in response.text
    assert "[DONE]" not in response.text
