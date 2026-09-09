"""Validation and adapter-boundary tests for proxy requests."""

import asyncio
import time

import pytest

from agentshield.core.config import Settings
from agentshield.core.credentials import InMemoryCredentialStore
from agentshield.core.errors import InvalidProviderEndpointError, InvalidProxyPayloadError
from agentshield.proxy.anthropic import AnthropicAdapter
from agentshield.proxy.openai import OpenAIAdapter


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "upstream_url",
    [
        "http://api.openai.com",
        "http://169.254.169.254/latest/meta-data",
        "https://synthetic-attacker.invalid",
        "https://user:password@api.openai.com",
    ],
)
async def test_openai_rejects_unsafe_production_endpoint(upstream_url: str) -> None:
    """Production credentials can only be sent to the official HTTPS endpoint."""
    adapter = OpenAIAdapter(
        credential_store=InMemoryCredentialStore(
            {"openai": "sk-synth-production-key-123456789012345"}
        ),
        settings=Settings(dev_mode=False, openai_upstream_base_url=upstream_url),
    )

    with pytest.raises(InvalidProviderEndpointError):
        await adapter.prepare_request(
            endpoint_path="/v1/responses",
            raw_body=b'{"model":"gpt-4o","input":"Synthetic request"}',
            incoming_headers={},
        )


@pytest.mark.asyncio
async def test_anthropic_rejects_unsafe_production_endpoint() -> None:
    """Anthropic credentials cannot be attached to a custom production target."""
    adapter = AnthropicAdapter(
        credential_store=InMemoryCredentialStore(
            {"anthropic": "sk-ant-synth-production-key-123456789012345"}
        ),
        settings=Settings(
            dev_mode=False,
            anthropic_upstream_base_url="https://synthetic-attacker.invalid",
        ),
    )

    with pytest.raises(InvalidProviderEndpointError):
        await adapter.prepare_request(
            endpoint_path="/v1/messages",
            raw_body=b'{"model":"claude-synth","max_tokens":16,"messages":[]}',
            incoming_headers={},
        )


@pytest.mark.asyncio
async def test_endpoint_and_payload_validation_precede_credential_access() -> None:
    """Unsafe configuration and ambiguous input fail before a key is retrieved."""

    class RecordingCredentialStore(InMemoryCredentialStore):
        accessed = False

        def get_provider_key(self, provider: str) -> str | None:
            self.accessed = True
            return super().get_provider_key(provider)

    credential_store = RecordingCredentialStore({"openai": "sk-synth-ordering-key"})
    unsafe_adapter = OpenAIAdapter(
        credential_store=credential_store,
        settings=Settings(
            dev_mode=False,
            openai_upstream_base_url="https://synthetic-attacker.invalid",
        ),
    )

    with pytest.raises(InvalidProviderEndpointError):
        await unsafe_adapter.prepare_request(
            endpoint_path="/v1/responses",
            raw_body=b'{"model":"gpt-4o"}',
            incoming_headers={},
        )
    assert credential_store.accessed is False

    safe_adapter = OpenAIAdapter(
        credential_store=credential_store,
        settings=Settings(),
    )
    with pytest.raises(InvalidProxyPayloadError):
        await safe_adapter.prepare_request(
            endpoint_path="/v1/responses",
            raw_body=b'{"model":"first","model":"second"}',
            incoming_headers={},
        )
    assert credential_store.accessed is False


@pytest.mark.asyncio
async def test_development_allows_loopback_mock_endpoint() -> None:
    """Development mode retains the local mock-provider workflow."""
    adapter = OpenAIAdapter(
        credential_store=InMemoryCredentialStore({"openai": "sk-synth-local-mock-key"}),
        settings=Settings(
            dev_mode=True,
            openai_upstream_base_url="http://127.0.0.1:9000",
        ),
    )

    request = await adapter.prepare_request(
        endpoint_path="/v1/responses",
        raw_body=b'{"model":"gpt-4o","input":"Synthetic request"}',
        incoming_headers={},
    )

    assert request.url == "http://127.0.0.1:9000/v1/responses"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [
        b'{"model":',
        b'{"model":"first","model":"second"}',
        b'["not", "an", "object"]',
        b'{"stream":false,"stream":true}',
    ],
)
async def test_openai_rejects_malformed_or_ambiguous_json(body: bytes) -> None:
    """Malformed, non-object, and duplicate-key payloads fail before forwarding."""
    adapter = OpenAIAdapter(
        credential_store=InMemoryCredentialStore({"openai": "sk-synth-json-key"}),
        settings=Settings(),
    )

    with pytest.raises(InvalidProxyPayloadError):
        await adapter.prepare_request(
            endpoint_path="/v1/responses",
            raw_body=body,
            incoming_headers={},
        )


@pytest.mark.asyncio
async def test_connection_nominated_request_header_is_removed() -> None:
    """Headers named by Connection are hop-by-hop even when otherwise unknown."""
    adapter = OpenAIAdapter(
        credential_store=InMemoryCredentialStore({"openai": "sk-synth-header-key"}),
        settings=Settings(),
    )

    request = await adapter.prepare_request(
        endpoint_path="/v1/responses",
        raw_body=b'{"model":"gpt-4o","input":"Synthetic request"}',
        incoming_headers={
            "Connection": "X-Hop-Only, X-Second-Hop",
            "X-Hop-Only": "synthetic-one",
            "X-Second-Hop": "synthetic-two",
            "OpenAI-Project": "project-synth",
        },
    )

    assert "Connection" not in request.headers
    assert "X-Hop-Only" not in request.headers
    assert "X-Second-Hop" not in request.headers
    assert request.headers["OpenAI-Project"] == "project-synth"


@pytest.mark.asyncio
async def test_keyring_lookup_does_not_block_event_loop() -> None:
    """Synchronous native credential access is isolated from the async proxy loop."""
    events: list[str] = []

    class SlowCredentialStore(InMemoryCredentialStore):
        def get_provider_key(self, provider: str) -> str | None:
            events.append("credential-start")
            time.sleep(0.1)
            events.append("credential-end")
            return "sk-synth-slow-key"

    async def ticker() -> None:
        await asyncio.sleep(0.01)
        events.append("event-loop-progress")

    adapter = OpenAIAdapter(credential_store=SlowCredentialStore(), settings=Settings())
    request_task = asyncio.create_task(
        adapter.prepare_request(
            endpoint_path="/v1/responses",
            raw_body=b'{"model":"gpt-4o","input":"Synthetic request"}',
            incoming_headers={},
        )
    )
    await ticker()
    await request_task

    assert events == ["credential-start", "event-loop-progress", "credential-end"]
