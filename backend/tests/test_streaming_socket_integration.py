"""Integration and contract tests for streaming, backpressure, and client disconnection."""

import asyncio
import json
import socket
from collections.abc import AsyncGenerator, AsyncIterator
from typing import Any

import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response, StreamingResponse
from starlette.routing import Route

from agentshield.api.app import create_app
from agentshield.api.dependencies import (
    get_credential_store,
    get_current_settings,
    get_forward_client,
    get_inspection_pipeline,
    get_pseudonym_vault,
)
from agentshield.core.auth import get_or_create_proxy_token
from agentshield.core.config import Settings
from agentshield.core.credentials import InMemoryCredentialStore
from agentshield.filtering.detectors.pii import StructuredPiiDetector
from agentshield.filtering.detectors.secrets import SecretDetector
from agentshield.filtering.engine import DetectorEngine
from agentshield.policies.engine import PolicyEngine
from agentshield.policies.models import PolicyProfile
from agentshield.proxy.client import ProxyForwardClient
from agentshield.proxy.inspection import RequestInspectionPipeline
from agentshield.proxy.rehydration import StreamingRehydrator
from agentshield.proxy.streaming import StreamingPipeline
from agentshield.proxy.types import Provider, ProxyRequest
from agentshield.pseudonyms.vault import InMemoryPseudonymVault


def _can_bind_sockets() -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return True
    except PermissionError, OSError:
        return False


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class LiveMockUpstream:
    """Live Starlette server tracking requests and stream lifecycle."""

    def __init__(self) -> None:
        self.recorded_requests: list[dict[str, Any]] = []
        self.stream_cancelled = asyncio.Event()
        self.stream_completed = asyncio.Event()
        self.chunks_yielded = 0
        self.app = Starlette(
            routes=[
                Route("/v1/chat/completions", self._chat_completions, methods=["POST"]),
            ]
        )

    async def _chat_completions(self, request: Request) -> Response:
        body = await request.body()
        data = json.loads(body.decode("utf-8")) if body else {}
        self.recorded_requests.append(data)

        if data.get("stream") is True:

            async def _stream():
                try:
                    for i in range(10):
                        self.chunks_yielded += 1
                        chunk = {
                            "id": "chatcmpl-live-001",
                            "object": "chat.completion.chunk",
                            "choices": [{"index": 0, "delta": {"content": f"chunk-{i} "}}],
                        }
                        yield f"data: {json.dumps(chunk)}\n\n".encode()
                        await asyncio.sleep(0.05)
                    yield b"data: [DONE]\n\n"
                    self.stream_completed.set()
                except asyncio.CancelledError:
                    self.stream_cancelled.set()
                    raise

            return StreamingResponse(_stream(), media_type="text/event-stream")

        return Response(
            content=json.dumps({"choices": [{"message": {"content": "live non-stream"}}]}),
            media_type="application/json",
        )


@pytest.fixture
async def live_upstream() -> AsyncGenerator[tuple[LiveMockUpstream, int]]:
    import uvicorn

    mock = LiveMockUpstream()
    port = _find_free_port()
    config = uvicorn.Config(mock.app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())

    while not server.started:  # noqa: ASYNC110
        await asyncio.sleep(0.02)

    try:
        yield mock, port
    finally:
        server.should_exit = True
        await task


@pytest.fixture
async def live_proxy(
    test_settings: Settings,
    live_upstream: tuple[LiveMockUpstream, int],
) -> AsyncGenerator[tuple[int, InMemoryPseudonymVault]]:
    import uvicorn

    _, upstream_port = live_upstream

    vault = InMemoryPseudonymVault(default_ttl_seconds=3600)
    key = b"live-socket-test-key-000000000"
    pipeline = RequestInspectionPipeline(
        detector_engine=DetectorEngine(
            (
                SecretDetector(fingerprint_key=key),
                StructuredPiiDetector(fingerprint_key=key),
            ),
            timeout_seconds=0.5,
        ),
        policy_engine=PolicyEngine(PolicyProfile.BALANCED),
        header_secret_detector=SecretDetector(fingerprint_key=key),
    )
    cred_store = InMemoryCredentialStore(initial_keys={"openai": "sk-synth-live-key-12345"})

    proxy_settings = test_settings.model_copy(
        update={
            "openai_upstream_base_url": f"http://127.0.0.1:{upstream_port}",
        }
    )
    forward_client = ProxyForwardClient(settings=proxy_settings)

    app = create_app(proxy_settings)
    app.dependency_overrides[get_current_settings] = lambda: proxy_settings
    app.dependency_overrides[get_forward_client] = lambda: forward_client
    app.dependency_overrides[get_credential_store] = lambda: cred_store
    app.dependency_overrides[get_inspection_pipeline] = lambda: pipeline
    app.dependency_overrides[get_pseudonym_vault] = lambda: vault

    proxy_port = _find_free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=proxy_port, log_level="error")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())

    while not server.started:  # noqa: ASYNC110
        await asyncio.sleep(0.02)

    try:
        yield proxy_port, vault
    finally:
        server.should_exit = True
        await task
        await forward_client.aclose()


@pytest.mark.skipif(
    not _can_bind_sockets(), reason="Local socket binding not permitted in sandboxed environment"
)
@pytest.mark.asyncio
async def test_live_socket_streaming_end_to_end(
    live_upstream: tuple[LiveMockUpstream, int],
    live_proxy: tuple[int, InMemoryPseudonymVault],
    test_settings: Settings,
) -> None:
    """Test full SSE streaming through real TCP sockets over Uvicorn."""
    mock, _ = live_upstream
    proxy_port, _ = live_proxy
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)

    async with (
        httpx.AsyncClient(timeout=10.0) as client,
        client.stream(
            "POST",
            f"http://127.0.0.1:{proxy_port}/proxy/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {proxy_token}"},
            json={
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": "Stream all chunks"}],
                "stream": True,
            },
        ) as response,
    ):
        assert response.status_code == 200
        assert "text/event-stream" in response.headers.get("content-type", "")

        chunks_received: list[str] = []
        async for line in response.aiter_lines():
            if line.startswith("data: "):
                chunks_received.append(line)

        assert len(chunks_received) >= 10
        assert any("[DONE]" in c for c in chunks_received)

    assert mock.stream_completed.is_set()


@pytest.mark.skipif(
    not _can_bind_sockets(), reason="Local socket binding not permitted in sandboxed environment"
)
@pytest.mark.asyncio
async def test_live_socket_client_disconnect_cancels_upstream(
    live_upstream: tuple[LiveMockUpstream, int],
    live_proxy: tuple[int, InMemoryPseudonymVault],
    test_settings: Settings,
) -> None:
    """Test that closing client socket mid-stream cancels upstream streaming immediately."""
    mock, _ = live_upstream
    proxy_port, _ = live_proxy
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)

    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)

    req_body = json.dumps(
        {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Disconnect me"}],
            "stream": True,
        }
    )
    http_request = (
        f"POST /proxy/openai/v1/chat/completions HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{proxy_port}\r\n"
        f"Authorization: Bearer {proxy_token}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(req_body)}\r\n"
        f"\r\n"
        f"{req_body}"
    )

    writer.write(http_request.encode("utf-8"))
    await writer.drain()

    received_bytes = bytearray()
    while b"chunk-0" not in received_bytes:
        chunk = await asyncio.wait_for(reader.read(1024), timeout=5.0)
        if not chunk:
            break
        received_bytes.extend(chunk)

    assert b"chunk-0" in received_bytes

    writer.close()
    await writer.wait_closed()

    try:
        await asyncio.wait_for(mock.stream_cancelled.wait(), timeout=3.0)
    except TimeoutError:
        pytest.fail("Upstream stream generator was not cancelled after client disconnect")

    assert mock.chunks_yielded < 10


# ============================================================================
# Deterministic in-process streaming cancellation tests (always run)
# ============================================================================


@pytest.mark.asyncio
async def test_forward_stream_already_disconnected_client_cancels(
    test_settings: Settings,
) -> None:
    """An already-disconnected client raises CancelledError without calling upstream."""

    class MockDisconnectedClientRequest:
        async def is_disconnected(self) -> bool:
            return True

    upstream_called = False

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal upstream_called
        upstream_called = True
        return httpx.Response(
            200, headers={"content-type": "text/event-stream"}, content=b"data: test\n\n"
        )

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    forward_client = ProxyForwardClient(settings=test_settings, client=mock_client)

    proxy_req = ProxyRequest(
        provider=Provider.OPENAI,
        url="http://localhost/test",
        method="POST",
        headers={},
        body=b"{}",
        is_streaming=True,
    )

    with pytest.raises(asyncio.CancelledError):
        await forward_client.forward_stream(
            proxy_request=proxy_req,
            client_request=MockDisconnectedClientRequest(),  # pyright: ignore[reportArgumentType]
        )

    assert upstream_called is False
    await mock_client.aclose()
    await forward_client.aclose()


@pytest.mark.asyncio
async def test_forward_stream_disconnect_during_streaming_cancels_upstream(
    test_settings: Settings,
) -> None:
    """When a client disconnects mid-stream, stream raises CancelledError and closes upstream."""

    class DelayedDisconnectClientRequest:
        def __init__(self) -> None:
            self.checks = 0

        async def is_disconnected(self) -> bool:
            self.checks += 1
            # Disconnect on the third check (after first chunk consumed)
            return self.checks >= 3

    upstream_cancelled = False
    chunks_yielded = 0

    async def slow_upstream_stream() -> AsyncIterator[bytes]:
        nonlocal chunks_yielded, upstream_cancelled
        try:
            for i in range(10):
                chunks_yielded += 1
                yield f"data: chunk-{i}\n\n".encode()
                await asyncio.sleep(0.01)
        except asyncio.CancelledError:
            upstream_cancelled = True
            raise

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=200,
            headers={"content-type": "text/event-stream"},
            content=slow_upstream_stream(),
        )

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    forward_client = ProxyForwardClient(settings=test_settings, client=mock_client)

    proxy_req = ProxyRequest(
        provider=Provider.OPENAI,
        url="http://localhost/test",
        method="POST",
        headers={},
        body=b"{}",
        is_streaming=True,
    )

    stream_result = await forward_client.forward_stream(
        proxy_request=proxy_req,
        client_request=DelayedDisconnectClientRequest(),  # pyright: ignore[reportArgumentType]
    )
    assert stream_result.stream is not None

    consumed_chunks: list[bytes] = []
    with pytest.raises(asyncio.CancelledError):
        async for chunk in stream_result.stream:
            consumed_chunks.append(chunk)

    # Verify at least one chunk was read before cancellation stopped it
    assert len(consumed_chunks) >= 1
    # Verify upstream did not finish all 10 chunks
    assert chunks_yielded < 10

    await mock_client.aclose()
    await forward_client.aclose()


@pytest.mark.asyncio
async def test_streaming_pipeline_client_cancellation_propagates() -> None:
    """When a downstream consumer cancels consumption, StreamingPipeline cancels upstream."""
    vault = InMemoryPseudonymVault()
    rehydrator = StreamingRehydrator(vault=vault, session_id="test-pipeline-cancel")

    upstream_cancelled = False

    async def slow_chunks() -> AsyncIterator[bytes]:
        nonlocal upstream_cancelled
        try:
            for i in range(20):
                chunk = {
                    "id": "chatcmpl-test",
                    "object": "chat.completion.chunk",
                    "choices": [{"index": 0, "delta": {"content": f"w{i} "}}],
                }
                yield f"data: {json.dumps(chunk)}\n\n".encode()
                await asyncio.sleep(0.01)
        except asyncio.CancelledError:
            upstream_cancelled = True
            raise

    pipeline = StreamingPipeline(
        raw_stream=slow_chunks(),
        rehydrator=rehydrator,
    )

    stream = pipeline.process()
    first_chunk = await anext(stream)
    assert b"w0" in first_chunk

    # Simulate client cancelling consumer task
    async def _consume():
        async for _ in stream:
            pass

    task = asyncio.create_task(_consume())
    await asyncio.sleep(0.02)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # Give event loop a cycle to finalize generator
    await asyncio.sleep(0.02)
    assert upstream_cancelled is True


@pytest.mark.asyncio
async def test_streaming_pipeline_backpressure() -> None:
    """Backpressure: a slow consumer should throttle the upstream generator via async yield."""
    vault = InMemoryPseudonymVault()
    rehydrator = StreamingRehydrator(vault=vault, session_id="test-backpressure")

    chunks_yielded = 0
    max_ahead = 0

    async def fast_upstream() -> AsyncIterator[bytes]:
        nonlocal chunks_yielded
        for i in range(20):
            chunks_yielded += 1
            chunk = {
                "id": "chatcmpl-bp",
                "object": "chat.completion.chunk",
                "choices": [{"index": 0, "delta": {"content": f"w{i} "}}],
            }
            yield f"data: {json.dumps(chunk)}\n\n".encode()

    pipeline = StreamingPipeline(
        raw_stream=fast_upstream(),
        rehydrator=rehydrator,
    )

    consumed = 0
    async for _chunk in pipeline.process():
        consumed += 1
        # Record how far ahead the producer is vs the consumer
        ahead = chunks_yielded - consumed
        if ahead > max_ahead:
            max_ahead = ahead
        # Simulate a slow consumer
        await asyncio.sleep(0.02)

    # All 20 chunks should eventually be consumed
    assert consumed >= 20
    # With async generator backpressure, the producer should not run far ahead.
    # Without backpressure, chunks_yielded would reach 20 immediately while consumed is 1.
    # Allow some slack for buffering but the producer should be throttled.
    assert max_ahead < 10, f"Producer ran {max_ahead} chunks ahead — backpressure not working"
