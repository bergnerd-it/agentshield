"""FastAPI routes for OpenAI and Anthropic reverse proxy endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response

from agentshield.api.dependencies import (
    get_anthropic_adapter,
    get_current_settings,
    get_forward_client,
    get_openai_adapter,
    require_proxy_auth,
)
from agentshield.core.config import Settings
from agentshield.core.errors import PayloadTooLargeError
from agentshield.proxy.anthropic import AnthropicAdapter
from agentshield.proxy.client import ProxyForwardClient
from agentshield.proxy.openai import OpenAIAdapter

router = APIRouter(prefix="/proxy", tags=["Proxy"])


async def _read_and_validate_body(request: Request, max_bytes: int) -> bytes:
    """Read request body while strictly enforcing maximum payload size."""
    content_length_header = request.headers.get("content-length")
    if content_length_header is not None:
        try:
            content_length = int(content_length_header)
            if content_length > max_bytes:
                raise PayloadTooLargeError(
                    f"Request payload size ({content_length} bytes) exceeds "
                    f"maximum limit of {max_bytes} bytes."
                )
        except ValueError:
            pass

    chunks: list[bytes] = []
    total_bytes = 0
    async for chunk in request.stream():
        total_bytes += len(chunk)
        if total_bytes > max_bytes:
            raise PayloadTooLargeError(
                f"Request payload size ({total_bytes} bytes) exceeds "
                f"maximum limit of {max_bytes} bytes."
            )
        chunks.append(chunk)

    return b"".join(chunks)


@router.post("/openai/v1/responses")
async def proxy_openai_responses(
    request: Request,
    _token: Annotated[str, Depends(require_proxy_auth)],
    settings: Annotated[Settings, Depends(get_current_settings)],
    adapter: Annotated[OpenAIAdapter, Depends(get_openai_adapter)],
    forward_client: Annotated[ProxyForwardClient, Depends(get_forward_client)],
) -> Response:
    """Proxy OpenAI Responses API requests."""
    body = await _read_and_validate_body(request, settings.proxy_max_body_bytes)
    proxy_request = adapter.prepare_request(
        endpoint_path="/v1/responses",
        raw_body=body,
        incoming_headers=dict(request.headers),
        method=request.method,
    )
    proxy_response = await forward_client.forward(proxy_request, client_request=request)
    return Response(
        content=proxy_response.body,
        status_code=proxy_response.status_code,
        headers=proxy_response.headers,
        media_type=proxy_response.media_type,
    )


@router.post("/openai/v1/chat/completions")
async def proxy_openai_chat_completions(
    request: Request,
    _token: Annotated[str, Depends(require_proxy_auth)],
    settings: Annotated[Settings, Depends(get_current_settings)],
    adapter: Annotated[OpenAIAdapter, Depends(get_openai_adapter)],
    forward_client: Annotated[ProxyForwardClient, Depends(get_forward_client)],
) -> Response:
    """Proxy OpenAI Chat Completions API requests."""
    body = await _read_and_validate_body(request, settings.proxy_max_body_bytes)
    proxy_request = adapter.prepare_request(
        endpoint_path="/v1/chat/completions",
        raw_body=body,
        incoming_headers=dict(request.headers),
        method=request.method,
    )
    proxy_response = await forward_client.forward(proxy_request, client_request=request)
    return Response(
        content=proxy_response.body,
        status_code=proxy_response.status_code,
        headers=proxy_response.headers,
        media_type=proxy_response.media_type,
    )


@router.post("/anthropic/v1/messages")
async def proxy_anthropic_messages(
    request: Request,
    _token: Annotated[str, Depends(require_proxy_auth)],
    settings: Annotated[Settings, Depends(get_current_settings)],
    adapter: Annotated[AnthropicAdapter, Depends(get_anthropic_adapter)],
    forward_client: Annotated[ProxyForwardClient, Depends(get_forward_client)],
) -> Response:
    """Proxy Anthropic Messages API requests."""
    body = await _read_and_validate_body(request, settings.proxy_max_body_bytes)
    proxy_request = adapter.prepare_request(
        endpoint_path="/v1/messages",
        raw_body=body,
        incoming_headers=dict(request.headers),
        method=request.method,
    )
    proxy_response = await forward_client.forward(proxy_request, client_request=request)
    return Response(
        content=proxy_response.body,
        status_code=proxy_response.status_code,
        headers=proxy_response.headers,
        media_type=proxy_response.media_type,
    )
