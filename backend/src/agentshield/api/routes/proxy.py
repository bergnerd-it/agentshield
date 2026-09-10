"""FastAPI routes for inspected OpenAI and Anthropic reverse proxy endpoints."""

import json
from typing import Annotated, Any
from uuid import uuid4

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import StreamingResponse

from agentshield.api.dependencies import (
    get_anthropic_adapter,
    get_current_settings,
    get_forward_client,
    get_inspection_pipeline,
    get_openai_adapter,
    get_pseudonym_vault,
    require_proxy_auth,
)
from agentshield.core.config import Settings
from agentshield.core.errors import ContentBlockedError, PayloadTooLargeError
from agentshield.core.logging import get_logger
from agentshield.policies.models import PolicyAction
from agentshield.proxy.anthropic import AnthropicAdapter
from agentshield.proxy.client import ProxyForwardClient
from agentshield.proxy.content_encoding import decode_request_body
from agentshield.proxy.inspection import RequestInspectionPipeline
from agentshield.proxy.openai import OpenAIAdapter
from agentshield.proxy.payload import parse_proxy_payload
from agentshield.proxy.rehydration import StreamingRehydrator, rehydrate_json
from agentshield.proxy.streaming import StreamingPipeline
from agentshield.proxy.types import Provider
from agentshield.pseudonyms.vault import InMemoryPseudonymVault

router = APIRouter(prefix="/proxy", tags=["Proxy"])
logger = get_logger("agentshield.proxy.routes")


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

    return decode_request_body(
        body=b"".join(chunks),
        content_encoding=request.headers.get("content-encoding"),
        max_decoded_bytes=max_bytes,
    )


def _extract_session_id(request: Request, payload: dict[str, Any]) -> str:
    """Extract or generate a stable session ID for pseudonym mapping."""
    header_session = request.headers.get("x-session-id")
    if header_session and header_session.strip():
        return header_session.strip()
    body_session = payload.get("session_id")
    if isinstance(body_session, str) and body_session.strip():
        return body_session.strip()
    return uuid4().hex


async def _inspect_body(
    *,
    body: bytes,
    request: Request,
    provider: Provider,
    endpoint: str,
    pipeline: RequestInspectionPipeline,
    vault: InMemoryPseudonymVault,
    session_id: str,
) -> tuple[bytes, dict[str, Any]]:
    payload = parse_proxy_payload(body, allow_streaming=True)
    result = await pipeline.inspect(
        provider=provider,
        endpoint=endpoint,
        payload=payload,
        headers=request.headers,
        vault=vault,
        session_id=session_id,
    )
    logger.info(
        "Request inspection provider=%s endpoint=%s findings=%d failures=%d action=%s",
        provider.value,
        endpoint,
        len(result.report.findings),
        len(result.report.failures),
        result.decision.action.name,
    )
    if result.decision.action is PolicyAction.BLOCK:
        raise ContentBlockedError(
            finding_count=len(result.report.findings),
            policy_version=result.decision.policy_version,
        )
    if result.decision.action is PolicyAction.REDACT:
        inspected_body = json.dumps(
            result.payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        return inspected_body, result.payload
    return body, payload


async def _handle_proxy_request(
    *,
    request: Request,
    provider: Provider,
    endpoint: str,
    settings: Settings,
    adapter: OpenAIAdapter | AnthropicAdapter,
    forward_client: ProxyForwardClient,
    pipeline: RequestInspectionPipeline,
    vault: InMemoryPseudonymVault,
) -> Response:
    body = await _read_and_validate_body(request, settings.proxy_max_body_bytes)
    initial_payload = parse_proxy_payload(body, allow_streaming=True)
    session_id = _extract_session_id(request, initial_payload)

    body, _ = await _inspect_body(
        body=body,
        request=request,
        provider=provider,
        endpoint=endpoint,
        pipeline=pipeline,
        vault=vault,
        session_id=session_id,
    )

    proxy_request = await adapter.prepare_request(
        endpoint_path=endpoint,
        raw_body=body,
        incoming_headers=dict(request.headers),
        method=request.method,
        session_id=session_id,
    )

    if proxy_request.is_streaming:
        stream_result = await forward_client.forward_stream(proxy_request, client_request=request)
        if stream_result.stream is None:
            # Upstream error returned before streaming started
            return Response(
                content=stream_result.body or b"",
                status_code=stream_result.status_code,
                headers=stream_result.headers,
                media_type=stream_result.media_type,
            )

        # Active stream: pass through rehydrator and secret detector
        rehydrator = StreamingRehydrator(vault=vault, session_id=session_id)
        streaming_pipeline = StreamingPipeline(
            raw_stream=stream_result.stream,
            rehydrator=rehydrator,
            secret_detector=pipeline.header_secret_detector,
            provider=provider,
            endpoint=endpoint,
            max_event_bytes=settings.sse_max_event_bytes,
        )
        return StreamingResponse(
            content=streaming_pipeline.process(),
            status_code=stream_result.status_code,
            headers=stream_result.headers,
            media_type=stream_result.media_type,
        )

    # Non-streaming request
    proxy_response = await forward_client.forward(proxy_request, client_request=request)
    resp_body = proxy_response.body
    if proxy_response.status_code == 200 and vault.has_session_mappings(session_id):
        try:
            parsed_resp = json.loads(resp_body.decode("utf-8"))
            rehydrated = rehydrate_json(parsed_resp, vault, session_id)
            resp_body = json.dumps(
                rehydrated,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        except Exception:
            logger.debug("Failed to rehydrate non-streaming response body", exc_info=True)

    return Response(
        content=resp_body,
        status_code=proxy_response.status_code,
        headers=proxy_response.headers,
        media_type=proxy_response.media_type,
    )


@router.post("/openai/v1/responses")
async def proxy_openai_responses(
    request: Request,
    _token: Annotated[str, Depends(require_proxy_auth)],
    settings: Annotated[Settings, Depends(get_current_settings)],
    adapter: Annotated[OpenAIAdapter, Depends(get_openai_adapter)],
    forward_client: Annotated[ProxyForwardClient, Depends(get_forward_client)],
    pipeline: Annotated[RequestInspectionPipeline, Depends(get_inspection_pipeline)],
    vault: Annotated[InMemoryPseudonymVault, Depends(get_pseudonym_vault)],
) -> Response:
    """Proxy OpenAI Responses API requests."""
    return await _handle_proxy_request(
        request=request,
        provider=Provider.OPENAI,
        endpoint="/v1/responses",
        settings=settings,
        adapter=adapter,
        forward_client=forward_client,
        pipeline=pipeline,
        vault=vault,
    )


@router.post("/openai/v1/chat/completions")
async def proxy_openai_chat_completions(
    request: Request,
    _token: Annotated[str, Depends(require_proxy_auth)],
    settings: Annotated[Settings, Depends(get_current_settings)],
    adapter: Annotated[OpenAIAdapter, Depends(get_openai_adapter)],
    forward_client: Annotated[ProxyForwardClient, Depends(get_forward_client)],
    pipeline: Annotated[RequestInspectionPipeline, Depends(get_inspection_pipeline)],
    vault: Annotated[InMemoryPseudonymVault, Depends(get_pseudonym_vault)],
) -> Response:
    """Proxy OpenAI Chat Completions API requests."""
    return await _handle_proxy_request(
        request=request,
        provider=Provider.OPENAI,
        endpoint="/v1/chat/completions",
        settings=settings,
        adapter=adapter,
        forward_client=forward_client,
        pipeline=pipeline,
        vault=vault,
    )


@router.post("/anthropic/v1/messages")
async def proxy_anthropic_messages(
    request: Request,
    _token: Annotated[str, Depends(require_proxy_auth)],
    settings: Annotated[Settings, Depends(get_current_settings)],
    adapter: Annotated[AnthropicAdapter, Depends(get_anthropic_adapter)],
    forward_client: Annotated[ProxyForwardClient, Depends(get_forward_client)],
    pipeline: Annotated[RequestInspectionPipeline, Depends(get_inspection_pipeline)],
    vault: Annotated[InMemoryPseudonymVault, Depends(get_pseudonym_vault)],
) -> Response:
    """Proxy Anthropic Messages API requests."""
    return await _handle_proxy_request(
        request=request,
        provider=Provider.ANTHROPIC,
        endpoint="/v1/messages",
        settings=settings,
        adapter=adapter,
        forward_client=forward_client,
        pipeline=pipeline,
        vault=vault,
    )
