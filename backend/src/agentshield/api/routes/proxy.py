"""FastAPI routes for inspected OpenAI and Anthropic reverse proxy endpoints."""

import hashlib
import json
import time
from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import uuid4

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from agentshield.api.dependencies import (
    get_anthropic_adapter,
    get_approval_manager,
    get_current_settings,
    get_forward_client,
    get_inspection_pipeline,
    get_openai_adapter,
    get_pseudonym_vault,
    require_proxy_auth,
)
from agentshield.approvals.manager import ApprovalManager
from agentshield.approvals.models import ApprovalStatus, FindingSummary
from agentshield.core.config import Settings
from agentshield.core.errors import (
    ApprovalDeniedError,
    ApprovalRequiredTimeoutError,
    ClientDisconnectedError,
    ContentBlockedError,
    PayloadTooLargeError,
)
from agentshield.core.logging import get_logger
from agentshield.persistence.db import get_db
from agentshield.persistence.models import AuditEvent
from agentshield.persistence.repository import AuditRepository
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


def _record_audit(
    *,
    db: Session | None,
    manager: ApprovalManager | None,
    request_id: str,
    session_id: str | None,
    agent: str | None,
    project: str | None,
    provider: str,
    model: str | None,
    endpoint: str,
    direction: str,
    action: str,
    rule_id: str | None,
    finding_counts: dict[str, int],
    metadata: dict[str, Any],
) -> None:
    now = datetime.now(UTC)
    event_id = uuid4().hex
    if db is not None:
        try:
            repo = AuditRepository(db)
            audit_event = AuditEvent(
                id=event_id,
                timestamp=now,
                request_id=request_id,
                session_id=session_id,
                agent=agent,
                project=project,
                provider=provider,
                model=model,
                endpoint=endpoint,
                direction=direction,
                action=action,
                rule_id=rule_id,
                finding_counts_json=json.dumps(finding_counts),
                metadata_json=json.dumps(metadata),
            )
            repo.record_event(audit_event)
            db.commit()
        except Exception:
            logger.debug("Failed to persist audit event", exc_info=True)

    if manager is not None:
        manager.publish_event(
            "audit_event",
            {
                "id": event_id,
                "timestamp": now.isoformat(),
                "request_id": request_id,
                "session_id": session_id,
                "agent": agent,
                "project": project,
                "provider": provider,
                "model": model,
                "endpoint": endpoint,
                "direction": direction,
                "action": action,
                "rule_id": rule_id,
                "finding_counts": finding_counts,
                "metadata": metadata,
            },
        )


async def _hold_and_resolve_approval(
    *,
    body: bytes,
    initial_payload: dict[str, Any],
    result: Any,
    provider: Provider,
    endpoint: str,
    model: str | None,
    agent: str | None,
    project: str | None,
    session_id: str,
    request: Request,
    settings: Settings,
    approval_manager: ApprovalManager,
    db: Session | None,
    request_id: str,
    start_time: float,
    finding_counts: dict[str, int],
    matched_rule_id: str | None,
) -> bytes:
    fingerprint = hashlib.sha256(body).hexdigest()
    finding_summaries = tuple(
        FindingSummary(
            category=f.category.value if hasattr(f.category, "value") else str(f.category),
            severity=f.severity.name if hasattr(f.severity, "name") else str(f.severity),
            detector_id=f.detector_id,
            message=f.metadata.get(
                "description",
                f"Protected content detected: {getattr(f.category, 'value', str(f.category))}",
            ),
            path=f.location.path,
            start_offset=f.location.start,
            end_offset=f.location.end,
            fingerprint=f.fingerprint,
        )
        for f in result.report.findings
    )
    approval_req = approval_manager.create_request(
        request_fingerprint=fingerprint,
        policy_version=result.decision.policy_version,
        provider=provider.value,
        model=model,
        endpoint=endpoint,
        direction="REQUEST",
        agent=agent,
        project=project,
        session_id=session_id,
        findings=finding_summaries,
        timeout_seconds=settings.approval_timeout_seconds,
        raw_payload_masked=initial_payload,
        redacted_payload=result.payload,
    )

    decision_status = await approval_manager.wait_for_decision(
        request_id=approval_req.id,
        timeout_seconds=settings.approval_timeout_seconds,
        is_client_disconnected=request.is_disconnected,
    )

    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
    if decision_status is ApprovalStatus.APPROVED:
        logger.info("Approval hold %s approved, forwarding upstream", approval_req.id)
        has_redactions = any(
            item.action is PolicyAction.REDACT for item in result.decision.finding_actions
        )
        if has_redactions:
            return json.dumps(
                result.payload,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8")
        return body

    if decision_status is ApprovalStatus.DENIED:
        _record_audit(
            db=db,
            manager=approval_manager,
            request_id=request_id,
            session_id=session_id,
            agent=agent,
            project=project,
            provider=provider.value,
            model=model,
            endpoint=endpoint,
            direction="REQUEST",
            action="REQUIRE_APPROVAL",
            rule_id=matched_rule_id,
            finding_counts=finding_counts,
            metadata={
                "duration_ms": duration_ms,
                "status_code": 403,
                "approval_status": "denied",
                "reason": approval_req.decision_reason,
            },
        )
        raise ApprovalDeniedError(approval_req.id, approval_req.decision_reason)

    if decision_status is ApprovalStatus.CANCELLED:
        _record_audit(
            db=db,
            manager=approval_manager,
            request_id=request_id,
            session_id=session_id,
            agent=agent,
            project=project,
            provider=provider.value,
            model=model,
            endpoint=endpoint,
            direction="REQUEST",
            action="REQUIRE_APPROVAL",
            rule_id=matched_rule_id,
            finding_counts=finding_counts,
            metadata={
                "duration_ms": duration_ms,
                "status_code": 499,
                "approval_status": "cancelled",
                "reason": approval_req.decision_reason,
            },
        )
        raise ClientDisconnectedError(approval_req.id)

    # EXPIRED
    _record_audit(
        db=db,
        manager=approval_manager,
        request_id=request_id,
        session_id=session_id,
        agent=agent,
        project=project,
        provider=provider.value,
        model=model,
        endpoint=endpoint,
        direction="REQUEST",
        action="REQUIRE_APPROVAL",
        rule_id=matched_rule_id,
        finding_counts=finding_counts,
        metadata={
            "duration_ms": duration_ms,
            "status_code": 403,
            "approval_status": "expired",
            "reason": approval_req.decision_reason,
        },
    )
    raise ApprovalRequiredTimeoutError(approval_req.id)


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
    approval_manager: ApprovalManager,
    db: Session | None = None,
) -> Response:
    start_time = time.perf_counter()
    request_id = uuid4().hex
    body = await _read_and_validate_body(request, settings.proxy_max_body_bytes)
    initial_payload = parse_proxy_payload(body, allow_streaming=True)
    session_id = _extract_session_id(request, initial_payload)
    raw_model = initial_payload.get("model")
    model = str(raw_model) if raw_model is not None else None
    agent = request.headers.get("x-agent-id") or request.headers.get("user-agent")
    project = request.headers.get("x-project-id")

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

    finding_counts: dict[str, int] = {}
    for f in result.report.findings:
        cat = f.category.value if hasattr(f.category, "value") else str(f.category)
        finding_counts[cat] = finding_counts.get(cat, 0) + 1
    matched_rule_id = (
        result.decision.matched_rule_ids[0] if result.decision.matched_rule_ids else None
    )

    # 1. BLOCK: fail closed immediately
    if result.decision.action is PolicyAction.BLOCK:
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        _record_audit(
            db=db,
            manager=approval_manager,
            request_id=request_id,
            session_id=session_id,
            agent=agent,
            project=project,
            provider=provider.value,
            model=model,
            endpoint=endpoint,
            direction="REQUEST",
            action="BLOCK",
            rule_id=matched_rule_id,
            finding_counts=finding_counts,
            metadata={
                "duration_ms": duration_ms,
                "status_code": 403,
                "reason": result.decision.reason,
            },
        )
        raise ContentBlockedError(
            finding_count=len(result.report.findings),
            policy_version=result.decision.policy_version,
        )

    # 2. REQUIRE_APPROVAL: hold before contacting provider
    if result.decision.action is PolicyAction.REQUIRE_APPROVAL:
        body = await _hold_and_resolve_approval(
            body=body,
            initial_payload=initial_payload,
            result=result,
            provider=provider,
            endpoint=endpoint,
            model=model,
            agent=agent,
            project=project,
            session_id=session_id,
            request=request,
            settings=settings,
            approval_manager=approval_manager,
            db=db,
            request_id=request_id,
            start_time=start_time,
            finding_counts=finding_counts,
            matched_rule_id=matched_rule_id,
        )

    # 3. REDACT
    elif result.decision.action is PolicyAction.REDACT:
        body = json.dumps(
            result.payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")

    # 4. Prepare upstream request and forward
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
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            _record_audit(
                db=db,
                manager=approval_manager,
                request_id=request_id,
                session_id=session_id,
                agent=agent,
                project=project,
                provider=provider.value,
                model=model,
                endpoint=endpoint,
                direction="REQUEST",
                action=result.decision.action.name,
                rule_id=matched_rule_id,
                finding_counts=finding_counts,
                metadata={"duration_ms": duration_ms, "status_code": stream_result.status_code},
            )
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
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        _record_audit(
            db=db,
            manager=approval_manager,
            request_id=request_id,
            session_id=session_id,
            agent=agent,
            project=project,
            provider=provider.value,
            model=model,
            endpoint=endpoint,
            direction="REQUEST",
            action=result.decision.action.name,
            rule_id=matched_rule_id,
            finding_counts=finding_counts,
            metadata={
                "duration_ms": duration_ms,
                "status_code": stream_result.status_code,
                "streaming": True,
            },
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

    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
    _record_audit(
        db=db,
        manager=approval_manager,
        request_id=request_id,
        session_id=session_id,
        agent=agent,
        project=project,
        provider=provider.value,
        model=model,
        endpoint=endpoint,
        direction="REQUEST",
        action=result.decision.action.name,
        rule_id=matched_rule_id,
        finding_counts=finding_counts,
        metadata={"duration_ms": duration_ms, "status_code": proxy_response.status_code},
    )

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
    approval_manager: Annotated[ApprovalManager, Depends(get_approval_manager)],
    db: Annotated[Session, Depends(get_db)],
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
        approval_manager=approval_manager,
        db=db,
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
    approval_manager: Annotated[ApprovalManager, Depends(get_approval_manager)],
    db: Annotated[Session, Depends(get_db)],
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
        approval_manager=approval_manager,
        db=db,
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
    approval_manager: Annotated[ApprovalManager, Depends(get_approval_manager)],
    db: Annotated[Session, Depends(get_db)],
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
        approval_manager=approval_manager,
        db=db,
    )
