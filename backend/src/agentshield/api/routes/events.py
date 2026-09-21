"""FastAPI routes for audit events and real-time SSE event stream."""

import asyncio
import contextlib
import json
from collections.abc import AsyncGenerator
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from agentshield.api.dependencies import (
    get_approval_manager,
    get_audit_repository,
    require_admin_auth,
)
from agentshield.approvals.manager import ApprovalManager
from agentshield.audit.service import SAFE_METADATA_KEYS
from agentshield.core.errors import NotFoundError
from agentshield.persistence.models import AuditEvent
from agentshield.persistence.repository import AuditRepository

router = APIRouter(prefix="/api/v1/events", tags=["Events & Audit"])


class AuditEventResponse(BaseModel):
    """Sanitized, privacy-preserving audit event representation."""

    id: str
    timestamp: str
    request_id: str
    session_id: str | None = None
    agent: str | None = None
    project: str | None = None
    provider: str
    model: str | None = None
    endpoint: str
    direction: str
    action: str
    rule_id: str | None = None
    finding_counts: dict[str, int] = {}
    metadata: dict[str, Any] = {}


class EventListResponse(BaseModel):
    """Paginated list of audit events."""

    items: list[AuditEventResponse]
    total: int
    limit: int
    offset: int


def _to_event_response(event: AuditEvent) -> AuditEventResponse:
    finding_counts: dict[str, int] = {}
    if event.finding_counts_json:
        with contextlib.suppress(Exception):
            finding_counts = json.loads(event.finding_counts_json)

    metadata: dict[str, Any] = {}
    if event.metadata_json:
        with contextlib.suppress(Exception):
            raw_metadata = json.loads(event.metadata_json)
            if isinstance(raw_metadata, dict):
                metadata = {k: v for k, v in raw_metadata.items() if k in SAFE_METADATA_KEYS}

    return AuditEventResponse(
        id=event.id,
        timestamp=event.timestamp.isoformat(),
        request_id=event.request_id,
        session_id=event.session_id,
        agent=event.agent,
        project=event.project,
        provider=event.provider,
        model=event.model,
        endpoint=event.endpoint,
        direction=event.direction,
        action=event.action,
        rule_id=event.rule_id,
        finding_counts=finding_counts,
        metadata=metadata,
    )


@router.get(
    "",
    response_model=EventListResponse,
    summary="List audit events",
    description="Paginated and filterable list of privacy-preserving audit logs.",
)
async def list_events(
    _admin: Annotated[str, Depends(require_admin_auth)],
    repo: Annotated[AuditRepository, Depends(get_audit_repository)],
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    action: str | None = None,
    provider: str | None = None,
    agent: str | None = None,
    project: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> EventListResponse:
    total = repo.count_events(
        action=action,
        provider=provider,
        agent=agent,
        project=project,
        start_time=start_time,
        end_time=end_time,
    )
    items = repo.list_events(
        limit=limit,
        offset=offset,
        action=action,
        provider=provider,
        agent=agent,
        project=project,
        start_time=start_time,
        end_time=end_time,
    )
    return EventListResponse(
        items=[_to_event_response(e) for e in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/stream",
    summary="Live events SSE stream",
    description="Server-Sent Events (SSE) feed for real-time proxy traffic and approval holds.",
)
async def events_stream(
    request: Request,
    _admin: Annotated[str, Depends(require_admin_auth)],
    manager: Annotated[ApprovalManager, Depends(get_approval_manager)],
    limit: Annotated[
        int | None,
        Query(
            description="Optional maximum number of live events to receive before closing stream."
        ),
    ] = None,
    stream_timeout: Annotated[
        float | None,
        Query(
            alias="timeout",
            description="Optional maximum stream duration in seconds before auto-closing.",
        ),
    ] = None,
) -> StreamingResponse:
    queue = manager.subscribe()

    async def event_generator() -> AsyncGenerator[str]:
        loop = asyncio.get_running_loop()
        start_time = loop.time()
        try:
            # Yield initial connection confirmation
            yield f"event: connected\ndata: {json.dumps({'status': 'connected'})}\n\n"
            if limit is not None and limit <= 0:
                return

            count = 0
            while limit is None or count < limit:
                if await request.is_disconnected():
                    break
                if stream_timeout is not None and (loop.time() - start_time) >= stream_timeout:
                    break
                try:
                    remaining_timeout = 15.0
                    if stream_timeout is not None:
                        time_left = stream_timeout - (loop.time() - start_time)
                        if time_left <= 0:
                            break
                        remaining_timeout = min(15.0, time_left)

                    event_type, data = await asyncio.wait_for(
                        queue.get(), timeout=remaining_timeout
                    )
                    clean_event_type = event_type.replace("\r", "").replace("\n", "")
                    yield f"event: {clean_event_type}\ndata: {json.dumps(data)}\n\n"
                    count += 1
                except TimeoutError:
                    if stream_timeout is not None and (loop.time() - start_time) >= stream_timeout:
                        break
                    # Keepalive comment
                    yield ": keepalive\n\n"
        finally:
            manager.unsubscribe(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get(
    "/{event_id}",
    response_model=AuditEventResponse,
    summary="Get audit event details",
    description="Fetch single audit record by event UUID.",
)
async def get_event(
    event_id: str,
    _admin: Annotated[str, Depends(require_admin_auth)],
    repo: Annotated[AuditRepository, Depends(get_audit_repository)],
) -> AuditEventResponse:
    event = repo.get_event(event_id)
    if event is None:
        raise NotFoundError(f"Audit event '{event_id}' not found")
    return _to_event_response(event)
