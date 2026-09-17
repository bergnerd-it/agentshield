"""FastAPI routes for manual approval management."""

import contextlib
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from agentshield.api.dependencies import get_approval_manager, require_admin_auth
from agentshield.approvals.manager import ApprovalManager
from agentshield.approvals.models import ApprovalRequest, ApprovalStatus
from agentshield.core.errors import NotFoundError

router = APIRouter(prefix="/api/v1/approvals", tags=["Approvals"])


class FindingDetailResponse(BaseModel):
    """Masked finding details for operator inspection."""

    category: str
    severity: str
    detector_id: str
    message: str
    path: list[str | int]
    start_offset: int | None = None
    end_offset: int | None = None
    fingerprint: str


class ApprovalSummaryResponse(BaseModel):
    """Summary representation of an approval hold."""

    id: str
    request_fingerprint: str
    provider: str
    model: str | None = None
    endpoint: str
    direction: str
    status: str
    finding_count: int
    finding_categories: list[str]
    created_at: str
    expires_at: str
    remaining_seconds: float
    agent: str | None = None
    project: str | None = None


class ApprovalDetailResponse(BaseModel):
    """Detailed approval representation with payload preview and findings."""

    id: str
    request_fingerprint: str
    policy_version: str
    provider: str
    model: str | None = None
    endpoint: str
    direction: str
    status: str
    finding_count: int
    finding_categories: list[str]
    created_at: str
    expires_at: str
    remaining_seconds: float
    agent: str | None = None
    project: str | None = None
    decided_at: str | None = None
    decision_reason: str | None = None
    findings: list[FindingDetailResponse]
    raw_payload_masked: dict[str, Any] | None = None
    redacted_payload: dict[str, Any] | None = None
    diff_available: bool = False


class ApprovalDecisionRequest(BaseModel):
    """Decision payload for approve or deny action."""

    reason: str | None = Field(default=None, max_length=500)


class ApprovalActionResponse(BaseModel):
    """Outcome of an approval transition."""

    id: str
    status: str
    message: str


def _to_summary(req: ApprovalRequest) -> ApprovalSummaryResponse:
    return ApprovalSummaryResponse(
        id=req.id,
        request_fingerprint=req.request_fingerprint,
        provider=req.provider,
        model=req.model,
        endpoint=req.endpoint,
        direction=req.direction,
        status=req.status.value,
        finding_count=len(req.findings),
        finding_categories=[f.category for f in req.findings],
        created_at=req.created_at.isoformat(),
        expires_at=req.expires_at.isoformat(),
        remaining_seconds=round(req.remaining_seconds, 1),
        agent=req.agent,
        project=req.project,
    )


def _to_detail(req: ApprovalRequest) -> ApprovalDetailResponse:
    findings = [
        FindingDetailResponse(
            category=f.category,
            severity=f.severity,
            detector_id=f.detector_id,
            message=f.message,
            path=list(f.path),
            start_offset=f.start_offset,
            end_offset=f.end_offset,
            fingerprint=f.fingerprint,
        )
        for f in req.findings
    ]
    diff_available = (
        req.raw_payload_masked is not None
        and req.redacted_payload is not None
        and req.raw_payload_masked != req.redacted_payload
    )
    return ApprovalDetailResponse(
        id=req.id,
        request_fingerprint=req.request_fingerprint,
        policy_version=req.policy_version,
        provider=req.provider,
        model=req.model,
        endpoint=req.endpoint,
        direction=req.direction,
        status=req.status.value,
        finding_count=len(req.findings),
        finding_categories=[f.category for f in req.findings],
        created_at=req.created_at.isoformat(),
        expires_at=req.expires_at.isoformat(),
        remaining_seconds=round(req.remaining_seconds, 1),
        agent=req.agent,
        project=req.project,
        decided_at=req.decided_at.isoformat() if req.decided_at else None,
        decision_reason=req.decision_reason,
        findings=findings,
        raw_payload_masked=req.raw_payload_masked,
        redacted_payload=req.redacted_payload,
        diff_available=diff_available,
    )


@router.get(
    "",
    response_model=list[ApprovalSummaryResponse],
    summary="List approval requests",
    description="List pending or historical manual approval holds.",
)
async def list_approvals(
    _admin: Annotated[str, Depends(require_admin_auth)],
    manager: Annotated[ApprovalManager, Depends(get_approval_manager)],
    status: str | None = None,
) -> list[ApprovalSummaryResponse]:
    filter_status: ApprovalStatus | None = None
    if status:
        with contextlib.suppress(ValueError):
            filter_status = ApprovalStatus(status.lower())
    requests = manager.list_requests(status=filter_status)
    return [_to_summary(r) for r in requests]


@router.get(
    "/{approval_id}",
    response_model=ApprovalDetailResponse,
    summary="Get approval details",
    description="Fetch single approval request including masked findings and diff preview.",
)
async def get_approval(
    approval_id: str,
    _admin: Annotated[str, Depends(require_admin_auth)],
    manager: Annotated[ApprovalManager, Depends(get_approval_manager)],
) -> ApprovalDetailResponse:
    req = manager.get_request(approval_id)
    if req is None:
        raise NotFoundError(f"Approval request '{approval_id}' not found")
    return _to_detail(req)


@router.post(
    "/{approval_id}/approve",
    response_model=ApprovalActionResponse,
    summary="Approve pending request",
    description="Atomically approve an in-flight request hold to allow forwarding upstream.",
)
async def approve_request(
    approval_id: str,
    _admin: Annotated[str, Depends(require_admin_auth)],
    manager: Annotated[ApprovalManager, Depends(get_approval_manager)],
    body: ApprovalDecisionRequest | None = None,
) -> ApprovalActionResponse:
    reason = body.reason if body else None
    req = await manager.approve(approval_id, reason=reason)
    return ApprovalActionResponse(
        id=req.id,
        status="approved",
        message="Request approved successfully",
    )


@router.post(
    "/{approval_id}/deny",
    response_model=ApprovalActionResponse,
    summary="Deny pending request",
    description="Atomically deny an in-flight request hold, blocking upstream transmission.",
)
async def deny_request(
    approval_id: str,
    _admin: Annotated[str, Depends(require_admin_auth)],
    manager: Annotated[ApprovalManager, Depends(get_approval_manager)],
    body: ApprovalDecisionRequest | None = None,
) -> ApprovalActionResponse:
    reason = body.reason if body else None
    req = await manager.deny(approval_id, reason=reason)
    return ApprovalActionResponse(
        id=req.id,
        status="denied",
        message="Request denied successfully",
    )
