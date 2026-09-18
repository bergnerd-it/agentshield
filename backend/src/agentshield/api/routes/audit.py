"""FastAPI route for privacy-preserving audit report export."""

from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel, Field

from agentshield.api.dependencies import get_audit_repository, require_admin_auth
from agentshield.audit.service import AuditExportService
from agentshield.persistence.repository import AuditRepository

router = APIRouter(prefix="/api/v1/audit", tags=["Audit & Exports"])


class AuditExportRequest(BaseModel):
    """Filter criteria and format selection for audit export."""

    format: Literal["json", "html"] = "json"
    start_time: datetime | None = None
    end_time: datetime | None = None
    agent: str | None = None
    provider: str | None = None
    action: str | None = None
    project: str | None = None
    limit: int = Field(default=5000, ge=1, le=50000)


@router.post(
    "/export",
    summary="Export audit records",
    description="Export filtered, privacy-preserving audit logs in JSON or standalone HTML format.",
    response_class=Response,
)
async def export_audit_events(
    body: AuditExportRequest,
    _admin: Annotated[str, Depends(require_admin_auth)],
    repo: Annotated[AuditRepository, Depends(get_audit_repository)],
) -> Response:
    """Generate and deliver audit report file as an attachment."""
    service = AuditExportService(repo)
    content, filename, media_type = service.export(
        export_format=body.format,
        start_time=body.start_time,
        end_time=body.end_time,
        agent=body.agent,
        provider=body.provider,
        action=body.action,
        project=body.project,
        limit=body.limit,
    )

    return Response(
        content=content.encode("utf-8"),
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )
