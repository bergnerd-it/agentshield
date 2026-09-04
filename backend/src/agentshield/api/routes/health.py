"""Health and system status diagnostic endpoints."""

import sys
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from agentshield import __version__
from agentshield.core.config import Settings, get_settings
from agentshield.persistence.db import get_db

router = APIRouter(tags=["Health & Status"])


class HealthResponse(BaseModel):
    """Liveness probe response."""

    status: str = Field(default="ok", description="Service liveness state")


class DatabaseStatus(BaseModel):
    """Database connection and migration state."""

    status: str
    migration_version: str | None = None


class SystemStatusResponse(BaseModel):
    """Readiness and diagnostic status information without sensitive data."""

    status: str = Field(description="Readiness status ('ready' or 'degraded')")
    version: str = Field(description="AgentShield version")
    platform: str = Field(description="Host platform identifier")
    profile: str = Field(description="Active security profile")
    host: str = Field(description="Bound host interface")
    port: int = Field(description="Bound network port")
    database: DatabaseStatus = Field(description="Database connectivity status")
    frontend_available: bool = Field(description="Whether frontend static assets are built")


@router.get(
    "/api/v1/health",
    response_model=HealthResponse,
    summary="Liveness check",
    description="Primary health liveness endpoint returning HTTP 200 with status ok.",
)
@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Liveness check alias",
    description="Documented compatibility alias for root/load-balancer liveness probes.",
)
async def health_check() -> dict[str, str]:
    return {"status": "ok"}


@router.get(
    "/api/v1/status",
    response_model=SystemStatusResponse,
    summary="System readiness and diagnostic status",
    description="Returns public diagnostic status without exposing sensitive credentials.",
)
async def system_status(
    settings: Annotated[Settings, Depends(get_settings)],
    db: Annotated[Session, Depends(get_db)],
) -> dict[str, Any]:
    # Check database migration version
    migration_version: str | None = None
    db_status = "connected"
    try:
        row = db.execute(text("SELECT version_num FROM alembic_version LIMIT 1")).fetchone()
        if row:
            migration_version = str(row[0])
    except Exception:
        db_status = "error"

    # Check frontend dist availability
    dist_dir = settings.effective_frontend_dist_dir
    frontend_available = (dist_dir / "index.html").is_file()

    return {
        "status": "ready" if db_status == "connected" else "degraded",
        "version": __version__,
        "platform": sys.platform,
        "profile": settings.profile,
        "host": settings.host,
        "port": settings.port,
        "database": {
            "status": db_status,
            "migration_version": migration_version,
        },
        "frontend_available": frontend_available,
    }
