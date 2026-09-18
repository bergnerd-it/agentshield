"""FastAPI routes for coding-agent integration management and previews."""

from pathlib import Path
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from agentshield.api.dependencies import (
    get_current_settings,
    get_db,
    require_admin_auth,
)
from agentshield.core.config import Settings
from agentshield.integrations.manager import IntegrationManager

router = APIRouter(prefix="/api/v1/integrations", tags=["Integrations"])


class IntegrationStatusResponse(BaseModel):
    """Response model for integration detection status."""

    agent_type: str
    configured: bool
    config_path: str
    proxy_url: str
    has_token: bool
    last_backup_path: str | None = None
    updated_at: str | None = None
    error: str | None = None


class ConfigDiffResponse(BaseModel):
    """Response model for configuration preview diff."""

    agent_type: str
    config_path: str
    original_content: str
    modified_content: str
    unified_diff: str
    has_changes: bool


class ConfigureRequest(BaseModel):
    """Optional path override for configuration."""

    path: str | None = Field(default=None, description="Custom configuration file path")


class ConnectionTestResponse(BaseModel):
    """Result of loopback connection test."""

    agent_type: str
    success: bool
    status_code: int | None = None
    message: str


def _get_manager(
    settings: Annotated[Settings, Depends(get_current_settings)],
    db: Annotated[Session, Depends(get_db)],
) -> IntegrationManager:
    return IntegrationManager(settings=settings, db=db)


@router.get(
    "",
    response_model=list[IntegrationStatusResponse],
    summary="List coding-agent integrations",
    description="Returns configuration and backup status for supported coding agents.",
)
async def list_integrations(
    _admin: Annotated[str, Depends(require_admin_auth)],
    manager: Annotated[IntegrationManager, Depends(_get_manager)],
) -> list[IntegrationStatusResponse]:
    statuses = manager.list_integrations()
    return [
        IntegrationStatusResponse(
            agent_type=s.agent_type,
            configured=s.configured,
            config_path=s.config_path,
            proxy_url=s.proxy_url,
            has_token=s.has_token,
            last_backup_path=s.last_backup_path,
            updated_at=s.updated_at,
            error=s.error,
        )
        for s in statuses
    ]


@router.get(
    "/{agent}/preview",
    response_model=ConfigDiffResponse,
    summary="Preview integration changes",
    description="Generate a unified diff preview before modifying configuration files.",
)
async def preview_integration(
    agent: str,
    _admin: Annotated[str, Depends(require_admin_auth)],
    manager: Annotated[IntegrationManager, Depends(_get_manager)],
    path: Annotated[str | None, Query(description="Custom config file path")] = None,
) -> ConfigDiffResponse:
    config_path = Path(path) if path else None
    diff = manager.preview(agent, config_path=config_path)
    return ConfigDiffResponse(
        agent_type=diff.agent_type,
        config_path=diff.config_path,
        original_content=diff.original_content,
        modified_content=diff.modified_content,
        unified_diff=diff.unified_diff,
        has_changes=diff.has_changes,
    )


@router.post(
    "/{agent}/configure",
    response_model=IntegrationStatusResponse,
    summary="Apply integration configuration",
    description="Atomically backup existing configuration and apply AgentShield settings.",
)
async def configure_integration(
    agent: str,
    _admin: Annotated[str, Depends(require_admin_auth)],
    manager: Annotated[IntegrationManager, Depends(_get_manager)],
    body: ConfigureRequest | None = None,
) -> IntegrationStatusResponse:
    config_path = Path(body.path) if body and body.path else None
    status = manager.apply(agent, config_path=config_path)
    return IntegrationStatusResponse(
        agent_type=status.agent_type,
        configured=status.configured,
        config_path=status.config_path,
        proxy_url=status.proxy_url,
        has_token=status.has_token,
        last_backup_path=status.last_backup_path,
        updated_at=status.updated_at,
        error=status.error,
    )


@router.post(
    "/{agent}/rollback",
    response_model=IntegrationStatusResponse,
    summary="Rollback integration configuration",
    description="Restore configuration from the latest atomic backup.",
)
async def rollback_integration(
    agent: str,
    _admin: Annotated[str, Depends(require_admin_auth)],
    manager: Annotated[IntegrationManager, Depends(_get_manager)],
    body: ConfigureRequest | None = None,
) -> IntegrationStatusResponse:
    config_path = Path(body.path) if body and body.path else None
    status = manager.rollback(agent, config_path=config_path)
    return IntegrationStatusResponse(
        agent_type=status.agent_type,
        configured=status.configured,
        config_path=status.config_path,
        proxy_url=status.proxy_url,
        has_token=status.has_token,
        last_backup_path=status.last_backup_path,
        updated_at=status.updated_at,
        error=status.error,
    )


@router.post(
    "/{agent}/test",
    response_model=ConnectionTestResponse,
    summary="Test integration connectivity",
    description="Send a lightweight probe through the local proxy using the integration token.",
)
async def test_integration_connection(
    agent: str,
    _admin: Annotated[str, Depends(require_admin_auth)],
    manager: Annotated[IntegrationManager, Depends(_get_manager)],
    settings: Annotated[Settings, Depends(get_current_settings)],
) -> ConnectionTestResponse:
    adapter = manager.get_adapter(agent)
    token = manager.get_or_create_token(agent)

    # Determine probe endpoint based on agent type
    endpoint = (
        f"http://127.0.0.1:{settings.port}/proxy/openai/v1/responses"
        if adapter.agent_type == "codex"
        else f"http://127.0.0.1:{settings.port}/proxy/anthropic/v1/messages"
    )

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            if adapter.agent_type == "claude-code":
                headers["x-api-key"] = token
                headers["anthropic-version"] = "2023-06-01"

            resp = await client.post(endpoint, headers=headers, json={"model": "test-probe"})
            # If we get anything other than 401 Unauthorized, token authentication succeeded!
            if resp.status_code != 401:
                return ConnectionTestResponse(
                    agent_type=agent,
                    success=True,
                    status_code=resp.status_code,
                    message="Proxy endpoint authenticated successfully.",
                )
            return ConnectionTestResponse(
                agent_type=agent,
                success=False,
                status_code=resp.status_code,
                message="Proxy authentication failed (HTTP 401).",
            )
    except Exception as e:
        return ConnectionTestResponse(
            agent_type=agent,
            success=False,
            status_code=None,
            message=f"Connection probe failed: {e}",
        )
