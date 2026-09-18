"""FastAPI routes for safe application settings inspection and configuration."""

import contextlib
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from agentshield.api.dependencies import (
    get_credential_store,
    get_current_settings,
    get_settings_repository,
    require_admin_auth,
)
from agentshield.core.config import Settings
from agentshield.core.credentials import CredentialStore
from agentshield.persistence.repository import SettingsRepository

router = APIRouter(prefix="/api/v1/settings", tags=["Settings"])


class SettingsResponse(BaseModel):
    """Sanitized application settings with protection boundaries and credential presence."""

    profile: str
    host: str
    port: int
    proxy_max_body_bytes: int
    sse_max_event_bytes: int
    detector_timeout_seconds: float
    pseudonym_ttl_seconds: int
    approval_timeout_seconds: float
    pii_detect_ip_addresses: bool
    pii_languages: list[str]
    custom_terms_count: int
    openai_configured: bool
    anthropic_configured: bool
    protection_limits: list[str]


class SettingsUpdateRequest(BaseModel):
    """Payload to update runtime settings overrides."""

    profile: str | None = Field(default=None, pattern="^(audit|balanced|strict)$")
    approval_timeout_seconds: float | None = Field(default=None, ge=1.0, le=3600.0)
    pseudonym_ttl_seconds: int | None = Field(default=None, ge=60, le=86400)


_PROTECTION_LIMITS = [
    "AgentShield Version 1 mediates only traffic explicitly routed through its proxy port.",
    "Direct outbound network connections by coding agents outside the proxy are NOT blocked.",
    "Detected credentials and secrets are irreversibly blocked and never stored or forwarded.",
    "Sensitive diff previews are retained strictly in memory and bounded by approval TTL.",
    "Management and proxy authentication tokens are strictly separated.",
]


@router.get(
    "",
    response_model=SettingsResponse,
    summary="Get application settings",
    description=(
        "Retrieve application configuration, detector limits, and provider "
        "credential presence without revealing secret keys."
    ),
)
async def get_settings(
    _admin: Annotated[str, Depends(require_admin_auth)],
    settings: Annotated[Settings, Depends(get_current_settings)],
    credential_store: Annotated[CredentialStore, Depends(get_credential_store)],
    repo: Annotated[SettingsRepository, Depends(get_settings_repository)],
) -> SettingsResponse:
    # Check overrides in database
    db_profile = repo.get_setting("profile")
    db_approval_timeout = repo.get_setting("approval_timeout_seconds")
    db_pseudonym_ttl = repo.get_setting("pseudonym_ttl_seconds")

    openai_configured = False
    anthropic_configured = False
    with contextlib.suppress(Exception):
        openai_configured = bool(credential_store.get_provider_key("openai"))
    with contextlib.suppress(Exception):
        anthropic_configured = bool(credential_store.get_provider_key("anthropic"))

    return SettingsResponse(
        profile=str(db_profile) if db_profile else settings.profile,
        host=settings.host,
        port=settings.port,
        proxy_max_body_bytes=settings.proxy_max_body_bytes,
        sse_max_event_bytes=settings.sse_max_event_bytes,
        detector_timeout_seconds=settings.detector_timeout_seconds,
        pseudonym_ttl_seconds=int(db_pseudonym_ttl)
        if db_pseudonym_ttl
        else settings.pseudonym_ttl_seconds,
        approval_timeout_seconds=float(db_approval_timeout)
        if db_approval_timeout
        else settings.approval_timeout_seconds,
        pii_detect_ip_addresses=settings.pii_detect_ip_addresses,
        pii_languages=list(settings.pii_languages),
        custom_terms_count=len(settings.custom_terms),
        openai_configured=openai_configured,
        anthropic_configured=anthropic_configured,
        protection_limits=_PROTECTION_LIMITS,
    )


@router.put(
    "",
    response_model=SettingsResponse,
    summary="Update application settings",
    description="Update runtime settings overrides stored in SQLite.",
)
async def update_settings(
    body: SettingsUpdateRequest,
    _admin: Annotated[str, Depends(require_admin_auth)],
    settings: Annotated[Settings, Depends(get_current_settings)],
    credential_store: Annotated[CredentialStore, Depends(get_credential_store)],
    repo: Annotated[SettingsRepository, Depends(get_settings_repository)],
) -> SettingsResponse:
    if body.profile is not None:
        repo.set_setting("profile", body.profile)
        settings.profile = body.profile  # pyright: ignore[reportAttributeAccessIssue]
    if body.approval_timeout_seconds is not None:
        repo.set_setting("approval_timeout_seconds", body.approval_timeout_seconds)
        settings.approval_timeout_seconds = body.approval_timeout_seconds
    if body.pseudonym_ttl_seconds is not None:
        repo.set_setting("pseudonym_ttl_seconds", body.pseudonym_ttl_seconds)
        settings.pseudonym_ttl_seconds = body.pseudonym_ttl_seconds

    return await get_settings(
        _admin=_admin,
        settings=settings,
        credential_store=credential_store,
        repo=repo,
    )
