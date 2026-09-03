"""FastAPI dependency injection providers for authentication, configuration, and database."""

from typing import Annotated

from fastapi import Depends, Header

from agentshield.core.auth import (
    get_or_create_admin_token,
    get_or_create_proxy_token,
    validate_token,
)
from agentshield.core.config import Settings, get_settings
from agentshield.core.errors import AuthenticationError


def get_current_settings() -> Settings:
    """Dependency provider for application settings."""
    return get_settings()


async def require_admin_auth(
    settings: Annotated[Settings, Depends(get_current_settings)],
    authorization: Annotated[str | None, Header()] = None,
    x_agentshield_token: Annotated[str | None, Header(alias="X-AgentShield-Token")] = None,
) -> str:
    """Validate administrative token from Authorization Bearer or X-AgentShield-Token header."""
    expected_token = get_or_create_admin_token(settings.effective_admin_token_path)

    token_candidate: str | None = None
    if authorization and authorization.lower().startswith("bearer "):
        token_candidate = authorization[7:].strip()
    elif x_agentshield_token:
        token_candidate = x_agentshield_token.strip()

    if not token_candidate or not validate_token(token_candidate, expected_token):
        raise AuthenticationError("Invalid or missing administrative token")

    return token_candidate


async def require_proxy_auth(
    settings: Annotated[Settings, Depends(get_current_settings)],
    authorization: Annotated[str | None, Header()] = None,
    x_api_key: Annotated[str | None, Header(alias="x-api-key")] = None,
) -> str:
    """Validate proxy token from Bearer or x-api-key header."""
    expected_token = get_or_create_proxy_token(settings.effective_proxy_token_path)

    token_candidate: str | None = None
    if authorization and authorization.lower().startswith("bearer "):
        token_candidate = authorization[7:].strip()
    elif x_api_key:
        token_candidate = x_api_key.strip()

    if not token_candidate or not validate_token(token_candidate, expected_token):
        raise AuthenticationError("Invalid or missing proxy token")

    return token_candidate
