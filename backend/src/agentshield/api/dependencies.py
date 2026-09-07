"""FastAPI dependency injection providers for authentication, configuration, and database."""

from typing import Annotated

from fastapi import Depends, Header

from agentshield.core.auth import (
    get_or_create_admin_token,
    get_or_create_proxy_token,
    validate_token,
)
from agentshield.core.config import Settings, get_settings
from agentshield.core.credentials import CredentialStore, KeyringCredentialStore
from agentshield.core.errors import AuthenticationError
from agentshield.proxy.anthropic import AnthropicAdapter
from agentshield.proxy.client import ProxyForwardClient
from agentshield.proxy.openai import OpenAIAdapter


def get_current_settings() -> Settings:
    """Dependency provider for application settings."""
    return get_settings()


_credential_store_instance: CredentialStore | None = None
_forward_client_instance: ProxyForwardClient | None = None


def get_credential_store(
    settings: Annotated[Settings, Depends(get_current_settings)],
) -> CredentialStore:
    """Dependency provider for the native credential store."""
    global _credential_store_instance
    if _credential_store_instance is None:
        _credential_store_instance = KeyringCredentialStore(settings=settings)
    return _credential_store_instance


def reset_credential_store(store: CredentialStore | None = None) -> CredentialStore | None:
    """Reset the credential store instance (primarily for testing)."""
    global _credential_store_instance
    _credential_store_instance = store
    return _credential_store_instance


def get_forward_client(
    settings: Annotated[Settings, Depends(get_current_settings)],
) -> ProxyForwardClient:
    """Dependency provider for proxy HTTP forwarding client."""
    global _forward_client_instance
    if _forward_client_instance is None:
        _forward_client_instance = ProxyForwardClient(settings=settings)
    return _forward_client_instance


def reset_forward_client(client: ProxyForwardClient | None = None) -> ProxyForwardClient | None:
    """Reset the forwarding client instance (primarily for testing)."""
    global _forward_client_instance
    _forward_client_instance = client
    return _forward_client_instance


def get_openai_adapter(
    credential_store: Annotated[CredentialStore, Depends(get_credential_store)],
    settings: Annotated[Settings, Depends(get_current_settings)],
) -> OpenAIAdapter:
    """Dependency provider for OpenAI adapter."""
    return OpenAIAdapter(credential_store=credential_store, settings=settings)


def get_anthropic_adapter(
    credential_store: Annotated[CredentialStore, Depends(get_credential_store)],
    settings: Annotated[Settings, Depends(get_current_settings)],
) -> AnthropicAdapter:
    """Dependency provider for Anthropic adapter."""
    return AnthropicAdapter(credential_store=credential_store, settings=settings)


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
