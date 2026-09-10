"""FastAPI dependency injection providers for authentication, configuration, and database."""

from typing import Annotated

from fastapi import Depends, Header

from agentshield.core.auth import (
    get_or_create_admin_token,
    get_or_create_fingerprint_key,
    get_or_create_proxy_token,
    validate_token,
)
from agentshield.core.config import Settings, get_settings
from agentshield.core.credentials import CredentialStore, KeyringCredentialStore
from agentshield.core.errors import AuthenticationError
from agentshield.filtering.detectors.custom_terms import (
    CustomTermDetector,
    CustomTermRule,
    MatchKind,
)
from agentshield.filtering.detectors.pii import (
    PresidioDetector,
    PresidioDetectorConfig,
    StructuredPiiDetector,
    StructuredPiiDetectorConfig,
)
from agentshield.filtering.detectors.secrets import SecretDetector, SecretDetectorConfig
from agentshield.filtering.detectors.unsupported import UnsupportedContentDetector
from agentshield.filtering.engine import DetectorEngine
from agentshield.filtering.models import Detector
from agentshield.policies.engine import PolicyEngine
from agentshield.policies.models import PolicyAction, PolicyProfile
from agentshield.proxy.anthropic import AnthropicAdapter
from agentshield.proxy.client import ProxyForwardClient
from agentshield.proxy.inspection import RequestInspectionPipeline
from agentshield.proxy.openai import OpenAIAdapter
from agentshield.pseudonyms.vault import InMemoryPseudonymVault


def get_current_settings() -> Settings:
    """Dependency provider for application settings."""
    return get_settings()


_credential_store_instance: CredentialStore | None = None
_forward_client_instance: ProxyForwardClient | None = None
_inspection_pipeline_instance: RequestInspectionPipeline | None = None
_inspection_pipeline_settings: Settings | None = None


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


_pseudonym_vault_instance: InMemoryPseudonymVault | None = None


def get_pseudonym_vault(
    settings: Annotated[Settings, Depends(get_current_settings)],
) -> InMemoryPseudonymVault:
    """Dependency provider for in-memory reversible pseudonym vault."""
    global _pseudonym_vault_instance
    if _pseudonym_vault_instance is None:
        _pseudonym_vault_instance = InMemoryPseudonymVault(
            default_ttl_seconds=settings.pseudonym_ttl_seconds
        )
    return _pseudonym_vault_instance


def reset_pseudonym_vault(
    vault: InMemoryPseudonymVault | None = None,
) -> InMemoryPseudonymVault | None:
    """Reset the pseudonym vault instance (primarily for testing)."""
    global _pseudonym_vault_instance
    _pseudonym_vault_instance = vault
    return _pseudonym_vault_instance


def _custom_term_rules(settings: Settings) -> tuple[CustomTermRule, ...]:
    return tuple(
        CustomTermRule(
            id=item.id,
            pattern=item.pattern,
            match_kind=MatchKind(item.match_kind),
            case_sensitive=item.case_sensitive,
            word_boundaries=item.word_boundaries,
            data_class=item.data_class,
            default_action=PolicyAction[item.default_action],
            excluded_path_prefixes=tuple(tuple(path) for path in item.excluded_path_prefixes),
        )
        for item in settings.custom_terms
    )


def get_inspection_pipeline(
    settings: Annotated[Settings, Depends(get_current_settings)],
) -> RequestInspectionPipeline:
    """Build one in-memory Milestone 3 pipeline for the active settings object."""
    global _inspection_pipeline_instance, _inspection_pipeline_settings
    if _inspection_pipeline_instance is None or _inspection_pipeline_settings is not settings:
        fingerprint_key = get_or_create_fingerprint_key(settings.effective_fingerprint_key_path)
        detectors: list[Detector] = [
            SecretDetector(
                fingerprint_key=fingerprint_key,
                config=SecretDetectorConfig(
                    excluded_fingerprints=frozenset(settings.secret_excluded_fingerprints)
                ),
            ),
            StructuredPiiDetector(
                fingerprint_key=fingerprint_key,
                config=StructuredPiiDetectorConfig(
                    detect_ip_addresses=settings.pii_detect_ip_addresses
                ),
            ),
        ]
        if settings.presidio_enabled:
            detectors.append(
                PresidioDetector(
                    fingerprint_key=fingerprint_key,
                    config=PresidioDetectorConfig(
                        languages=tuple(settings.pii_languages),
                        entity_types=tuple(settings.pii_entity_types),
                        model_names=tuple(
                            (language, settings.presidio_model_names[language])
                            for language in settings.pii_languages
                        ),
                        minimum_confidence=settings.pii_minimum_confidence,
                    ),
                )
            )
        detectors.extend(
            (
                CustomTermDetector(
                    fingerprint_key=fingerprint_key,
                    rules=_custom_term_rules(settings),
                ),
                UnsupportedContentDetector(fingerprint_key=fingerprint_key),
            )
        )
        _inspection_pipeline_instance = RequestInspectionPipeline(
            detector_engine=DetectorEngine(
                detectors=detectors,
                timeout_seconds=settings.detector_timeout_seconds,
            ),
            policy_engine=PolicyEngine(PolicyProfile(settings.profile)),
            header_secret_detector=SecretDetector(
                fingerprint_key=fingerprint_key,
                config=SecretDetectorConfig(
                    excluded_fingerprints=frozenset(settings.secret_excluded_fingerprints)
                ),
            ),
        )
        _inspection_pipeline_settings = settings
    return _inspection_pipeline_instance


def reset_inspection_pipeline() -> None:
    """Drop the in-memory pipeline and its keyed fingerprint namespace."""
    global _inspection_pipeline_instance, _inspection_pipeline_settings
    _inspection_pipeline_instance = None
    _inspection_pipeline_settings = None


async def close_forward_client() -> None:
    """Close the global forwarding client instance during app shutdown."""
    global _forward_client_instance
    if _forward_client_instance is not None:
        await _forward_client_instance.aclose()
        _forward_client_instance = None


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

    candidates: list[str] = []
    if authorization and authorization.lower().startswith("bearer "):
        candidates.append(authorization[7:].strip())
    if x_agentshield_token:
        candidates.append(x_agentshield_token.strip())

    for c in candidates:
        if c and validate_token(c, expected_token):
            return c

    raise AuthenticationError("Invalid or missing administrative token")


async def require_proxy_auth(
    settings: Annotated[Settings, Depends(get_current_settings)],
    authorization: Annotated[str | None, Header()] = None,
    x_api_key: Annotated[str | None, Header(alias="x-api-key")] = None,
) -> str:
    """Validate proxy token from Bearer or x-api-key header."""
    expected_token = get_or_create_proxy_token(settings.effective_proxy_token_path)

    candidates: list[str] = []
    if authorization and authorization.lower().startswith("bearer "):
        candidates.append(authorization[7:].strip())
    if x_api_key:
        candidates.append(x_api_key.strip())

    for c in candidates:
        if c and validate_token(c, expected_token):
            return c

    raise AuthenticationError("Invalid or missing proxy token")
