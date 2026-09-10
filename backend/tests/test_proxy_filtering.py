"""Milestone 3 request-scanning integration and disclosure regression tests."""

import logging
import sqlite3
from collections.abc import Generator

import httpx
import pytest
from fastapi.testclient import TestClient

from agentshield.api.app import create_app
from agentshield.api.dependencies import (
    get_credential_store,
    get_forward_client,
    get_inspection_pipeline,
)
from agentshield.core.auth import get_or_create_proxy_token
from agentshield.core.config import Settings
from agentshield.core.credentials import InMemoryCredentialStore
from agentshield.filtering.detectors.custom_terms import CustomTermDetector, CustomTermRule
from agentshield.filtering.detectors.pii import StructuredPiiDetector
from agentshield.filtering.detectors.secrets import SecretDetector
from agentshield.filtering.detectors.unsupported import UnsupportedContentDetector
from agentshield.filtering.engine import DetectorEngine
from agentshield.policies.engine import PolicyEngine
from agentshield.policies.models import PolicyAction, PolicyProfile
from agentshield.proxy.client import ProxyForwardClient
from agentshield.proxy.inspection import RequestInspectionPipeline
from tests.mock_providers import MockAnthropicServer, MockOpenAIServer


def _pipeline(
    profile: PolicyProfile,
    *,
    custom_rules: tuple[CustomTermRule, ...] = (),
) -> RequestInspectionPipeline:
    key = b"integration-test-fingerprint-key"
    return RequestInspectionPipeline(
        detector_engine=DetectorEngine(
            (
                SecretDetector(fingerprint_key=key),
                StructuredPiiDetector(fingerprint_key=key),
                CustomTermDetector(fingerprint_key=key, rules=custom_rules),
                UnsupportedContentDetector(fingerprint_key=key),
            ),
            timeout_seconds=0.5,
        ),
        policy_engine=PolicyEngine(profile),
        header_secret_detector=SecretDetector(fingerprint_key=key),
    )


@pytest.fixture
def filtered_openai_client(
    test_settings: Settings,
) -> Generator[tuple[TestClient, MockOpenAIServer]]:
    mock = MockOpenAIServer()
    upstream = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=mock.app),  # pyright: ignore[reportArgumentType]
        base_url=test_settings.openai_upstream_base_url,
    )
    forwarder = ProxyForwardClient(settings=test_settings, client=upstream)
    app = create_app(test_settings)
    app.dependency_overrides[get_forward_client] = lambda: forwarder
    app.dependency_overrides[get_credential_store] = lambda: InMemoryCredentialStore(
        initial_keys={"openai": "sk-synth-provider-only-1234567890"}
    )
    app.dependency_overrides[get_inspection_pipeline] = lambda: _pipeline(PolicyProfile.BALANCED)
    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        yield client, mock


def test_openai_secret_blocks_before_provider_and_never_leaks(
    filtered_openai_client: tuple[TestClient, MockOpenAIServer],
    test_settings: Settings,
    caplog: pytest.LogCaptureFixture,
) -> None:
    client, mock = filtered_openai_client
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)
    marker = "sk-synth_blocked_marker_1234567890abcdef"

    with caplog.at_level(logging.DEBUG):
        response = client.post(
            "/proxy/openai/v1/responses",
            headers={"Authorization": f"Bearer {proxy_token}"},
            json={"model": "gpt-4o", "input": f"Do not send {marker}"},
        )

    assert response.status_code == 403
    assert response.json()["type"] == "urn:agentshield:error:content-blocked"
    assert mock.recorded_requests == []
    assert marker not in response.text
    assert marker not in caplog.text
    with sqlite3.connect(test_settings.data_dir / "agentshield.db") as connection:
        dump = "\n".join(connection.iterdump())
    assert marker not in dump


def test_unexpected_header_secret_is_scanned_but_local_auth_is_separate(
    filtered_openai_client: tuple[TestClient, MockOpenAIServer],
    test_settings: Settings,
) -> None:
    client, mock = filtered_openai_client
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)

    response = client.post(
        "/proxy/openai/v1/responses",
        headers={
            "Authorization": f"Bearer {proxy_token}",
            "X-Unexpected-Debug": "sk-synth_header_marker_1234567890abcdef",
        },
        json={"model": "gpt-4o", "input": "safe"},
    )

    assert response.status_code == 403
    assert mock.recorded_requests == []


def test_openai_pii_is_redacted_without_mutating_unknown_fields(
    filtered_openai_client: tuple[TestClient, MockOpenAIServer],
    test_settings: Settings,
) -> None:
    client, mock = filtered_openai_client
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)
    email = "fictional.person@example.invalid"
    payload = {
        "model": "gpt-4o",
        "input": f"Contact {email}",
        "unknown_vendor_field": email,
        "custom_number": 42,
    }

    response = client.post(
        "/proxy/openai/v1/responses",
        headers={"Authorization": f"Bearer {proxy_token}"},
        json=payload,
    )

    assert response.status_code == 200
    recorded = mock.recorded_requests[0]
    assert recorded.json is not None
    assert email not in recorded.json["input"]
    assert recorded.json["unknown_vendor_field"] == email
    assert recorded.json["model"] == "gpt-4o"
    assert recorded.json["custom_number"] == 42


def test_balanced_warning_forwards_original_supported_text(test_settings: Settings) -> None:
    mock = MockOpenAIServer()
    upstream = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=mock.app),  # pyright: ignore[reportArgumentType]
        base_url=test_settings.openai_upstream_base_url,
    )
    forwarder = ProxyForwardClient(settings=test_settings, client=upstream)
    rule = CustomTermRule(id="warn-term", pattern="SyntheticWarningTerm")
    app = create_app(test_settings)
    app.dependency_overrides[get_forward_client] = lambda: forwarder
    app.dependency_overrides[get_credential_store] = lambda: InMemoryCredentialStore(
        initial_keys={"openai": "sk-synth-provider-only-1234567890"}
    )
    app.dependency_overrides[get_inspection_pipeline] = lambda: _pipeline(
        PolicyProfile.BALANCED, custom_rules=(rule,)
    )
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)

    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        response = client.post(
            "/proxy/openai/v1/responses",
            headers={"Authorization": f"Bearer {proxy_token}"},
            json={"model": "gpt-4o", "input": "Keep SyntheticWarningTerm unchanged"},
        )

    assert response.status_code == 200
    assert mock.recorded_requests[0].json is not None
    assert mock.recorded_requests[0].json["input"] == "Keep SyntheticWarningTerm unchanged"


def test_anthropic_custom_term_redaction_preserves_structure(test_settings: Settings) -> None:
    mock = MockAnthropicServer()
    upstream = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=mock.app),  # pyright: ignore[reportArgumentType]
        base_url=test_settings.anthropic_upstream_base_url,
    )
    forwarder = ProxyForwardClient(settings=test_settings, client=upstream)
    rule = CustomTermRule(
        id="fictional-project",
        pattern="ProjectCeruleanSynthetic",
        data_class="internal_project",
        default_action=PolicyAction.REDACT,
    )
    app = create_app(test_settings)
    app.dependency_overrides[get_forward_client] = lambda: forwarder
    app.dependency_overrides[get_credential_store] = lambda: InMemoryCredentialStore(
        initial_keys={"anthropic": "sk-ant-synth-provider-only-1234567890"}
    )
    app.dependency_overrides[get_inspection_pipeline] = lambda: _pipeline(
        PolicyProfile.BALANCED, custom_rules=(rule,)
    )
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)

    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        response = client.post(
            "/proxy/anthropic/v1/messages",
            headers={"x-api-key": proxy_token},
            json={
                "model": "claude-synthetic",
                "max_tokens": 64,
                "messages": [{"role": "user", "content": "Review ProjectCeruleanSynthetic"}],
                "unknown": {"keep": True},
            },
        )

    assert response.status_code == 200
    recorded = mock.recorded_requests[0]
    assert recorded.json is not None
    assert "ProjectCeruleanSynthetic" not in recorded.body.decode()
    assert recorded.json["messages"][0]["content"].startswith("Review <AS:TERM:")
    assert recorded.json["unknown"] == {"keep": True}


def test_strict_profile_blocks_unsupported_image_before_provider(test_settings: Settings) -> None:
    mock = MockAnthropicServer()
    upstream = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=mock.app),  # pyright: ignore[reportArgumentType]
        base_url=test_settings.anthropic_upstream_base_url,
    )
    forwarder = ProxyForwardClient(settings=test_settings, client=upstream)
    app = create_app(test_settings)
    app.dependency_overrides[get_forward_client] = lambda: forwarder
    app.dependency_overrides[get_credential_store] = lambda: InMemoryCredentialStore(
        initial_keys={"anthropic": "sk-ant-synth-provider-only-1234567890"}
    )
    app.dependency_overrides[get_inspection_pipeline] = lambda: _pipeline(PolicyProfile.STRICT)
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)

    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        response = client.post(
            "/proxy/anthropic/v1/messages",
            headers={"x-api-key": proxy_token},
            json={
                "model": "claude-synthetic",
                "max_tokens": 64,
                "messages": [
                    {
                        "role": "user",
                        "content": [{"type": "image", "source": {"data": "SYNTHETIC-BINARY"}}],
                    }
                ],
            },
        )

    assert response.status_code == 403
    assert mock.recorded_requests == []
