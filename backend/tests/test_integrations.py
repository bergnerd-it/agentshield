"""Tests for coding-agent integration adapters, manager, atomic rollback, and token attribution."""

import json
import tomllib
from collections.abc import Generator
from pathlib import Path

import httpx
import pytest
from sqlalchemy.orm import Session

from agentshield.api.app import create_app
from agentshield.api.dependencies import get_forward_client
from agentshield.core.auth import get_or_create_admin_token, get_or_create_proxy_token
from agentshield.core.config import Settings
from agentshield.core.errors import NotFoundError
from agentshield.integrations.claude_code import ClaudeCodeAdapter
from agentshield.integrations.codex import CodexAdapter
from agentshield.integrations.manager import IntegrationManager
from agentshield.persistence.db import get_session_factory
from agentshield.persistence.repository import AuditRepository
from agentshield.proxy.client import ProxyForwardClient
from tests.mock_providers import MockOpenAIServer


@pytest.fixture
def integration_db(temp_data_dir: Path, test_settings: Settings) -> Generator[Session]:
    """Provide a clean database session for integration tests."""
    factory = get_session_factory()
    session = factory()
    yield session
    session.close()


def test_codex_adapter_render_and_preserve(temp_data_dir: Path) -> None:
    """Verify Codex adapter renders config and preserves existing sections."""
    adapter = CodexAdapter(proxy_url="http://127.0.0.1:8765/proxy/openai/v1")

    # 1. Fresh file render
    rendered = adapter.render_config("synth_token_123", None)
    data = tomllib.loads(rendered)
    assert data["model_provider"]["base_url"] == "http://127.0.0.1:8765/proxy/openai/v1"
    assert data["model_provider"]["api_key"] == "synth_token_123"

    # 2. Existing file with other sections
    existing = "[general]\ntheme = 'dark'\n\n[editor]\ntab_size = 4\n"
    rendered_existing = adapter.render_config("synth_token_456", existing)
    parsed = tomllib.loads(rendered_existing)
    assert parsed["general"]["theme"] == "dark"
    assert parsed["editor"]["tab_size"] == 4
    assert parsed["model_provider"]["api_key"] == "synth_token_456"

    # 3. Detection
    config_file = temp_data_dir / "codex_config.toml"
    config_file.write_text(rendered_existing, encoding="utf-8")
    status = adapter.detect(config_file)
    assert status.configured is True
    assert status.has_token is True


def test_claude_code_adapter_render_and_preserve(temp_data_dir: Path) -> None:
    """Verify Claude Code adapter renders JSON and preserves user settings."""
    adapter = ClaudeCodeAdapter(proxy_url="http://127.0.0.1:8765/proxy/anthropic/v1")

    existing_json = json.dumps({"autoUpdate": True, "preferredTheme": "nord"})
    rendered = adapter.render_config("synth_claude_token", existing_json)
    data = json.loads(rendered)

    assert data["autoUpdate"] is True
    assert data["preferredTheme"] == "nord"
    assert data["primaryApiKey"] == "synth_claude_token"
    assert data["anthropicBaseUrl"] == "http://127.0.0.1:8765/proxy/anthropic/v1"

    config_file = temp_data_dir / "claude.json"
    config_file.write_text(rendered, encoding="utf-8")
    status = adapter.detect(config_file)
    assert status.configured is True
    assert status.has_token is True


def test_integration_manager_backup_apply_and_rollback(
    test_settings: Settings, integration_db: Session, temp_data_dir: Path
) -> None:
    """Verify atomic modifications, timestamped backups, and 1-click rollback."""
    manager = IntegrationManager(settings=test_settings, db=integration_db)

    test_config_path = temp_data_dir / "codex" / "config.toml"
    test_config_path.parent.mkdir(parents=True, exist_ok=True)
    initial_content = "# Original User Config\n[general]\ncustom = 'user_value'\n"
    test_config_path.write_text(initial_content, encoding="utf-8")

    # 1. Preview changes
    diff = manager.preview("codex", config_path=test_config_path)
    assert diff.has_changes is True
    assert "+[model_provider]" in diff.unified_diff
    assert test_config_path.read_text(encoding="utf-8") == initial_content

    # 2. Apply changes
    status = manager.apply("codex", config_path=test_config_path)
    assert status.configured is True
    assert status.last_backup_path is not None
    backup_path = Path(status.last_backup_path)
    assert backup_path.is_file()
    assert backup_path.read_text(encoding="utf-8") == initial_content

    # Modified file now has model_provider
    current_content = test_config_path.read_text(encoding="utf-8")
    assert "[model_provider]" in current_content
    assert "custom = 'user_value'" in current_content

    # 3. Rollback
    status_rb = manager.rollback("codex", config_path=test_config_path)
    assert status_rb.configured is False
    assert test_config_path.read_text(encoding="utf-8") == initial_content


def test_apply_recovers_session_after_database_commit_failure(
    test_settings: Settings,
    integration_db: Session,
    temp_data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A post-write DB failure is visible without poisoning the shared session."""
    manager = IntegrationManager(settings=test_settings, db=integration_db)
    config_path = temp_data_dir / "codex" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text("[general]\nvalue = 'original'\n", encoding="utf-8")

    def fail_commit() -> None:
        raise RuntimeError("UNSAFE_DATABASE_DETAIL")

    monkeypatch.setattr(integration_db, "commit", fail_commit)
    status = manager.apply("codex", config_path=config_path)

    assert status.configured is True
    assert "[model_provider]" in config_path.read_text(encoding="utf-8")
    assert "failed to record backup path" in caplog.text
    assert "RuntimeError" in caplog.text
    assert "UNSAFE_DATABASE_DETAIL" not in caplog.text
    # The rollback in apply() keeps subsequent repository access usable.
    assert manager.get_status("codex", config_path=config_path).configured is True


def test_token_generation_and_agent_attribution(
    test_settings: Settings, integration_db: Session
) -> None:
    """Verify dedicated per-integration tokens and automatic attribution."""
    manager = IntegrationManager(settings=test_settings, db=integration_db)

    codex_token = manager.get_or_create_token("codex")
    claude_token = manager.get_or_create_token("claude-code")

    assert codex_token.startswith("as_prx_codex_")
    assert claude_token.startswith("as_prx_claude_")
    assert codex_token != claude_token

    # Attribution verification
    assert manager.get_agent_for_token(codex_token) == "codex"
    assert manager.get_agent_for_token(claude_token) == "claude-code"
    assert manager.get_agent_for_token("unknown_token_value") is None


@pytest.mark.asyncio
async def test_proxy_traffic_attribution_via_integration_tokens(
    test_settings: Settings, integration_db: Session
) -> None:
    """Verify incoming proxy requests are attributed to agent based on integration token."""
    manager = IntegrationManager(settings=test_settings, db=integration_db)
    codex_token = manager.get_or_create_token("codex")
    global_proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)

    app = create_app(test_settings)
    mock = MockOpenAIServer()
    upstream = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=mock.app),  # pyright: ignore[reportArgumentType]
        base_url=test_settings.openai_upstream_base_url,
    )
    forwarder = ProxyForwardClient(settings=test_settings, client=upstream)
    app.dependency_overrides[get_forward_client] = lambda: forwarder
    repo = AuditRepository(integration_db)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),  # pyright: ignore[reportArgumentType]
        base_url="http://127.0.0.1:8765",
    ) as client:
        # Request with Codex token (triggers BLOCK with synthetic secret)
        resp1 = await client.post(
            "/proxy/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {codex_token}"},
            json={
                "model": "gpt-4o",
                "messages": [
                    {
                        "role": "user",
                        "content": "sk-synth-live-key-abcdefghijklmnopqrstuvwxyz123456",
                    }
                ],
            },
        )
        assert resp1.status_code == 403

        # Verify audit record has agent="codex"
        events = repo.list_events(limit=5)
        assert len(events) >= 1
        latest_event = events[0]
        assert latest_event.agent == "codex"
        assert latest_event.action == "BLOCK"

        # Request with global proxy token falls back to headers or None
        resp2 = await client.post(
            "/proxy/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {global_proxy_token}",
                "X-Agent-ID": "custom-cli",
            },
            json={
                "model": "gpt-4o",
                "messages": [
                    {
                        "role": "user",
                        "content": "sk-synth-live-key-abcdefghijklmnopqrstuvwxyz123456",
                    }
                ],
            },
        )
        assert resp2.status_code == 403
        events2 = repo.list_events(limit=5)
        assert events2[0].agent == "custom-cli"


@pytest.mark.asyncio
async def test_integrations_management_api(
    test_settings: Settings, integration_db: Session, temp_data_dir: Path
) -> None:
    """Verify management API endpoints for listing, preview, configure, and rollback."""
    app = create_app(test_settings)
    admin_token = get_or_create_admin_token(test_settings.effective_admin_token_path)

    codex_path = temp_data_dir / "api_test_codex.toml"
    codex_path.write_text("[general]\nactive = true\n", encoding="utf-8")

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),  # pyright: ignore[reportArgumentType]
        base_url="http://127.0.0.1:8765",
    ) as client:
        auth_headers = {"Authorization": f"Bearer {admin_token}"}

        # 1. List integrations
        resp_list = await client.get("/api/v1/integrations", headers=auth_headers)
        assert resp_list.status_code == 200
        agents = [item["agent_type"] for item in resp_list.json()]
        assert "codex" in agents
        assert "claude-code" in agents

        # 2. Preview
        resp_prev = await client.get(
            "/api/v1/integrations/codex/preview",
            headers=auth_headers,
            params={"path": str(codex_path)},
        )
        assert resp_prev.status_code == 200
        assert resp_prev.json()["has_changes"] is True
        assert "+[model_provider]" in resp_prev.json()["unified_diff"]

        # 3. Configure
        resp_cfg = await client.post(
            "/api/v1/integrations/codex/configure",
            headers=auth_headers,
            json={"path": str(codex_path)},
        )
        assert resp_cfg.status_code == 200
        assert resp_cfg.json()["configured"] is True
        assert resp_cfg.json()["last_backup_path"] is not None

        # 4. Rollback
        resp_rb = await client.post(
            "/api/v1/integrations/codex/rollback",
            headers=auth_headers,
            json={"path": str(codex_path)},
        )
        assert resp_rb.status_code == 200
        assert resp_rb.json()["configured"] is False
        assert codex_path.read_text(encoding="utf-8") == "[general]\nactive = true\n"


def test_rollback_without_backup_raises_not_found(
    temp_data_dir: Path, test_settings: Settings, integration_db: Session
) -> None:
    """Verify that attempting to roll back an integration with no backup raises NotFoundError."""
    manager = IntegrationManager(settings=test_settings, db=integration_db)

    fresh_codex_path = temp_data_dir / "fresh_unbacked_codex.toml"
    fresh_codex_path.write_text("[general]\nfresh = true\n", encoding="utf-8")

    with pytest.raises(NotFoundError, match="No backup available to rollback integration"):
        manager.rollback("codex", config_path=fresh_codex_path)
