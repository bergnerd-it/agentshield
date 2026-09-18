"""Anthropic Claude Code CLI integration adapter (~/.claude.json)."""

import difflib
import json
from pathlib import Path

from agentshield.integrations.base import BaseIntegrationAdapter, ConfigDiff, IntegrationStatus

DEFAULT_CLAUDE_CONFIG_PATH = Path.home() / ".claude.json"
FALLBACK_CLAUDE_CONFIG_PATH = Path.home() / ".claude" / "settings.json"
DEFAULT_ANTHROPIC_PROXY_URL = "http://127.0.0.1:8765/proxy/anthropic/v1"


class ClaudeCodeAdapter(BaseIntegrationAdapter):
    """Configuration adapter for Anthropic Claude Code CLI."""

    agent_type = "claude-code"

    def __init__(
        self,
        default_config_path: Path | None = None,
        proxy_url: str = DEFAULT_ANTHROPIC_PROXY_URL,
    ) -> None:
        if default_config_path is not None:
            self.default_config_path = default_config_path
        elif DEFAULT_CLAUDE_CONFIG_PATH.is_file():
            self.default_config_path = DEFAULT_CLAUDE_CONFIG_PATH
        elif FALLBACK_CLAUDE_CONFIG_PATH.is_file():
            self.default_config_path = FALLBACK_CLAUDE_CONFIG_PATH
        else:
            self.default_config_path = DEFAULT_CLAUDE_CONFIG_PATH
        self.proxy_url = proxy_url

    def detect(self, config_path: Path | None = None) -> IntegrationStatus:
        target = config_path or self.default_config_path
        if not target.is_file():
            # Also check fallback if default was not explicitly customized
            if config_path is None and FALLBACK_CLAUDE_CONFIG_PATH.is_file():
                target = FALLBACK_CLAUDE_CONFIG_PATH
            else:
                return IntegrationStatus(
                    agent_type=self.agent_type,
                    configured=False,
                    config_path=str(target),
                    proxy_url=self.proxy_url,
                    has_token=False,
                )

        try:
            content = target.read_text(encoding="utf-8")
            data = json.loads(content)
            base_url = str(
                data.get("anthropicBaseUrl")
                or data.get("baseUrl")
                or data.get("customBaseUrl")
                or ""
            ).strip()
            api_key = str(data.get("primaryApiKey") or data.get("apiKey") or "").strip()

            is_configured = (
                self.proxy_url in base_url
                or "127.0.0.1:8765/proxy/anthropic" in base_url
                or "localhost:8765/proxy/anthropic" in base_url
            ) and bool(api_key)

            return IntegrationStatus(
                agent_type=self.agent_type,
                configured=is_configured,
                config_path=str(target),
                proxy_url=self.proxy_url,
                has_token=bool(api_key),
            )
        except Exception as e:
            return IntegrationStatus(
                agent_type=self.agent_type,
                configured=False,
                config_path=str(target),
                proxy_url=self.proxy_url,
                has_token=False,
                error=f"Failed to parse JSON configuration: {e}",
            )

    def render_config(self, token: str, existing_content: str | None) -> str:
        data: dict[str, object] = {}
        if existing_content and existing_content.strip():
            try:
                parsed = json.loads(existing_content)
                if isinstance(parsed, dict):
                    data = parsed
            except Exception:
                data = {}

        data["primaryApiKey"] = token
        data["anthropicBaseUrl"] = self.proxy_url

        return json.dumps(data, indent=2, ensure_ascii=False) + "\n"

    def preview(self, token: str, config_path: Path | None = None) -> ConfigDiff:
        target = config_path or self.default_config_path
        original = target.read_text(encoding="utf-8") if target.is_file() else ""
        modified = self.render_config(token, original)

        diff = difflib.unified_diff(
            original.splitlines(keepends=True),
            modified.splitlines(keepends=True),
            fromfile=f"a/{target.name}" if original else "/dev/null",
            tofile=f"b/{target.name}",
            n=3,
        )
        diff_text = "".join(diff)

        return ConfigDiff(
            agent_type=self.agent_type,
            config_path=str(target),
            original_content=original,
            modified_content=modified,
            unified_diff=diff_text,
            has_changes=original != modified,
        )
