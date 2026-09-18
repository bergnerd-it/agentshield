"""OpenAI Codex CLI integration adapter (~/.codex/config.toml)."""

import difflib
import tomllib
from pathlib import Path

from agentshield.integrations.base import BaseIntegrationAdapter, ConfigDiff, IntegrationStatus

DEFAULT_CODEX_CONFIG_PATH = Path.home() / ".codex" / "config.toml"
DEFAULT_OPENAI_PROXY_URL = "http://127.0.0.1:8765/proxy/openai/v1"


class CodexAdapter(BaseIntegrationAdapter):
    """Configuration adapter for OpenAI Codex CLI."""

    agent_type = "codex"

    def __init__(
        self,
        default_config_path: Path | None = None,
        proxy_url: str = DEFAULT_OPENAI_PROXY_URL,
    ) -> None:
        self.default_config_path = default_config_path or DEFAULT_CODEX_CONFIG_PATH
        self.proxy_url = proxy_url

    def detect(self, config_path: Path | None = None) -> IntegrationStatus:
        target = config_path or self.default_config_path
        if not target.is_file():
            return IntegrationStatus(
                agent_type=self.agent_type,
                configured=False,
                config_path=str(target),
                proxy_url=self.proxy_url,
                has_token=False,
            )

        try:
            content = target.read_text(encoding="utf-8")
            data = tomllib.loads(content)
            model_prov = data.get("model_provider", {})
            base_url = str(model_prov.get("base_url", "")).strip()
            api_key = str(model_prov.get("api_key", "")).strip()

            is_configured = (
                self.proxy_url in base_url
                or "127.0.0.1:8765/proxy/openai" in base_url
                or "localhost:8765/proxy/openai" in base_url
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
                error=f"Failed to parse TOML configuration: {e}",
            )

    def _append_missing_fields(
        self, lines: list[str], proxy_url: str, token: str, found_base: bool, found_key: bool
    ) -> None:
        if not found_base:
            lines.append(f'base_url = "{proxy_url}"')
        if not found_key:
            lines.append(f'api_key = "{token}"')

    def _handle_table_field(
        self, line: str, stripped: str, proxy_url: str, token: str
    ) -> tuple[str, bool, bool]:
        if stripped.startswith("base_url"):
            return f'base_url = "{proxy_url}"', True, False
        if stripped.startswith("api_key"):
            return f'api_key = "{token}"', False, True
        return line, False, False

    def render_config(self, token: str, existing_content: str | None) -> str:
        if not existing_content or not existing_content.strip():
            return (
                "# OpenAI Codex configuration for AgentShield Local Security Proxy\n"
                "[model_provider]\n"
                f'base_url = "{self.proxy_url}"\n'
                f'api_key = "{token}"\n'
            )

        lines = existing_content.splitlines()
        new_lines: list[str] = []
        in_model_provider = False
        found_model_provider = False
        found_base_url = False
        found_api_key = False

        for line in lines:
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                if in_model_provider:
                    self._append_missing_fields(
                        new_lines, self.proxy_url, token, found_base_url, found_api_key
                    )
                    in_model_provider = False

                if stripped == "[model_provider]":
                    in_model_provider = True
                    found_model_provider = True

                new_lines.append(line)
                continue

            if in_model_provider:
                out_line, is_base, is_key = self._handle_table_field(
                    line, stripped, self.proxy_url, token
                )
                found_base_url = found_base_url or is_base
                found_api_key = found_api_key or is_key
                new_lines.append(out_line)
            else:
                new_lines.append(line)

        if in_model_provider:
            self._append_missing_fields(
                new_lines, self.proxy_url, token, found_base_url, found_api_key
            )

        if not found_model_provider:
            if new_lines and new_lines[-1].strip():
                new_lines.append("")
            new_lines.extend(
                [
                    "[model_provider]",
                    f'base_url = "{self.proxy_url}"',
                    f'api_key = "{token}"',
                ]
            )

        return "\n".join(new_lines) + "\n"

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
