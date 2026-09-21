"""Integration manager for previewing, atomically applying, and rolling back agent configs."""

import contextlib
import os
import re
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from sqlalchemy.orm import Session

from agentshield.core.auth import (
    generate_secure_token,
    read_secure_file,
    validate_token,
    write_secure_file,
)
from agentshield.core.config import Settings, ensure_secure_dir
from agentshield.core.errors import NotFoundError
from agentshield.core.logging import get_logger
from agentshield.integrations.base import BaseIntegrationAdapter, ConfigDiff, IntegrationStatus
from agentshield.integrations.claude_code import ClaudeCodeAdapter
from agentshield.integrations.codex import CodexAdapter
from agentshield.persistence.models import IntegrationConfig
from agentshield.persistence.repository import IntegrationRepository

logger = get_logger("agentshield.integrations.manager")


class IntegrationManager:
    """Coordinates coding-agent adapters, atomic backups, rollbacks, and tokens."""

    def __init__(
        self,
        settings: Settings,
        db: Session | None = None,
        adapters: dict[str, BaseIntegrationAdapter] | None = None,
    ) -> None:
        self.settings = settings
        self.db = db
        self.tokens_dir = ensure_secure_dir(settings.data_dir / "tokens")

        if adapters is not None:
            self.adapters = adapters
        else:
            self.adapters = {
                "codex": CodexAdapter(
                    proxy_url=f"http://127.0.0.1:{settings.port}/proxy/openai/v1"
                ),
                "claude-code": ClaudeCodeAdapter(
                    proxy_url=f"http://127.0.0.1:{settings.port}/proxy/anthropic/v1"
                ),
            }

    def get_adapter(self, agent_type: str) -> BaseIntegrationAdapter:
        """Retrieve registered adapter for agent type."""
        adapter = self.adapters.get(agent_type.lower())
        if adapter is None:
            raise NotFoundError(f"Unsupported agent integration: '{agent_type}'")
        return adapter

    def get_token_path(self, agent_type: str) -> Path:
        """Get filesystem path for dedicated per-integration proxy token."""
        clean_name = re.sub(r"[^a-z0-9_]", "", agent_type.lower().replace("-", "_"))
        if not clean_name:
            raise ValueError(f"Invalid agent_type for token path: '{agent_type}'")
        token_file = (self.tokens_dir / f"{clean_name}.token").resolve()
        try:
            token_file.relative_to(self.tokens_dir.resolve())
        except ValueError:
            raise ValueError(
                f"Token path for '{agent_type}' resolved outside tokens directory"
            ) from None
        return token_file

    def get_or_create_token(self, agent_type: str) -> str:
        """Load or create dedicated proxy token for an agent integration."""
        path = self.get_token_path(agent_type)
        existing = read_secure_file(path)
        if existing:
            return existing

        prefix = f"as_prx_{agent_type.lower().replace('-', '_')[:6]}_"
        token = generate_secure_token(prefix=prefix)
        write_secure_file(path, token)
        return token

    def get_agent_for_token(self, provided_token: str | None) -> str | None:
        """Attribute incoming proxy token to a specific agent integration."""
        if not provided_token:
            return None

        clean = provided_token.strip()
        for agent_name in self.adapters:
            token_path = self.get_token_path(agent_name)
            expected = read_secure_file(token_path)
            if expected and validate_token(clean, expected):
                return agent_name

        return None

    def get_status(self, agent_type: str, config_path: Path | None = None) -> IntegrationStatus:
        """Get live detection status enriched with SQLite backup metadata."""
        adapter = self.get_adapter(agent_type)
        status = adapter.detect(config_path)

        last_backup: str | None = None
        updated_at: str | None = None
        if self.db is not None:
            repo = IntegrationRepository(self.db)
            rec = repo.get_integration(agent_type)
            if rec:
                last_backup = rec.last_backup_path
                updated_at = rec.updated_at.isoformat()

        token_exists = self.get_token_path(agent_type).is_file()

        return IntegrationStatus(
            agent_type=status.agent_type,
            configured=status.configured,
            config_path=status.config_path,
            proxy_url=status.proxy_url,
            has_token=token_exists,
            last_backup_path=last_backup,
            updated_at=updated_at,
            error=status.error,
        )

    def list_integrations(self) -> list[IntegrationStatus]:
        """List all supported agent integrations with status and backup info."""
        return [self.get_status(agent) for agent in self.adapters]

    def preview(self, agent_type: str, config_path: Path | None = None) -> ConfigDiff:
        """Generate unified diff preview of configuration changes."""
        adapter = self.get_adapter(agent_type)
        token = self.get_or_create_token(agent_type)
        return adapter.preview(token, config_path)

    def apply(self, agent_type: str, config_path: Path | None = None) -> IntegrationStatus:
        """Atomically back up existing configuration and write proxy settings."""
        adapter = self.get_adapter(agent_type)
        target = config_path or adapter.default_config_path
        target_dir = ensure_secure_dir(target.parent)

        token = self.get_or_create_token(agent_type)
        existing_content = target.read_text(encoding="utf-8") if target.is_file() else None
        new_content = adapter.render_config(token, existing_content)

        # 1. Create timestamped backup if target file exists
        backup_path_str: str | None = None
        if target.is_file():
            timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
            backup_file = target.parent / f"{target.name}.bak.{timestamp}"
            shutil.copy2(target, backup_file)
            if hasattr(os, "chmod") and sys.platform != "win32":
                with contextlib.suppress(OSError):
                    backup_file.chmod(0o600)
            backup_path_str = str(backup_file)
            logger.info("Created backup for %s at %s", agent_type, backup_path_str)

        # 2. Atomic write via temporary sibling file
        temp_file = target_dir / f"{target.name}.tmp.{uuid4().hex}"
        try:
            write_secure_file(temp_file, new_content)
            temp_file.replace(target)
        finally:
            if temp_file.exists():
                with contextlib.suppress(OSError):
                    temp_file.unlink()

        # 3. Update SQLite record
        if self.db is not None:
            try:
                repo = IntegrationRepository(self.db)
                rec = repo.get_integration(agent_type)
                if not rec:
                    rec = IntegrationConfig(agent_type=agent_type)
                rec.status = "configured"
                if backup_path_str:
                    rec.last_backup_path = backup_path_str
                rec.updated_at = datetime.now(UTC)
                repo.save_integration(rec)
                self.db.commit()
            except Exception as e:
                logger.warning(
                    "Config written atomically to %s, but failed to record backup path in "
                    "database: %s",
                    target,
                    e,
                )

        logger.info("Successfully configured integration %s at %s", agent_type, target)
        return self.get_status(agent_type, config_path=target)

    def _find_latest_backup(self, agent_type: str, target: Path) -> Path | None:
        """Find the most recent valid backup file for this integration."""
        target_parent_resolved = target.parent.resolve()
        if self.db is not None:
            repo = IntegrationRepository(self.db)
            rec = repo.get_integration(agent_type)
            if rec and rec.last_backup_path:
                candidate = Path(rec.last_backup_path).resolve()
                # Security: guard against path traversal if DB record was tampered with
                try:
                    candidate.relative_to(target_parent_resolved)
                    if candidate.is_file():
                        return candidate
                except ValueError:
                    logger.warning(
                        "Stored backup path %s is outside target parent directory %s; ignoring",
                        candidate,
                        target_parent_resolved,
                    )

        if target.parent.is_dir():
            backups = sorted(
                target.parent.glob(f"{target.name}.bak.*"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            if backups:
                return backups[0]
        return None

    def rollback(self, agent_type: str, config_path: Path | None = None) -> IntegrationStatus:
        """Atomically restore configuration from the latest backup."""
        adapter = self.get_adapter(agent_type)
        target = config_path or adapter.default_config_path
        target_dir = ensure_secure_dir(target.parent)
        backup_file = self._find_latest_backup(agent_type, target)

        if backup_file is None or not backup_file.is_file():
            raise NotFoundError(
                f"No backup available to rollback integration '{agent_type}' at {target}"
            )

        # Atomic restore
        temp_file = target_dir / f"{target.name}.tmp.{uuid4().hex}"
        try:
            shutil.copy2(backup_file, temp_file)
            if hasattr(os, "chmod") and sys.platform != "win32":
                with contextlib.suppress(OSError):
                    temp_file.chmod(0o600)
            temp_file.replace(target)
        finally:
            if temp_file.exists():
                with contextlib.suppress(OSError):
                    temp_file.unlink()

        # Update SQLite record
        if self.db is not None:
            repo = IntegrationRepository(self.db)
            rec = repo.get_integration(agent_type)
            if rec:
                rec.status = "rolled_back"
                rec.updated_at = datetime.now(UTC)
                repo.save_integration(rec)
                self.db.commit()

        logger.info("Successfully rolled back %s from %s", agent_type, backup_file)
        return self.get_status(agent_type, config_path=target)
