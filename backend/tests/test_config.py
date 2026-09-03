"""Tests for configuration management and platform data directory resolution."""

import os
import sys
from pathlib import Path

from agentshield.core.config import Settings, ensure_secure_dir, get_default_data_dir


def test_platform_default_data_dir(monkeypatch: object) -> None:
    """Verify default data directory resolves according to platform conventions."""
    # Test env override
    import pytest

    mp = pytest.MonkeyPatch()
    mp.setenv("AGENTSHIELD_DATA_DIR", "/tmp/custom_agentshield_data")
    assert get_default_data_dir() == Path("/tmp/custom_agentshield_data").resolve()
    mp.undo()

    # Test platform resolution
    resolved = get_default_data_dir()
    assert isinstance(resolved, Path)
    if sys.platform == "darwin":
        assert "Application Support/AgentShield" in str(resolved)
    elif sys.platform == "win32":
        assert "AgentShield" in str(resolved)
    else:
        assert "agentshield" in str(resolved)


def test_settings_effective_paths(temp_data_dir: Path) -> None:
    """Verify settings properties derive proper paths from data directory."""
    settings = Settings(data_dir=temp_data_dir)
    assert settings.effective_database_url == f"sqlite:///{temp_data_dir / 'agentshield.db'}"
    assert settings.effective_admin_token_path == temp_data_dir / "admin.token"
    assert settings.effective_proxy_token_path == temp_data_dir / "proxy.token"


def test_ensure_secure_dir(temp_data_dir: Path) -> None:
    """Verify directory creation enforces restricted permissions on POSIX."""
    sub_dir = temp_data_dir / "secure_sub"
    created = ensure_secure_dir(sub_dir)
    assert created.is_dir()
    if sys.platform != "win32" and hasattr(os, "stat"):
        mode = oct(sub_dir.stat().st_mode)[-3:]
        assert mode == "700"
