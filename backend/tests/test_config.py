"""Tests for configuration management and platform data directory resolution."""

import os
import sys
from pathlib import Path

import pytest

from agentshield.core.config import (
    CustomTermSettings,
    Settings,
    ensure_secure_dir,
    get_default_data_dir,
)


def test_custom_term_configuration_is_validated_without_echoing_pattern(
    temp_data_dir: Path,
) -> None:
    from pydantic import ValidationError

    confidential_pattern = "(SyntheticConfidential+)+"
    with pytest.raises(ValidationError) as exc_info:
        CustomTermSettings(
            id="unsafe-regex",
            pattern=confidential_pattern,
            match_kind="regex",
        )

    assert confidential_pattern not in str(exc_info.value)


def test_duplicate_custom_term_ids_are_rejected(temp_data_dir: Path) -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="rule ids must be unique"):
        Settings(
            data_dir=temp_data_dir,
            custom_terms=[
                CustomTermSettings(id="duplicate", pattern="SyntheticOne"),
                CustomTermSettings(id="duplicate", pattern="SyntheticTwo"),
            ],
        )


def test_secret_exclusions_accept_only_non_plaintext_fingerprints(temp_data_dir: Path) -> None:
    from pydantic import ValidationError

    marker = "SyntheticPlaintextSecretExclusion"
    with pytest.raises(ValidationError) as exc_info:
        Settings(data_dir=temp_data_dir, secret_excluded_fingerprints=[marker])

    assert marker not in str(exc_info.value)


def test_presidio_requires_one_safe_local_model_name_per_language(temp_data_dir: Path) -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="one safe local model"):
        Settings(
            data_dir=temp_data_dir,
            pii_languages=["en", "de"],
            presidio_model_names={"en": "en_core_web_lg"},
        )


def test_platform_default_data_dir(monkeypatch: object) -> None:
    """Verify default data directory resolves according to platform conventions."""
    # Test env override
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
    assert settings.effective_fingerprint_key_path == temp_data_dir / "fingerprint.key"


def test_ensure_secure_dir(temp_data_dir: Path) -> None:
    """Verify directory creation enforces restricted permissions on POSIX."""
    sub_dir = temp_data_dir / "secure_sub"
    created = ensure_secure_dir(sub_dir)
    assert created.is_dir()
    if sys.platform != "win32" and hasattr(os, "stat"):
        mode = oct(sub_dir.stat().st_mode)[-3:]
        assert mode == "700"
