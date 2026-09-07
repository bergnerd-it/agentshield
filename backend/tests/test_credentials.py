"""Unit tests for CredentialStore abstractions and implementations."""

from pathlib import Path

import pytest

from agentshield.core.config import Settings
from agentshield.core.credentials import (
    InMemoryCredentialStore,
    KeyringCredentialStore,
)


def test_in_memory_credential_store_crud() -> None:
    """Test get, set, and delete operations on InMemoryCredentialStore."""
    store = InMemoryCredentialStore()

    assert store.get_provider_key("openai") is None
    assert store.get_provider_key("anthropic") is None

    store.set_provider_key("openai", "sk-synth-openai-test-key-12345")
    store.set_provider_key("ANTHROPIC", "sk-ant-synth-test-key-67890")

    assert store.get_provider_key("openai") == "sk-synth-openai-test-key-12345"
    assert store.get_provider_key("OPENAI") == "sk-synth-openai-test-key-12345"
    assert store.get_provider_key("anthropic") == "sk-ant-synth-test-key-67890"

    store.delete_provider_key("openai")
    assert store.get_provider_key("openai") is None
    assert store.get_provider_key("anthropic") == "sk-ant-synth-test-key-67890"


def test_in_memory_credential_store_dev_mode_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test dev mode environment variable fallback in InMemoryCredentialStore."""
    monkeypatch.setenv("AGENTSHIELD_OPENAI_API_KEY", "sk-synth-env-openai-key")
    monkeypatch.setenv("AGENTSHIELD_ANTHROPIC_API_KEY", "sk-ant-synth-env-anthropic-key")

    # Disabled dev mode -> should return None
    store_prod = InMemoryCredentialStore(dev_mode=False)
    assert store_prod.get_provider_key("openai") is None
    assert store_prod.get_provider_key("anthropic") is None

    # Enabled dev mode -> should return env key
    store_dev = InMemoryCredentialStore(dev_mode=True)
    assert store_dev.get_provider_key("openai") == "sk-synth-env-openai-key"
    assert store_dev.get_provider_key("anthropic") == "sk-ant-synth-env-anthropic-key"


def test_keyring_credential_store_with_mock(
    monkeypatch: pytest.MonkeyPatch,
    temp_data_dir: Path,
) -> None:
    """Test KeyringCredentialStore with mocked keyring backend."""
    mock_vault: dict[tuple[str, str], str] = {}

    def mock_get_password(service: str, username: str) -> str | None:
        return mock_vault.get((service, username))

    def mock_set_password(service: str, username: str, password: str) -> None:
        mock_vault[(service, username)] = password

    def mock_delete_password(service: str, username: str) -> None:
        mock_vault.pop((service, username), None)

    monkeypatch.setattr("keyring.get_password", mock_get_password)
    monkeypatch.setattr("keyring.set_password", mock_set_password)
    monkeypatch.setattr("keyring.delete_password", mock_delete_password)

    settings = Settings(data_dir=temp_data_dir, dev_mode=False)
    store = KeyringCredentialStore(settings=settings)

    assert store.get_provider_key("openai") is None
    store.set_provider_key("openai", "sk-synth-keyring-openai")
    assert store.get_provider_key("openai") == "sk-synth-keyring-openai"

    store.delete_provider_key("openai")
    assert store.get_provider_key("openai") is None
