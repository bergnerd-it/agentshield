"""Native credential store abstraction and implementations."""

import os
from typing import Protocol, runtime_checkable

import keyring
import keyring.errors

from agentshield.core.config import Settings, get_settings
from agentshield.core.logging import get_logger

logger = get_logger("agentshield.credentials")

SERVICE_NAME = "agentshield"


@runtime_checkable
class CredentialStore(Protocol):
    """Protocol for provider credential management."""

    def get_provider_key(self, provider: str) -> str | None:
        """Retrieve upstream API key for a provider."""
        ...

    def set_provider_key(self, provider: str, key: str) -> None:
        """Store upstream API key for a provider."""
        ...

    def delete_provider_key(self, provider: str) -> None:
        """Delete upstream API key for a provider."""
        ...


def _get_dev_mode_env_key(provider: str) -> str | None:
    """Check environment variables for fallback API keys in dev mode."""
    provider_upper = provider.upper()
    # Check AGENTSHIELD_<PROVIDER>_API_KEY first, then standard <PROVIDER>_API_KEY
    candidates = [
        f"AGENTSHIELD_{provider_upper}_API_KEY",
        f"{provider_upper}_API_KEY",
    ]
    for env_var in candidates:
        val = os.environ.get(env_var)
        if val:
            logger.warning(
                "Using fallback %s environment variable for '%s' in dev mode.",
                env_var,
                provider,
            )
            return val.strip()
    return None


class KeyringCredentialStore:
    """OS-native credential store implementation using the keyring package."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings

    @property
    def dev_mode(self) -> bool:
        settings = self._settings or get_settings()
        return settings.dev_mode

    def get_provider_key(self, provider: str) -> str | None:
        """Retrieve provider API key from OS keyring, falling back to dev env if enabled."""
        norm_provider = provider.strip().lower()
        key: str | None = None
        try:
            key = keyring.get_password(SERVICE_NAME, norm_provider)
        except keyring.errors.KeyringError as exc:
            logger.warning(
                "Keyring retrieval failed for provider '%s': %s", norm_provider, str(exc)
            )
        except Exception as exc:  # Broad catch for native backend initialization errors
            logger.warning(
                "Unexpected error accessing OS keyring for provider '%s': %s",
                norm_provider,
                str(exc),
            )

        if key:
            return key.strip()

        if self.dev_mode:
            return _get_dev_mode_env_key(norm_provider)

        return None

    def set_provider_key(self, provider: str, key: str) -> None:
        """Store provider API key in OS keyring."""
        norm_provider = provider.strip().lower()
        try:
            keyring.set_password(SERVICE_NAME, norm_provider, key.strip())
        except keyring.errors.KeyringError as exc:
            logger.error(
                "Failed to store API key in OS keyring for provider '%s': %s",
                norm_provider,
                str(exc),
            )
            raise
        except Exception as exc:
            logger.error(
                "Unexpected error storing API key in OS keyring for provider '%s': %s",
                norm_provider,
                str(exc),
            )
            raise

    def delete_provider_key(self, provider: str) -> None:
        """Delete provider API key from OS keyring."""
        norm_provider = provider.strip().lower()
        try:
            keyring.delete_password(SERVICE_NAME, norm_provider)
        except keyring.errors.PasswordDeleteError:
            # Not found is fine during deletion
            pass
        except keyring.errors.KeyringError as exc:
            logger.warning(
                "Failed to delete API key from OS keyring for provider '%s': %s",
                norm_provider,
                str(exc),
            )
        except Exception as exc:
            logger.warning(
                "Unexpected error deleting API key from OS keyring for provider '%s': %s",
                norm_provider,
                str(exc),
            )


class InMemoryCredentialStore:
    """In-memory credential store for tests and offline/mock scenarios."""

    def __init__(self, initial_keys: dict[str, str] | None = None, dev_mode: bool = False) -> None:
        self._keys: dict[str, str] = {}
        self.dev_mode = dev_mode
        if initial_keys:
            for prov, k in initial_keys.items():
                self._keys[prov.strip().lower()] = k.strip()

    def get_provider_key(self, provider: str) -> str | None:
        """Retrieve provider API key from memory, falling back to dev env if enabled."""
        norm_provider = provider.strip().lower()
        if norm_provider in self._keys:
            return self._keys[norm_provider]

        if self.dev_mode:
            return _get_dev_mode_env_key(norm_provider)

        return None

    def set_provider_key(self, provider: str, key: str) -> None:
        """Store provider API key in memory."""
        self._keys[provider.strip().lower()] = key.strip()

    def delete_provider_key(self, provider: str) -> None:
        """Delete provider API key from memory."""
        self._keys.pop(provider.strip().lower(), None)
