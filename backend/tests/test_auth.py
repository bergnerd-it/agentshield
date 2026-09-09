"""Tests for local authentication token generation, restricted file permissions, and validation."""

import os
import sys
from pathlib import Path

from agentshield.core.auth import (
    generate_secure_token,
    get_or_create_admin_token,
    get_or_create_fingerprint_key,
    get_or_create_proxy_token,
    read_secure_file,
    validate_token,
    write_secure_file,
)


def test_token_generation_entropy_and_prefix() -> None:
    """Verify generated tokens contain appropriate entropy and optional prefixes."""
    t1 = generate_secure_token()
    t2 = generate_secure_token(prefix="as_adm_")
    t3 = generate_secure_token(prefix="as_prx_")

    assert len(t1) >= 32
    assert t2.startswith("as_adm_")
    assert t3.startswith("as_prx_")
    assert t1 != t2


def test_secure_file_writing_and_permissions(temp_data_dir: Path) -> None:
    """Verify token file is created with 0600 mode on POSIX systems."""
    token_file = temp_data_dir / "test.token"
    content = "secret-token-value-xyz"
    write_secure_file(token_file, content)

    read_back = read_secure_file(token_file)
    assert read_back == content

    if sys.platform != "win32" and hasattr(os, "stat"):
        mode = oct(token_file.stat().st_mode)[-3:]
        assert mode == "600"


def test_get_or_create_admin_and_proxy_tokens(temp_data_dir: Path) -> None:
    """Verify admin and proxy tokens are idempotently created and loaded."""
    adm_path = temp_data_dir / "admin.token"
    prx_path = temp_data_dir / "proxy.token"

    adm_token1 = get_or_create_admin_token(adm_path)
    prx_token1 = get_or_create_proxy_token(prx_path)

    assert adm_token1.startswith("as_adm_")
    assert prx_token1.startswith("as_prx_")
    assert adm_token1 != prx_token1

    # Second call returns existing token
    adm_token2 = get_or_create_admin_token(adm_path)
    assert adm_token1 == adm_token2


def test_constant_time_validation() -> None:
    """Verify validate_token accurately validates tokens with constant-time equality."""
    expected = "as_adm_secret_token_1234567890"

    assert validate_token(expected, expected) is True
    assert validate_token(f" {expected} ", expected) is True
    assert validate_token("wrong_token", expected) is False
    assert validate_token("", expected) is False
    assert validate_token(None, expected) is False


def test_fingerprint_key_is_stable_and_stored_with_restricted_permissions(
    temp_data_dir: Path,
) -> None:
    path = temp_data_dir / "fingerprint.key"

    first = get_or_create_fingerprint_key(path)
    second = get_or_create_fingerprint_key(path)

    assert first == second
    assert len(first) >= 32
    if sys.platform != "win32":
        assert path.stat().st_mode & 0o777 == 0o600
