"""Local token generation, storage with 0600 permissions, and validation."""

import contextlib
import hmac
import os
import secrets
import sys
from pathlib import Path

from agentshield.core.config import ensure_secure_dir


def generate_secure_token(prefix: str = "") -> str:
    """Generate a high-entropy cryptographically secure token."""
    raw = secrets.token_urlsafe(32)
    return f"{prefix}{raw}" if prefix else raw


def write_secure_file(path: Path, content: str) -> None:
    """Write file content with restricted 0600 permissions on POSIX systems."""
    ensure_secure_dir(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    mode = 0o600

    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd = os.open(str(path), flags, mode)
    try:
        data = content.encode("utf-8")
        total_written = 0
        while total_written < len(data):
            written = os.write(fd, data[total_written:])
            total_written += written
    finally:
        os.close(fd)

    if hasattr(os, "chmod") and sys.platform != "win32":
        with contextlib.suppress(OSError):
            path.chmod(0o600)


def read_secure_file(path: Path) -> str | None:
    """Read file content if it exists, trimming whitespace."""
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8").strip()


def get_or_create_admin_token(token_path: Path) -> str:
    """Load existing administrative token or generate a new one with 0600 permissions."""
    existing = read_secure_file(token_path)
    if existing:
        return existing
    token = generate_secure_token(prefix="as_adm_")
    write_secure_file(token_path, token)
    return token


def get_or_create_proxy_token(token_path: Path) -> str:
    """Load existing proxy token or generate a new one with 0600 permissions."""
    existing = read_secure_file(token_path)
    if existing:
        return existing
    token = generate_secure_token(prefix="as_prx_")
    write_secure_file(token_path, token)
    return token


def validate_token(provided_token: str | None, expected_token: str) -> bool:
    """Validate token using constant-time comparison to prevent timing attacks."""
    if not provided_token or not expected_token:
        return False
    return hmac.compare_digest(provided_token.strip(), expected_token.strip())
