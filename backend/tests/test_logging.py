"""Tests for safe structured logging and credential sanitization."""

import io
import logging

from agentshield.core.logging import (
    SafeFormatter,
    SafeLogFilter,
    SafeLogger,
    get_logger,
    sanitize_text,
)

# Synthetic test credentials conforming to non-real test values
SYNTHETIC_OPENAI_KEY = "sk-proj-test1234567890abcdef1234567890abcdef"
SYNTHETIC_ANTHROPIC_KEY = "sk-ant-api03-test1234567890abcdef1234567890abcdef"
SYNTHETIC_GITHUB_PAT = "ghp_1234567890abcdefghijklmnopqrstuvwx"
SYNTHETIC_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
SYNTHETIC_BEARER_TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
SYNTHETIC_ADMIN_TOKEN = "as_adm_synthetic_admin_token_abcdef123456"
SYNTHETIC_PASSWORD_ASSIGNMENT = "password = SuperSecretMasterKey123!"


def test_sanitize_text_various_secrets() -> None:
    """Verify sanitize_text scrubs synthetic secrets and leaves ordinary text intact."""
    msg = f"Connecting using {SYNTHETIC_OPENAI_KEY} and Anthropic {SYNTHETIC_ANTHROPIC_KEY}"
    sanitized = sanitize_text(msg)
    assert SYNTHETIC_OPENAI_KEY not in sanitized
    assert SYNTHETIC_ANTHROPIC_KEY not in sanitized
    assert "[REDACTED]" in sanitized

    msg2 = f"GitHub auth: {SYNTHETIC_GITHUB_PAT}, AWS: {SYNTHETIC_AWS_KEY}"
    sanitized2 = sanitize_text(msg2)
    assert SYNTHETIC_GITHUB_PAT not in sanitized2
    assert SYNTHETIC_AWS_KEY not in sanitized2

    msg3 = f"Authorization: {SYNTHETIC_BEARER_TOKEN}"
    sanitized3 = sanitize_text(msg3)
    assert "Bearer [REDACTED]" in sanitized3

    msg4 = f"Config setting: {SYNTHETIC_PASSWORD_ASSIGNMENT}"
    sanitized4 = sanitize_text(msg4)
    assert "SuperSecretMasterKey123!" not in sanitized4


def test_safe_logger_absence_of_synthetic_secrets() -> None:
    """Verify SafeLogger never outputs synthetic secrets into log handler streams."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(SafeFormatter("%(message)s"))
    handler.addFilter(SafeLogFilter())

    base_logger = logging.getLogger("test.safe.logger")
    base_logger.setLevel(logging.DEBUG)
    base_logger.addHandler(handler)

    safe_logger = SafeLogger(base_logger)
    safe_logger.info("Initializing with admin token %s", SYNTHETIC_ADMIN_TOKEN)
    safe_logger.error("Failed call with OpenAI key: %s", SYNTHETIC_OPENAI_KEY)
    safe_logger.warning("Assignment failed: password='super_secret_passwd_999'")

    log_output = stream.getvalue()

    # Invariant: zero synthetic credentials present in log output
    assert SYNTHETIC_ADMIN_TOKEN not in log_output
    assert SYNTHETIC_OPENAI_KEY not in log_output
    assert "super_secret_passwd_999" not in log_output
    assert "[REDACTED]" in log_output


def test_get_logger_factory() -> None:
    """Verify get_logger returns wrapped SafeLogger."""
    logger = get_logger("agentshield.test")
    assert isinstance(logger, SafeLogger)
