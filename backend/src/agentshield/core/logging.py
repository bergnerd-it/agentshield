"""Safe structured logging abstraction with secret and credential sanitization."""

import logging
import re
import sys
from typing import Any

# Standard secret pattern signatures to sanitize from logs
SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"sk-[a-zA-Z0-9_\-]{20,}", re.IGNORECASE),
    re.compile(r"sk-ant-[a-zA-Z0-9_\-]{20,}", re.IGNORECASE),
    re.compile(r"ghp_[a-zA-Z0-9]{20,}", re.IGNORECASE),
    re.compile(r"github_pat_[a-zA-Z0-9_]{22,}", re.IGNORECASE),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"Bearer\s+[a-zA-Z0-9._\-]{10,}", re.IGNORECASE),
    re.compile(r"as_adm_[a-zA-Z0-9_\-]+", re.IGNORECASE),
    re.compile(r"as_prx_[a-zA-Z0-9_\-]+", re.IGNORECASE),
    re.compile(r"as_fpr_[a-zA-Z0-9_\-]+", re.IGNORECASE),
    re.compile(
        r"(?:password|passwd|secret|api_key|access_token|token)\s*[:=]\s*[\"']?([^\s\"',;]+)[\"']?",
        re.IGNORECASE,
    ),
]

REDACTED_PLACEHOLDER = "[REDACTED]"


def sanitize_text(text: str) -> str:
    """Sanitize secrets, tokens, and sensitive credential patterns from text."""
    if not text:
        return text

    sanitized = text

    # First sanitize standard key-value assignments
    def _kv_sub(match: re.Match[str]) -> str:
        full_match = match.group(0)
        secret_val = match.group(1) if match.lastindex and match.lastindex >= 1 else ""
        if secret_val:
            return full_match.replace(secret_val, REDACTED_PLACEHOLDER)
        return full_match

    # Apply specific token signatures
    for pattern in SECRET_PATTERNS:
        if "[:=]" in pattern.pattern:
            sanitized = pattern.sub(_kv_sub, sanitized)
        elif "Bearer" in pattern.pattern:
            sanitized = pattern.sub(f"Bearer {REDACTED_PLACEHOLDER}", sanitized)
        else:
            sanitized = pattern.sub(REDACTED_PLACEHOLDER, sanitized)

    return sanitized


class SafeLogFilter(logging.Filter):
    """Logging filter that sanitizes message contents and log arguments."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = sanitize_text(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: sanitize_text(str(v)) if isinstance(v, str) else v
                    for k, v in record.args.items()
                }
            elif isinstance(record.args, (list, tuple)):
                record.args = tuple(
                    sanitize_text(str(a)) if isinstance(a, str) else a for a in record.args
                )
        return True


class SafeFormatter(logging.Formatter):
    """Logging formatter that ensures formatted strings and tracebacks are sanitized."""

    def format(self, record: logging.LogRecord) -> str:
        formatted = super().format(record)
        return sanitize_text(formatted)


def setup_logging(level: str = "INFO") -> None:
    """Configure root logger and agentshield logging with sanitization."""
    log_level = getattr(logging, level.upper(), logging.INFO)
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Replace or add handlers with SafeFormatter and SafeLogFilter
    if not root_logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            SafeFormatter(
                fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        handler.addFilter(SafeLogFilter())
        root_logger.addHandler(handler)
    else:
        for handler in root_logger.handlers:
            handler.setFormatter(
                SafeFormatter(
                    fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                )
            )
            handler.addFilter(SafeLogFilter())


class SafeLogger:
    """Wrapper around logging.Logger ensuring safe formatting of arguments."""

    def __init__(self, logger: logging.Logger) -> None:
        self._logger = logger

    def debug(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.debug(sanitize_text(msg), *args, **kwargs)

    def info(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.info(sanitize_text(msg), *args, **kwargs)

    def warning(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.warning(sanitize_text(msg), *args, **kwargs)

    def error(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.error(sanitize_text(msg), *args, **kwargs)

    def critical(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.critical(sanitize_text(msg), *args, **kwargs)

    def exception(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.exception(sanitize_text(msg), *args, **kwargs)


def get_logger(name: str) -> SafeLogger:
    """Get a safe logger instance."""
    logger = logging.getLogger(name)
    logger.addFilter(SafeLogFilter())
    return SafeLogger(logger)
