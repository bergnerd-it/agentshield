"""Proxy types, provider enumerations, and data structures."""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Provider(StrEnum):
    """Supported upstream LLM providers."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"


HOP_BY_HOP_HEADERS: frozenset[str] = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "content-length",
        "content-encoding",
        "host",
    }
)

LOCAL_AUTH_HEADERS: frozenset[str] = frozenset(
    {
        "authorization",
        "x-api-key",
        "x-agentshield-token",
    }
)


@dataclass(frozen=True)
class ProxyRequest:
    """Prepared upstream proxy request."""

    provider: Provider
    url: str
    method: str
    headers: dict[str, str]
    body: bytes
    json_payload: dict[str, Any] | None = None
    is_streaming: bool = False


@dataclass(frozen=True)
class ProxyResponse:
    """Response returned from upstream provider."""

    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    media_type: str = "application/json"
