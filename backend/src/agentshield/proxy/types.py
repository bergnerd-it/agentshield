"""Proxy types, provider enumerations, and data structures."""

from collections.abc import AsyncIterator, Mapping
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
        "proxy-connection",
        "te",
        "trailer",
        "trailers",
        "transfer-encoding",
        "upgrade",
    }
)

BODY_REBUILT_HEADERS: frozenset[str] = frozenset({"content-length", "content-encoding"})
REQUEST_STRIPPED_HEADERS: frozenset[str] = HOP_BY_HOP_HEADERS | BODY_REBUILT_HEADERS | {"host"}
RESPONSE_STRIPPED_HEADERS: frozenset[str] = HOP_BY_HOP_HEADERS | BODY_REBUILT_HEADERS

LOCAL_AUTH_HEADERS: frozenset[str] = frozenset(
    {
        "authorization",
        "x-api-key",
        "x-agentshield-token",
    }
)


def connection_header_names(headers: Mapping[str, str]) -> frozenset[str]:
    """Return lower-case header names declared hop-by-hop by Connection."""
    names: set[str] = set()
    for key, value in headers.items():
        if key.casefold() == "connection":
            names.update(part.strip().casefold() for part in value.split(",") if part.strip())
    return frozenset(names)


@dataclass(frozen=True)
class ProxyRequest:
    """Prepared upstream proxy request."""

    provider: Provider
    url: str
    method: str
    headers: dict[str, str] = field(repr=False)
    body: bytes = field(repr=False)
    json_payload: dict[str, Any] | None = field(default=None, repr=False)
    is_streaming: bool = False
    session_id: str | None = None


@dataclass(frozen=True)
class ProxyResponse:
    """Response returned from upstream provider."""

    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    media_type: str = "application/json"


@dataclass(frozen=True)
class ProxyStreamResult:
    """Result of an upstream streaming request."""

    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    media_type: str = "text/event-stream"
    body: bytes | None = None
    stream: AsyncIterator[bytes] | None = None
