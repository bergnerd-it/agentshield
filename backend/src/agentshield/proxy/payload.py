"""Provider-neutral JSON payload validation."""

import json
from typing import Any, Never, cast

from agentshield.core.errors import InvalidProxyPayloadError, StreamingNotSupportedError


class _DuplicateKeyError(ValueError):
    """Internal marker for ambiguous JSON objects."""


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError
        result[key] = value
    return result


def _reject_non_finite_number(_value: str) -> Never:
    raise ValueError


def parse_non_streaming_json(raw_body: bytes) -> dict[str, Any]:
    """Parse one unambiguous JSON object and reject streaming requests."""
    try:
        parsed = json.loads(
            raw_body.decode("utf-8"),
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_non_finite_number,
        )
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise InvalidProxyPayloadError() from exc

    if not isinstance(parsed, dict):
        raise InvalidProxyPayloadError()

    payload = cast(dict[str, Any], parsed)
    if payload.get("stream") is True:
        raise StreamingNotSupportedError()
    return payload
