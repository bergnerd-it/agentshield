"""Bounded request content decoding for inspectable proxy payloads."""

import gzip
import zlib
from io import BytesIO

from agentshield.core.errors import (
    InvalidCompressedContentError,
    PayloadTooLargeError,
    UnsupportedContentEncodingError,
)


def decode_request_body(
    body: bytes,
    content_encoding: str | None,
    max_decoded_bytes: int,
) -> bytes:
    """Decode a supported request content coding without exceeding the body limit."""
    if content_encoding is None:
        return body

    codings = [
        coding.strip().casefold() for coding in content_encoding.split(",") if coding.strip()
    ]
    if codings == ["identity"]:
        return body
    if codings != ["gzip"]:
        raise UnsupportedContentEncodingError()

    try:
        with gzip.GzipFile(fileobj=BytesIO(body), mode="rb") as compressed:
            decoded = compressed.read(max_decoded_bytes + 1)
    except (gzip.BadGzipFile, EOFError, OSError, zlib.error) as exc:
        raise InvalidCompressedContentError() from exc

    if len(decoded) > max_decoded_bytes:
        raise PayloadTooLargeError("Decompressed request payload exceeds the maximum allowed size.")
    return decoded
