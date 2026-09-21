"""Incremental, robust Server-Sent Events (SSE) parser and serializer."""

import codecs
import contextlib
from dataclasses import dataclass
from typing import Self

from agentshield.core.errors import PayloadTooLargeError

DEFAULT_MAX_EVENT_BYTES: int = 65536


@dataclass(frozen=True, slots=True)
class SSEEvent:
    """Represents a single Server-Sent Event."""

    data: str
    event: str | None = None
    id: str | None = None
    retry: int | None = None
    comment: str | None = None

    @classmethod
    def from_comment(cls, comment: str) -> Self:
        return cls(data="", comment=comment)

    @property
    def is_comment(self) -> bool:
        return self.comment is not None

    def matches_done(self) -> bool:
        """Check if this event signals the standard [DONE] stream termination."""
        return self.data.strip() == "[DONE]"


class SSEParser:
    """Incremental SSE parser handling arbitrary chunk fragmentation and split UTF-8."""

    def __init__(self, max_event_bytes: int = DEFAULT_MAX_EVENT_BYTES) -> None:
        self.max_event_bytes = max_event_bytes
        # Use 'replace' error mode: invalid UTF-8 sequences become U+FFFD rather
        # than crashing the proxy. Replaced characters cannot match secret patterns,
        # so this fails safe. Log a warning if replacement occurs in a future hardening pass.
        self._decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self._line_buffer = ""
        self._current_event: str | None = None
        self._current_data_lines: list[str] = []
        self._current_id: str | None = None
        self._current_retry: int | None = None
        self._total_event_bytes = 0
        self._errored = False

    def feed(self, chunk: bytes) -> list[SSEEvent]:
        """Feed a raw byte chunk and return any completed SSE events."""
        if self._errored:
            raise PayloadTooLargeError(
                "SSE parser is in an errored state due to previous size violation."
            )
        text = self._decoder.decode(chunk)
        return self._process_text(text)

    def _process_text(self, text: str) -> list[SSEEvent]:
        events: list[SSEEvent] = []
        combined = self._line_buffer + text
        self._line_buffer = ""

        # If text ends with '\r', hold back the trailing '\r' to see if '\n' follows in next chunk
        trailing_cr = ""
        if combined.endswith("\r"):
            combined = combined[:-1]
            trailing_cr = "\r"

        # Normalize \r\n and lone \r to \n
        combined = combined.replace("\r\n", "\n").replace("\r", "\n")
        lines = combined.split("\n")

        # The last element after split was either after a trailing newline (empty string)
        # or an incomplete line.
        for line in lines[:-1]:
            event = self._process_line(line)
            if event is not None:
                events.append(event)

        self._line_buffer = lines[-1] + trailing_cr
        if len(self._line_buffer.encode("utf-8")) > self.max_event_bytes:
            self._errored = True
            raise PayloadTooLargeError(
                f"SSE line exceeds maximum allowed size of {self.max_event_bytes} bytes."
            )

        return events

    def _process_line(self, line: str) -> SSEEvent | None:
        # Empty line triggers dispatch of accumulated event
        if not line:
            return self._dispatch_event()

        line_bytes = len(line.encode("utf-8"))
        self._total_event_bytes += line_bytes
        if self._total_event_bytes > self.max_event_bytes:
            self._errored = True
            raise PayloadTooLargeError(
                f"SSE event exceeds maximum allowed size of {self.max_event_bytes} bytes."
            )

        # Comment line starts with ':'
        if line.startswith(":"):
            # Comment line
            comment_text = line[1:].lstrip(" ")
            # If we had no pending data, emit comment event
            if not self._current_data_lines and self._current_event is None:
                return SSEEvent.from_comment(comment_text)
            return None

        field, separator, value = line.partition(":")
        if separator and value.startswith(" "):
            value = value[1:]
        elif not separator:
            value = ""

        self._handle_field(field, value)
        return None

    def _handle_field(self, field: str, value: str) -> None:
        match field:
            case "event":
                self._current_event = value
            case "data":
                self._current_data_lines.append(value)
            case "id":
                self._current_id = value
            case "retry":
                with contextlib.suppress(ValueError):
                    self._current_retry = int(value.strip())
            case _:
                pass

    def _dispatch_event(self) -> SSEEvent | None:
        if (
            not self._current_data_lines
            and self._current_event is None
            and self._current_id is None
        ):
            self._total_event_bytes = 0
            return None

        data = "\n".join(self._current_data_lines)
        event = SSEEvent(
            data=data,
            event=self._current_event,
            id=self._current_id,
            retry=self._current_retry,
        )

        # Reset accumulator
        self._current_event = None
        self._current_data_lines = []
        self._current_id = None
        self._current_retry = None
        self._total_event_bytes = 0

        return event

    def flush(self) -> list[SSEEvent]:
        """Flush any remaining buffered data at end of stream."""
        events: list[SSEEvent] = []
        # Flush the incremental decoder in case of trailing bytes
        remaining_text = self._decoder.decode(b"", final=True)
        if remaining_text:
            events.extend(self._process_text(remaining_text))

        if self._line_buffer:
            event = self._process_line(self._line_buffer)
            if event is not None:
                events.append(event)
            self._line_buffer = ""

        # If data is pending without trailing empty line, dispatch it
        final_event = self._dispatch_event()
        if final_event is not None:
            events.append(final_event)

        return events


class SSESerializer:
    """Serializes SSEEvent objects back into faithful wire format."""

    @staticmethod
    def serialize(event: SSEEvent) -> bytes:
        """Serialize an SSEEvent to UTF-8 bytes with standard SSE framing."""
        if event.is_comment:
            clean_comment = (event.comment or "").replace("\r", "").replace("\n", " ")
            return f": {clean_comment}\n\n".encode()

        parts: list[str] = []
        if event.event is not None:
            clean_event = event.event.replace("\r", "").replace("\n", "")
            parts.append(f"event: {clean_event}")
        if event.id is not None:
            clean_id = event.id.replace("\r", "").replace("\n", "")
            parts.append(f"id: {clean_id}")
        if event.retry is not None:
            parts.append(f"retry: {event.retry}")

        for line in event.data.split("\n"):
            parts.append(f"data: {line}")

        return ("\n".join(parts) + "\n\n").encode("utf-8")
