"""Unit tests for incremental SSE parser and serializer."""

import pytest

from agentshield.core.errors import PayloadTooLargeError
from agentshield.proxy.sse import SSEEvent, SSEParser, SSESerializer


def test_standard_single_event() -> None:
    parser = SSEParser()
    raw = b"event: message\ndata: Hello world\nid: 1\n\n"
    events = parser.feed(raw)
    assert len(events) == 1
    ev = events[0]
    assert ev.event == "message"
    assert ev.data == "Hello world"
    assert ev.id == "1"


def test_multiline_data_and_crlf() -> None:
    parser = SSEParser()
    raw = b"data: line 1\r\ndata: line 2\r\ndata: line 3\r\n\r\n"
    events = parser.feed(raw)
    assert len(events) == 1
    assert events[0].data == "line 1\nline 2\nline 3"


def test_comment_lines() -> None:
    parser = SSEParser()
    raw = b": keep-alive\n\ndata: actual data\n\n"
    events = parser.feed(raw)
    assert len(events) == 2
    assert events[0].is_comment
    assert events[0].comment == "keep-alive"
    assert events[1].data == "actual data"


def test_split_utf8_multibyte_across_chunks() -> None:
    parser = SSEParser()
    # German umlaut 'ä' is b'\xc3\xa4', emoji 🛡️ is b'\xf0\x9f\x9b\xa1\xef\xb8\x8f'
    part1 = b"data: Greetings \xc3"
    part2 = b"\xa4 and \xf0\x9f"
    part3 = b"\x9b\xa1\xef\xb8\x8f\n\n"

    events1 = parser.feed(part1)
    assert len(events1) == 0

    events2 = parser.feed(part2)
    assert len(events2) == 0

    events3 = parser.feed(part3)
    assert len(events3) == 1
    assert events3[0].data == "Greetings ä and 🛡️"


def test_byte_by_byte_fragmentation() -> None:
    parser = SSEParser()
    payload = b'event: update\ndata: {"key":"value"}\n\n'
    collected: list[SSEEvent] = []
    for byte in payload:
        collected.extend(parser.feed(bytes([byte])))

    assert len(collected) == 1
    assert collected[0].event == "update"
    assert collected[0].data == '{"key":"value"}'


def test_multiple_events_in_single_chunk() -> None:
    parser = SSEParser()
    chunk = b"data: first\n\ndata: second\n\ndata: [DONE]\n\n"
    events = parser.feed(chunk)
    assert len(events) == 3
    assert events[0].data == "first"
    assert events[1].data == "second"
    assert events[2].matches_done()


def test_flush_without_trailing_newline() -> None:
    parser = SSEParser()
    events = parser.feed(b"data: final incomplete")
    assert len(events) == 0
    flushed = parser.flush()
    assert len(flushed) == 1
    assert flushed[0].data == "final incomplete"


def test_max_event_size_exceeded_raises_error() -> None:
    parser = SSEParser(max_event_bytes=100)
    huge_data = b"data: " + (b"x" * 150) + b"\n\n"
    with pytest.raises(PayloadTooLargeError, match=r"SSE (line|event) exceeds maximum"):
        parser.feed(huge_data)


def test_serializer_round_trip() -> None:
    ev = SSEEvent(data='{"delta":{"content":"Hi"}}', event="content_block_delta", id="evt_42")
    serialized = SSESerializer.serialize(ev)
    assert b"event: content_block_delta\n" in serialized
    assert b"id: evt_42\n" in serialized
    assert b'data: {"delta":{"content":"Hi"}}\n\n' in serialized

    # Re-parse serialized output
    parser = SSEParser()
    reparsed = parser.feed(serialized)
    assert len(reparsed) == 1
    assert reparsed[0].event == ev.event
    assert reparsed[0].data == ev.data
    assert reparsed[0].id == ev.id
