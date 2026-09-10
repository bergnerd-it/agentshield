"""Local in-memory ASGI mock provider servers for OpenAI and Anthropic LLM APIs."""

import json
from dataclasses import dataclass
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route


@dataclass
class RecordedRequest:
    """Captured upstream request for inspection in tests."""

    method: str
    path: str
    headers: dict[str, str]
    body: bytes
    json: dict[str, Any] | None = None


class MockOpenAIServer:
    """In-memory ASGI mock server for OpenAI Responses and Chat Completions APIs."""

    def __init__(self) -> None:
        self.recorded_requests: list[RecordedRequest] = []
        self.next_status_code: int = 200
        self.next_response_body: dict[str, Any] | bytes | None = None
        self.next_headers: dict[str, str] = {"content-type": "application/json"}
        self.next_stream_events: list[bytes] | None = None
        self.app = self._build_app()

    def _build_app(self) -> Starlette:
        routes = [
            Route("/v1/responses", self._handle_responses, methods=["POST"]),
            Route("/v1/chat/completions", self._handle_chat_completions, methods=["POST"]),
        ]
        return Starlette(routes=routes)

    async def _record(self, request: Request) -> RecordedRequest:
        body = await request.body()
        parsed_json: dict[str, Any] | None = None
        try:
            parsed_json = json.loads(body.decode("utf-8"))
        except Exception:
            parsed_json = None

        headers = {k.lower(): v for k, v in request.headers.items()}
        rec = RecordedRequest(
            method=request.method,
            path=request.url.path,
            headers=headers,
            body=body,
            json=parsed_json,
        )
        self.recorded_requests.append(rec)
        return rec

    async def _handle_responses(self, request: Request) -> Response:
        rec = await self._record(request)
        if self.next_response_body is not None:
            if isinstance(self.next_response_body, bytes):
                return Response(
                    content=self.next_response_body,
                    status_code=self.next_status_code,
                    headers=self.next_headers,
                )
            return JSONResponse(
                content=self.next_response_body,
                status_code=self.next_status_code,
                headers=self.next_headers,
            )

        if self.next_stream_events is not None:
            from starlette.responses import StreamingResponse

            events = list(self.next_stream_events)
            self.next_stream_events = None

            async def _custom_stream():
                for ev in events:
                    yield ev

            headers = dict(self.next_headers)
            headers.setdefault("content-type", "text/event-stream")
            return StreamingResponse(
                _custom_stream(), status_code=self.next_status_code, headers=headers
            )

        if rec.json and rec.json.get("stream") is True:
            from starlette.responses import StreamingResponse

            async def _stream_responses():
                events = [
                    {
                        "type": "response.text.delta",
                        "output_index": 0,
                        "delta": "Synthetic test completion response.",
                    },
                    {"type": "response.done", "output_index": 0},
                ]
                for ev in events:
                    yield f"data: {json.dumps(ev)}\n\n".encode()
                yield b"data: [DONE]\n\n"

            return StreamingResponse(_stream_responses(), media_type="text/event-stream")

        # Default standard OpenAI response
        return JSONResponse(
            content={
                "id": "resp-synth-001",
                "object": "response",
                "created": 1700000000,
                "model": "gpt-4o",
                "output": [
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [
                            {"type": "text", "text": "Synthetic test completion response."}
                        ],
                    }
                ],
            },
            status_code=200,
            headers=self.next_headers,
        )

    async def _handle_chat_completions(self, request: Request) -> Response:
        rec = await self._record(request)
        if self.next_response_body is not None:
            if isinstance(self.next_response_body, bytes):
                return Response(
                    content=self.next_response_body,
                    status_code=self.next_status_code,
                    headers=self.next_headers,
                )
            return JSONResponse(
                content=self.next_response_body,
                status_code=self.next_status_code,
                headers=self.next_headers,
            )

        if self.next_stream_events is not None:
            from starlette.responses import StreamingResponse

            chat_events = list(self.next_stream_events)
            self.next_stream_events = None

            async def _custom_chat_stream():
                for ev in chat_events:
                    yield ev

            headers = dict(self.next_headers)
            headers.setdefault("content-type", "text/event-stream")
            return StreamingResponse(
                _custom_chat_stream(), status_code=self.next_status_code, headers=headers
            )

        if rec.json and rec.json.get("stream") is True:
            from starlette.responses import StreamingResponse

            async def _stream_chat():
                chunks = [
                    {
                        "id": "chatcmpl-synth-001",
                        "object": "chat.completion.chunk",
                        "created": 1700000000,
                        "model": "gpt-4o",
                        "choices": [
                            {
                                "index": 0,
                                "delta": {"content": "Synthetic test chat completion."},
                                "finish_reason": None,
                            }
                        ],
                    },
                    {
                        "id": "chatcmpl-synth-001",
                        "object": "chat.completion.chunk",
                        "created": 1700000000,
                        "model": "gpt-4o",
                        "choices": [
                            {
                                "index": 0,
                                "delta": {},
                                "finish_reason": "stop",
                            }
                        ],
                    },
                ]
                for c in chunks:
                    yield f"data: {json.dumps(c)}\n\n".encode()
                yield b"data: [DONE]\n\n"

            return StreamingResponse(_stream_chat(), media_type="text/event-stream")

        # Default standard OpenAI chat completion
        return JSONResponse(
            content={
                "id": "chatcmpl-synth-001",
                "object": "chat.completion",
                "created": 1700000000,
                "model": "gpt-4o",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "Synthetic test chat completion.",
                        },
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            },
            status_code=200,
            headers=self.next_headers,
        )


class MockAnthropicServer:
    """In-memory ASGI mock server for Anthropic Messages API."""

    def __init__(self) -> None:
        self.recorded_requests: list[RecordedRequest] = []
        self.next_status_code: int = 200
        self.next_response_body: dict[str, Any] | bytes | None = None
        self.next_headers: dict[str, str] = {"content-type": "application/json"}
        self.next_stream_events: list[bytes] | None = None
        self.app = self._build_app()

    def _build_app(self) -> Starlette:
        routes = [
            Route("/v1/messages", self._handle_messages, methods=["POST"]),
        ]
        return Starlette(routes=routes)

    async def _record(self, request: Request) -> RecordedRequest:
        body = await request.body()
        parsed_json: dict[str, Any] | None = None
        try:
            parsed_json = json.loads(body.decode("utf-8"))
        except Exception:
            parsed_json = None

        headers = {k.lower(): v for k, v in request.headers.items()}
        rec = RecordedRequest(
            method=request.method,
            path=request.url.path,
            headers=headers,
            body=body,
            json=parsed_json,
        )
        self.recorded_requests.append(rec)
        return rec

    async def _handle_messages(self, request: Request) -> Response:
        rec = await self._record(request)
        if self.next_response_body is not None:
            if isinstance(self.next_response_body, bytes):
                return Response(
                    content=self.next_response_body,
                    status_code=self.next_status_code,
                    headers=self.next_headers,
                )
            return JSONResponse(
                content=self.next_response_body,
                status_code=self.next_status_code,
                headers=self.next_headers,
            )

        if self.next_stream_events is not None:
            from starlette.responses import StreamingResponse

            msg_events = list(self.next_stream_events)
            self.next_stream_events = None

            async def _custom_msg_stream():
                for ev in msg_events:
                    yield ev

            headers = dict(self.next_headers)
            headers.setdefault("content-type", "text/event-stream")
            return StreamingResponse(
                _custom_msg_stream(), status_code=self.next_status_code, headers=headers
            )

        if rec.json and rec.json.get("stream") is True:
            from starlette.responses import StreamingResponse

            async def _stream_messages():
                events = [
                    (
                        "message_start",
                        {
                            "type": "message_start",
                            "message": {
                                "id": "msg_synth_001",
                                "type": "message",
                                "role": "assistant",
                                "content": [],
                                "model": "claude-3-5-sonnet-20241022",
                            },
                        },
                    ),
                    (
                        "content_block_start",
                        {
                            "type": "content_block_start",
                            "index": 0,
                            "content_block": {"type": "text", "text": ""},
                        },
                    ),
                    (
                        "content_block_delta",
                        {
                            "type": "content_block_delta",
                            "index": 0,
                            "delta": {
                                "type": "text_delta",
                                "text": "Synthetic test Anthropic response.",
                            },
                        },
                    ),
                    (
                        "content_block_stop",
                        {"type": "content_block_stop", "index": 0},
                    ),
                    (
                        "message_stop",
                        {"type": "message_stop"},
                    ),
                ]
                for event_type, data in events:
                    yield f"event: {event_type}\ndata: {json.dumps(data)}\n\n".encode()

            return StreamingResponse(_stream_messages(), media_type="text/event-stream")

        # Default standard Anthropic response
        return JSONResponse(
            content={
                "id": "msg_synth_001",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "text", "text": "Synthetic test Anthropic response."}],
                "model": "claude-3-5-sonnet-20241022",
                "stop_reason": "end_turn",
                "stop_sequence": None,
                "usage": {"input_tokens": 12, "output_tokens": 8},
            },
            status_code=200,
            headers=self.next_headers,
        )
