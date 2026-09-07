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
        await self._record(request)
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
        await self._record(request)
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
        await self._record(request)
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
