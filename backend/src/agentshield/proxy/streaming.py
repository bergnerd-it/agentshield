"""Streaming pipeline coordinating SSE parsing, rolling secret scan, and rehydration."""

import asyncio
import json
import time
from collections.abc import AsyncIterator

from agentshield.core.errors import UpstreamCredentialLeakError, UpstreamResponseTooLargeError
from agentshield.core.logging import get_logger
from agentshield.filtering.detectors.secrets import SecretDetector
from agentshield.filtering.models import ScanContext, ScanDirection, ScanTarget
from agentshield.proxy.rehydration import StreamingRehydrator
from agentshield.proxy.sse import DEFAULT_MAX_EVENT_BYTES, SSEEvent, SSEParser, SSESerializer
from agentshield.proxy.types import Provider

logger = get_logger("agentshield.proxy.streaming")


class StreamingPipeline:
    """Processes an incoming SSE byte stream with rolling secret checks and rehydration."""

    def __init__(
        self,
        *,
        raw_stream: AsyncIterator[bytes],
        rehydrator: StreamingRehydrator,
        secret_detector: SecretDetector | None = None,
        provider: Provider = Provider.OPENAI,
        endpoint: str = "/v1/chat/completions",
        max_event_bytes: int = DEFAULT_MAX_EVENT_BYTES,
    ) -> None:
        self.raw_stream = raw_stream
        self.rehydrator = rehydrator
        self.secret_detector = secret_detector
        self.provider = provider
        self.endpoint = endpoint
        self.max_event_bytes = max_event_bytes
        self._rolling_window = ""

    async def _has_secret(self, text: str) -> bool:
        if self.secret_detector is None:
            return False

        # Maintain a 256-character rolling window to catch secrets across event boundaries
        combined = self._rolling_window[-256:] + text
        self._rolling_window = combined[-256:]

        context = ScanContext(
            provider=self.provider.value,
            endpoint=self.endpoint,
            direction=ScanDirection.RESPONSE,
            targets=(ScanTarget(path=("stream", "data"), text=combined),),
        )
        try:
            findings = await self.secret_detector.detect(context)
            return any(f.category.is_secret for f in findings)
        except Exception:
            # On detector error during stream, fail safe
            return True

    async def _is_secret_event(self, event: SSEEvent) -> bool:
        if event.is_comment or event.matches_done() or not event.data:
            return False
        return await self._has_secret(self._scan_text(event))

    @staticmethod
    def _scan_text(event: SSEEvent) -> str:
        """Extract the logical text delta so secrets split across SSE events stay adjacent."""
        try:
            data = json.loads(event.data)
        except json.JSONDecodeError, TypeError:
            return event.data
        if not isinstance(data, dict):
            return event.data

        if isinstance(data.get("delta"), str):
            return data["delta"]
        delta = data.get("delta")
        if isinstance(delta, dict) and isinstance(delta.get("text"), str):
            return delta["text"]

        choice_text = StreamingPipeline._extract_choice_text(data.get("choices"))
        if choice_text is not None:
            return choice_text
        return event.data

    @staticmethod
    def _extract_choice_text(choices: object) -> str | None:
        if not isinstance(choices, list):
            return None
        fragments: list[str] = []
        for choice in choices:
            if not isinstance(choice, dict) or not isinstance(choice.get("delta"), dict):
                continue
            choice_delta = choice["delta"]
            content = choice_delta.get("content")
            if isinstance(content, str):
                fragments.append(content)
            tool_calls = choice_delta.get("tool_calls")
            if not isinstance(tool_calls, list):
                continue
            for tool_call in tool_calls:
                if not isinstance(tool_call, dict):
                    continue
                function = tool_call.get("function")
                if isinstance(function, dict) and isinstance(function.get("arguments"), str):
                    fragments.append(function["arguments"])
        return "".join(fragments) if fragments else None

    async def _emit_events(self, events: list[SSEEvent]) -> AsyncIterator[bytes]:
        for event in events:
            if await self._is_secret_event(event):
                logger.error(
                    "Secret detected in SSE stream for %s %s; terminating",
                    self.provider.value,
                    self.endpoint,
                )
                self._stopped = True
                return
            for tev in self.rehydrator.transform_event(event):
                yield SSESerializer.serialize(tev)

    async def process(self) -> AsyncIterator[bytes]:
        """Stream transformed SSE byte chunks to downstream client."""
        parser = SSEParser(max_event_bytes=self.max_event_bytes)
        self._stopped = False
        t0 = time.monotonic()
        first_byte_logged = False

        try:
            async for chunk in self.raw_stream:
                async for item in self._emit_events(parser.feed(chunk)):
                    if not first_byte_logged:
                        ttfb = (time.monotonic() - t0) * 1000
                        logger.debug(
                            "TTFB %.1fms for %s %s",
                            ttfb,
                            self.provider.value,
                            self.endpoint,
                        )
                        first_byte_logged = True
                    yield item
                if self._stopped:
                    return
        except UpstreamCredentialLeakError, UpstreamResponseTooLargeError:
            logger.error(
                "Stream terminated due to security violation or limit for %s %s",
                self.provider.value,
                self.endpoint,
            )
            return
        except asyncio.CancelledError:
            raise

        # Flush parser buffer
        async for item in self._emit_events(parser.flush()):
            yield item
        if self._stopped:
            return

        # Flush rehydrator holdback buffer
        async for item in self._flush_rehydrator():
            yield item

    async def _flush_rehydrator(self) -> AsyncIterator[bytes]:
        """Flush rehydrator holdback buffer and check for secrets."""
        for event in self.rehydrator.flush():
            if event.data and await self._has_secret(event.data):
                logger.error("Secret detected in holdback flush; terminating")
                return
            yield SSESerializer.serialize(event)
