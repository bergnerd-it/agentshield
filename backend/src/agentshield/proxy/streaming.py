"""Streaming pipeline coordinating SSE parsing, rolling secret scan, and rehydration."""

import asyncio
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
        return await self._has_secret(event.data)

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

        try:
            async for chunk in self.raw_stream:
                async for item in self._emit_events(parser.feed(chunk)):
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
        for event in self.rehydrator.flush():
            if event.data and await self._has_secret(event.data):
                logger.error("Secret detected in holdback flush; terminating")
                return
            yield SSESerializer.serialize(event)
