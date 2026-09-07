"""Asynchronous HTTP proxy forwarding client."""

import asyncio

import httpx
from fastapi import Request

from agentshield.core.config import Settings, get_settings
from agentshield.core.errors import BadGatewayError, GatewayTimeoutError
from agentshield.core.logging import get_logger
from agentshield.proxy.types import HOP_BY_HOP_HEADERS, ProxyRequest, ProxyResponse

logger = get_logger("agentshield.proxy.client")


class ProxyForwardClient:
    """Handles async HTTP forwarding to upstream LLM providers without retries."""

    def __init__(
        self,
        settings: Settings | None = None,
        client: httpx.AsyncClient | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self._custom_client = client
        self._custom_transport = transport

    def _build_client(self) -> httpx.AsyncClient:
        if self._custom_client is not None:
            return self._custom_client

        timeout = httpx.Timeout(
            connect=self.settings.proxy_connect_timeout_seconds,
            read=self.settings.proxy_read_timeout_seconds,
            write=self.settings.proxy_write_timeout_seconds,
            pool=5.0,
        )
        transport = self._custom_transport or httpx.AsyncHTTPTransport(retries=0)
        return httpx.AsyncClient(transport=transport, timeout=timeout)

    async def _send_with_disconnect_guard(
        self,
        client: httpx.AsyncClient,
        proxy_request: ProxyRequest,
        client_request: Request | None,
    ) -> httpx.Response:
        """Send HTTP request while watching for client disconnect."""

        async def _execute() -> httpx.Response:
            return await client.request(
                method=proxy_request.method,
                url=proxy_request.url,
                headers=proxy_request.headers,
                content=proxy_request.body,
            )

        async def _watch_disconnect(req: Request) -> None:
            while True:
                if await req.is_disconnected():
                    return
                await asyncio.sleep(0.1)

        upstream_task = asyncio.create_task(_execute())
        disconnect_task = (
            asyncio.create_task(_watch_disconnect(client_request))
            if client_request is not None
            else None
        )

        try:
            if disconnect_task is not None:
                done, _ = await asyncio.wait(
                    [upstream_task, disconnect_task],
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if disconnect_task in done:
                    upstream_task.cancel()
                    logger.info(
                        "Client disconnected; cancelled upstream request to %s",
                        proxy_request.url,
                    )
                    raise asyncio.CancelledError()

            return await upstream_task
        except asyncio.CancelledError:
            upstream_task.cancel()
            raise
        finally:
            if disconnect_task is not None and not disconnect_task.done():
                disconnect_task.cancel()

    async def forward(
        self,
        proxy_request: ProxyRequest,
        client_request: Request | None = None,
    ) -> ProxyResponse:
        """Send proxy request to upstream provider and return faithful ProxyResponse."""
        client = self._build_client()
        close_client = self._custom_client is None

        try:
            response = await self._send_with_disconnect_guard(
                client=client,
                proxy_request=proxy_request,
                client_request=client_request,
            )
        except (httpx.TimeoutException, TimeoutError) as exc:
            logger.warning("Upstream request timed out: %s", str(exc))
            raise GatewayTimeoutError() from exc
        except (
            httpx.ConnectError,
            httpx.NetworkError,
            httpx.ProtocolError,
            httpx.HTTPError,
        ) as exc:
            logger.warning("Upstream HTTP error: %s", str(exc))
            raise BadGatewayError() from exc
        finally:
            if close_client:
                await client.aclose()

        response_headers = {
            k: v for k, v in response.headers.items() if k.lower() not in HOP_BY_HOP_HEADERS
        }
        media_type = response.headers.get("content-type", "application/json")

        return ProxyResponse(
            status_code=response.status_code,
            headers=response_headers,
            body=response.content,
            media_type=media_type,
        )
