"""Asynchronous HTTP proxy forwarding client."""

import asyncio

import httpx
from fastapi import Request

from agentshield.core.config import Settings, get_settings
from agentshield.core.errors import (
    BadGatewayError,
    GatewayTimeoutError,
    UpstreamCredentialLeakError,
    UpstreamResponseTooLargeError,
)
from agentshield.core.logging import get_logger
from agentshield.proxy.types import (
    RESPONSE_STRIPPED_HEADERS,
    ProxyRequest,
    ProxyResponse,
    connection_header_names,
)

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
        self._client: httpx.AsyncClient | None = client
        self._owns_client: bool = client is None

    def _get_client(self) -> httpx.AsyncClient:
        """Get or lazily initialize the reusable AsyncClient."""
        if self._client is None or self._client.is_closed:
            timeout = httpx.Timeout(
                connect=self.settings.proxy_connect_timeout_seconds,
                read=self.settings.proxy_read_timeout_seconds,
                write=self.settings.proxy_write_timeout_seconds,
                pool=5.0,
            )
            transport = self._custom_transport or httpx.AsyncHTTPTransport(retries=0)
            self._client = httpx.AsyncClient(
                transport=transport,
                timeout=timeout,
                follow_redirects=False,
            )
            self._owns_client = True
        return self._client

    @property
    def client(self) -> httpx.AsyncClient | None:
        """Access the underlying HTTP client instance."""
        return self._client

    async def aclose(self) -> None:
        """Close the underlying HTTP client if owned by this instance."""
        if self._owns_client and self._client is not None and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    @staticmethod
    def _provider_credential_values(proxy_request: ProxyRequest) -> tuple[str, ...]:
        """Extract exact upstream credentials for response leak prevention."""
        credentials: list[str] = []
        for name, value in proxy_request.headers.items():
            name_lower = name.casefold()
            if name_lower == "x-api-key" and value:
                credentials.append(value)
            elif name_lower == "authorization":
                scheme, separator, credential = value.partition(" ")
                if separator and scheme.casefold() == "bearer" and credential:
                    credentials.append(credential.strip())
        return tuple(value for value in credentials if value)

    def _validate_credential_absence(
        self,
        proxy_request: ProxyRequest,
        response_headers: httpx.Headers,
        response_body: bytes,
    ) -> None:
        """Fail closed if a provider reflects the credential used for its request."""
        credentials = self._provider_credential_values(proxy_request)
        for credential in credentials:
            if credential.encode("utf-8") in response_body or any(
                credential in value for value in response_headers.values()
            ):
                logger.error(
                    "Blocked upstream response containing provider credential for %s",
                    proxy_request.provider.value,
                )
                raise UpstreamCredentialLeakError()

    async def _execute(
        self, client: httpx.AsyncClient, proxy_request: ProxyRequest
    ) -> ProxyResponse:
        """Stream one non-streaming response into a strictly bounded buffer."""
        async with client.stream(
            method=proxy_request.method,
            url=proxy_request.url,
            headers=proxy_request.headers,
            content=proxy_request.body,
        ) as response:
            body = bytearray()
            async for chunk in response.aiter_bytes():
                if len(body) + len(chunk) > self.settings.proxy_max_response_bytes:
                    logger.warning(
                        "Upstream response exceeded size limit for %s",
                        proxy_request.provider.value,
                    )
                    raise UpstreamResponseTooLargeError()
                body.extend(chunk)

            response_body = bytes(body)
            self._validate_credential_absence(proxy_request, response.headers, response_body)
            connection_headers = connection_header_names(response.headers)
            response_headers = {
                key: value
                for key, value in response.headers.items()
                if key.casefold() not in RESPONSE_STRIPPED_HEADERS
                and key.casefold() not in connection_headers
            }
            media_type = response.headers.get("content-type", "application/json")
            return ProxyResponse(
                status_code=response.status_code,
                headers=response_headers,
                body=response_body,
                media_type=media_type,
            )

    async def _send_with_disconnect_guard(
        self,
        client: httpx.AsyncClient,
        proxy_request: ProxyRequest,
        client_request: Request | None,
    ) -> ProxyResponse:
        """Send HTTP request while watching for client disconnect."""

        async def _watch_disconnect(req: Request) -> None:
            while True:
                if await req.is_disconnected():
                    return
                await asyncio.sleep(0.1)

        if client_request is not None and await client_request.is_disconnected():
            logger.info(
                "Client was disconnected before upstream request for %s",
                proxy_request.provider.value,
            )
            raise asyncio.CancelledError()

        disconnect_task = (
            asyncio.create_task(_watch_disconnect(client_request))
            if client_request is not None
            else None
        )

        upstream_task = asyncio.create_task(self._execute(client, proxy_request))

        try:
            if disconnect_task is not None:
                done, _ = await asyncio.wait(
                    [upstream_task, disconnect_task],
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if disconnect_task in done:
                    upstream_task.cancel()
                    await asyncio.gather(upstream_task, return_exceptions=True)
                    logger.info(
                        "Client disconnected; cancelled upstream request for %s",
                        proxy_request.provider.value,
                    )
                    raise asyncio.CancelledError()

            return await upstream_task
        except asyncio.CancelledError:
            upstream_task.cancel()
            await asyncio.gather(upstream_task, return_exceptions=True)
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
        client = self._get_client()

        try:
            return await self._send_with_disconnect_guard(
                client=client,
                proxy_request=proxy_request,
                client_request=client_request,
            )
        except (httpx.TimeoutException, TimeoutError) as exc:
            logger.warning("Upstream request timed out: %s", str(exc))
            raise GatewayTimeoutError() from exc
        except httpx.InvalidURL, httpx.UnsupportedProtocol:
            raise
        except httpx.HTTPError as exc:
            logger.warning("Upstream HTTP error: %s", str(exc))
            raise BadGatewayError() from exc
