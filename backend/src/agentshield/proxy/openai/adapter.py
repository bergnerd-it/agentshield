"""OpenAI protocol adapter for Responses and Chat Completions APIs."""

import asyncio
from collections.abc import Mapping

from agentshield.core.config import Settings, get_settings
from agentshield.core.credentials import CredentialStore
from agentshield.core.errors import MissingCredentialError
from agentshield.proxy.loop_detector import LOOP_DETECTION_HEADER, check_request_loop
from agentshield.proxy.payload import parse_non_streaming_json
from agentshield.proxy.types import (
    LOCAL_AUTH_HEADERS,
    REQUEST_STRIPPED_HEADERS,
    Provider,
    ProxyRequest,
    connection_header_names,
)
from agentshield.proxy.upstream import validate_upstream_base_url


class OpenAIAdapter:
    """Transforms and normalizes requests for OpenAI upstream endpoints."""

    def __init__(
        self,
        credential_store: CredentialStore,
        settings: Settings | None = None,
    ) -> None:
        self.credential_store = credential_store
        self.settings = settings or get_settings()

    def _build_headers(
        self,
        incoming_headers: Mapping[str, str],
        api_key: str,
    ) -> dict[str, str]:
        outbound: dict[str, str] = {}
        connection_headers = connection_header_names(incoming_headers)
        for key, value in incoming_headers.items():
            k_lower = key.lower()
            if (
                k_lower in REQUEST_STRIPPED_HEADERS
                or k_lower in LOCAL_AUTH_HEADERS
                or k_lower in connection_headers
            ):
                continue
            outbound[key] = value

        outbound["Authorization"] = f"Bearer {api_key}"
        outbound[LOOP_DETECTION_HEADER] = "1"
        if "Content-Type" not in outbound and "content-type" not in outbound:
            outbound["Content-Type"] = "application/json"
        return outbound

    async def prepare_request(
        self,
        endpoint_path: str,
        raw_body: bytes,
        incoming_headers: Mapping[str, str],
        method: str = "POST",
    ) -> ProxyRequest:
        """Validate, normalize, and construct a ProxyRequest targeting OpenAI."""
        norm_path = "/" + endpoint_path.lstrip("/")
        target_url = f"{self.settings.openai_upstream_base_url.rstrip('/')}{norm_path}"
        validate_upstream_base_url(
            provider=Provider.OPENAI,
            base_url=self.settings.openai_upstream_base_url,
            dev_mode=self.settings.dev_mode,
        )

        check_request_loop(
            target_url=target_url,
            incoming_headers=incoming_headers,
            local_host=self.settings.host,
            local_port=self.settings.port,
        )

        json_payload = parse_non_streaming_json(raw_body)
        api_key = await asyncio.to_thread(self.credential_store.get_provider_key, "openai")
        if not api_key:
            raise MissingCredentialError("openai")

        outbound_headers = self._build_headers(incoming_headers, api_key)

        return ProxyRequest(
            provider=Provider.OPENAI,
            url=target_url,
            method=method,
            headers=outbound_headers,
            body=raw_body,
            json_payload=json_payload,
            is_streaming=False,
        )
