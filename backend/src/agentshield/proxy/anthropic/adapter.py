"""Anthropic protocol adapter for Messages API."""

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

DEFAULT_ANTHROPIC_VERSION = "2023-06-01"


class AnthropicAdapter:
    """Transforms and normalizes requests for Anthropic upstream endpoints."""

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
        anthropic_version_found = False
        connection_headers = connection_header_names(incoming_headers)

        for key, value in incoming_headers.items():
            k_lower = key.lower()
            if (
                k_lower in REQUEST_STRIPPED_HEADERS
                or k_lower in LOCAL_AUTH_HEADERS
                or k_lower in connection_headers
            ):
                continue
            if k_lower == "anthropic-version":
                anthropic_version_found = True
            outbound[key] = value

        outbound["x-api-key"] = api_key
        outbound[LOOP_DETECTION_HEADER] = "1"
        if not anthropic_version_found:
            outbound["anthropic-version"] = DEFAULT_ANTHROPIC_VERSION
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
        """Validate, normalize, and construct a ProxyRequest targeting Anthropic."""
        norm_path = "/" + endpoint_path.lstrip("/")
        target_url = f"{self.settings.anthropic_upstream_base_url.rstrip('/')}{norm_path}"
        validate_upstream_base_url(
            provider=Provider.ANTHROPIC,
            base_url=self.settings.anthropic_upstream_base_url,
            dev_mode=self.settings.dev_mode,
        )

        check_request_loop(
            target_url=target_url,
            incoming_headers=incoming_headers,
            local_host=self.settings.host,
            local_port=self.settings.port,
        )

        json_payload = parse_non_streaming_json(raw_body)
        api_key = await asyncio.to_thread(self.credential_store.get_provider_key, "anthropic")
        if not api_key:
            raise MissingCredentialError("anthropic")

        outbound_headers = self._build_headers(incoming_headers, api_key)

        return ProxyRequest(
            provider=Provider.ANTHROPIC,
            url=target_url,
            method=method,
            headers=outbound_headers,
            body=raw_body,
            json_payload=json_payload,
            is_streaming=False,
        )
