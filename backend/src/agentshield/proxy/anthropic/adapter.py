"""Anthropic protocol adapter for Messages API."""

import json
from collections.abc import Mapping
from typing import Any

from agentshield.core.config import Settings, get_settings
from agentshield.core.credentials import CredentialStore
from agentshield.core.errors import MissingCredentialError, StreamingNotSupportedError
from agentshield.proxy.loop_detector import LOOP_DETECTION_HEADER, check_request_loop
from agentshield.proxy.types import (
    LOCAL_AUTH_HEADERS,
    REQUEST_STRIPPED_HEADERS,
    Provider,
    ProxyRequest,
)

DEFAULT_ANTHROPIC_VERSION = "2023-06-01"


def _check_streaming_and_parse_json(raw_body: bytes) -> dict[str, Any] | None:
    """Parse JSON body and reject streaming requests."""
    if not raw_body:
        return None
    try:
        parsed = json.loads(raw_body.decode("utf-8"))
        if isinstance(parsed, dict):
            if parsed.get("stream") is True:
                raise StreamingNotSupportedError()
            return parsed
    except json.JSONDecodeError, UnicodeDecodeError:
        pass
    return None


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

        for key, value in incoming_headers.items():
            k_lower = key.lower()
            if k_lower in REQUEST_STRIPPED_HEADERS or k_lower in LOCAL_AUTH_HEADERS:
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

    def prepare_request(
        self,
        endpoint_path: str,
        raw_body: bytes,
        incoming_headers: Mapping[str, str],
        method: str = "POST",
    ) -> ProxyRequest:
        """Validate, normalize, and construct a ProxyRequest targeting Anthropic."""
        norm_path = "/" + endpoint_path.lstrip("/")
        target_url = f"{self.settings.anthropic_upstream_base_url.rstrip('/')}{norm_path}"

        check_request_loop(
            target_url=target_url,
            incoming_headers=incoming_headers,
            local_host=self.settings.host,
            local_port=self.settings.port,
        )

        api_key = self.credential_store.get_provider_key("anthropic")
        if not api_key:
            raise MissingCredentialError("anthropic")

        json_payload = _check_streaming_and_parse_json(raw_body)
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
