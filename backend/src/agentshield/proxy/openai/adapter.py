"""OpenAI protocol adapter for Responses and Chat Completions APIs."""

import json
from collections.abc import Mapping
from typing import Any

from agentshield.core.config import Settings, get_settings
from agentshield.core.credentials import CredentialStore
from agentshield.core.errors import MissingCredentialError, StreamingNotSupportedError
from agentshield.proxy.loop_detector import LOOP_DETECTION_HEADER, check_request_loop
from agentshield.proxy.types import HOP_BY_HOP_HEADERS, LOCAL_AUTH_HEADERS, Provider, ProxyRequest


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
        for key, value in incoming_headers.items():
            k_lower = key.lower()
            if k_lower in HOP_BY_HOP_HEADERS or k_lower in LOCAL_AUTH_HEADERS:
                continue
            outbound[key] = value

        outbound["Authorization"] = f"Bearer {api_key}"
        outbound[LOOP_DETECTION_HEADER] = "1"
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
        """Validate, normalize, and construct a ProxyRequest targeting OpenAI."""
        norm_path = "/" + endpoint_path.lstrip("/")
        target_url = f"{self.settings.openai_upstream_base_url.rstrip('/')}{norm_path}"

        check_request_loop(
            target_url=target_url,
            incoming_headers=incoming_headers,
            local_host=self.settings.host,
            local_port=self.settings.port,
        )

        api_key = self.credential_store.get_provider_key("openai")
        if not api_key:
            raise MissingCredentialError("openai")

        json_payload = _check_streaming_and_parse_json(raw_body)
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
