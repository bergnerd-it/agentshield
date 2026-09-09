"""Validation for credential-bearing upstream provider endpoints."""

import ipaddress
from urllib.parse import SplitResult, urlsplit

from agentshield.core.errors import InvalidProviderEndpointError
from agentshield.proxy.types import Provider

_OFFICIAL_HOSTS: dict[Provider, str] = {
    Provider.OPENAI: "api.openai.com",
    Provider.ANTHROPIC: "api.anthropic.com",
}


def _safe_split(provider: Provider, base_url: str) -> SplitResult:
    try:
        parsed = urlsplit(base_url)
        port = parsed.port
    except ValueError as exc:
        raise InvalidProviderEndpointError(provider.value) from exc

    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise InvalidProviderEndpointError(provider.value)
    return parsed


def _is_loopback(hostname: str) -> bool:
    if hostname.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def validate_upstream_base_url(provider: Provider, base_url: str, dev_mode: bool) -> None:
    """Allow official HTTPS endpoints and explicit loopback development endpoints."""
    parsed = _safe_split(provider, base_url)
    hostname = parsed.hostname
    if hostname is None:
        raise InvalidProviderEndpointError(provider.value)

    is_official = hostname.casefold() == _OFFICIAL_HOSTS[provider]
    if is_official and parsed.scheme.casefold() == "https" and parsed.port in (None, 443):
        return

    if dev_mode and parsed.scheme.casefold() in {"http", "https"} and _is_loopback(hostname):
        return

    raise InvalidProviderEndpointError(provider.value)
