"""Self-referential proxy loop detection."""

from collections.abc import Mapping
from urllib.parse import urlparse

from agentshield.core.errors import ProxyLoopError
from agentshield.core.logging import get_logger

logger = get_logger("agentshield.proxy.loop_detector")

LOOP_DETECTION_HEADER = "x-agentshield-loop-detection"


def check_request_loop(
    target_url: str,
    incoming_headers: Mapping[str, str],
    local_host: str = "127.0.0.1",
    local_port: int = 8765,
) -> None:
    """Verify that a request does not cause a cyclic loop back into AgentShield."""
    # Check for loop detection header in incoming request
    for key in incoming_headers:
        if key.lower() == LOOP_DETECTION_HEADER:
            logger.warning(
                "Detected %s header in incoming request. Rejecting loop.", LOOP_DETECTION_HEADER
            )
            raise ProxyLoopError("Proxy loop detected: request contains loop detection marker.")

    # Check target URL host & port
    parsed = urlparse(target_url)
    target_hostname = parsed.hostname or ""
    target_port = parsed.port or (443 if parsed.scheme == "https" else 80)

    is_local_host = target_hostname.lower() in {
        "127.0.0.1",
        "localhost",
        "::1",
        "0.0.0.0",  # noqa: S104 - loop detection target check
        local_host.lower(),
    }

    if is_local_host and target_port == local_port:
        logger.warning(
            "Target URL '%s' points back to AgentShield instance at %s:%d.",
            target_url,
            local_host,
            local_port,
        )
        raise ProxyLoopError("Proxy loop detected: upstream target URL points to AgentShield.")
