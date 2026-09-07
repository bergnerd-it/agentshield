"""Proxy package for upstream LLM providers."""

from agentshield.proxy.anthropic import AnthropicAdapter
from agentshield.proxy.client import ProxyForwardClient
from agentshield.proxy.loop_detector import check_request_loop
from agentshield.proxy.openai import OpenAIAdapter
from agentshield.proxy.types import Provider, ProxyRequest, ProxyResponse

__all__ = [
    "AnthropicAdapter",
    "OpenAIAdapter",
    "Provider",
    "ProxyForwardClient",
    "ProxyRequest",
    "ProxyResponse",
    "check_request_loop",
]
