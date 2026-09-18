"""Coding-agent integration adapters and management."""

from agentshield.integrations.base import BaseIntegrationAdapter, ConfigDiff, IntegrationStatus
from agentshield.integrations.claude_code import ClaudeCodeAdapter
from agentshield.integrations.codex import CodexAdapter
from agentshield.integrations.manager import IntegrationManager

__all__ = [
    "BaseIntegrationAdapter",
    "ClaudeCodeAdapter",
    "CodexAdapter",
    "ConfigDiff",
    "IntegrationManager",
    "IntegrationStatus",
]
