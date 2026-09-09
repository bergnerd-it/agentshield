"""Provider-aware selection of explicitly supported request text fields."""

from typing import Any

from agentshield.filtering.models import (
    ScanContext,
    ScanDirection,
    ScanTarget,
    UnsupportedContent,
)
from agentshield.proxy.types import Provider

_CONTROL_VALUE_KEYS = frozenset(
    {
        "model",
        "stream",
        "role",
        "type",
        "name",
        "id",
        "call_id",
        "tool_call_id",
        "status",
        "finish_reason",
        "const",
        "default",
        "enum",
    }
)
_UNSUPPORTED_TYPES = frozenset(
    {"image", "input_image", "image_url", "audio", "input_audio", "file", "document"}
)


def _walk_content(
    value: object,
    path: tuple[str | int, ...],
    targets: list[ScanTarget],
    unsupported: list[UnsupportedContent],
) -> None:
    if isinstance(value, str):
        targets.append(ScanTarget(path=path, text=value))
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _walk_content(item, (*path, index), targets, unsupported)
        return
    if not isinstance(value, dict):
        return

    content_type = value.get("type")
    if isinstance(content_type, str) and content_type.casefold() in _UNSUPPORTED_TYPES:
        unsupported.append(UnsupportedContent(path=path, content_type=content_type.casefold()))
        return
    for key, item in value.items():
        if key.casefold() in _CONTROL_VALUE_KEYS:
            continue
        _walk_content(item, (*path, key), targets, unsupported)


def _walk_tool_descriptions(
    value: object,
    path: tuple[str | int, ...],
    targets: list[ScanTarget],
    unsupported: list[UnsupportedContent],
) -> None:
    if isinstance(value, list):
        for index, item in enumerate(value):
            _walk_tool_descriptions(item, (*path, index), targets, unsupported)
        return
    if not isinstance(value, dict):
        return
    for key, item in value.items():
        child_path = (*path, key)
        if key.casefold() == "description":
            _walk_content(item, child_path, targets, unsupported)
        elif isinstance(item, (dict, list)):
            _walk_tool_descriptions(item, child_path, targets, unsupported)


def build_request_scan_context(
    provider: Provider,
    endpoint: str,
    payload: dict[str, Any],
) -> ScanContext:
    """Select request text while preserving provider control and unknown root fields."""
    roots: tuple[str, ...]
    if provider is Provider.OPENAI and endpoint == "/v1/responses":
        roots = ("instructions", "input", "tools")
    elif provider is Provider.OPENAI and endpoint == "/v1/chat/completions":
        roots = ("messages", "tools")
    elif provider is Provider.ANTHROPIC and endpoint == "/v1/messages":
        roots = ("system", "messages", "tools")
    else:
        roots = ()

    targets: list[ScanTarget] = []
    unsupported: list[UnsupportedContent] = []
    for root in roots:
        if root not in payload:
            continue
        if root == "tools":
            _walk_tool_descriptions(payload[root], (root,), targets, unsupported)
        else:
            _walk_content(payload[root], (root,), targets, unsupported)
    return ScanContext(
        provider=provider.value,
        endpoint=endpoint,
        direction=ScanDirection.REQUEST,
        targets=tuple(targets),
        model=payload.get("model") if isinstance(payload.get("model"), str) else None,
        unsupported_content=tuple(unsupported),
    )
