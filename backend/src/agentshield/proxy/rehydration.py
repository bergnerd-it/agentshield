"""Rehydration service for non-streaming and streaming LLM responses."""

import json
import re
from typing import Any

from agentshield.proxy.sse import SSEEvent
from agentshield.pseudonyms.vault import InMemoryPseudonymVault

PLACEHOLDER_REGEX = re.compile(r"<AS:[A-Z_]+:[a-zA-Z0-9_-]+:\d{4}>")
# Regex for matching potential prefix of a placeholder at the end of a string:
# Matches <, <A, <AS, <AS:..., etc.
POTENTIAL_PREFIX_REGEX = re.compile(r"<(?:A(?:S(?::[A-Z_]*(?::[a-zA-Z0-9_-]*(?::\d{0,4})?)?)?)?)?$")
MAX_HOLDBACK_CHARS: int = 64


def rehydrate_text(text: str, vault: InMemoryPseudonymVault, session_id: str) -> str:
    """Rehydrate all exact issued placeholders in a string."""
    if not vault.has_session_mappings(session_id) or "<AS:" not in text:
        return text

    def _replace_match(match: re.Match[str]) -> str:
        placeholder = match.group(0)
        original = vault.rehydrate(session_id=session_id, placeholder=placeholder)
        return original if original is not None else placeholder

    return PLACEHOLDER_REGEX.sub(_replace_match, text)


def rehydrate_json(payload: Any, vault: InMemoryPseudonymVault, session_id: str) -> Any:
    """Recursively rehydrate string values in a JSON payload."""
    if not vault.has_session_mappings(session_id):
        return payload

    if isinstance(payload, str):
        return rehydrate_text(payload, vault, session_id)
    if isinstance(payload, list):
        return [rehydrate_json(item, vault, session_id) for item in payload]
    if isinstance(payload, dict):
        return {key: rehydrate_json(value, vault, session_id) for key, value in payload.items()}
    return payload


class TextStreamRehydrator:
    """Maintains a holdback buffer for one textual delta stream (e.g. choice 0 content)."""

    def __init__(self, vault: InMemoryPseudonymVault, session_id: str) -> None:
        self.vault = vault
        self.session_id = session_id
        self._holdback = ""

    def process_delta(self, delta: str) -> str:
        """Process incoming text delta, resolving split placeholders and updating holdback."""
        combined = self._holdback + delta
        self._holdback = ""

        if "<" not in combined:
            return combined

        # Rehydrate any complete placeholders
        rehydrated = rehydrate_text(combined, self.vault, self.session_id)

        # Check if rehydrated ends with an incomplete placeholder prefix
        match = POTENTIAL_PREFIX_REGEX.search(rehydrated)
        if match and len(match.group(0)) <= MAX_HOLDBACK_CHARS:
            prefix_start = match.start()
            self._holdback = rehydrated[prefix_start:]
            return rehydrated[:prefix_start]

        return rehydrated

    def flush(self) -> str:
        """Flush remaining holdback buffer at stream end."""
        flushed = self._holdback
        self._holdback = ""
        return flushed


class StreamingRehydrator:
    """SSE event rehydrator supporting OpenAI and Anthropic streaming protocols."""

    def __init__(self, vault: InMemoryPseudonymVault, session_id: str) -> None:
        self.vault = vault
        self.session_id = session_id
        self._active = vault.has_session_mappings(session_id)
        self._stream_rehydrators: dict[str, TextStreamRehydrator] = {}

    def _get_rehydrator(self, key: str) -> TextStreamRehydrator:
        if key not in self._stream_rehydrators:
            self._stream_rehydrators[key] = TextStreamRehydrator(self.vault, self.session_id)
        return self._stream_rehydrators[key]

    def transform_event(self, event: SSEEvent) -> list[SSEEvent]:
        """Transform an SSEEvent, rehydrating split placeholders in supported text deltas."""
        if not self._active or event.is_comment or event.matches_done():
            return [event]

        # Attempt to parse event data as JSON
        try:
            data = json.loads(event.data)
        except Exception:
            # Not JSON or malformed, return as-is
            return [event]

        if not isinstance(data, dict):
            return [event]

        modified = False

        if "choices" in data and isinstance(data["choices"], list):
            modified = self._transform_openai_chat(data)
        elif (
            data.get("type") == "response.text.delta"
            and "delta" in data
            and isinstance(data["delta"], str)
        ):
            modified = self._transform_openai_responses(data)
        elif data.get("type") == "content_block_delta":
            modified = self._transform_anthropic(data)

        if modified:
            new_data = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
            return [
                SSEEvent(
                    data=new_data,
                    event=event.event,
                    id=event.id,
                    retry=event.retry,
                    comment=event.comment,
                )
            ]

        return [event]

    def _transform_openai_chat(self, data: dict[str, Any]) -> bool:
        modified = False
        choices = data.get("choices")
        if not isinstance(choices, list):
            return False
        for i, choice in enumerate(choices):
            if not isinstance(choice, dict):
                continue
            delta = choice.get("delta")
            if not isinstance(delta, dict):
                continue

            if "content" in delta and isinstance(delta["content"], str):
                key = f"openai_chat_{i}_content"
                new_content = self._get_rehydrator(key).process_delta(delta["content"])
                if new_content != delta["content"]:
                    delta["content"] = new_content
                    modified = True

            if self._transform_openai_tool_calls(delta, i):
                modified = True
        return modified

    def _transform_openai_tool_calls(self, delta: dict[str, Any], choice_idx: int) -> bool:
        tool_calls = delta.get("tool_calls")
        if not isinstance(tool_calls, list):
            return False
        modified = False
        for j, tc in enumerate(tool_calls):
            if isinstance(tc, dict) and "function" in tc and isinstance(tc["function"], dict):
                fn = tc["function"]
                if "arguments" in fn and isinstance(fn["arguments"], str):
                    key = f"openai_chat_{choice_idx}_tc_{j}_args"
                    new_args = self._get_rehydrator(key).process_delta(fn["arguments"])
                    if new_args != fn["arguments"]:
                        fn["arguments"] = new_args
                        modified = True
        return modified

    def _transform_openai_responses(self, data: dict[str, Any]) -> bool:
        item_id = str(data.get("output_index", 0))
        key = f"openai_resp_{item_id}"
        new_delta = self._get_rehydrator(key).process_delta(data["delta"])
        if new_delta != data["delta"]:
            data["delta"] = new_delta
            return True
        return False

    def _transform_anthropic(self, data: dict[str, Any]) -> bool:
        idx = str(data.get("index", 0))
        delta = data.get("delta")
        if not isinstance(delta, dict):
            return False

        modified = False
        if delta.get("type") == "text_delta" and isinstance(delta.get("text"), str):
            key = f"anthropic_{idx}_text"
            new_text = self._get_rehydrator(key).process_delta(delta["text"])
            if new_text != delta["text"]:
                delta["text"] = new_text
                modified = True
        elif delta.get("type") == "input_json_delta" and isinstance(delta.get("partial_json"), str):
            key = f"anthropic_{idx}_json"
            new_json = self._get_rehydrator(key).process_delta(delta["partial_json"])
            if new_json != delta["partial_json"]:
                delta["partial_json"] = new_json
                modified = True
        return modified

    def flush(self) -> list[SSEEvent]:
        """Flush any remaining held back text as final SSE events."""
        events: list[SSEEvent] = []
        for key, rehydrator in self._stream_rehydrators.items():
            remainder = rehydrator.flush()
            if not remainder:
                continue

            if key.startswith("openai_chat_") and key.endswith("_content"):
                try:
                    idx = int(key.split("_")[2])
                except IndexError, ValueError:
                    idx = 0
                data = {
                    "choices": [
                        {
                            "index": idx,
                            "delta": {"content": remainder},
                            "finish_reason": None,
                        }
                    ]
                }
                events.append(SSEEvent(data=json.dumps(data, separators=(",", ":"))))
            elif key.startswith("anthropic_") and key.endswith("_text"):
                try:
                    idx = int(key.split("_")[1])
                except IndexError, ValueError:
                    idx = 0
                data = {
                    "type": "content_block_delta",
                    "index": idx,
                    "delta": {"type": "text_delta", "text": remainder},
                }
                events.append(
                    SSEEvent(
                        event="content_block_delta",
                        data=json.dumps(data, separators=(",", ":")),
                    )
                )

        return events
