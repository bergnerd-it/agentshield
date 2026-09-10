"""Unit tests for non-streaming and streaming response rehydration."""

import json

from agentshield.filtering.models import FindingCategory
from agentshield.proxy.rehydration import (
    StreamingRehydrator,
    TextStreamRehydrator,
    rehydrate_json,
    rehydrate_text,
)
from agentshield.proxy.sse import SSEEvent
from agentshield.pseudonyms.vault import InMemoryPseudonymVault


def test_rehydrate_text_and_json() -> None:
    vault = InMemoryPseudonymVault()
    p_email = vault.get_or_create(
        session_id="sess_1",
        original_value="alice@example.com",
        category=FindingCategory.PII_EMAIL,
    )
    p_name = vault.get_or_create(
        session_id="sess_1",
        original_value="Alice Smith",
        category=FindingCategory.PII_PERSON,
    )

    text = f"User {p_name} has email {p_email}."
    rehydrated = rehydrate_text(text, vault, "sess_1")
    assert rehydrated == "User Alice Smith has email alice@example.com."

    # Unknown placeholder preserved
    unknown_text = f"User {p_name} and <AS:PERSON:sess_1:9999>"
    assert (
        rehydrate_text(unknown_text, vault, "sess_1")
        == "User Alice Smith and <AS:PERSON:sess_1:9999>"
    )

    # JSON rehydration
    payload = {
        "user": p_name,
        "nested": {"contact": p_email, "count": 5},
        "list": [f"Item {p_name}", "unchanged"],
    }
    rehydrated_payload = rehydrate_json(payload, vault, "sess_1")
    assert rehydrated_payload == {
        "user": "Alice Smith",
        "nested": {"contact": "alice@example.com", "count": 5},
        "list": ["Item Alice Smith", "unchanged"],
    }


def test_text_stream_rehydrator_split_across_deltas() -> None:
    vault = InMemoryPseudonymVault()
    ph = vault.get_or_create(
        session_id="sess_split",
        original_value="SecretTerm",
        category=FindingCategory.CUSTOM_TERM,
    )

    rehydrator = TextStreamRehydrator(vault, "sess_split")

    # Split: "Prefix " + first half of ph
    half = len(ph) // 2
    part1 = f"Prefix {ph[:half]}"
    part2 = f"{ph[half:]} suffix"

    out1 = rehydrator.process_delta(part1)
    assert out1 == "Prefix "  # holdback holds ph[:half]

    out2 = rehydrator.process_delta(part2)
    assert out2 == "SecretTerm suffix"

    assert rehydrator.flush() == ""


def test_text_stream_rehydrator_split_across_three_deltas() -> None:
    vault = InMemoryPseudonymVault()
    ph = vault.get_or_create(
        session_id="sess_3",
        original_value="Bob",
        category=FindingCategory.PII_PERSON,
    )

    rehydrator = TextStreamRehydrator(vault, "sess_3")

    p1 = f"Hello {ph[:3]}"
    p2 = ph[3:12]
    p3 = f"{ph[12:]}!"

    out1 = rehydrator.process_delta(p1)
    assert out1 == "Hello "

    out2 = rehydrator.process_delta(p2)
    assert out2 == ""

    out3 = rehydrator.process_delta(p3)
    assert out3 == "Bob!"


def test_text_stream_rehydrator_false_alarm_flushes() -> None:
    vault = InMemoryPseudonymVault()
    rehydrator = TextStreamRehydrator(vault, "sess_false")

    # "<AS:NOTAPH" looks like a prefix
    out1 = rehydrator.process_delta("Start <AS:NOT_A_PH")
    assert out1 == "Start "

    # But then followed by something that closes without matching a placeholder
    out2 = rehydrator.process_delta("ONE> end")
    assert out2 == "<AS:NOT_A_PHONE> end"


def test_streaming_rehydrator_openai_chat_events() -> None:
    vault = InMemoryPseudonymVault()
    ph = vault.get_or_create(
        session_id="sess_openai",
        original_value="AcmeCorp",
        category=FindingCategory.PII_ORGANIZATION,
    )

    rehydrator = StreamingRehydrator(vault, "sess_openai")

    part1 = ph[:10]
    part2 = ph[10:]

    ev1 = SSEEvent(
        data=json.dumps({"choices": [{"index": 0, "delta": {"content": f"Welcome to {part1}"}}]})
    )
    ev2 = SSEEvent(
        data=json.dumps({"choices": [{"index": 0, "delta": {"content": f"{part2} portal."}}]})
    )
    ev_done = SSEEvent(data="[DONE]")

    transformed1 = rehydrator.transform_event(ev1)
    assert len(transformed1) == 1
    d1 = json.loads(transformed1[0].data)
    assert d1["choices"][0]["delta"]["content"] == "Welcome to "

    transformed2 = rehydrator.transform_event(ev2)
    assert len(transformed2) == 1
    d2 = json.loads(transformed2[0].data)
    assert d2["choices"][0]["delta"]["content"] == "AcmeCorp portal."

    transformed_done = rehydrator.transform_event(ev_done)
    assert len(transformed_done) == 1
    assert transformed_done[0].matches_done()


def test_streaming_rehydrator_anthropic_events() -> None:
    vault = InMemoryPseudonymVault()
    ph = vault.get_or_create(
        session_id="sess_claude",
        original_value="Alice",
        category=FindingCategory.PII_PERSON,
    )

    rehydrator = StreamingRehydrator(vault, "sess_claude")

    part1 = ph[:8]
    part2 = ph[8:]

    ev1 = SSEEvent(
        event="content_block_delta",
        data=json.dumps(
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": f"Hello {part1}"},
            }
        ),
    )
    ev2 = SSEEvent(
        event="content_block_delta",
        data=json.dumps(
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": f"{part2}!"},
            }
        ),
    )

    transformed1 = rehydrator.transform_event(ev1)
    assert len(transformed1) == 1
    d1 = json.loads(transformed1[0].data)
    assert d1["delta"]["text"] == "Hello "

    transformed2 = rehydrator.transform_event(ev2)
    assert len(transformed2) == 1
    d2 = json.loads(transformed2[0].data)
    assert d2["delta"]["text"] == "Alice!"
