"""Provider request text selection and unsupported-content normalization."""

from agentshield.filtering.detectors.unsupported import UnsupportedContentDetector
from agentshield.filtering.models import FindingCategory
from agentshield.proxy.scanning import build_request_scan_context
from agentshield.proxy.types import Provider


def test_openai_scans_supported_nested_text_without_control_or_unknown_roots() -> None:
    payload = {
        "model": "must-not-scan-model",
        "input": [
            {
                "role": "user",
                "content": [
                    {"type": "input_text", "text": "scan prompt"},
                    {"type": "tool_result", "content": "scan tool result"},
                ],
            }
        ],
        "tools": [
            {
                "type": "function",
                "name": "must_not_scan_or_rewrite",
                "description": "scan tool description",
                "parameters": {"type": "object", "const": "must-not-scan-schema-value"},
            }
        ],
        "unknown_vendor_field": "must remain uninspected",
    }

    context = build_request_scan_context(Provider.OPENAI, "/v1/responses", payload)

    assert [(target.path, target.text) for target in context.targets] == [
        (("input", 0, "content", 0, "text"), "scan prompt"),
        (("input", 0, "content", 1, "content"), "scan tool result"),
        (("tools", 0, "description"), "scan tool description"),
    ]


async def test_anthropic_marks_multimodal_nodes_without_scanning_encoded_data() -> None:
    payload = {
        "model": "claude-synthetic",
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "scan me"},
                    {
                        "type": "image",
                        "source": {"type": "base64", "data": "DO-NOT-SCAN-BINARY"},
                    },
                ],
            }
        ],
    }

    context = build_request_scan_context(Provider.ANTHROPIC, "/v1/messages", payload)
    findings = await UnsupportedContentDetector(fingerprint_key=b"test-key").detect(context)

    assert [(target.path, target.text) for target in context.targets] == [
        (("messages", 0, "content", 0, "text"), "scan me")
    ]
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.UNSUPPORTED_CONTENT
    assert findings[0].location.start is None
    assert "DO-NOT-SCAN-BINARY" not in repr(findings)
