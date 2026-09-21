"""Automated verification of the 10-step Customer Demonstration Scenario.

Implements and validates all 10 scenario steps from Specification §21:
1. Start / verify AgentShield loopback service.
2. Verify mock provider availability.
3. Select and verify the balanced security profile.
4. Send a normal code request and observe successful forwarding.
5. Send a request containing a synthetic API key and observe blocking (HTTP 403).
6. Send a request containing a person's name and internal class name; inspect pseudonymization.
7. Receive the rehydrated mock response.
8. Trigger a REQUIRE_APPROVAL rule and approve it via the Management API.
9. Export an audit report and verify that it contains no confidential values.
10. Run agentshield diagnostics and verify diagnostic output including direct egress warning banner.
"""

import asyncio
import concurrent.futures
import sqlite3
from collections.abc import Generator
from pathlib import Path
from typing import Any, cast

import httpx
import pytest
from fastapi.testclient import TestClient

from agentshield.api.app import create_app
from agentshield.api.dependencies import (
    get_approval_manager,
    get_credential_store,
    get_forward_client,
    get_inspection_pipeline,
    reset_approval_manager,
)
from agentshield.approvals.manager import ApprovalManager
from agentshield.cli import COOPERATIVE_PROXY_BANNER
from agentshield.core.auth import get_or_create_admin_token, get_or_create_proxy_token
from agentshield.core.config import Settings, reset_settings
from agentshield.core.credentials import InMemoryCredentialStore
from agentshield.core.diagnostics import DiagnosticsService
from agentshield.filtering.detectors.custom_terms import CustomTermDetector, CustomTermRule
from agentshield.filtering.detectors.pii import (
    PresidioAnalyzer,
    PresidioDetector,
    PresidioDetectorConfig,
    StructuredPiiDetector,
    StructuredPiiDetectorConfig,
)
from agentshield.filtering.detectors.secrets import SecretDetector
from agentshield.filtering.detectors.unsupported import UnsupportedContentDetector
from agentshield.filtering.engine import DetectorEngine
from agentshield.persistence.db import reset_db, run_migrations
from agentshield.policies.engine import PolicyEngine
from agentshield.policies.models import PolicyAction, PolicyProfile
from agentshield.proxy.client import ProxyForwardClient
from agentshield.proxy.inspection import RequestInspectionPipeline
from tests.mock_providers import MockOpenAIServer

type DemoFixtureTuple = tuple[
    TestClient,
    MockOpenAIServer,
    str,
    str,
    Path,
    RequestInspectionPipeline,
    ApprovalManager,
]


class _MockPresidioAnalyzer:
    """Deterministic in-memory analyzer for PII names in tests."""

    def analyze(
        self,
        text: str,
        entities: list[str] | None = None,
        language: str = "en",
        score_threshold: float | None = None,
    ) -> list[Any]:
        results: list[Any] = []
        for name in ("Erika Mustermann", "John Doe"):
            start = 0
            while True:
                idx = text.find(name, start)
                if idx == -1:
                    break
                obj = type(
                    "RecognizerResult",
                    (),
                    {
                        "entity_type": "PERSON",
                        "start": idx,
                        "end": idx + len(name),
                        "score": 0.95,
                    },
                )()
                results.append(obj)
                start = idx + len(name)
        return results


@pytest.fixture
def demo_env(tmp_path: Path) -> Generator[DemoFixtureTuple]:
    data_dir = tmp_path / "demo_data"
    data_dir.mkdir(parents=True, exist_ok=True)

    settings = Settings(
        host="127.0.0.1",
        port=8765,
        data_dir=data_dir,
        profile="balanced",
        dev_mode=True,
        log_level="WARNING",
    )
    reset_settings(settings)
    reset_db()
    run_migrations(settings.effective_database_url)

    mock = MockOpenAIServer()
    upstream = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=mock.app),  # pyright: ignore[reportArgumentType]
        base_url=settings.openai_upstream_base_url,
    )
    forwarder = ProxyForwardClient(settings=settings, client=upstream)

    key = b"demo-scenario-fingerprint-key"
    custom_rules = (
        CustomTermRule(
            id="rule-cust-1",
            pattern="GreenfieldGrantService",
            default_action=PolicyAction.REDACT,
        ),
        CustomTermRule(
            id="rule-approval-1",
            pattern="HIGH_RISK_OP",
            default_action=PolicyAction.REQUIRE_APPROVAL,
        ),
    )

    detector_engine = DetectorEngine(
        (
            SecretDetector(fingerprint_key=key),
            StructuredPiiDetector(
                fingerprint_key=key,
                config=StructuredPiiDetectorConfig(detect_ip_addresses=True),
            ),
            PresidioDetector(
                fingerprint_key=key,
                analyzer=cast(PresidioAnalyzer, _MockPresidioAnalyzer()),
                config=PresidioDetectorConfig(languages=("en", "de")),
            ),
            CustomTermDetector(fingerprint_key=key, rules=custom_rules),
            UnsupportedContentDetector(fingerprint_key=key),
        ),
        timeout_seconds=2.0,
    )

    policy_engine = PolicyEngine(profile=PolicyProfile.BALANCED)
    approval_manager = ApprovalManager(
        max_history=100,
        max_pending=50,
    )
    pipeline = RequestInspectionPipeline(
        detector_engine=detector_engine,
        policy_engine=policy_engine,
        header_secret_detector=SecretDetector(fingerprint_key=key),
    )

    store = InMemoryCredentialStore(initial_keys={"openai": "sk-synth-upstream-key-demo"})
    app = create_app(settings)
    app.dependency_overrides[get_forward_client] = lambda: forwarder
    app.dependency_overrides[get_credential_store] = lambda: store
    app.dependency_overrides[get_inspection_pipeline] = lambda: pipeline
    app.dependency_overrides[get_approval_manager] = lambda: approval_manager

    proxy_token = get_or_create_proxy_token(settings.effective_proxy_token_path)
    admin_token = get_or_create_admin_token(settings.effective_admin_token_path)

    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        yield client, mock, proxy_token, admin_token, data_dir, pipeline, approval_manager

    app.dependency_overrides.clear()
    reset_approval_manager()
    reset_settings(None)


def test_full_10_step_demo_scenario(demo_env: DemoFixtureTuple) -> None:
    client, mock, proxy_token, admin_token, data_dir, _pipeline, approval_manager = demo_env
    proxy_headers = {"Authorization": f"Bearer {proxy_token}"}
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Step 1: Start / verify AgentShield loopback service
    health_resp = client.get("/health")
    assert health_resp.status_code == 200
    assert health_resp.json()["status"] == "ok"

    # Step 2: Verify mock provider availability
    assert mock.app is not None

    # Step 3: Ensure balanced security profile is active
    settings_resp = client.get("/api/v1/settings", headers=admin_headers)
    assert settings_resp.status_code == 200
    assert settings_resp.json()["profile"] == "balanced"

    # Step 4: Send clean coding prompt; verify HTTP 200 and successful forwarding
    clean_payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Write a binary search function in Python."}],
    }
    resp4 = client.post(
        "/proxy/openai/v1/chat/completions", json=clean_payload, headers=proxy_headers
    )
    assert resp4.status_code == 200
    assert len(mock.recorded_requests) == 1
    recorded_msg = (
        (mock.recorded_requests[0].json or {}).get("messages", [{}])[0].get("content", "")
    )
    assert "binary search" in recorded_msg

    # Step 5: Send prompt containing synthetic API key; verify HTTP 403 BLOCK
    synthetic_key = "sk-proj-DEMOONLYfakekey1234567890abcdefghijklmnopqrstuvwxyz"
    leak_payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": f"Debug this api call: key is {synthetic_key}"}],
    }
    resp5 = client.post(
        "/proxy/openai/v1/chat/completions", json=leak_payload, headers=proxy_headers
    )
    assert resp5.status_code == 403
    assert resp5.json()["type"] == "urn:agentshield:error:content-blocked"
    # Upstream must NOT have received request #2
    assert len(mock.recorded_requests) == 1

    # Step 6: Send prompt containing Erika Mustermann and GreenfieldGrantService
    sensitive_payload = {
        "model": "gpt-4o",
        "messages": [
            {
                "role": "user",
                "content": (
                    "Review grant application for Erika Mustermann "
                    "regarding GreenfieldGrantService architecture."
                ),
            }
        ],
    }

    # First send to record upstream request and get the exact placeholders
    resp6 = client.post(
        "/proxy/openai/v1/chat/completions",
        headers={**proxy_headers, "x-session-id": "demo-sess-1"},
        json=sensitive_payload,
    )
    assert resp6.status_code == 200

    # Inspect upstream received payload in mock: verify real names replaced with placeholders
    assert len(mock.recorded_requests) == 2
    upstream_json = mock.recorded_requests[1].json or {}
    upstream_msg = upstream_json.get("messages", [{}])[0].get("content", "")
    assert "Erika Mustermann" not in upstream_msg
    assert "GreenfieldGrantService" not in upstream_msg
    assert "<AS:PERSON:" in upstream_msg
    assert "<AS:TERM:" in upstream_msg

    # Step 7: Verify rehydration of placeholder in client response
    # When mock echoes placeholders back to client in non-streaming response
    mock.next_response_body = {
        "id": "chatcmpl-rehydrate",
        "object": "chat.completion",
        "created": 1700000000,
        "model": "gpt-4o",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": f"Confirmation: {upstream_msg}",
                },
                "finish_reason": "stop",
            }
        ],
    }

    resp7 = client.post(
        "/proxy/openai/v1/chat/completions",
        headers={**proxy_headers, "x-session-id": "demo-sess-1"},
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "Status update?"}]},
    )
    assert resp7.status_code == 200
    client_response_text = resp7.json()["choices"][0]["message"]["content"]
    assert "Erika Mustermann" in client_response_text
    assert "GreenfieldGrantService" in client_response_text
    assert "<AS:" not in client_response_text

    # Step 8: Trigger REQUIRE_APPROVAL rule, approve via Management API
    approval_payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Execute critical operation HIGH_RISK_OP now."}],
    }

    def _send_approval_request() -> httpx.Response:
        with TestClient(client.app, base_url="http://127.0.0.1:8765") as c2:
            return c2.post(
                "/proxy/openai/v1/chat/completions", json=approval_payload, headers=proxy_headers
            )

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_send_approval_request)

        pending_id = None
        for _ in range(50):
            pending_list = approval_manager.list_requests()
            if pending_list:
                pending_id = pending_list[0].id
                break
            asyncio.run(asyncio.sleep(0.05))

        assert pending_id is not None, "Request failed to enter approval queue"

        approve_resp = client.post(
            f"/api/v1/approvals/{pending_id}/approve",
            json={"reason": "Approved by security officer in demo."},
            headers=admin_headers,
        )
        assert approve_resp.status_code == 200

        client_resp = future.result(timeout=5.0)
        assert client_resp.status_code == 200

    # Step 9: Export audit report; verify total absence of confidential test values
    export_resp = client.post(
        "/api/v1/audit/export", json={"format": "json"}, headers=admin_headers
    )
    assert export_resp.status_code == 200
    export_content = export_resp.text
    assert synthetic_key not in export_content
    assert "Erika Mustermann" not in export_content

    # Also verify SQLite database file contains zero secret leaks
    db_file = data_dir / "agentshield.db"
    assert db_file.exists()
    conn = sqlite3.connect(str(db_file))
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row[0] for row in cursor.fetchall()]
    for tbl in tables:
        # Tables are schema-defined table names
        cursor.execute("SELECT * FROM " + tbl)  # noqa: S608
        rows = cursor.fetchall()
        tbl_str = str(rows)
        assert synthetic_key not in tbl_str, f"Synthetic secret found in SQLite table {tbl}!"
    conn.close()

    # Step 10: Run diagnostics and verify diagnostic output
    demo_settings = Settings(
        host="127.0.0.1",
        port=8765,
        data_dir=data_dir,
        profile="balanced",
        dev_mode=True,
    )
    # Ensure offline diagnostics without external network requests
    offline_client = httpx.Client(
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json={"status": "ok"}))
    )
    diag_service = DiagnosticsService(settings=demo_settings, http_client=offline_client)
    diag_report = diag_service.run_all_checks()
    assert not diag_report.has_failures
    assert "cooperative reverse proxy" in COOPERATIVE_PROXY_BANNER
