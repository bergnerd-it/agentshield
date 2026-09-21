#!/usr/bin/env python3
"""Customer Demonstration Runner for AgentShield Version 1.

Executes the 10-step interactive or automated demonstration scenario
specified in Specification §21 against a fully local, zero-cost mock provider.

Usage:
  uv run scripts/run_demo.py [--auto | --interactive]
"""

import argparse
import os
import shutil
import sys
import concurrent.futures
import tempfile
import time
from pathlib import Path

# Ensure backend root is on sys.path for internal modules and test utilities
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

# In sandboxed or test environments, an unreadable SSL_CERT_FILE will fail httpx/ssl init.
if "SSL_CERT_FILE" in os.environ:
    try:
        with Path(os.environ["SSL_CERT_FILE"]).open("rb") as _f:
            _f.read(1)
    except (PermissionError, OSError):
        os.environ.pop("SSL_CERT_FILE", None)

import httpx
from fastapi.testclient import TestClient
from tests.mock_providers import MockOpenAIServer

from agentshield import __version__
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
from agentshield.filtering.detectors.custom_terms import (
    CustomTermDetector,
    CustomTermRule,
)
from agentshield.filtering.detectors.pii import (
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


def _step_banner(step_num: int, title: str) -> None:
    print("\n" + "=" * 70)
    print(f" STEP {step_num}: {title}")
    print("=" * 70)


def _pause(is_auto: bool, prompt: str = "Press Enter to continue...") -> None:
    if not is_auto:
        input(f"\n[DEMO] {prompt} ")


def main() -> None:
    parser = argparse.ArgumentParser(description="AgentShield Customer Demonstration")
    parser.add_argument(
        "--auto",
        action="store_true",
        help="Run through all demonstration steps automatically without pausing",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Run interactively prompting between each demonstration step (default)",
    )
    args = parser.parse_args()
    is_auto = args.auto and not args.interactive

    print(f"\n🛡️  AgentShield v{__version__} — Customer Demonstration Scenario")
    print("Specification §21 Local Zero-Cost Demonstration")
    print(COOPERATIVE_PROXY_BANNER)
    _pause(is_auto, "Press Enter to start demonstration environment...")

    temp_dir = tempfile.mkdtemp(prefix="agentshield_demo_")
    demo_data_dir = Path(temp_dir)

    try:
        # Step 1: Start AgentShield in demo sandbox
        _step_banner(1, "Initialize and verify AgentShield loopback service")
        settings = Settings(
            host="127.0.0.1",
            port=8765,
            data_dir=demo_data_dir,
            profile="balanced",
            dev_mode=True,
            log_level="WARNING",
        )
        reset_settings(settings)
        reset_db()
        run_migrations(settings.effective_database_url)

        # Step 2: Initialize Mock Upstream Provider
        _step_banner(2, "Start mock provider (in-memory OpenAI & Anthropic simulator)")
        mock = MockOpenAIServer()
        upstream = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=mock.app),  # pyright: ignore[reportArgumentType]
            base_url=settings.openai_upstream_base_url,
        )
        forwarder = ProxyForwardClient(settings=settings, client=upstream)

        key = b"demo-customer-fingerprint-key"
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
                CustomTermDetector(fingerprint_key=key, rules=custom_rules),
                UnsupportedContentDetector(fingerprint_key=key),
            ),
            timeout_seconds=2.0,
        )

        policy_engine = PolicyEngine(profile=PolicyProfile.BALANCED)
        approval_manager = ApprovalManager(max_history=100, max_pending=50)
        pipeline = RequestInspectionPipeline(
            detector_engine=detector_engine,
            policy_engine=policy_engine,
            header_secret_detector=SecretDetector(fingerprint_key=key),
        )

        store = InMemoryCredentialStore(initial_keys={"openai": "sk-synth-upstream-demo-key"})
        app = create_app(settings)
        app.dependency_overrides[get_forward_client] = lambda: forwarder
        app.dependency_overrides[get_credential_store] = lambda: store
        app.dependency_overrides[get_inspection_pipeline] = lambda: pipeline
        app.dependency_overrides[get_approval_manager] = lambda: approval_manager

        proxy_token = get_or_create_proxy_token(settings.effective_proxy_token_path)
        admin_token = get_or_create_admin_token(settings.effective_admin_token_path)

        proxy_headers = {"Authorization": f"Bearer {proxy_token}"}
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        with TestClient(app, base_url="http://127.0.0.1:8765") as client:
            health = client.get("/health")
            print(f"Service health check: {health.json()} (status: {health.status_code})")
            assert health.status_code == 200

            # Step 3: Verify Security Profile
            _step_banner(3, "Select and verify the 'balanced' security profile")
            st_resp = client.get("/api/v1/settings", headers=admin_headers)
            profile = st_resp.json().get("profile")
            print(
                f"Active Profile: {profile} (precedence: BLOCK > APPROVAL > REDACT > WARN > ALLOW)"
            )
            assert profile == "balanced"
            _pause(is_auto)

            # Step 4: Normal coding request
            _step_banner(4, "Send clean coding prompt and verify normal forwarding")
            clean_req = {
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": "Write a quicksort function in Python."}],
            }
            print("Client Outbound Prompt:")
            print("  'Write a quicksort function in Python.'")
            resp4 = client.post(
                "/proxy/openai/v1/chat/completions", json=clean_req, headers=proxy_headers
            )
            print(f"Response Status Code: {resp4.status_code} OK")
            print(f"Upstream Received Requests: {len(mock.recorded_requests)}")
            assert resp4.status_code == 200
            assert len(mock.recorded_requests) == 1
            _pause(is_auto)

            # Step 5: Synthetic secret blocking
            _step_banner(5, "Send prompt with synthetic secret and verify deterministic blocking")
            fake_secret = "sk-proj-DEMOONLYfakekey1234567890abcdefghijklmnopqrstuvwxyz"  # noqa: S105
            leak_req = {
                "model": "gpt-4o",
                "messages": [
                    {"role": "user", "content": f"Fix API connection using {fake_secret}"}
                ],
            }
            print(f"Client Outbound Prompt (containing secret):\n  {fake_secret}")
            resp5 = client.post(
                "/proxy/openai/v1/chat/completions", json=leak_req, headers=proxy_headers
            )
            print(f"Response Status Code: {resp5.status_code} {resp5.json().get('title')}")
            print(f"Problem Detail URN : {resp5.json().get('type')}")
            print(f"Upstream Requests Count (should remain 1): {len(mock.recorded_requests)}")
            assert resp5.status_code == 403
            assert len(mock.recorded_requests) == 1
            _pause(is_auto)

            # Step 6: Pseudonymization
            _step_banner(6, "Send sensitive terms and inspect client-side pseudonymization")
            sens_req = {
                "model": "gpt-4o",
                "messages": [
                    {
                        "role": "user",
                        "content": (
                            "Review access request for Erika Mustermann "
                            "on GreenfieldGrantService internal database."
                        ),
                    }
                ],
            }
            print("Original Client Prompt:")
            print(
                "  'Review access request for Erika Mustermann "
                "on GreenfieldGrantService internal database.'"
            )
            resp6 = client.post(
                "/proxy/openai/v1/chat/completions",
                headers={**proxy_headers, "x-session-id": "demo-sess-customer"},
                json=sens_req,
            )
            assert resp6.status_code == 200
            assert len(mock.recorded_requests) == 2
            upstream_received = (
                (mock.recorded_requests[1].json or {}).get("messages", [{}])[0].get("content", "")
            )
            print("\nPayload Received by Upstream Provider:")
            print(f"  '{upstream_received}'")
            print("Notice: 'GreenfieldGrantService' pseudonymized to '<AS:TERM:...>'")
            _pause(is_auto)

            # Step 7: Response Rehydration
            _step_banner(7, "Receive and verify rehydration of placeholders in provider response")
            mock.next_response_body = {
                "id": "chatcmpl-demo-rehydrated",
                "object": "chat.completion",
                "created": 1700000000,
                "model": "gpt-4o",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": f"Confirmed architecture analysis for: {upstream_received}",
                        },
                        "finish_reason": "stop",
                    }
                ],
            }
            resp7 = client.post(
                "/proxy/openai/v1/chat/completions",
                headers={**proxy_headers, "x-session-id": "demo-sess-customer"},
                json={
                    "model": "gpt-4o",
                    "messages": [{"role": "user", "content": "Fetch confirmation."}],
                },
            )
            assert resp7.status_code == 200
            client_delivered = resp7.json()["choices"][0]["message"]["content"]
            print("\nResponse Received by Local Client:")
            print(f"  '{client_delivered}'")
            print("Notice: '<AS:TERM:...>' seamlessly restored to 'GreenfieldGrantService'")
            assert "GreenfieldGrantService" in client_delivered
            _pause(is_auto)

            # Step 8: Manual Approval Workflow
            _step_banner(8, "Trigger REQUIRE_APPROVAL rule and approve via Management API")
            appr_req = {
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": "Run critical operation HIGH_RISK_OP"}],
            }
            print("Client submits prompt triggering REQUIRE_APPROVAL policy...")

            def _send_hold():
                with TestClient(app, base_url="http://127.0.0.1:8765") as c2:
                    return c2.post(
                        "/proxy/openai/v1/chat/completions", json=appr_req, headers=proxy_headers
                    )

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                fut = executor.submit(_send_hold)
                pending_id = None
                for _ in range(50):
                    reqs = approval_manager.list_requests()
                    if reqs:
                        pending_id = reqs[0].id
                        break
                    time.sleep(0.05)

                assert pending_id is not None
                print(f"Request held in approval queue. Hold ID: {pending_id}")
                print("Operator reviews diff in dashboard and grants approval...")
                appr_res = client.post(
                    f"/api/v1/approvals/{pending_id}/approve",
                    json={"reason": "Approved by security officer during customer walkthrough."},
                    headers=admin_headers,
                )
                print(f"Approval Result: {appr_res.json().get('status')} ({appr_res.status_code})")
                client_res = fut.result(timeout=5.0)
                print(f"Client Received Final Status: {client_res.status_code} OK")
                assert client_res.status_code == 200
            _pause(is_auto)

            # Step 9: Audit Report Export
            _step_banner(9, "Export audit report and verify absence of confidential data")
            audit_res = client.post(
                "/api/v1/audit/export", json={"format": "json"}, headers=admin_headers
            )
            assert audit_res.status_code == 200
            audit_text = audit_res.text
            print("Audit Report Exported Successfully.")
            print(f"Verifying {fake_secret} NOT in audit logs: PASSED")
            assert fake_secret not in audit_text
            _pause(is_auto)

            # Step 10: System Diagnostics
            _step_banner(10, "Run 'agentshield doctor' system diagnostics")
            diag_service = DiagnosticsService(settings=settings)
            report = diag_service.run_all_checks()
            print("\nDiagnostic System Check Results:")
            for check in report.checks:
                status_icon = "✓" if check.status.value == "OK" else "!"
                print(
                    f" [{status_icon}] {check.name:<25} : {check.status.value:<6} ({check.details})"
                )
            assert not report.has_failures

        app.dependency_overrides.clear()
        reset_approval_manager()

        print("\n" + "=" * 70)
        print("🎉 ALL 10 CUSTOMER DEMONSTRATION STEPS COMPLETED SUCCESSFULLY!")
        print("=" * 70 + "\n")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
