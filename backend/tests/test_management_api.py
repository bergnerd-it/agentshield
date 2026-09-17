"""Tests for control plane Management APIs: approvals, events, policies, detectors, settings."""

import json

import pytest
from fastapi.testclient import TestClient

from agentshield.api.app import create_app
from agentshield.api.dependencies import get_approval_manager, reset_approval_manager
from agentshield.approvals.manager import ApprovalManager
from agentshield.approvals.models import FindingSummary
from agentshield.core.auth import get_or_create_admin_token, get_or_create_proxy_token
from agentshield.core.config import Settings
from agentshield.persistence.models import AuditEvent
from agentshield.persistence.repository import AuditRepository


@pytest.fixture
def mgmt_client(test_settings: Settings) -> tuple[TestClient, str, str, ApprovalManager]:
    admin_token = get_or_create_admin_token(test_settings.effective_admin_token_path)
    proxy_token = get_or_create_proxy_token(test_settings.effective_proxy_token_path)
    manager = ApprovalManager()
    reset_approval_manager(manager)

    app = create_app(test_settings)
    app.dependency_overrides[get_approval_manager] = lambda: manager
    client = TestClient(app, base_url="http://127.0.0.1:8765")
    return client, admin_token, proxy_token, manager


def test_management_api_auth_separation(
    mgmt_client: tuple[TestClient, str, str, ApprovalManager],
) -> None:
    """Security Invariant: Management APIs require admin token, rejecting proxy tokens."""
    client, admin_token, proxy_token, _ = mgmt_client

    endpoints = [
        "/api/v1/approvals",
        "/api/v1/events",
        "/api/v1/policies",
        "/api/v1/detectors",
        "/api/v1/settings",
    ]

    for ep in endpoints:
        # 1. No token -> 401
        res_no_auth = client.get(ep)
        assert res_no_auth.status_code == 401, f"{ep} allowed unauthenticated access"

        # 2. Proxy token -> 401
        res_proxy_auth = client.get(ep, headers={"Authorization": f"Bearer {proxy_token}"})
        assert res_proxy_auth.status_code == 401, f"{ep} allowed proxy token access"

        # 3. Admin token -> 200
        res_admin_auth = client.get(ep, headers={"Authorization": f"Bearer {admin_token}"})
        assert res_admin_auth.status_code == 200, f"{ep} failed: {res_admin_auth.status_code}"


def test_approvals_api_workflow(
    mgmt_client: tuple[TestClient, str, str, ApprovalManager],
) -> None:
    """Test approvals listing, details, masking, and decision actions."""
    client, admin_token, _, manager = mgmt_client
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Populate a test hold
    finding = FindingSummary(
        category="PII_EMAIL",
        severity="HIGH",
        detector_id="structured-pii",
        message="Email detected",
        path=("messages", 0, "content"),
        start_offset=10,
        end_offset=25,
        fingerprint="fp12345",
    )
    req = manager.create_request(
        request_fingerprint="sha256-fingerprint-test",
        policy_version="v1.0",
        provider="openai",
        model="gpt-4o",
        endpoint="/v1/chat/completions",
        findings=(finding,),
        timeout_seconds=60.0,
        raw_payload_masked={"messages": [{"role": "user", "content": "Contact alice@example.com"}]},
        redacted_payload={"messages": [{"role": "user", "content": "Contact <AS:PII:1234>"}]},
    )

    # List approvals
    res = client.get("/api/v1/approvals", headers=headers)
    assert res.status_code == 200
    items = res.json()
    assert len(items) == 1
    assert items[0]["id"] == req.id
    assert items[0]["finding_count"] == 1
    assert items[0]["status"] == "pending"

    # Get approval details
    detail_res = client.get(f"/api/v1/approvals/{req.id}", headers=headers)
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["id"] == req.id
    assert detail["diff_available"] is True
    assert len(detail["findings"]) == 1
    assert detail["findings"][0]["category"] == "PII_EMAIL"

    # Approve request
    approve_res = client.post(
        f"/api/v1/approvals/{req.id}/approve",
        headers=headers,
        json={"reason": "Approved by auditor"},
    )
    assert approve_res.status_code == 200
    assert approve_res.json()["status"] == "approved"

    # Re-approving fails with 409 Conflict
    conflict_res = client.post(
        f"/api/v1/approvals/{req.id}/approve",
        headers=headers,
        json={"reason": "Repeat"},
    )
    assert conflict_res.status_code == 409


def test_events_api_pagination_and_filtering(
    mgmt_client: tuple[TestClient, str, str, ApprovalManager],
    test_settings: Settings,
) -> None:
    """Test events pagination and filtering."""
    client, admin_token, _, _ = mgmt_client
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Record some audit events in db
    from agentshield.persistence.db import get_db_session

    with get_db_session() as session:
        repo = AuditRepository(session)
        for i in range(5):
            repo.record_event(
                AuditEvent(
                    id=f"evt-{i}",
                    request_id=f"req-{i}",
                    provider="openai" if i % 2 == 0 else "anthropic",
                    endpoint="/v1/chat/completions",
                    direction="REQUEST",
                    action="ALLOW" if i % 2 == 0 else "BLOCK",
                    agent="agent-alpha" if i < 3 else "agent-beta",
                    project="project-x",
                    finding_counts_json=json.dumps({"PII_EMAIL": 1}),
                    metadata_json=json.dumps({"latency_ms": 12.5}),
                )
            )

    # Test list all
    res = client.get("/api/v1/events?limit=10", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 5
    assert len(data["items"]) == 5

    # Filter by action=BLOCK
    res_block = client.get("/api/v1/events?action=BLOCK", headers=headers)
    assert res_block.status_code == 200
    assert res_block.json()["total"] == 2

    # Filter by agent=agent-beta
    res_agent = client.get("/api/v1/events?agent=agent-beta", headers=headers)
    assert res_agent.status_code == 200
    assert res_agent.json()["total"] == 2

    # Single event detail
    single = client.get("/api/v1/events/evt-0", headers=headers)
    assert single.status_code == 200
    assert single.json()["id"] == "evt-0"
    assert single.json()["metadata"]["latency_ms"] == 12.5


def test_policies_and_detectors_api(
    mgmt_client: tuple[TestClient, str, str, ApprovalManager],
) -> None:
    """Test policy inspection, creation, updates, and detector catalog."""
    client, admin_token, _, _ = mgmt_client
    headers = {"Authorization": f"Bearer {admin_token}"}

    # List policies
    res = client.get("/api/v1/policies", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "effective_precedence" in data
    assert data["effective_precedence"] == ["BLOCK", "REQUIRE_APPROVAL", "REDACT", "WARN", "ALLOW"]

    # Create policy
    create_res = client.post(
        "/api/v1/policies",
        headers=headers,
        json={
            "name": "Strict Corporate Policy",
            "profile": "strict",
            "version": "v1.2",
            "is_active": True,
            "rules": [
                {
                    "id": "require-approval-custom",
                    "action": "REQUIRE_APPROVAL",
                    "priority": 10,
                    "category": "CUSTOM_TERM",
                }
            ],
        },
    )
    assert create_res.status_code == 200
    created = create_res.json()
    assert created["name"] == "Strict Corporate Policy"
    assert len(created["rules"]) == 1
    assert created["rules"][0]["action"] == "REQUIRE_APPROVAL"

    # Update policy
    update_res = client.put(
        f"/api/v1/policies/{created['id']}",
        headers=headers,
        json={"is_active": False},
    )
    assert update_res.status_code == 200
    assert update_res.json()["is_active"] is False

    # List detectors
    det_res = client.get("/api/v1/detectors", headers=headers)
    assert det_res.status_code == 200
    detectors = det_res.json()["detectors"]
    detector_ids = {d["id"] for d in detectors}
    assert "secret-patterns" in detector_ids
    assert "structured-pii" in detector_ids
    assert "custom-terms" in detector_ids


def test_settings_api_safe_inspection(
    mgmt_client: tuple[TestClient, str, str, ApprovalManager],
) -> None:
    """Test settings retrieval, ensuring credentials are never returned."""
    client, admin_token, _, _ = mgmt_client
    headers = {"Authorization": f"Bearer {admin_token}"}

    res = client.get("/api/v1/settings", headers=headers)
    assert res.status_code == 200
    data = res.json()

    # Verify no credentials in response
    serialized = json.dumps(data)
    assert "sk-" not in serialized
    assert "api_key" not in data
    assert "admin_token" not in data
    assert "proxy_token" not in data

    # Verify fields
    assert "profile" in data
    assert "protection_limits" in data
    assert len(data["protection_limits"]) > 0

    # Update settings
    put_res = client.put(
        "/api/v1/settings",
        headers=headers,
        json={"profile": "strict", "approval_timeout_seconds": 120.0},
    )
    assert put_res.status_code == 200
    updated = put_res.json()
    assert updated["profile"] == "strict"
    assert updated["approval_timeout_seconds"] == 120.0
