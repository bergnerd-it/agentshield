"""Tests for health, status, and static frontend endpoints."""

from fastapi.testclient import TestClient

from agentshield import __version__


def test_health_liveness_endpoint(client: TestClient) -> None:
    """Verify /health returns HTTP 200 with status ok."""
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_system_status_endpoint_security_invariants(client: TestClient) -> None:
    """Verify /api/v1/status returns diagnostic data without leaking credentials or tokens."""
    resp = client.get("/api/v1/status")
    assert resp.status_code == 200

    data = resp.json()
    assert data["status"] == "ready"
    assert data["version"] == __version__
    assert data["profile"] == "balanced"
    assert data["host"] == "127.0.0.1"
    assert data["port"] == 8765
    assert data["database"]["status"] == "connected"
    assert data["database"]["migration_version"] == "0001_baseline_schema"

    # Crucial security invariants: no tokens, secrets, or credential paths in response body
    body_str = resp.text.lower()
    assert "as_adm_" not in body_str
    assert "as_prx_" not in body_str
    assert "sk-" not in body_str
    assert "token" not in data  # No top-level token fields


def test_static_frontend_serving(client: TestClient) -> None:
    """Verify root GET / returns SPA HTML content."""
    resp = client.get("/")
    assert resp.status_code == 200
    assert "AgentShield" in resp.text
