"""Tests for security middleware: Host validation, Origin/CORS validation, and security headers."""

from fastapi.testclient import TestClient


def test_valid_loopback_hosts(client: TestClient) -> None:
    """Verify loopback Host headers succeed."""
    r1 = client.get("/health", headers={"Host": "127.0.0.1:8765"})
    assert r1.status_code == 200

    r2 = client.get("/health", headers={"Host": "localhost:8765"})
    assert r2.status_code == 200

    r3 = client.get("/health", headers={"Host": "127.0.0.1"})
    assert r3.status_code == 200


def test_invalid_foreign_host_rejected(client: TestClient) -> None:
    """Verify foreign Host headers return 400 Bad Request Problem Details."""
    r = client.get("/health", headers={"Host": "attacker.com"})
    assert r.status_code == 400
    assert r.headers["Content-Type"] == "application/problem+json"
    body = r.json()
    assert body["type"] == "urn:agentshield:error:invalid-host"
    assert "attacker.com" in body["detail"]


def test_cors_allowed_loopback_origin(client: TestClient) -> None:
    """Verify permitted Vite dev server loopback Origin receives CORS headers."""
    # Preflight OPTIONS
    resp = client.options(
        "/api/v1/status",
        headers={
            "Origin": "http://127.0.0.1:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert resp.status_code == 204
    assert resp.headers["Access-Control-Allow-Origin"] == "http://127.0.0.1:5173"
    assert "GET" in resp.headers["Access-Control-Allow-Methods"]

    # Regular GET with Origin
    resp_get = client.get("/health", headers={"Origin": "http://127.0.0.1:5173"})
    assert resp_get.status_code == 200
    assert resp_get.headers["Access-Control-Allow-Origin"] == "http://127.0.0.1:5173"


def test_cors_forbidden_unauthorized_origin(client: TestClient) -> None:
    """Verify unauthorized external origin is rejected and wildcard CORS is never returned."""
    # OPTIONS preflight
    resp_preflight = client.options(
        "/api/v1/status",
        headers={
            "Origin": "http://evil.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert resp_preflight.status_code == 403
    assert resp_preflight.headers["Content-Type"] == "application/problem+json"

    # GET with unauthorized origin
    resp_get = client.get("/health", headers={"Origin": "http://evil.com"})
    assert resp_get.status_code == 403

    # Invariant: Wildcard CORS is never emitted
    allowed_origin_header = resp_get.headers.get("Access-Control-Allow-Origin")
    assert allowed_origin_header != "*"


def test_security_hardening_headers(client: TestClient) -> None:
    """Verify security hardening headers are attached to responses."""
    resp = client.get("/health")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "no-referrer"
    assert "default-src 'self'" in resp.headers["Content-Security-Policy"]

    # API endpoints must include no-store Cache-Control
    resp_api = client.get("/api/v1/status")
    assert "no-store" in resp_api.headers["Cache-Control"]
