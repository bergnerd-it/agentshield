"""Tests for system diagnostics and agentshield doctor CLI command."""

from pathlib import Path

import httpx
from typer.testing import CliRunner

from agentshield.cli import app
from agentshield.core.config import Settings
from agentshield.core.credentials import CredentialStore
from agentshield.core.diagnostics import (
    DiagnosticCheckResult,
    DiagnosticReport,
    DiagnosticsService,
    DiagnosticStatus,
)

runner = CliRunner()


class MockCredentialStore(CredentialStore):
    """Test credential store returning configured synthetic credentials."""

    def __init__(self, creds: dict[str, str] | None = None) -> None:
        self.creds = creds or {}

    def get_provider_key(self, provider: str) -> str | None:
        return self.creds.get(provider)

    def set_provider_key(self, provider: str, key: str) -> None:
        self.creds[provider] = key

    def delete_provider_key(self, provider: str) -> None:
        self.creds.pop(provider, None)


def test_diagnostics_service_all_12_checks(temp_data_dir: Path, test_settings: Settings) -> None:
    """Test that all 12 checks from Specification §17.2 execute and produce valid statuses."""
    mock_store = MockCredentialStore({"openai": "sk-synth-test", "anthropic": "sk-ant-test"})

    # Mock reachability client that simulates offline / air-gapped dev
    def mock_transport(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Network unreachable in mock")

    mock_client = httpx.Client(transport=httpx.MockTransport(mock_transport))

    service = DiagnosticsService(
        settings=test_settings,
        credential_store=mock_store,
        http_client=mock_client,
    )
    report = service.run_all_checks()

    assert len(report.checks) == 12
    check_names = {c.name for c in report.checks}
    assert "Python Runtime" in check_names
    assert "Data Directory" in check_names
    assert "SQLite Database" in check_names
    assert "Default Port (8765)" in check_names
    assert "Local Auth Tokens" in check_names
    assert "Credential Store" in check_names
    assert "Provider Credentials" in check_names
    assert "Agent Configurations" in check_names
    assert "Upstream Reachability" in check_names
    assert "Loop Detection Guard" in check_names
    assert "Frontend SPA Bundle" in check_names
    assert "Security Profile" in check_names

    # Check 9: Upstream reachability must report WARN when offline, NOT FAIL
    reachability_check = next(c for c in report.checks if c.name == "Upstream Reachability")
    assert reachability_check.status == DiagnosticStatus.WARN
    assert "unreachable" in reachability_check.details

    # Check 7: Provider credentials should report present without leaking secrets
    cred_check = next(c for c in report.checks if c.name == "Provider Credentials")
    assert cred_check.status == DiagnosticStatus.OK
    assert "sk-synth-test" not in cred_check.details
    assert "sk-ant-test" not in cred_check.details
    assert "OpenAI: present" in cred_check.details


def test_diagnostics_service_missing_credentials(
    temp_data_dir: Path, test_settings: Settings
) -> None:
    """Test that absent upstream credentials report WARN rather than FAIL."""
    mock_store = MockCredentialStore({})
    service = DiagnosticsService(settings=test_settings, credential_store=mock_store)
    res = service.check_upstream_credentials()
    assert res.status == DiagnosticStatus.WARN
    assert "No upstream credentials" in res.details


def test_diagnostics_report_has_failures() -> None:
    """Test has_failures property on DiagnosticReport."""
    ok_report = DiagnosticReport(
        checks=[
            DiagnosticCheckResult("A", DiagnosticStatus.OK, "ok"),
            DiagnosticCheckResult("B", DiagnosticStatus.WARN, "warning"),
        ]
    )
    assert not ok_report.has_failures

    fail_report = DiagnosticReport(
        checks=[
            DiagnosticCheckResult("A", DiagnosticStatus.OK, "ok"),
            DiagnosticCheckResult("B", DiagnosticStatus.FAIL, "critical failure"),
        ]
    )
    assert fail_report.has_failures


def test_cli_doctor_output_banner(temp_data_dir: Path, test_settings: Settings) -> None:
    """Test that 'agentshield doctor' prints the mandatory cooperative proxy warning banner."""
    result = runner.invoke(app, ["doctor"])
    assert "cooperative reverse proxy" in result.output
    assert "X-AgentShield-Loop-Detect" in result.output or "System Diagnostics" in result.output
