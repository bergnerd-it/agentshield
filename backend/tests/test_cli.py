"""Tests for CLI entrypoint commands (start and doctor)."""

import pytest
from typer.testing import CliRunner

from agentshield.cli import app
from agentshield.core.config import Settings

runner = CliRunner()


def test_cli_doctor_command(
    test_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify 'agentshield doctor' runs diagnostics and exits cleanly."""

    def port_is_available(_host: str, _port: int) -> bool:
        return False

    monkeypatch.setattr("agentshield.cli.is_port_in_use", port_is_available)
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "System Diagnostics" in result.stdout
    assert "All core systems diagnostic checks passed" in result.stdout


def test_cli_start_non_loopback_host_fails() -> None:
    """Verify 'agentshield start' rejects non-loopback bindings like 0.0.0.0."""
    result = runner.invoke(app, ["start", "--host", "0.0.0.0"])
    assert result.exit_code == 1
    assert "not a local loopback interface" in result.stderr
