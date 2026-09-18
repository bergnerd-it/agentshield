"""Command-line interface for AgentShield."""

import os
import socket
from pathlib import Path
from typing import Annotated

import httpx
import typer
import uvicorn
from rich.console import Console
from rich.table import Table

from agentshield import __version__
from agentshield.core.config import get_settings
from agentshield.core.diagnostics import DiagnosticsService, DiagnosticStatus
from agentshield.integrations.manager import IntegrationManager
from agentshield.persistence.db import get_db_session

app = typer.Typer(
    name="agentshield",
    help="AgentShield: Local security reverse proxy for coding-agent traffic",
    no_args_is_help=True,
)
console = Console()
err_console = Console(stderr=True)


def is_port_in_use(host: str, port: int) -> bool:
    """Check if a network port is already in use."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        try:
            sock.bind((host, port))
            return False
        except OSError:
            return True


def check_existing_instance(host: str, port: int) -> bool:
    """Check if an existing AgentShield server is running on the host/port."""
    try:
        url = f"http://{host}:{port}/health"
        resp = httpx.get(url, timeout=1.0)
        return resp.status_code == 200 and resp.json().get("status") == "ok"
    except Exception:
        return False


@app.command()
def start(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Loopback interface to bind"),
    port: int = typer.Option(8765, "--port", "-p", help="Port to listen on"),
    profile: str = typer.Option(
        "balanced", "--profile", help="Active security profile (audit, balanced, strict)"
    ),
    dev: bool = typer.Option(False, "--dev", help="Enable hot-reloading development mode"),
) -> None:
    """Start the AgentShield management server and proxy."""
    # Enforce loopback binding invariant
    clean_host = host.strip().lower()
    if clean_host not in ["127.0.0.1", "localhost", "::1"]:
        err_console.print(
            f"[bold red]Error:[/bold red] Host '{host}' is not a local loopback interface. "
            f"AgentShield strictly binds to loopback (127.0.0.1) for local security."
        )
        raise typer.Exit(code=1)

    # Check port collision
    if is_port_in_use(clean_host, port):
        is_agentshield = check_existing_instance(clean_host, port)
        if is_agentshield:
            msg = (
                f"[bold yellow]Warning:[/bold yellow] "
                f"AgentShield is already running on http://{clean_host}:{port}\n"
                f"Use running instance or run with [bold]--port <PORT>[/bold] for another port."
            )
            err_console.print(msg)
        else:
            msg = (
                f"[bold red]Error:[/bold red] "
                f"Port {port} on {clean_host} is in use by another process.\n"
                f"Choose a different port via [bold]--port <PORT>[/bold] "
                f"or stop conflicting service."
            )
            err_console.print(msg)
        raise typer.Exit(code=1)

    # Apply configuration overrides to environment for uvicorn workers
    os.environ["AGENTSHIELD_HOST"] = clean_host
    os.environ["AGENTSHIELD_PORT"] = str(port)
    os.environ["AGENTSHIELD_PROFILE"] = profile
    if dev:
        os.environ["AGENTSHIELD_DEV_MODE"] = "true"

    settings = get_settings()
    settings.host = clean_host
    settings.port = port
    settings.profile = profile  # pyright: ignore[reportAttributeAccessIssue]

    console.print(f"[bold green]🛡️ Starting AgentShield v{__version__}[/bold green]")
    console.print(f" • Bound interface : [cyan]http://{clean_host}:{port}[/cyan]")
    console.print(f" • Security profile: [cyan]{profile}[/cyan]")
    console.print(f" • Data directory  : [cyan]{settings.data_dir}[/cyan]")

    uvicorn.run(
        "agentshield.main:app",
        host=clean_host,
        port=port,
        reload=dev,
        log_level="info",
    )


COOPERATIVE_PROXY_BANNER = (
    "[bold yellow]⚠️  Notice: AgentShield Version 1 is a cooperative reverse proxy.\n"
    "It inspects only traffic explicitly routed through its loopback endpoints.\n"
    "Direct network requests made outside the proxy are not intercepted or blocked.[/bold yellow]"
)


@app.command()
def doctor() -> None:
    """Run comprehensive diagnostics implementing Specification §17.2 checks."""
    console.print(COOPERATIVE_PROXY_BANNER)
    console.print(f"\n[bold cyan]AgentShield v{__version__} System Diagnostics[/bold cyan]\n")

    settings = get_settings()
    service = DiagnosticsService(settings=settings)
    report = service.run_all_checks()

    table = Table(title="System Diagnostics (§17.2)", show_header=True, header_style="bold magenta")
    table.add_column("Component", style="dim", width=25)
    table.add_column("Status", width=12)
    table.add_column("Details")

    for check in report.checks:
        if check.status == DiagnosticStatus.OK:
            status_str = "[green]OK[/green]"
        elif check.status == DiagnosticStatus.WARN:
            status_str = "[yellow]WARN[/yellow]"
        else:
            status_str = "[red]FAIL[/red]"
        table.add_row(check.name, status_str, check.details)

    console.print(table)

    if not report.has_failures:
        console.print("\n[bold green]✓ All core systems diagnostic checks passed.[/bold green]\n")
        raise typer.Exit(code=0)

    console.print(
        "\n[bold red]✗ Some diagnostic checks failed. Please review above output.[/bold red]\n"
    )
    raise typer.Exit(code=1)


configure_app = typer.Typer(name="configure", help="Configure coding-agent integrations")
rollback_app = typer.Typer(name="rollback", help="Rollback coding-agent integrations")


@configure_app.command("codex")
def configure_codex(
    preview: Annotated[
        bool, typer.Option("--preview", help="Preview configuration diff without applying changes")
    ] = False,
    path: Annotated[
        Path | None, typer.Option("--path", help="Custom configuration file path")
    ] = None,
) -> None:
    """Configure OpenAI Codex CLI to route traffic through AgentShield."""
    _run_configure("codex", preview=preview, config_path=path)


@configure_app.command("claude-code")
def configure_claude_code(
    preview: Annotated[
        bool, typer.Option("--preview", help="Preview configuration diff without applying changes")
    ] = False,
    path: Annotated[
        Path | None, typer.Option("--path", help="Custom configuration file path")
    ] = None,
) -> None:
    """Configure Anthropic Claude Code CLI to route traffic through AgentShield."""
    _run_configure("claude-code", preview=preview, config_path=path)


@rollback_app.command("codex")
def rollback_codex(
    path: Annotated[
        Path | None, typer.Option("--path", help="Custom configuration file path")
    ] = None,
) -> None:
    """Roll back OpenAI Codex CLI configuration to the latest backup."""
    _run_rollback("codex", config_path=path)


@rollback_app.command("claude-code")
def rollback_claude_code(
    path: Annotated[
        Path | None, typer.Option("--path", help="Custom configuration file path")
    ] = None,
) -> None:
    """Roll back Anthropic Claude Code CLI configuration to the latest backup."""
    _run_rollback("claude-code", config_path=path)


def _run_configure(agent: str, preview: bool, config_path: Path | None) -> None:
    settings = get_settings()
    try:
        with get_db_session() as session:
            manager = IntegrationManager(settings=settings, db=session)
            if preview:
                diff = manager.preview(agent, config_path=config_path)
                console.print(
                    f"\n[bold cyan]Planned changes for {agent} ({diff.config_path}):[/bold cyan]\n"
                )
                if not diff.has_changes:
                    console.print("[dim]Configuration is already up to date.[/dim]")
                else:
                    for line in diff.unified_diff.splitlines():
                        if line.startswith("+") and not line.startswith("+++"):
                            console.print(f"[green]{line}[/green]")
                        elif line.startswith("-") and not line.startswith("---"):
                            console.print(f"[red]{line}[/red]")
                        else:
                            console.print(line)
                return

            status = manager.apply(agent, config_path=config_path)
            console.print(
                f"\n[bold green]✓ Successfully configured {agent} integration.[/bold green]"
            )
            console.print(f" • Config path : [cyan]{status.config_path}[/cyan]")
            console.print(f" • Proxy target: [cyan]{status.proxy_url}[/cyan]")
            if status.last_backup_path:
                console.print(f" • Backup file : [dim]{status.last_backup_path}[/dim]")
            console.print()
    except Exception as e:
        err_console.print(f"[bold red]Error configuring {agent}:[/bold red] {e}")
        raise typer.Exit(code=1) from None


def _run_rollback(agent: str, config_path: Path | None) -> None:
    settings = get_settings()
    try:
        with get_db_session() as session:
            manager = IntegrationManager(settings=settings, db=session)
            status = manager.rollback(agent, config_path=config_path)
            console.print(
                f"\n[bold green]✓ Successfully rolled back {agent} configuration.[/bold green]"
            )
            console.print(f" • Restored path: [cyan]{status.config_path}[/cyan]\n")
    except Exception as e:
        err_console.print(f"[bold red]Error rolling back {agent}:[/bold red] {e}")
        raise typer.Exit(code=1) from None


app.add_typer(configure_app)
app.add_typer(rollback_app)


if __name__ == "__main__":
    app()
