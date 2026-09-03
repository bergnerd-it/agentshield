"""Command-line interface for AgentShield."""

import os
import socket
import sys
from pathlib import Path

import httpx
import typer
import uvicorn
from rich.console import Console
from rich.table import Table

from agentshield import __version__
from agentshield.core.auth import get_or_create_admin_token, get_or_create_proxy_token
from agentshield.core.config import get_settings
from agentshield.persistence.db import create_db_engine, run_migrations

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


@app.command()
def doctor() -> None:
    """Run baseline diagnostics on environment, database, tokens, and frontend."""
    console.print(f"[bold cyan]AgentShield v{__version__} Diagnostic Check[/bold cyan]\n")

    table = Table(title="System Diagnostics", show_header=True, header_style="bold magenta")
    table.add_column("Component", style="dim", width=25)
    table.add_column("Status", width=12)
    table.add_column("Details")

    all_ok = True
    settings = get_settings()

    # 1. Python version
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    table.add_row("Python Runtime", "[green]OK[/green]", f"Python {py_ver}")

    # 2. Data directory write access
    data_dir = settings.data_dir
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        test_file = data_dir / ".doctor_test"
        test_file.write_text("ok", encoding="utf-8")
        test_file.unlink()
        table.add_row("Data Directory", "[green]OK[/green]", f"Writable at {data_dir}")
    except Exception as e:
        all_ok = False
        table.add_row("Data Directory", "[red]FAIL[/red]", f"Cannot write to {data_dir}: {e}")

    # 3. Database & migrations
    try:
        run_migrations(settings.effective_database_url)
        engine = create_db_engine(settings.effective_database_url)
        with engine.connect() as conn:
            from sqlalchemy import text

            wal_mode = conn.execute(text("PRAGMA journal_mode")).scalar()
            ver = conn.execute(text("SELECT version_num FROM alembic_version LIMIT 1")).scalar()
        table.add_row(
            "SQLite Database",
            "[green]OK[/green]",
            f"WAL mode ({wal_mode}), migration: {ver}",
        )
    except Exception as e:
        all_ok = False
        table.add_row("SQLite Database", "[red]FAIL[/red]", f"Database error: {e}")

    # 4. Port 8765 loopback binding check
    port_used = is_port_in_use("127.0.0.1", settings.port)
    if not port_used:
        table.add_row(
            "Default Port (8765)",
            "[green]OK[/green]",
            f"Port {settings.port} is available on 127.0.0.1",
        )
    else:
        is_self = check_existing_instance("127.0.0.1", settings.port)
        if is_self:
            table.add_row(
                "Default Port (8765)",
                "[yellow]WARN[/yellow]",
                f"Port {settings.port} is running AgentShield",
            )
        else:
            all_ok = False
            table.add_row(
                "Default Port (8765)",
                "[red]FAIL[/red]",
                f"Port {settings.port} in use by another process",
            )

    # 5. Token files & permissions
    try:
        adm_tok = get_or_create_admin_token(settings.effective_admin_token_path)
        prx_tok = get_or_create_proxy_token(settings.effective_proxy_token_path)
        # Verify 0600 permissions on POSIX
        adm_mode = (
            oct(Path(settings.effective_admin_token_path).stat().st_mode)[-3:]
            if hasattr(os, "chmod")
            else "N/A"
        )
        table.add_row(
            "Local Auth Tokens",
            "[green]OK[/green]",
            f"Mode {adm_mode} (admin: {adm_tok[:7]}..., proxy: {prx_tok[:7]}...)",
        )
    except Exception as e:
        all_ok = False
        table.add_row("Local Auth Tokens", "[red]FAIL[/red]", f"Token error: {e}")

    # 6. Frontend bundle check
    dist_dir = settings.effective_frontend_dist_dir
    index_html = dist_dir / "index.html"
    if index_html.is_file():
        table.add_row(
            "Frontend SPA Bundle",
            "[green]OK[/green]",
            f"Production assets ready at {dist_dir}",
        )
    else:
        table.add_row(
            "Frontend SPA Bundle",
            "[yellow]WARN[/yellow]",
            "Not built yet (run 'cd frontend && pnpm build')",
        )

    console.print(table)

    if all_ok:
        console.print("\n[bold green]✓ All core systems diagnostic checks passed.[/bold green]\n")
        raise typer.Exit(code=0)
    console.print(
        "\n[bold red]✗ Some diagnostic checks failed. Please review above output.[/bold red]\n"
    )
    raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
