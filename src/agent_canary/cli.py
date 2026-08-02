"""Click CLI for Agent Canary."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from .models import Canary, TriggerEvent, Vector
from .registry import Registry

console = Console()

# Optional vector imports — CLI still works without them
try:
    from .vectors.files import plant_file, FileWatcher
except ImportError:
    plant_file = None  # type: ignore[assignment]
    FileWatcher = None  # type: ignore[assignment]

try:
    from .vectors.mcp import create_mcp_server, run_mcp_sse, run_mcp_stdio, default_tripwire_tools
except ImportError:
    create_mcp_server = None  # type: ignore[assignment]
    run_mcp_sse = None  # type: ignore[assignment]
    run_mcp_stdio = None  # type: ignore[assignment]
    default_tripwire_tools = None  # type: ignore[assignment]

try:
    from .vectors.api import create_api_app, default_decoy_endpoints
except ImportError:
    create_api_app = None  # type: ignore[assignment]
    default_decoy_endpoints = None  # type: ignore[assignment]

from .alerts import dispatch_alerts


def _get_registry() -> Registry:
    reg = Registry()
    if not reg.config_dir.exists():
        click.echo("Not initialized. Run 'agent-canary init' first.", err=True)
        raise SystemExit(1)
    return reg


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------

@click.group()
def main() -> None:
    """Agent Canary — tripwire detection for autonomous AI agents."""


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------

@main.command()
def init() -> None:
    """Initialize .agent-canary/ in the current directory."""
    reg = Registry()
    reg.init()
    console.print(f"[green]Initialized[/green] {reg.config_dir}")


# ---------------------------------------------------------------------------
# plant (group)
# ---------------------------------------------------------------------------

@main.group()
def plant() -> None:
    """Plant canary tripwires."""


_NOTICE_HELP = (
    "Soft scope notice for agents: off (default silent), "
    "static (fixed banner), or stochastic (sampled text). "
    "Forensics/measurement only; not a hard control."
)


@plant.command("file")
@click.argument("path")
@click.option("--template", required=True, help="Template name (aws_creds, db_creds, ssh_key, api_keys, pii_data, internal_doc)")
@click.option("--name", default=None, help="Human-readable name for this canary")
@click.option(
    "--notice",
    "notice_mode",
    type=click.Choice(["off", "static", "stochastic"], case_sensitive=False),
    default="off",
    show_default=True,
    help=_NOTICE_HELP,
)
def plant_file_cmd(path: str, template: str, name: str | None, notice_mode: str) -> None:
    """Plant a file honeypot at PATH."""
    reg = _get_registry()
    template = template.replace("-", "_")  # accept hyphens or underscores
    resolved = str(Path(path).resolve())
    notice_mode = notice_mode.lower()

    if plant_file is not None:
        canary = plant_file(
            reg, resolved, template_name=template, notice_mode=notice_mode
        )
    else:
        # Fallback: write template content directly (watchdog not installed)
        from .templates import get_template
        from .scope_notice import prefix_file_content, render_notice

        canary_id = Canary.generate_id(Vector.FILE, name or Path(path).name)
        content = get_template(template)(canary_id)
        notice = render_notice(canary_id, notice_mode, access_n=1)
        if notice is not None:
            content = prefix_file_content(content, notice)
        dest = Path(path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content)
        canary = Canary(
            id=canary_id, vector=Vector.FILE,
            name=name or dest.name, path_or_url=resolved, template=template,
            notice_mode=notice_mode,
        )
        reg.add_canary(canary)

    console.print(
        f"[green]Planted[/green] file canary [bold]{canary.id}[/bold] "
        f"at {path} (notice={canary.notice_mode})"
    )


@plant.command("mcp-tool")
@click.argument("name")
@click.option("--description", required=True, help="Tool description visible to agents")
@click.option(
    "--notice",
    "notice_mode",
    type=click.Choice(["off", "static", "stochastic"], case_sensitive=False),
    default="off",
    show_default=True,
    help=_NOTICE_HELP,
)
def plant_mcp_tool(name: str, description: str, notice_mode: str) -> None:
    """Register an MCP tripwire tool."""
    reg = _get_registry()
    notice_mode = notice_mode.lower()
    canary_id = Canary.generate_id(Vector.MCP_TOOL, name)
    canary = Canary(
        id=canary_id,
        vector=Vector.MCP_TOOL,
        name=name,
        path_or_url=f"mcp://{name}",
        template=description,
        notice_mode=notice_mode,
    )
    reg.add_canary(canary)
    console.print(
        f"[green]Registered[/green] MCP tripwire [bold]{canary_id}[/bold] "
        f"— {name} (notice={notice_mode})"
    )


@plant.command("api")
@click.argument("url")
@click.option("--method", required=True, help="HTTP method (GET, POST, etc.)")
@click.option("--description", required=True, help="Endpoint description")
@click.option(
    "--notice",
    "notice_mode",
    type=click.Choice(["off", "static", "stochastic"], case_sensitive=False),
    default="off",
    show_default=True,
    help=_NOTICE_HELP,
)
def plant_api(url: str, method: str, description: str, notice_mode: str) -> None:
    """Register a decoy API endpoint."""
    reg = _get_registry()
    notice_mode = notice_mode.lower()
    name = f"{method.upper()} {url}"
    canary_id = Canary.generate_id(Vector.API_ENDPOINT, name)
    canary = Canary(
        id=canary_id,
        vector=Vector.API_ENDPOINT,
        name=name,
        path_or_url=url,
        template=description,
        notice_mode=notice_mode,
    )
    reg.add_canary(canary)
    console.print(
        f"[green]Registered[/green] API canary [bold]{canary_id}[/bold] "
        f"— {method.upper()} {url} (notice={notice_mode})"
    )

# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------

@main.command("list")
def list_canaries() -> None:
    """List all active canaries."""
    reg = _get_registry()
    canaries = reg.list_canaries()

    if not canaries:
        console.print("[dim]No canaries registered.[/dim]")
        return

    table = Table(title="Active Canaries")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Vector", style="magenta")
    table.add_column("Name")
    table.add_column("Path / URL", style="dim")
    table.add_column("Template")
    table.add_column("Notice")
    table.add_column("Active", justify="center")

    for c in canaries:
        table.add_row(
            c.id,
            c.vector.value,
            c.name,
            c.path_or_url,
            c.template or "",
            c.notice_mode or "off",
            "[green]yes[/green]" if c.active else "[red]no[/red]",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# triggers
# ---------------------------------------------------------------------------

@main.command()
@click.option("--canary", "canary_id", default=None, help="Filter by canary ID")
@click.option("--limit", default=50, help="Max number of triggers to show")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table", help="Output format")
def triggers(canary_id: str | None, limit: int, fmt: str) -> None:
    """Show trigger history."""
    reg = _get_registry()
    events = reg.get_triggers(canary_id=canary_id, limit=limit)

    if not events:
        console.print("[dim]No triggers recorded.[/dim]")
        return

    if fmt == "json":
        click.echo(json.dumps([e.to_dict() for e in events], indent=2))
        return

    table = Table(title="Trigger History")
    table.add_column("Event ID", style="cyan", no_wrap=True)
    table.add_column("Canary ID", style="magenta")
    table.add_column("Vector")
    table.add_column("Triggered At", style="dim")

    for e in events:
        table.add_row(e.id, e.canary_id, e.vector.value, e.triggered_at)

    console.print(table)


# ---------------------------------------------------------------------------
# serve-mcp
# ---------------------------------------------------------------------------

@main.command("serve-mcp")
@click.option("--port", default=8100, help="Port for MCP SSE server")
@click.option("--stdio", "use_stdio", is_flag=True, default=False, help="Use stdio transport (for Claude Code/Desktop)")
def serve_mcp(port: int, use_stdio: bool) -> None:
    """Start the MCP tripwire server.

    Default: SSE transport on --port (for HTTP-based MCP clients).
    With --stdio: stdio transport (for Claude Code / Claude Desktop integration).
    """
    if create_mcp_server is None:
        click.echo("MCP vector not available. Install with: pip install agent-canary[mcp]", err=True)
        raise SystemExit(1)

    reg = _get_registry()
    server = create_mcp_server(reg, port=port)

    if use_stdio:
        console.print("[green]Starting MCP tripwire server[/green] via stdio transport")
        run_mcp_stdio(server)
    else:
        console.print(f"[green]Starting MCP tripwire server[/green] (SSE) on port {port}")
        run_mcp_sse(server, port=port)


# ---------------------------------------------------------------------------
# serve-api
# ---------------------------------------------------------------------------

@main.command("serve-api")
@click.option("--port", default=9999, help="Port for decoy API server")
def serve_api(port: int) -> None:
    """Start the decoy API server."""
    if create_api_app is None:
        click.echo("API vector not available.", err=True)
        raise SystemExit(1)

    import uvicorn
    reg = _get_registry()
    app = create_api_app(reg)
    console.print(f"[green]Starting decoy API server[/green] on port {port}")
    uvicorn.run(app, host="0.0.0.0", port=port)


# ---------------------------------------------------------------------------
# watch
# ---------------------------------------------------------------------------

@main.command()
def watch() -> None:
    """Start filesystem watcher for file canaries."""
    if FileWatcher is None:
        click.echo("File vector not available.", err=True)
        raise SystemExit(1)

    reg = _get_registry()
    watcher = FileWatcher(reg)
    console.print("[green]Watching file canaries...[/green] Press Ctrl+C to stop.")
    try:
        watcher.start()
        # Block until interrupted
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        watcher.stop()
        console.print("\n[dim]Watcher stopped.[/dim]")


# ---------------------------------------------------------------------------
# run (all services)
# ---------------------------------------------------------------------------

@main.command()
@click.option("--mcp-port", default=8100, help="Port for MCP server")
@click.option("--api-port", default=9999, help="Port for decoy API server")
def run(mcp_port: int, api_port: int) -> None:
    """Run all services (file watcher + MCP server + API server)."""
    reg = _get_registry()

    async def _run_all() -> None:
        tasks = []

        # File watcher in a thread
        if FileWatcher is not None:
            watcher = FileWatcher(reg)

            async def _watch() -> None:
                watcher.start()
                try:
                    while True:
                        await asyncio.sleep(1)
                except asyncio.CancelledError:
                    watcher.stop()

            tasks.append(asyncio.create_task(_watch()))
            console.print("[green]File watcher started[/green]")

        # MCP server (SSE transport)
        if create_mcp_server is not None:
            mcp = create_mcp_server(reg, port=mcp_port)
            tasks.append(asyncio.create_task(mcp.run_sse_async()))
            console.print(f"[green]MCP server starting[/green] (SSE) on port {mcp_port}")

        # API server
        if create_api_app is not None:
            import uvicorn
            api_app = create_api_app(reg)
            api_config = uvicorn.Config(api_app, host="0.0.0.0", port=api_port, log_level="info")
            api_server = uvicorn.Server(api_config)
            tasks.append(asyncio.create_task(api_server.serve()))
            console.print(f"[green]API server starting[/green] on port {api_port}")

        if not tasks:
            console.print("[yellow]No services available to run.[/yellow]")
            return

        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            pass

    try:
        asyncio.run(_run_all())
    except KeyboardInterrupt:
        console.print("\n[dim]All services stopped.[/dim]")


# ---------------------------------------------------------------------------
# alert (group)
# ---------------------------------------------------------------------------

@main.group()
def alert() -> None:
    """Manage alert destinations."""


@alert.command("add")
@click.argument("type_", metavar="TYPE")
@click.argument("url")
def alert_add(type_: str, url: str) -> None:
    """Add an alert destination (webhook, slack, or discord)."""
    type_map = {"webhook": "webhooks", "webhooks": "webhooks", "slack": "slack", "discord": "discord"}
    key = type_map.get(type_.lower())
    if key is None:
        click.echo(f"Invalid type '{type_}'. Must be one of: webhook, slack, discord", err=True)
        raise SystemExit(1)

    reg = _get_registry()
    reg.add_alert(key, url)
    console.print(f"[green]Added[/green] {key} alert: {url}")


@alert.command("test")
def alert_test() -> None:
    """Send a test alert to all configured destinations."""
    reg = _get_registry()
    config = reg.get_alert_config()

    fake_event = TriggerEvent(
        canary_id="test:00000000",
        vector=Vector.FILE,
    )

    async def _send() -> dict:
        return await dispatch_alerts(config, fake_event)

    results = asyncio.run(_send())

    if not results:
        console.print("[yellow]No alert destinations configured.[/yellow]")
        return

    for alert_type, outcomes in results.items():
        for i, ok in enumerate(outcomes):
            status = "[green]OK[/green]" if ok else "[red]FAIL[/red]"
            console.print(f"  {alert_type}[{i}]: {status}")


@alert.command("list")
def alert_list() -> None:
    """List configured alert destinations."""
    reg = _get_registry()
    config = reg.get_alert_config()

    has_any = False
    for alert_type, urls in config.items():
        for url in urls:
            has_any = True
            console.print(f"  [cyan]{alert_type}[/cyan]: {url}")

    if not has_any:
        console.print("[dim]No alert destinations configured.[/dim]")
