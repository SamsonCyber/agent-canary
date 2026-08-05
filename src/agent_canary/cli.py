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

from .alerts import dispatch_alerts, fire_alerts


def _get_registry(root: Path | None = None) -> Registry:
    reg = Registry(root=root) if root is not None else Registry()
    if not reg.config_dir.exists():
        click.echo("Not initialized. Run 'agent-canary init' first.", err=True)
        raise SystemExit(1)
    return reg


def _alert_callback(reg: Registry):
    """Wire registry triggers to configured alert destinations."""

    def _cb(event: TriggerEvent) -> None:
        try:
            fire_alerts(event, registry=reg)
        except Exception:
            # Never break the tripwire path on alert failure
            pass

    return _cb


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------

@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    epilog=(
        "Examples:\n"
        "  agent-canary init\n"
        "  agent-canary plant file .env.production --template aws_creds\n"
        "  agent-canary list\n"
        "  agent-canary triggers\n"
        "  agent-canary serve-mcp\n"
        "\n"
        "Primary offline path after init: plant + list (no network)."
    ),
)
def main() -> None:
    """Agent Canary - tripwire detection for autonomous AI agents."""


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
    server = create_mcp_server(reg, port=port, on_trigger=_alert_callback(reg))

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
    app = create_api_app(reg, on_trigger=_alert_callback(reg))
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
    watcher = FileWatcher(reg, callback=_alert_callback(reg))
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
    on_alert = _alert_callback(reg)

    async def _run_all() -> None:
        tasks = []

        # File watcher in a thread
        if FileWatcher is not None:
            watcher = FileWatcher(reg, callback=on_alert)

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
            mcp = create_mcp_server(reg, port=mcp_port, on_trigger=on_alert)
            tasks.append(asyncio.create_task(mcp.run_sse_async()))
            console.print(f"[green]MCP server starting[/green] (SSE) on port {mcp_port}")

        # API server
        if create_api_app is not None:
            import uvicorn
            api_app = create_api_app(reg, on_trigger=on_alert)
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
# dash (operator web UI)
# ---------------------------------------------------------------------------

@main.command("dash")
@click.option("--host", default="127.0.0.1", show_default=True, help="Bind address")
@click.option("--port", default=8765, show_default=True, type=int, help="HTTP port")
@click.option(
    "--root",
    "root_path",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    default=None,
    help="Project root that contains .agent-canary/ (default: cwd)",
)
@click.option("--trigger-limit", default=100, show_default=True, type=int, help="Max triggers in UI payload")
def dash(host: str, port: int, root_path: Path | None, trigger_limit: int) -> None:
    """Start the read-only operator web dashboard.

    Serves a professional UI at http://HOST:PORT/ plus JSON under /api/*.
    Bound to one project root. Plant/remove stay on the CLI.
    """
    import uvicorn

    from .dashboard import create_dashboard_app

    reg = _get_registry(root_path)
    app = create_dashboard_app(reg, trigger_limit=trigger_limit)
    console.print(
        f"[green]Agent Canary dashboard[/green] "
        f"http://{host}:{port}/  root={reg.root}"
    )
    console.print("[dim]Read-only · Ctrl+C to stop[/dim]")
    uvicorn.run(app, host=host, port=port, log_level="info")


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
    """Add an alert destination (webhook, slack, discord, or nostr relay).

    For Nostr, URL is a WebSocket relay, e.g. wss://relay.damus.io
    """
    type_map = {
        "webhook": "webhooks",
        "webhooks": "webhooks",
        "slack": "slack",
        "discord": "discord",
        "nostr": "nostr",
        "relay": "nostr",
    }
    key = type_map.get(type_.lower())
    if key is None:
        click.echo(
            f"Invalid type '{type_}'. Must be one of: webhook, slack, discord, nostr",
            err=True,
        )
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
    for alert_type, value in config.items():
        if alert_type == "nostr":
            if isinstance(value, dict):
                for url in value.get("relays") or []:
                    has_any = True
                    console.print(f"  [cyan]nostr[/cyan]: {url}")
            elif isinstance(value, list):
                for url in value:
                    has_any = True
                    console.print(f"  [cyan]nostr[/cyan]: {url}")
            continue
        if isinstance(value, list):
            for url in value:
                has_any = True
                console.print(f"  [cyan]{alert_type}[/cyan]: {url}")

    if not has_any:
        console.print("[dim]No alert destinations configured.[/dim]")


# ---------------------------------------------------------------------------
# nostr (group)
# ---------------------------------------------------------------------------

@main.group()
def nostr() -> None:
    """Nostr keys, status, and forensic publish."""


@nostr.command("init")
@click.option("--force", is_flag=True, default=False, help="Overwrite existing nsec")
def nostr_init(force: bool) -> None:
    """Generate a Nostr keypair for signing forensic seals (stored under .agent-canary/nostr/)."""
    reg = _get_registry()
    try:
        from .nostr.keys import (
            generate_keypair,
            load_private_key,
            nsec_path,
            save_private_key,
            xonly_pubkey_hex,
        )
        from .nostr.nip19 import npub_encode, nsec_encode
    except ImportError as exc:
        click.echo(f"Nostr deps missing: {exc}. pip install agent-canary[nostr]", err=True)
        raise SystemExit(1)

    existing = load_private_key(reg.root)
    if existing and not force:
        pub = xonly_pubkey_hex(existing)
        console.print(
            f"[yellow]Key already exists[/yellow] at {nsec_path(reg.root)}\n"
            f"  npub: [cyan]{npub_encode(pub)}[/cyan]\n"
            f"  hex:  {pub}\n"
            f"Use --force to rotate (breaks signature continuity for new seals)."
        )
        return

    sk, pk = generate_keypair()
    path = save_private_key(reg.root, sk)
    console.print(f"[green]Generated Nostr keypair[/green] → {path}")
    console.print(f"  npub: [cyan]{npub_encode(pk)}[/cyan]")
    console.print(f"  nsec: [dim]{nsec_encode(sk)[:20]}…[/dim] (file only; do not commit)")
    console.print("  hex pubkey: " + pk)
    console.print(
        "\n[dim]Add relays:[/dim] agent-canary alert add nostr wss://relay.damus.io"
    )


@nostr.command("status")
def nostr_status() -> None:
    """Show key, relays, and chain tip."""
    reg = _get_registry()
    try:
        from .nostr.keys import load_private_key, nsec_path, xonly_pubkey_hex
        from .nostr.nip19 import npub_encode
    except ImportError as exc:
        click.echo(f"Nostr deps missing: {exc}", err=True)
        raise SystemExit(1)

    key = load_private_key(reg.root)
    if key:
        pub = xonly_pubkey_hex(key)
        console.print(f"[green]nsec loaded[/green] ({nsec_path(reg.root)})")
        console.print(f"  npub: [cyan]{npub_encode(pub)}[/cyan]")
        console.print(f"  hex:  {pub}")
    else:
        console.print("[yellow]No nsec[/yellow]. Run: agent-canary nostr init")

    ncfg = reg.get_nostr_config()
    relays = ncfg.get("relays") or []
    if relays:
        console.print(f"Relays (auto_publish={ncfg.get('auto_publish')} kind={ncfg.get('kind')}):")
        for r in relays:
            console.print(f"  • {r}")
    else:
        console.print("[dim]No Nostr relays configured.[/dim]")

    tip_hash, tip_seq = reg.get_chain_tip()
    console.print(f"Chain tip: seq={tip_seq} hash={tip_hash[:16]}…" if tip_seq else "Chain tip: empty (genesis)")


@nostr.command("publish")
@click.argument("event_id", required=False)
@click.option("--last", "publish_last", is_flag=True, default=False, help="Publish most recent trigger")
@click.option("--limit", default=1, help="With --last, how many recent events to publish")
def nostr_publish(event_id: str | None, publish_last: bool, limit: int) -> None:
    """Publish sealed trigger(s) to configured Nostr relays."""
    reg = _get_registry()
    try:
        from .nostr.client import publish_trigger_sync
        from .nostr.keys import load_private_key
    except ImportError as exc:
        click.echo(f"Nostr deps missing: {exc}", err=True)
        raise SystemExit(1)

    key = load_private_key(reg.root)
    if not key:
        click.echo("No nsec. Run: agent-canary nostr init", err=True)
        raise SystemExit(1)

    ncfg = reg.get_nostr_config()
    relays = ncfg.get("relays") or []
    if not relays:
        click.echo("No relays. Run: agent-canary alert add nostr wss://…", err=True)
        raise SystemExit(1)

    events = reg.get_triggers(limit=max(limit, 50))
    if event_id:
        targets = [e for e in events if e.id == event_id]
        if not targets:
            # fetch more broadly
            all_e = reg.get_triggers(limit=500)
            targets = [e for e in all_e if e.id == event_id]
        if not targets:
            click.echo(f"Event not found: {event_id}", err=True)
            raise SystemExit(1)
    elif publish_last:
        targets = events[:limit]
    else:
        click.echo("Pass EVENT_ID or --last", err=True)
        raise SystemExit(1)

    for ev in targets:
        if ev.chain_seal is None:
            reg.seal_trigger(ev)
        nostr_ev, results = publish_trigger_sync(
            ev, key, relays, kind=int(ncfg.get("kind") or 31240)
        )
        reg.update_trigger_event(ev)
        ok = [u for u, v in results.items() if v]
        bad = [u for u, v in results.items() if not v]
        console.print(
            f"  {ev.id} → nostr [cyan]{nostr_ev.id[:16]}…[/cyan] "
            f"ok={len(ok)} fail={len(bad)}"
        )


# ---------------------------------------------------------------------------
# forensic (group)
# ---------------------------------------------------------------------------

@main.group()
def forensic() -> None:
    """Crypto-verified forensic chain tools."""


@forensic.command("verify")
@click.option("--require-signature", is_flag=True, default=False, help="Fail unsigned seals")
@click.option("--limit", default=1000, help="Max events to load")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def forensic_verify(require_signature: bool, limit: int, fmt: str) -> None:
    """Verify the local hash/signature chain for stored triggers."""
    from .forensic.chain import verify_chain

    reg = _get_registry()
    events = reg.get_triggers(limit=limit)
    # get_triggers returns newest first; verify_chain sorts by seq
    expected_pub = None
    try:
        from .nostr.keys import load_private_key, xonly_pubkey_hex

        key = load_private_key(reg.root)
        if key:
            expected_pub = xonly_pubkey_hex(key)
    except Exception:
        pass

    report = verify_chain(
        events,
        require_signature=require_signature,
        expected_pubkey=expected_pub,
    )

    if fmt == "json":
        click.echo(json.dumps(report, indent=2))
        return

    if report.get("empty"):
        console.print("[dim]Chain empty (no sealed triggers yet).[/dim]")
    elif report["ok"]:
        console.print(
            f"[green]Chain OK[/green] checked={report['checked']} "
            f"tip={report['tip_hash'][:16]}…"
        )
    else:
        console.print(
            f"[red]Chain FAILED[/red] checked={report['checked']} "
            f"unsigned={report['unsigned']} errors={len(report['errors'])}"
        )
        for err in report["errors"][:20]:
            console.print(f"  [red]•[/red] {err}")

    if not report["ok"]:
        raise SystemExit(2)


@forensic.command("export")
@click.option("--limit", default=100, help="Max events")
@click.option("--out", "out_path", default=None, type=click.Path(), help="Write JSON to file")
def forensic_export(limit: int, out_path: str | None) -> None:
    """Export sealed trigger events as a portable forensic bundle."""
    reg = _get_registry()
    events = reg.get_triggers(limit=limit)
    # oldest-first for chain readers
    events_sorted = sorted(
        events,
        key=lambda e: (e.chain_seal.seq if e.chain_seal else 0, e.triggered_at),
    )
    tip_hash, tip_seq = reg.get_chain_tip()
    bundle = {
        "format": "agent-canary-forensic-v1",
        "exported_at": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).isoformat(),
        "tip_seq": tip_seq,
        "tip_hash": tip_hash,
        "events": [e.to_dict() for e in events_sorted],
    }
    text = json.dumps(bundle, indent=2)
    if out_path:
        Path(out_path).write_text(text, encoding="utf-8")
        console.print(f"[green]Wrote[/green] {out_path} ({len(events_sorted)} events)")
    else:
        click.echo(text)


@forensic.command("show")
@click.argument("event_id")
def forensic_show(event_id: str) -> None:
    """Show chain seal detail for one trigger event."""
    from .forensic.chain import verify_seal

    reg = _get_registry()
    events = reg.get_triggers(limit=500)
    match = next((e for e in events if e.id == event_id), None)
    if match is None:
        click.echo(f"Event not found: {event_id}", err=True)
        raise SystemExit(1)

    console.print_json(data=match.to_dict())
    errs = verify_seal(match)
    if errs:
        console.print(f"[red]Seal errors:[/red] {errs}")
    else:
        console.print("[green]Seal verifies[/green]")
