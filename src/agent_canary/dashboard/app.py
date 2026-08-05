"""Starlette HTTP app: professional operator UI + JSON API."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route

from ..registry import Registry
from .data import (
    dashboard_payload,
    forensic_chain_view,
    list_canary_rows,
    list_trigger_rows,
    summary_stats,
)

STATIC_DIR = Path(__file__).resolve().parent / "static"


def create_dashboard_app(
    registry: Registry,
    *,
    trigger_limit: int = 100,
) -> Starlette:
    """Build a read-only dashboard bound to one Registry (project root)."""

    async def index(_request: Request) -> Response:
        html_path = STATIC_DIR / "index.html"
        if not html_path.exists():
            return HTMLResponse(
                "<h1>Agent Canary</h1><p>Dashboard UI missing.</p>",
                status_code=500,
            )
        body = html_path.read_text(encoding="utf-8")
        payload = dashboard_payload(registry, trigger_limit=trigger_limit)
        # SSR bootstrap so the page paints even if client JS/fetch fails
        boot = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
        body = body.replace("{{ROOT}}", _escape_html(str(registry.root)))
        body = body.replace("{{BOOTSTRAP_JSON}}", boot)
        return HTMLResponse(
            body,
            headers={
                "Cache-Control": "no-store, no-cache, must-revalidate",
                "Pragma": "no-cache",
            },
        )

    async def api_health(_request: Request) -> JSONResponse:
        return JSONResponse({"ok": True, "service": "agent-canary-dashboard"})

    async def api_summary(_request: Request) -> JSONResponse:
        return JSONResponse(summary_stats(registry))

    async def api_canaries(_request: Request) -> JSONResponse:
        return JSONResponse({"canaries": list_canary_rows(registry)})

    async def api_triggers(request: Request) -> JSONResponse:
        limit = _int_query(request, "limit", trigger_limit, lo=1, hi=1000)
        return JSONResponse({"triggers": list_trigger_rows(registry, limit=limit)})

    async def api_dashboard(request: Request) -> JSONResponse:
        limit = _int_query(request, "limit", trigger_limit, lo=1, hi=1000)
        return JSONResponse(dashboard_payload(registry, trigger_limit=limit))

    async def api_chain(request: Request) -> JSONResponse:
        limit = _int_query(request, "limit", 200, lo=1, hi=1000)
        return JSONResponse(forensic_chain_view(registry, limit=limit))

    async def api_trigger_detail(request: Request) -> JSONResponse:
        event_id = request.path_params.get("event_id", "")
        for row in list_trigger_rows(registry, limit=500):
            if row["id"] == event_id:
                return JSONResponse(row)
        return JSONResponse({"error": "not_found", "id": event_id}, status_code=404)

    routes = [
        Route("/", index, methods=["GET"]),
        Route("/api/health", api_health, methods=["GET"]),
        Route("/api/summary", api_summary, methods=["GET"]),
        Route("/api/canaries", api_canaries, methods=["GET"]),
        Route("/api/triggers", api_triggers, methods=["GET"]),
        Route("/api/triggers/{event_id}", api_trigger_detail, methods=["GET"]),
        Route("/api/chain", api_chain, methods=["GET"]),
        Route("/api/dashboard", api_dashboard, methods=["GET"]),
    ]
    return Starlette(routes=routes)


def _int_query(
    request: Request, name: str, default: int, *, lo: int, hi: int
) -> int:
    raw = request.query_params.get(name)
    if raw is None:
        return default
    try:
        n = int(raw)
    except ValueError:
        return default
    return max(lo, min(hi, n))


def _escape_html(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def render_dashboard_json(registry: Registry, **kwargs: Any) -> str:
    """Helper for tests: JSON string of the full dashboard payload."""
    return json.dumps(dashboard_payload(registry, **kwargs))
