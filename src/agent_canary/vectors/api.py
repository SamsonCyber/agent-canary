"""Decoy API server — exposes fake HTTP endpoints that capture forensic data on access."""
from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass, field
from typing import Any, Callable

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from ..models import ForensicChain, TriggerEvent, Vector
from ..registry import Registry
from ..scope_notice import api_error_payload, render_notice

logger = logging.getLogger("agent_canary.vectors.api")

# Headers worth extracting for forensic analysis
_FORENSIC_HEADERS = {"user-agent", "authorization", "x-forwarded-for", "x-api-key", "referer"}


@dataclass
class DecoyEndpoint:
    """A fake API endpoint that acts as a lure."""

    path: str
    method: str  # GET, POST, PUT, DELETE, etc.
    description: str
    response_body: dict[str, Any] = field(default_factory=dict)
    response_status: int = 403
    canary_id: str | None = None
    notice_mode: str = "off"


def default_decoy_endpoints() -> list[DecoyEndpoint]:
    """Common decoy endpoints that legitimate agents should never hit."""
    canary_tag = secrets.token_hex(8)
    return [
        DecoyEndpoint(
            path="/v1/users/export",
            method="POST",
            description="Data exfiltration lure",
            response_body={"error": "forbidden", "message": "Insufficient permissions for bulk export."},
            response_status=403,
        ),
        DecoyEndpoint(
            path="/admin/config",
            method="GET",
            description="Admin config access lure",
            response_body={"error": "unauthorized", "message": "Authentication required."},
            response_status=401,
        ),
        DecoyEndpoint(
            path="/metadata/latest/credentials",
            method="GET",
            description="Cloud metadata credential endpoint",
            response_body={
                "AccessKeyId": f"AKIA{'X' * 12}CANARY",
                "SecretAccessKey": f"canary/{canary_tag}/DO_NOT_USE",
                "Token": f"canary-session-{canary_tag}",
                "Expiration": "2099-12-31T23:59:59Z",
            },
            response_status=200,
        ),
        DecoyEndpoint(
            path="/v1/secret/data/production",
            method="POST",
            description="Vault-style secret endpoint",
            response_body={"errors": ["permission denied"]},
            response_status=403,
        ),
    ]


def endpoints_from_registry(registry: Registry) -> list[DecoyEndpoint]:
    """Build decoys from planted API canaries, then fill with defaults."""
    endpoints: list[DecoyEndpoint] = []
    seen: set[str] = set()
    for c in registry.list_canaries():
        if c.vector != Vector.API_ENDPOINT or not c.active:
            continue
        path = c.path_or_url
        method = "GET"
        if c.name and " " in c.name:
            # plant api stores name as "METHOD /path"
            parts = c.name.split(" ", 1)
            if parts[0].isalpha() and len(parts[0]) <= 7:
                method = parts[0].upper()
                if len(parts) > 1 and parts[1].startswith("/"):
                    path = parts[1]
        endpoints.append(
            DecoyEndpoint(
                path=path,
                method=method,
                description=c.template or c.name,
                response_body={
                    "error": "forbidden",
                    "message": "Insufficient permissions.",
                },
                response_status=403,
                canary_id=c.id,
                notice_mode=c.notice_mode,
            )
        )
        seen.add(path.rstrip("/") or path)
    for ep in default_decoy_endpoints():
        key = ep.path.rstrip("/") or ep.path
        if key not in seen:
            endpoints.append(ep)
    return endpoints


def create_api_app(
    registry: Registry,
    endpoints: list[DecoyEndpoint] | None = None,
    on_trigger: Callable[[TriggerEvent], Any] | None = None,
) -> Starlette:
    """Return a Starlette ASGI app that serves decoy API endpoints.

    Every request to a mounted endpoint captures full request forensics,
    logs the trigger event, and returns the configured response.
    """
    if endpoints is None:
        endpoints = endpoints_from_registry(registry)

    routes: list[Route] = []

    for ep in endpoints:
        # Capture ep in closure via default arg
        handler = _make_handler(ep, registry, on_trigger)
        # Accept any HTTP method on the route so we catch unexpected methods too
        routes.append(Route(ep.path, handler, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]))

    return Starlette(routes=routes)


def _make_handler(
    endpoint: DecoyEndpoint,
    registry: Registry,
    on_trigger: Callable[[TriggerEvent], Any] | None,
):
    """Build an async request handler for a single decoy endpoint."""

    async def handler(request: Request) -> JSONResponse:
        # Capture request body (may be empty for GET)
        try:
            body = await request.json()
        except Exception:
            body = None

        # Extract forensically interesting headers
        interesting_headers = {
            k: v for k, v in request.headers.items() if k.lower() in _FORENSIC_HEADERS
        }

        raw_request = {
            "method": request.method,
            "path": str(request.url.path),
            "query_params": dict(request.query_params),
            "headers": interesting_headers,
            "body": body,
            "client_ip": request.client.host if request.client else "unknown",
        }

        reg_canary = registry.find_api_canary(endpoint.path)
        canary_id = (
            (reg_canary.id if reg_canary else None)
            or endpoint.canary_id
            or f"api_endpoint:{endpoint.path}"
        )
        notice_mode = (
            reg_canary.notice_mode if reg_canary else endpoint.notice_mode
        )
        if reg_canary:
            access_n = registry.bump_access_count(canary_id) or 1
        else:
            access_n = 1

        notice = render_notice(canary_id, notice_mode, access_n=access_n)
        response_body = dict(endpoint.response_body)
        if notice is not None:
            response_body = api_error_payload(response_body, notice)

        event = TriggerEvent(
            vector=Vector.API_ENDPOINT,
            canary_id=canary_id,
            forensic_chain=ForensicChain(
                raw_args={
                    "path": endpoint.path,
                    "method": request.method,
                    "authorization": interesting_headers.get("authorization"),
                    "user_agent": interesting_headers.get("user-agent"),
                },
            ),
            raw_request=raw_request,
            scope_notice=notice.to_dict() if notice else None,
        )

        logger.warning(
            "API decoy triggered: %s %s from=%s event_id=%s notice=%s",
            request.method,
            endpoint.path,
            raw_request["client_ip"],
            event.id,
            notice.family if notice else "off",
        )

        registry.log_trigger(event)

        if on_trigger is not None:
            on_trigger(event)

        return JSONResponse(response_body, status_code=endpoint.response_status)

    return handler
