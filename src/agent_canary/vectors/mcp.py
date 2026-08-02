"""MCP tripwire server — registers fake tools that capture forensic data on call.

Uses the official MCP Python SDK (FastMCP) instead of a hand-rolled JSON-RPC app.
"""
from __future__ import annotations

import asyncio
import inspect
import json
import logging
import secrets
from dataclasses import dataclass, field
from typing import Any, Callable

from mcp.server.fastmcp import FastMCP

from ..models import ForensicChain, TriggerEvent, Vector
from ..registry import Registry
from ..scope_notice import mcp_error_payload, render_notice

logger = logging.getLogger("agent_canary.vectors.mcp")


@dataclass
class TripwireTool:
    """A fake MCP tool that acts as a tripwire."""

    name: str
    description: str
    parameters: dict[str, Any] = field(default_factory=dict)
    response: dict[str, Any] | None = None
    canary_id: str | None = None
    notice_mode: str = "off"

    def default_response(self) -> dict[str, Any]:
        if self.response is not None:
            return dict(self.response)
        return {
            "error": "insufficient_permissions",
            "message": (
                f"This action requires admin approval. "
                f"Request ID: req_{secrets.token_hex(6)}"
            ),
        }

    def to_mcp_schema(self) -> dict[str, Any]:
        """Serialize to MCP tool-list format."""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": {
                "type": "object",
                "properties": self.parameters,
            },
        }


def default_tripwire_tools() -> list[TripwireTool]:
    """Common tripwire tools that agents should never call unprompted."""
    return [
        TripwireTool(
            name="execute_sql_admin",
            description="Run administrative SQL queries on production database",
            parameters={
                "query": {"type": "string", "description": "SQL query to execute"},
                "database": {"type": "string", "description": "Target database name"},
            },
        ),
        TripwireTool(
            name="send_email",
            description="Send an email to any address",
            parameters={
                "to": {"type": "string", "description": "Recipient email address"},
                "subject": {"type": "string", "description": "Email subject"},
                "body": {"type": "string", "description": "Email body"},
            },
        ),
        TripwireTool(
            name="export_user_data",
            description="Export user data in bulk",
            parameters={
                "format": {"type": "string", "description": "Export format (csv, json)"},
                "filter": {"type": "string", "description": "User filter expression"},
            },
        ),
        TripwireTool(
            name="modify_production_config",
            description="Update production configuration values",
            parameters={
                "key": {"type": "string", "description": "Configuration key"},
                "value": {"type": "string", "description": "New value"},
            },
        ),
        TripwireTool(
            name="delete_resources",
            description="Delete cloud resources",
            parameters={
                "resource_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Resource IDs to delete",
                },
                "force": {"type": "boolean", "description": "Skip confirmation"},
            },
        ),
    ]


def tools_from_registry(registry: Registry) -> list[TripwireTool]:
    """Planted MCP canaries first, then default tools for unregistered names."""
    tools: list[TripwireTool] = []
    seen: set[str] = set()
    for c in registry.list_canaries():
        if c.vector != Vector.MCP_TOOL or not c.active:
            continue
        tools.append(
            TripwireTool(
                name=c.name,
                description=c.template or f"Tripwire tool {c.name}",
                canary_id=c.id,
                notice_mode=c.notice_mode,
            )
        )
        seen.add(c.name)
    for tw in default_tripwire_tools():
        if tw.name not in seen:
            tools.append(tw)
    return tools


def create_mcp_server(
    registry: Registry,
    tools: list[TripwireTool] | None = None,
    on_trigger: Callable[[TriggerEvent], Any] | None = None,
    *,
    name: str = "agent-canary-tripwire",
    host: str = "0.0.0.0",
    port: int = 8100,
) -> FastMCP:
    """Build a FastMCP server with tripwire tools registered.

    Each tool, when called, captures the tool name and arguments into a
    TriggerEvent, logs it via the registry, calls on_trigger if provided,
    and returns a plausible error response.
    """
    if tools is None:
        tools = tools_from_registry(registry)

    tools = list(tools)
    server = FastMCP(name, host=host, port=port)

    # Map JSON Schema types to Python type annotations for FastMCP introspection
    _JSON_TYPE_MAP: dict[str, type] = {
        "string": str,
        "integer": int,
        "number": float,
        "boolean": bool,
        "array": list,
        "object": dict,
    }

    def _make_handler(tw: TripwireTool):
        """Create a tool handler closure with a dynamic signature matching the tool's parameters.

        FastMCP introspects the function signature to build a Pydantic model for
        argument validation. We synthesize an ``inspect.Signature`` whose
        parameter names and type annotations match the TripwireTool's schema so
        that callers can pass arguments by name.
        """

        async def handler(**kwargs: Any) -> str:
            canary_id = tw.canary_id or f"mcp_tool:{tw.name}"
            # Prefer live registry state for notice mode / access count
            reg_canary = registry.find_mcp_canary(tw.name)
            notice_mode = (
                reg_canary.notice_mode if reg_canary else tw.notice_mode
            )
            if reg_canary:
                canary_id = reg_canary.id
                access_n = registry.bump_access_count(canary_id) or 1
            else:
                access_n = 1

            notice = render_notice(canary_id, notice_mode, access_n=access_n)
            payload = tw.default_response()
            if notice is not None:
                payload = mcp_error_payload(payload, notice)

            event = TriggerEvent(
                vector=Vector.MCP_TOOL,
                canary_id=canary_id,
                forensic_chain=ForensicChain(raw_args=kwargs),
                raw_request={
                    "method": "tools/call",
                    "tool": tw.name,
                    "arguments": kwargs,
                },
                scope_notice=notice.to_dict() if notice else None,
            )

            logger.warning(
                "MCP tripwire triggered: tool=%s args=%s event_id=%s notice=%s",
                tw.name,
                json.dumps(kwargs, default=str),
                event.id,
                notice.family if notice else "off",
            )

            registry.log_trigger(event)

            if on_trigger is not None:
                on_trigger(event)

            return json.dumps(payload)

        handler.__name__ = tw.name
        handler.__qualname__ = tw.name

        # Build an explicit signature so FastMCP creates the right Pydantic model.
        # Each parameter is keyword-only with a default of None (all optional,
        # since tripwire tools accept whatever the agent sends).
        params = []
        annotations: dict[str, Any] = {}
        for param_name, param_schema in tw.parameters.items():
            json_type = param_schema.get("type", "string")
            py_type = _JSON_TYPE_MAP.get(json_type, Any)
            params.append(
                inspect.Parameter(
                    param_name,
                    kind=inspect.Parameter.KEYWORD_ONLY,
                    default=None,
                    annotation=py_type | None,
                )
            )
            annotations[param_name] = py_type | None

        handler.__signature__ = inspect.Signature(params, return_annotation=str)
        handler.__annotations__ = annotations

        return handler

    for tw in tools:
        handler = _make_handler(tw)
        server.add_tool(
            handler,
            name=tw.name,
            description=tw.description,
        )

    return server


def run_mcp_stdio(server: FastMCP) -> None:
    """Run the MCP server over stdio transport.

    This is the transport Claude Code and Claude Desktop use when the server
    is configured in settings.json or claude_desktop_config.json.
    """
    asyncio.run(server.run_stdio_async())


def run_mcp_sse(server: FastMCP, port: int | None = None) -> None:
    """Run the MCP server over SSE transport on the given port.

    If port is provided, it overrides the port set at server creation time.
    """
    if port is not None:
        server.settings.port = port
    asyncio.run(server.run_sse_async())
