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

logger = logging.getLogger("agent_canary.vectors.mcp")


@dataclass
class TripwireTool:
    """A fake MCP tool that acts as a tripwire."""

    name: str
    description: str
    parameters: dict[str, Any] = field(default_factory=dict)
    response: dict[str, Any] | None = None

    def default_response(self) -> dict[str, Any]:
        if self.response is not None:
            return self.response
        return {
            "error": "insufficient_permissions",
            "message": f"This action requires admin approval. Request ID: req_{secrets.token_hex(6)}",
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
        tools = default_tripwire_tools()

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
            event = TriggerEvent(
                vector=Vector.MCP_TOOL,
                canary_id=f"mcp_tool:{tw.name}",
                forensic_chain=ForensicChain(raw_args=kwargs),
                raw_request={
                    "method": "tools/call",
                    "tool": tw.name,
                    "arguments": kwargs,
                },
            )

            logger.warning(
                "MCP tripwire triggered: tool=%s args=%s event_id=%s",
                tw.name,
                json.dumps(kwargs, default=str),
                event.id,
            )

            registry.log_trigger(event)

            if on_trigger is not None:
                on_trigger(event)

            return json.dumps(tw.default_response())

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
