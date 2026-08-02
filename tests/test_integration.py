"""End-to-end integration tests for Agent Canary.

These tests exercise the full pipeline: planting canaries, triggering them
through their respective vectors, and verifying forensic data survives the
roundtrip through the registry.
"""
from __future__ import annotations

import os

import httpx
import pytest
import pytest_asyncio

from agent_canary.models import (
    Canary,
    ForensicChain,
    ScopeRule,
    TriggerEvent,
    Vector,
)
from agent_canary.registry import Registry
from agent_canary.vectors.files import check_file_access, plant_file
from agent_canary.vectors.mcp import TripwireTool, create_mcp_server
from agent_canary.vectors.api import DecoyEndpoint, create_api_app


@pytest.fixture
def reg(tmp_path):
    """Initialized registry in an isolated temp directory."""
    r = Registry(root=tmp_path)
    r.init()
    yield r
    r.close()


# ── 1. File canary: plant and detect ────────────────────────────────────────


def test_plant_and_detect_file_canary(reg, tmp_path):
    honeypot_path = tmp_path / "secrets" / ".env.production"
    canary = plant_file(reg, honeypot_path, template_name="aws_creds")

    # The file should exist on disk with embedded canary ID
    assert honeypot_path.exists()
    content = honeypot_path.read_text()
    assert canary.id in content

    # Simulate agent access via manual check
    trigger = check_file_access(reg, honeypot_path)

    assert trigger is not None
    assert isinstance(trigger, TriggerEvent)
    assert trigger.canary_id == canary.id
    assert trigger.vector == Vector.FILE
    assert trigger.raw_request["check_type"] == "manual"


# ── 2. MCP tripwire trigger ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_mcp_tripwire_trigger(reg):
    tool = TripwireTool(
        name="execute_sql_admin",
        description="Run admin SQL on production",
        parameters={"query": {"type": "string"}},
    )
    server = create_mcp_server(reg, tools=[tool])

    # Call the tool directly on the FastMCP server instance
    result = await server.call_tool("execute_sql_admin", {"query": "SELECT * FROM users"})

    # The response should contain the error message baked into the tripwire
    assert len(result) > 0
    result_text = result[0].text if hasattr(result[0], "text") else str(result[0])
    assert "insufficient_permissions" in result_text

    # Verify the trigger was logged in the registry
    triggers = reg.get_triggers()
    assert len(triggers) == 1
    assert triggers[0].canary_id == "mcp_tool:execute_sql_admin"
    assert triggers[0].vector == Vector.MCP_TOOL


# ── 3. API decoy trigger ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_api_decoy_trigger(reg):
    endpoint = DecoyEndpoint(
        path="/v1/users/export",
        method="POST",
        description="Bulk export lure",
        response_body={"error": "forbidden"},
        response_status=403,
    )
    app = create_api_app(reg, endpoints=[endpoint])

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post("/v1/users/export", json={"format": "csv"})

    assert resp.status_code == 403
    assert resp.json() == {"error": "forbidden"}

    # Verify trigger logged
    triggers = reg.get_triggers()
    assert len(triggers) == 1
    assert triggers[0].canary_id == "api_endpoint:/v1/users/export"
    assert triggers[0].vector == Vector.API_ENDPOINT


# ── 4. Full pipeline: all three vectors ─────────────────────────────────────


@pytest.mark.asyncio
async def test_full_pipeline(reg, tmp_path):
    # --- Plant file canary ---
    honeypot = tmp_path / "secrets" / "api_keys.yaml"
    file_canary = plant_file(reg, honeypot, template_name="api_keys")

    # --- Create MCP server with one tripwire ---
    mcp_tool = TripwireTool(
        name="delete_resources",
        description="Delete cloud resources",
        parameters={"resource_ids": {"type": "array"}},
    )
    mcp_server = create_mcp_server(reg, tools=[mcp_tool])

    # --- Create API app with one decoy ---
    api_endpoint = DecoyEndpoint(
        path="/admin/config",
        method="GET",
        description="Admin config lure",
        response_body={"error": "unauthorized"},
        response_status=401,
    )
    api_app = create_api_app(reg, endpoints=[api_endpoint])

    # --- Trigger all three ---
    # 1) File
    file_trigger = check_file_access(reg, honeypot)
    assert file_trigger is not None

    # 2) MCP — call tool directly on the FastMCP server
    await mcp_server.call_tool("delete_resources", {"resource_ids": ["res-001", "res-002"]})

    # 3) API
    api_transport = httpx.ASGITransport(app=api_app)
    async with httpx.AsyncClient(transport=api_transport, base_url="http://testserver") as client:
        await client.get("/admin/config")

    # --- Verify registry has all 3 triggers ---
    triggers = reg.get_triggers()
    assert len(triggers) == 3

    vectors = {t.vector for t in triggers}
    assert vectors == {Vector.FILE, Vector.MCP_TOOL, Vector.API_ENDPOINT}

    # Verify forensic data roundtrip for the MCP trigger
    mcp_triggers = [t for t in triggers if t.vector == Vector.MCP_TOOL]
    assert len(mcp_triggers) == 1
    assert mcp_triggers[0].forensic_chain.raw_args["resource_ids"] == ["res-001", "res-002"]

    # Verify forensic data roundtrip for the API trigger
    api_triggers = [t for t in triggers if t.vector == Vector.API_ENDPOINT]
    assert len(api_triggers) == 1
    assert api_triggers[0].forensic_chain.raw_args["path"] == "/admin/config"


# ── 5. Scope rules end-to-end ───────────────────────────────────────────────


def test_scope_rules_end_to_end(reg, tmp_path):
    """Plant a file canary with an allow list. Allowed agents don't trigger,
    unlisted agents do. The scope check happens before calling check_file_access,
    which mirrors how a real MCP wrapper would gate access."""
    honeypot = tmp_path / "scoped" / ".env"
    scope = ScopeRule(allow_agents=["safe-agent"])
    canary = plant_file(reg, honeypot, template_name="aws_creds", scope=scope)

    # Resolve the canary from the registry (simulates runtime lookup)
    found = reg.get_canary_by_path(str(honeypot), Vector.FILE)
    assert found is not None

    # Safe agent: scope says no trigger
    assert found.scope.should_trigger("safe-agent") is False
    # So a well-behaved wrapper would skip check_file_access entirely.

    # Rogue agent: scope says trigger
    assert found.scope.should_trigger("rogue-agent") is True
    trigger = check_file_access(reg, honeypot)
    assert trigger is not None
    assert trigger.canary_id == canary.id

    # Only 1 trigger event in the registry (the rogue access)
    triggers = reg.get_triggers()
    assert len(triggers) == 1
    assert triggers[0].vector == Vector.FILE
