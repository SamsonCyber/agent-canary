"""Tests for stochastic / static scope notices."""
from __future__ import annotations

import json

import httpx
import pytest

from agent_canary.models import Canary, TriggerEvent, Vector
from agent_canary.registry import Registry
from agent_canary.scope_notice import (
    NoticeMode,
    api_error_payload,
    mcp_error_payload,
    parse_notice_mode,
    prefix_file_content,
    render_notice,
)
from agent_canary.vectors.api import DecoyEndpoint, create_api_app
from agent_canary.vectors.files import check_file_access, plant_file
from agent_canary.vectors.mcp import TripwireTool, create_mcp_server


@pytest.fixture
def reg(tmp_path):
    r = Registry(root=tmp_path)
    r.init()
    yield r
    r.close()


def test_parse_notice_mode():
    assert parse_notice_mode(None) is NoticeMode.OFF
    assert parse_notice_mode("off") is NoticeMode.OFF
    assert parse_notice_mode("STATIC") is NoticeMode.STATIC
    assert parse_notice_mode("stochastic") is NoticeMode.STOCHASTIC
    with pytest.raises(ValueError, match="Invalid notice mode"):
        parse_notice_mode("loud")


def test_render_off_returns_none():
    assert render_notice("file:abc", "off") is None


def test_render_static_stable():
    a = render_notice("file:abc", "static", access_n=1)
    b = render_notice("file:abc", "static", access_n=1)
    assert a is not None and b is not None
    assert a.text == b.text
    assert a.family.startswith("static")
    assert a.notice_id == b.notice_id
    assert "file:abc" in a.text
    assert "n=1" in a.text


def test_render_stochastic_deterministic_per_access():
    a1 = render_notice("file:xyz", "stochastic", access_n=1)
    a1b = render_notice("file:xyz", "stochastic", access_n=1)
    a2 = render_notice("file:xyz", "stochastic", access_n=2)
    assert a1 is not None and a1b is not None and a2 is not None
    assert a1.text == a1b.text
    assert a1.notice_id == a1b.notice_id
    # Different access_n usually changes sample; allow rare collision
    assert a1.access_n == 1 and a2.access_n == 2


def test_escalation_on_retry():
    n = render_notice("c:1", "static", access_n=3)
    assert n is not None
    assert "Repeated unauthorized" in n.text
    assert "escalated" in n.family


def test_prefix_and_payloads():
    n = render_notice("c:1", "static", access_n=1)
    assert n is not None
    prefixed = prefix_file_content("SECRET=1\n", n)
    assert prefixed.startswith("# AGENT SCOPE NOTICE")
    assert "SECRET=1" in prefixed
    mcp = mcp_error_payload({"error": "insufficient_permissions"}, n)
    assert mcp["scope_notice"]["notice_id"] == n.notice_id
    assert n.text in mcp["message"]
    api = api_error_payload({"error": "forbidden"}, n)
    assert api["scope_notice"]["mode"] == "static"
    assert api["message"] == n.text


def test_plant_file_notice_banner(reg, tmp_path):
    path = tmp_path / "secrets.env"
    canary = plant_file(reg, path, "aws_creds", notice_mode="static")
    text = path.read_text(encoding="utf-8")
    assert "AGENT SCOPE NOTICE" in text
    assert canary.notice_mode == "static"
    loaded = reg.get_canary(canary.id)
    assert loaded is not None
    assert loaded.notice_mode == "static"


def test_plant_file_default_off_no_banner(reg, tmp_path):
    path = tmp_path / "plain.env"
    plant_file(reg, path, "aws_creds")
    text = path.read_text(encoding="utf-8")
    assert "AGENT SCOPE NOTICE" not in text


def test_check_file_access_records_notice(reg, tmp_path):
    path = tmp_path / "bait.env"
    canary = plant_file(reg, path, "aws_creds", notice_mode="static")
    event = check_file_access(reg, path)
    assert event is not None
    assert event.scope_notice is not None
    assert event.scope_notice["mode"] == "static"
    assert event.scope_notice["access_n"] == 1
    assert reg.get_canary(canary.id).access_count == 1

    # Roundtrip through DB
    stored = reg.get_triggers(canary_id=canary.id)
    assert len(stored) == 1
    assert stored[0].scope_notice is not None
    assert stored[0].scope_notice["notice_id"] == event.scope_notice["notice_id"]


def test_bump_access_count(reg):
    c = Canary(
        id="file:test0001",
        vector=Vector.FILE,
        name="t",
        path_or_url="/x",
        notice_mode="stochastic",
    )
    reg.add_canary(c)
    assert reg.bump_access_count(c.id) == 1
    assert reg.bump_access_count(c.id) == 2
    assert reg.get_canary(c.id).access_count == 2


@pytest.mark.asyncio
async def test_mcp_tripwire_with_notice(reg):
    canary = Canary(
        id="mcp_tool:noticetest",
        vector=Vector.MCP_TOOL,
        name="execute_sql_admin",
        path_or_url="mcp://execute_sql_admin",
        template="admin sql",
        notice_mode="static",
    )
    reg.add_canary(canary)
    tool = TripwireTool(
        name="execute_sql_admin",
        description="admin sql",
        parameters={"query": {"type": "string"}},
        canary_id=canary.id,
        notice_mode="static",
    )
    server = create_mcp_server(reg, tools=[tool])
    result = await server.call_tool("execute_sql_admin", {"query": "SELECT 1"})
    # FastMCP may return (list[TextContent], meta) or a plain list
    content_list = result[0] if isinstance(result, tuple) else result
    first = content_list[0]
    result_text = first.text if hasattr(first, "text") else str(first)
    payload = json.loads(result_text)
    assert "scope_notice" in payload
    assert payload["scope_notice"]["mode"] == "static"
    assert "Engagement" in payload["message"] or "scope" in payload["message"].lower()

    triggers = reg.get_triggers()
    assert len(triggers) == 1
    assert triggers[0].scope_notice is not None
    assert triggers[0].scope_notice["access_n"] == 1


@pytest.mark.asyncio
async def test_api_decoy_with_notice(reg):
    canary = Canary(
        id="api_endpoint:export",
        vector=Vector.API_ENDPOINT,
        name="POST /v1/users/export",
        path_or_url="/v1/users/export",
        template="export lure",
        notice_mode="static",
    )
    reg.add_canary(canary)
    endpoint = DecoyEndpoint(
        path="/v1/users/export",
        method="POST",
        description="Bulk export lure",
        response_body={"error": "forbidden", "message": "nope"},
        response_status=403,
        canary_id=canary.id,
        notice_mode="static",
    )
    app = create_api_app(reg, endpoints=[endpoint])
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/v1/users/export", json={"all": True})
    assert resp.status_code == 403
    body = resp.json()
    assert "scope_notice" in body
    assert body["scope_notice"]["mode"] == "static"
    assert body["message"]  # notice overwrites deny message

    triggers = reg.get_triggers()
    assert len(triggers) == 1
    assert triggers[0].scope_notice is not None


def test_trigger_event_to_dict_includes_scope_notice():
    event = TriggerEvent(
        canary_id="file:x",
        vector=Vector.FILE,
        scope_notice={"mode": "static", "notice_id": "abc"},
    )
    d = event.to_dict()
    assert d["scope_notice"]["notice_id"] == "abc"
