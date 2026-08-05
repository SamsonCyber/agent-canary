"""Dashboard data helpers + HTTP entry path tests (real Registry + Starlette)."""
from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from agent_canary.dashboard.app import create_dashboard_app
from agent_canary.dashboard.data import (
    dashboard_payload,
    forensic_chain_view,
    list_canary_rows,
    list_trigger_rows,
    summary_stats,
)
from agent_canary.models import Canary, TriggerEvent, Vector
from agent_canary.registry import Registry
from agent_canary.vectors.files import plant_file


@pytest.fixture
def reg(tmp_path: Path):
    r = Registry(root=tmp_path)
    r.init()
    yield r
    r.close()


@pytest.fixture
def planted(reg: Registry, tmp_path: Path):
    """Known canary + sealed trigger for assertions."""
    honeypot = tmp_path / "traps" / ".env.production"
    canary = plant_file(reg, honeypot, template_name="aws_creds")
    event = TriggerEvent(
        canary_id=canary.id,
        vector=Vector.FILE,
        raw_request={"file_path": str(honeypot), "check_type": "dashboard_test"},
    )
    reg.log_trigger(event, publish=False)
    return {"canary": canary, "event": event, "path": honeypot}


def test_list_canary_rows_includes_planted(reg, planted):
    rows = list_canary_rows(reg)
    ids = {r["id"] for r in rows}
    assert planted["canary"].id in ids
    row = next(r for r in rows if r["id"] == planted["canary"].id)
    assert row["vector"] == "file"
    assert row["active"] is True
    assert "path_or_url" in row and row["path_or_url"]
    assert row["trigger_count"] >= 1


def test_list_trigger_rows_includes_seal(reg, planted):
    rows = list_trigger_rows(reg, limit=50)
    ids = {r["id"] for r in rows}
    assert planted["event"].id in ids
    row = next(r for r in rows if r["id"] == planted["event"].id)
    assert row["canary_id"] == planted["canary"].id
    assert row["vector"] == "file"
    assert row["triggered_at"]
    seal = row["seal"]
    assert seal["present"] is True
    assert seal["seq"] == 1
    assert seal["content_hash"]
    assert seal["algorithm"] in ("sha256", "sha256-bip340")
    assert seal["valid"] is True


def test_summary_stats_from_live_registry(reg, planted):
    s = summary_stats(reg)
    assert s["canary_total"] >= 1
    assert s["canaries_by_vector"].get("file", 0) >= 1
    assert s["trigger_total"] >= 1
    assert s["sealed_triggers"] >= 1
    assert s["chain_tip_seq"] >= 1
    assert s["chain_tip_hash"]
    assert s["root"] == str(reg.root)
    # Not hard-coded demo junk
    assert "demo" not in str(s).lower() or planted["canary"].id in str(s)


def test_dashboard_payload_roundtrip(reg, planted):
    payload = dashboard_payload(reg)
    assert payload["summary"]["canary_total"] >= 1
    assert any(c["id"] == planted["canary"].id for c in payload["canaries"])
    assert any(t["id"] == planted["event"].id for t in payload["triggers"])
    assert "chain" in payload
    assert payload["chain"]["length"] >= 1
    assert any(l["event_id"] == planted["event"].id for l in payload["chain"]["links"])


def test_forensic_chain_view_linked(reg, planted):
    # Second sealed trigger continues the chain
    e2 = TriggerEvent(
        canary_id=planted["canary"].id,
        vector=Vector.FILE,
        raw_request={"file_path": str(planted["path"]), "check_type": "chain_test_2"},
    )
    reg.log_trigger(e2, publish=False)

    chain = forensic_chain_view(reg)
    assert chain["ok"] is True
    assert chain["length"] >= 2
    links = chain["links"]
    assert links[0]["seq"] == 1
    assert links[1]["prev_hash"] == links[0]["content_hash"]
    assert chain["tip_hash"] == links[-1]["content_hash"]
    # File name exposed for UI
    assert links[0]["target_kind"] == "file"
    assert links[0]["target_name"] == planted["path"].name
    assert str(planted["path"]) in (links[0]["target_path"] or "")


@pytest.mark.asyncio
async def test_http_dashboard_and_api(reg, planted):
    app = create_dashboard_app(reg)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        health = await client.get("/api/health")
        assert health.status_code == 200
        assert health.json()["ok"] is True

        summary = await client.get("/api/summary")
        assert summary.status_code == 200
        body = summary.json()
        assert body["canary_total"] >= 1
        assert body["trigger_total"] >= 1

        canaries = await client.get("/api/canaries")
        assert canaries.status_code == 200
        assert any(c["id"] == planted["canary"].id for c in canaries.json()["canaries"])

        triggers = await client.get("/api/triggers")
        assert triggers.status_code == 200
        trows = triggers.json()["triggers"]
        match = next(t for t in trows if t["id"] == planted["event"].id)
        assert match["seal"]["content_hash"]
        assert match["seal"]["seq"] == 1

        dash = await client.get("/api/dashboard")
        assert dash.status_code == 200
        d = dash.json()
        assert any(c["id"] == planted["canary"].id for c in d["canaries"])
        assert any(t["id"] == planted["event"].id for t in d["triggers"])
        assert d["chain"]["length"] >= 1
        assert any(l["event_id"] == planted["event"].id for l in d["chain"]["links"])

        chain = await client.get("/api/chain")
        assert chain.status_code == 200
        assert chain.json()["links"][0]["content_hash"]

        page = await client.get("/")
        assert page.status_code == 200
        html = page.text
        assert "Agent Canary" in html
        assert "Planted canaries" in html
        assert "Trigger history" in html
        assert "Forensic chain" in html
        # Root path embedded in HTML
        assert str(reg.root) in html or "Operator overview" in html
        # SSR bootstrap includes chain tip
        assert planted["event"].id in html
