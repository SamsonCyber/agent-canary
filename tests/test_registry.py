"""Tests for the canary registry."""
from __future__ import annotations

import pytest

from agent_canary.models import Canary, ScopeRule, TriggerEvent, Vector
from agent_canary.registry import Registry


@pytest.fixture
def reg(tmp_path):
    """Create an initialized registry in an isolated temp directory."""
    r = Registry(root=tmp_path)
    r.init()
    return r


def _make_canary(vector=Vector.FILE, name="test-canary", path="/fake/path") -> Canary:
    return Canary(
        id=Canary.generate_id(vector, name),
        vector=vector,
        name=name,
        path_or_url=path,
    )


def test_init_creates_config(tmp_path):
    r = Registry(root=tmp_path)
    r.init()
    assert (tmp_path / ".agent-canary" / "config.yaml").exists()
    assert (tmp_path / ".agent-canary" / "triggers.db").exists()


def test_add_and_list_canary(reg):
    canary = _make_canary()
    reg.add_canary(canary)
    canaries = reg.list_canaries()
    assert len(canaries) == 1
    assert canaries[0].name == "test-canary"
    assert canaries[0].vector == Vector.FILE


def test_duplicate_canary_raises(reg):
    canary = _make_canary()
    reg.add_canary(canary)
    # Same path + vector should raise
    dupe = _make_canary()
    with pytest.raises(ValueError, match="already exists"):
        reg.add_canary(dupe)


def test_remove_canary(reg):
    canary = _make_canary()
    reg.add_canary(canary)
    assert len(reg.list_canaries()) == 1
    removed = reg.remove_canary(canary.id)
    assert removed is True
    assert len(reg.list_canaries()) == 0


def test_log_and_get_triggers(reg):
    canary = _make_canary()
    reg.add_canary(canary)

    event = TriggerEvent(canary_id=canary.id, vector=Vector.FILE)
    reg.log_trigger(event)

    triggers = reg.get_triggers(canary_id=canary.id)
    assert len(triggers) == 1
    assert triggers[0].canary_id == canary.id


def test_trigger_count(reg):
    canary = _make_canary()
    reg.add_canary(canary)

    for _ in range(3):
        event = TriggerEvent(canary_id=canary.id, vector=Vector.FILE)
        reg.log_trigger(event)

    assert reg.trigger_count(canary.id) == 3


def test_add_alert(reg):
    reg.add_alert("webhooks", "https://example.com/hook")
    config = reg.get_alert_config()
    assert "https://example.com/hook" in config["webhooks"]


def test_trigger_forensic_roundtrip(reg):
    """Verify forensic data survives the log → get_triggers roundtrip."""
    canary = _make_canary()
    reg.add_canary(canary)

    from agent_canary.models import ForensicChain, AgentFingerprint
    event = TriggerEvent(
        canary_id=canary.id,
        vector=Vector.FILE,
        forensic_chain=ForensicChain(
            trigger_prompt="Read the secret file",
            reasoning_trace="User asked for database credentials",
            raw_args={"path": "/etc/secrets"},
        ),
        agent_fingerprint=AgentFingerprint(
            model="claude-sonnet-4-6",
            model_confidence=0.92,
            framework="claude-code",
        ),
        raw_request={"method": "READ", "path": "/etc/secrets"},
    )
    reg.log_trigger(event)

    retrieved = reg.get_triggers(canary_id=canary.id)
    assert len(retrieved) == 1
    r = retrieved[0]
    assert r.forensic_chain.trigger_prompt == "Read the secret file"
    assert r.forensic_chain.raw_args["path"] == "/etc/secrets"
    assert r.agent_fingerprint.model == "claude-sonnet-4-6"
    assert r.agent_fingerprint.model_confidence == 0.92
    assert r.raw_request["method"] == "READ"
