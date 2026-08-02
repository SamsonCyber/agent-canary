"""Tests for the core data models."""
from __future__ import annotations

from agent_canary.models import Canary, ScopeRule, TriggerEvent, Vector


def test_canary_generate_id():
    id_a = Canary.generate_id(Vector.FILE, "secrets.env")
    id_b = Canary.generate_id(Vector.FILE, "secrets.env")
    id_c = Canary.generate_id(Vector.MCP_TOOL, "secrets.env")

    # Each call includes a random token, so IDs differ even for same inputs
    assert id_a != id_b
    # All file IDs share the vector prefix
    assert id_a.startswith("file:")
    assert id_c.startswith("mcp_tool:")


def test_scope_rule_default_triggers():
    rule = ScopeRule()
    # Default rule triggers for any agent (no allow/deny lists)
    assert rule.should_trigger() is True
    assert rule.should_trigger("claude-code") is True
    assert rule.should_trigger("cursor") is True


def test_scope_rule_allow_list():
    rule = ScopeRule(allow_agents=["trusted-bot"])
    # Allowed agent should NOT trigger
    assert rule.should_trigger("trusted-bot") is False
    # Unknown agent should trigger
    assert rule.should_trigger("rogue-agent") is True
    # No agent ID should trigger (can't match allow list)
    assert rule.should_trigger(None) is True


def test_scope_rule_deny_list():
    rule = ScopeRule(deny_agents=["bad-agent"])
    # Denied agent triggers
    assert rule.should_trigger("bad-agent") is True
    # Non-denied agent does NOT trigger (deny-only mode)
    assert rule.should_trigger("neutral-agent") is False
    # No agent ID doesn't trigger (can't match deny list)
    assert rule.should_trigger(None) is False


def test_scope_rule_both_lists():
    rule = ScopeRule(allow_agents=["safe"], deny_agents=["bad"])
    # Allowed agent is safe regardless of deny list
    assert rule.should_trigger("safe") is False
    # Unknown agent triggers (not in allow list)
    assert rule.should_trigger("unknown") is True
    # Denied agent triggers
    assert rule.should_trigger("bad") is True


def test_trigger_event_to_dict():
    event = TriggerEvent(
        canary_id="file:abcd1234",
        vector=Vector.FILE,
    )
    d = event.to_dict()

    assert isinstance(d, dict)
    assert d["canary_id"] == "file:abcd1234"
    assert d["vector"] == "file"
    assert "triggered_at" in d
    assert "agent_fingerprint" in d
    assert "forensic_chain" in d
    assert "classification" in d
