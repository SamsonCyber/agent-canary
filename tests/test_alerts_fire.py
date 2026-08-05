"""Alerts must fire from the real trigger callback path, not only `alert test`."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from agent_canary.alerts import fire_alerts
from agent_canary.models import TriggerEvent, Vector
from agent_canary.registry import Registry


@pytest.fixture
def reg(tmp_path):
    r = Registry(root=tmp_path)
    r.init()
    yield r
    r.close()


def test_fire_alerts_no_destinations_is_noop(reg):
    event = TriggerEvent(canary_id="file:x", vector=Vector.FILE)
    assert fire_alerts(event, registry=reg) == {}


def test_fire_alerts_calls_dispatch_with_config(reg):
    reg.add_alert("webhooks", "https://example.test/hook")
    event = TriggerEvent(canary_id="file:x", vector=Vector.FILE)

    with patch(
        "agent_canary.alerts.dispatch_alerts",
        new_callable=AsyncMock,
        return_value={"webhooks": [True]},
    ) as mock_dispatch:
        results = fire_alerts(event, registry=reg)

    assert results == {"webhooks": [True]}
    assert mock_dispatch.await_count == 1
    args, kwargs = mock_dispatch.call_args
    assert "https://example.test/hook" in args[0]["webhooks"]
    assert args[1] is event
    assert kwargs.get("registry") is reg
