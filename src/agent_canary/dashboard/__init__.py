"""Read-only operator dashboard for Agent Canary."""

from .data import (
    dashboard_payload,
    forensic_chain_view,
    list_canary_rows,
    list_trigger_rows,
    summary_stats,
)
from .app import create_dashboard_app

__all__ = [
    "create_dashboard_app",
    "dashboard_payload",
    "forensic_chain_view",
    "list_canary_rows",
    "list_trigger_rows",
    "summary_stats",
]
