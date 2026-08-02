"""Canary registry — manages canary configs and trigger log."""
from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from pathlib import Path

import yaml

from .models import AgentFingerprint, Canary, ForensicChain, ScopeRule, TriggerEvent, Vector

CONFIG_DIR = ".agent-canary"
CONFIG_FILE = "config.yaml"
DB_FILE = "triggers.db"


class Registry:
    """Manages canary configurations and trigger event storage."""

    def __init__(self, root: Path | None = None):
        self.root = root or Path.cwd()
        self.config_dir = self.root / CONFIG_DIR
        self.config_path = self.config_dir / CONFIG_FILE
        self.db_path = self.config_dir / DB_FILE
        self._db: sqlite3.Connection | None = None

    def init(self) -> None:
        """Initialize the canary config directory and database."""
        self.config_dir.mkdir(parents=True, exist_ok=True)

        if not self.config_path.exists():
            config = {
                "version": 1,
                "canaries": [],
                "alerts": {"webhooks": [], "discord": [], "slack": []},
            }
            self.config_path.write_text(yaml.dump(config, default_flow_style=False))

        self._init_db()

    def _init_db(self) -> None:
        self._db = sqlite3.connect(str(self.db_path))
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS triggers (
                id TEXT PRIMARY KEY,
                canary_id TEXT NOT NULL,
                triggered_at TEXT NOT NULL,
                vector TEXT NOT NULL,
                event_json TEXT NOT NULL
            )
        """)
        self._db.execute("""
            CREATE INDEX IF NOT EXISTS idx_triggers_canary ON triggers(canary_id)
        """)
        self._db.commit()

    def close(self) -> None:
        """Close the SQLite connection."""
        if self._db is not None:
            self._db.close()
            self._db = None

    @property
    def db(self) -> sqlite3.Connection:
        if self._db is None:
            self._init_db()
        return self._db

    def _load_config(self) -> dict:
        if not self.config_path.exists():
            return {"version": 1, "canaries": [], "alerts": {}}
        return yaml.safe_load(self.config_path.read_text()) or {}

    def _save_config(self, config: dict) -> None:
        self.config_path.write_text(yaml.dump(config, default_flow_style=False, sort_keys=False))

    def add_canary(self, canary: Canary) -> None:
        """Add a canary to the registry."""
        config = self._load_config()
        canaries = config.get("canaries", [])

        # Check for duplicate path
        for c in canaries:
            if c["path_or_url"] == canary.path_or_url and c["vector"] == canary.vector.value:
                raise ValueError(f"Canary already exists at {canary.path_or_url}")

        canaries.append({
            "id": canary.id,
            "vector": canary.vector.value,
            "name": canary.name,
            "path_or_url": canary.path_or_url,
            "template": canary.template,
            "scope": asdict(canary.scope),
            "created_at": canary.created_at,
            "active": canary.active,
            "notice_mode": getattr(canary, "notice_mode", "off") or "off",
            "access_count": int(getattr(canary, "access_count", 0) or 0),
        })
        config["canaries"] = canaries
        self._save_config(config)

    def remove_canary(self, canary_id: str) -> bool:
        """Remove a canary by ID. Returns True if found and removed."""
        config = self._load_config()
        canaries = config.get("canaries", [])
        before = len(canaries)
        config["canaries"] = [c for c in canaries if c["id"] != canary_id]
        if len(config["canaries"]) < before:
            self._save_config(config)
            return True
        return False

    def list_canaries(self) -> list[Canary]:
        """List all registered canaries."""
        config = self._load_config()
        result = []
        for c in config.get("canaries", []):
            scope_data = c.get("scope", {})
            result.append(Canary(
                id=c["id"],
                vector=Vector(c["vector"]),
                name=c["name"],
                path_or_url=c["path_or_url"],
                template=c.get("template"),
                scope=ScopeRule(
                    deny_agents=scope_data.get("deny_agents", []),
                    allow_agents=scope_data.get("allow_agents", []),
                    deny_tasks=scope_data.get("deny_tasks", []),
                    tags=scope_data.get("tags", []),
                ),
                created_at=c.get("created_at", ""),
                active=c.get("active", True),
                notice_mode=c.get("notice_mode", "off") or "off",
                access_count=int(c.get("access_count", 0) or 0),
            ))
        return result

    def get_canary_by_path(self, path: str, vector: Vector) -> Canary | None:
        """Find a canary by its path/URL and vector type."""
        for c in self.list_canaries():
            if c.path_or_url == path and c.vector == vector:
                return c
        return None

    def log_trigger(self, event: TriggerEvent) -> None:
        """Log a trigger event to the database."""
        self.db.execute(
            "INSERT INTO triggers (id, canary_id, triggered_at, vector, event_json) VALUES (?, ?, ?, ?, ?)",
            (event.id, event.canary_id, event.triggered_at, event.vector.value, json.dumps(event.to_dict())),
        )
        self.db.commit()

    def bump_access_count(self, canary_id: str) -> int:
        """Increment access_count for a canary. Returns new 1-based count."""
        config = self._load_config()
        canaries = config.get("canaries", [])
        new_n = 0
        for c in canaries:
            if c.get("id") == canary_id:
                new_n = int(c.get("access_count", 0) or 0) + 1
                c["access_count"] = new_n
                break
        if new_n:
            config["canaries"] = canaries
            self._save_config(config)
        return new_n

    def get_canary(self, canary_id: str) -> Canary | None:
        for c in self.list_canaries():
            if c.id == canary_id:
                return c
        return None

    def find_mcp_canary(self, tool_name: str) -> Canary | None:
        """Match registered MCP canary by tool name or path mcp://name."""
        for c in self.list_canaries():
            if c.vector != Vector.MCP_TOOL or not c.active:
                continue
            if c.name == tool_name or c.path_or_url in (f"mcp://{tool_name}", tool_name):
                return c
        return None

    def find_api_canary(self, path: str) -> Canary | None:
        for c in self.list_canaries():
            if c.vector != Vector.API_ENDPOINT or not c.active:
                continue
            if c.path_or_url == path or c.path_or_url.rstrip("/") == path.rstrip("/"):
                return c
        return None

    def get_triggers(self, canary_id: str | None = None, limit: int = 50) -> list[TriggerEvent]:
        """Retrieve trigger events, optionally filtered by canary ID."""
        if canary_id:
            rows = self.db.execute(
                "SELECT event_json FROM triggers WHERE canary_id = ? ORDER BY triggered_at DESC LIMIT ?",
                (canary_id, limit),
            ).fetchall()
        else:
            rows = self.db.execute(
                "SELECT event_json FROM triggers ORDER BY triggered_at DESC LIMIT ?",
                (limit,),
            ).fetchall()

        events = []
        for (event_json,) in rows:
            data = json.loads(event_json)
            fc = data.get("forensic_chain", {})
            af = data.get("agent_fingerprint", {})
            cl = data.get("classification", {})
            events.append(TriggerEvent(
                id=data["id"],
                canary_id=data["canary_id"],
                triggered_at=data["triggered_at"],
                vector=Vector(data["vector"]),
                forensic_chain=ForensicChain(
                    trigger_prompt=fc.get("trigger_prompt"),
                    reasoning_trace=fc.get("reasoning_trace"),
                    raw_args=fc.get("raw_args", {}),
                    context_summary=fc.get("context_summary"),
                ),
                agent_fingerprint=AgentFingerprint(
                    model=af.get("model"),
                    model_confidence=af.get("model_confidence", 0.0),
                    framework=af.get("framework"),
                    framework_confidence=af.get("framework_confidence", 0.0),
                ),
                raw_request=data.get("raw_request", {}),
                scope_notice=data.get("scope_notice"),
            ))
        return events

    def trigger_count(self, canary_id: str) -> int:
        """Count triggers for a specific canary."""
        row = self.db.execute(
            "SELECT COUNT(*) FROM triggers WHERE canary_id = ?", (canary_id,)
        ).fetchone()
        return row[0] if row else 0

    def get_alert_config(self) -> dict:
        """Get alert configuration."""
        config = self._load_config()
        return config.get("alerts", {})

    def add_alert(self, alert_type: str, url: str) -> None:
        """Add an alert destination."""
        config = self._load_config()
        alerts = config.setdefault("alerts", {})
        destinations = alerts.setdefault(alert_type, [])
        if url not in destinations:
            destinations.append(url)
        self._save_config(config)
