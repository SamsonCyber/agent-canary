"""Canary registry — manages canary configs and trigger log."""
from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import asdict
from pathlib import Path

import yaml

from .forensic.chain import ChainSeal, GENESIS_HASH, seal_event
from .models import (
    AgentFingerprint,
    Canary,
    Classification,
    ForensicChain,
    ScopeRule,
    Severity,
    ToolCall,
    TriggerCause,
    TriggerEvent,
    Vector,
)

logger = logging.getLogger("agent_canary.registry")

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
                "alerts": {
                    "webhooks": [],
                    "discord": [],
                    "slack": [],
                    "nostr": {"relays": [], "auto_publish": True, "kind": 31240},
                },
                "forensics": {"seal": True, "require_signature": False},
            }
            self.config_path.write_text(yaml.dump(config, default_flow_style=False))

        self._init_db()

    def _init_db(self) -> None:
        # check_same_thread=False: dashboard / uvicorn may read from worker threads
        self._db = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS triggers (
                id TEXT PRIMARY KEY,
                canary_id TEXT NOT NULL,
                triggered_at TEXT NOT NULL,
                vector TEXT NOT NULL,
                event_json TEXT NOT NULL,
                chain_seq INTEGER,
                content_hash TEXT,
                prev_hash TEXT,
                nostr_event_id TEXT
            )
        """)
        self._db.execute("""
            CREATE INDEX IF NOT EXISTS idx_triggers_canary ON triggers(canary_id)
        """)
        self._db.execute("""
            CREATE INDEX IF NOT EXISTS idx_triggers_chain_seq ON triggers(chain_seq)
        """)
        # Migrate older DBs that lack seal columns
        cols = {
            row[1]
            for row in self._db.execute("PRAGMA table_info(triggers)").fetchall()
        }
        for col, decl in (
            ("chain_seq", "INTEGER"),
            ("content_hash", "TEXT"),
            ("prev_hash", "TEXT"),
            ("nostr_event_id", "TEXT"),
        ):
            if col not in cols:
                self._db.execute(f"ALTER TABLE triggers ADD COLUMN {col} {decl}")
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

    def get_forensics_config(self) -> dict:
        config = self._load_config()
        defaults = {"seal": True, "require_signature": False}
        raw = config.get("forensics") or {}
        return {**defaults, **raw}

    def get_chain_tip(self) -> tuple[str, int]:
        """Return (content_hash, seq) of the latest sealed trigger, or genesis."""
        row = self.db.execute(
            "SELECT content_hash, chain_seq FROM triggers "
            "WHERE content_hash IS NOT NULL AND chain_seq IS NOT NULL "
            "ORDER BY chain_seq DESC LIMIT 1"
        ).fetchone()
        if not row or not row[0]:
            return GENESIS_HASH, 0
        return str(row[0]), int(row[1] or 0)

    def _load_signing_key(self) -> str | None:
        try:
            from .nostr.keys import load_private_key
        except ImportError:
            return None
        try:
            return load_private_key(self.root)
        except Exception as exc:
            logger.warning("Could not load Nostr private key: %s", exc)
            return None

    def seal_trigger(self, event: TriggerEvent) -> ChainSeal | None:
        """Attach a crypto seal to *event* using the local chain tip + nsec."""
        cfg = self.get_forensics_config()
        if not cfg.get("seal", True):
            return None
        prev_hash, prev_seq = self.get_chain_tip()
        key = self._load_signing_key()
        return seal_event(
            event,
            prev_hash=prev_hash,
            seq=prev_seq + 1,
            private_key_hex=key,
        )

    def log_trigger(
        self,
        event: TriggerEvent,
        *,
        seal: bool | None = None,
        publish: bool | None = None,
    ) -> None:
        """Log a trigger event. Seals into the forensic chain by default.

        When Nostr relays are configured with auto_publish and an nsec is
        present, publishes a signed kind-31240 event after the local write.
        """
        do_seal = seal if seal is not None else self.get_forensics_config().get("seal", True)
        if do_seal and event.chain_seal is None:
            try:
                self.seal_trigger(event)
            except Exception:
                logger.exception("Failed to seal trigger %s; storing unsealed", event.id)

        seal_obj = event.chain_seal
        chain_seq = seal_obj.seq if isinstance(seal_obj, ChainSeal) else None
        content_hash = seal_obj.content_hash if isinstance(seal_obj, ChainSeal) else None
        prev_hash = seal_obj.prev_hash if isinstance(seal_obj, ChainSeal) else None
        nostr_event_id = seal_obj.nostr_event_id if isinstance(seal_obj, ChainSeal) else None

        self.db.execute(
            "INSERT INTO triggers "
            "(id, canary_id, triggered_at, vector, event_json, "
            " chain_seq, content_hash, prev_hash, nostr_event_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event.id,
                event.canary_id,
                event.triggered_at,
                event.vector.value,
                json.dumps(event.to_dict()),
                chain_seq,
                content_hash,
                prev_hash,
                nostr_event_id,
            ),
        )
        self.db.commit()

        ncfg = self.get_nostr_config()
        do_publish = publish if publish is not None else ncfg.get("auto_publish", True)
        if do_publish and ncfg.get("relays"):
            self._auto_publish_nostr(event, ncfg)

    def _auto_publish_nostr(self, event: TriggerEvent, ncfg: dict) -> None:
        key = self._load_signing_key()
        if not key:
            logger.debug("Nostr auto-publish skipped: no nsec")
            return
        try:
            from .nostr.client import publish_trigger_sync

            nostr_ev, results = publish_trigger_sync(
                event,
                key,
                list(ncfg.get("relays") or []),
                kind=int(ncfg.get("kind") or 31240),
            )
            ok = sum(1 for v in results.values() if v)
            logger.info(
                "Nostr publish event=%s nostr_id=%s relays_ok=%d/%d",
                event.id,
                getattr(nostr_ev, "id", "?")[:16],
                ok,
                len(results),
            )
            self.update_trigger_event(event)
        except Exception:
            logger.exception("Nostr auto-publish failed for %s", event.id)

    def update_trigger_event(self, event: TriggerEvent) -> None:
        """Rewrite event_json after post-log updates (e.g. Nostr publish)."""
        seal_obj = event.chain_seal
        self.db.execute(
            "UPDATE triggers SET event_json = ?, content_hash = ?, prev_hash = ?, "
            "chain_seq = ?, nostr_event_id = ? WHERE id = ?",
            (
                json.dumps(event.to_dict()),
                seal_obj.content_hash if isinstance(seal_obj, ChainSeal) else None,
                seal_obj.prev_hash if isinstance(seal_obj, ChainSeal) else None,
                seal_obj.seq if isinstance(seal_obj, ChainSeal) else None,
                seal_obj.nostr_event_id if isinstance(seal_obj, ChainSeal) else None,
                event.id,
            ),
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
            events.append(self._event_from_dict(data))
        return events

    def _event_from_dict(self, data: dict) -> TriggerEvent:
        """Rehydrate a full TriggerEvent from stored event_json (no field drops)."""
        fc = data.get("forensic_chain") or {}
        af = data.get("agent_fingerprint") or {}
        cl = data.get("classification") or {}

        preceding: list[ToolCall] = []
        for tc in fc.get("preceding_tool_calls") or []:
            if not isinstance(tc, dict):
                continue
            preceding.append(
                ToolCall(
                    tool=str(tc.get("tool") or ""),
                    args=dict(tc.get("args") or {}),
                    timestamp=str(tc.get("timestamp") or ""),
                    relative_time=str(tc.get("relative_time") or ""),
                )
            )

        cause = TriggerCause.UNKNOWN
        raw_cause = cl.get("cause", TriggerCause.UNKNOWN)
        try:
            cause = TriggerCause(raw_cause) if not isinstance(raw_cause, TriggerCause) else raw_cause
        except ValueError:
            cause = TriggerCause.UNKNOWN

        severity = Severity.MEDIUM
        raw_sev = cl.get("severity", Severity.MEDIUM)
        try:
            severity = Severity(raw_sev) if not isinstance(raw_sev, Severity) else raw_sev
        except ValueError:
            severity = Severity.MEDIUM

        return TriggerEvent(
            id=data["id"],
            canary_id=data["canary_id"],
            triggered_at=data["triggered_at"],
            vector=Vector(data["vector"]),
            forensic_chain=ForensicChain(
                trigger_prompt=fc.get("trigger_prompt"),
                reasoning_trace=fc.get("reasoning_trace"),
                preceding_tool_calls=preceding,
                context_summary=fc.get("context_summary"),
                raw_args=fc.get("raw_args") or {},
            ),
            agent_fingerprint=AgentFingerprint(
                model=af.get("model"),
                model_confidence=float(af.get("model_confidence") or 0.0),
                framework=af.get("framework"),
                framework_confidence=float(af.get("framework_confidence") or 0.0),
                session_id=af.get("session_id"),
                system_prompt_hash=af.get("system_prompt_hash"),
            ),
            classification=Classification(
                cause=cause,
                severity=severity,
                injected_content=bool(cl.get("injected_content", False)),
                recommendations=list(cl.get("recommendations") or []),
            ),
            raw_request=data.get("raw_request") or {},
            scope_notice=data.get("scope_notice"),
            chain_seal=ChainSeal.from_dict(data.get("chain_seal")),
        )

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
        if alert_type == "nostr":
            nostr = alerts.setdefault("nostr", {"relays": [], "auto_publish": True, "kind": 31240})
            if isinstance(nostr, list):
                # Legacy shape: list of relays
                if url not in nostr:
                    nostr.append(url)
                alerts["nostr"] = {"relays": nostr, "auto_publish": True, "kind": 31240}
            else:
                relays = nostr.setdefault("relays", [])
                if url not in relays:
                    relays.append(url)
            self._save_config(config)
            return

        destinations = alerts.setdefault(alert_type, [])
        if url not in destinations:
            destinations.append(url)
        self._save_config(config)

    def get_nostr_config(self) -> dict:
        """Normalized Nostr alert config: relays, auto_publish, kind."""
        alerts = self.get_alert_config()
        raw = alerts.get("nostr", {})
        if isinstance(raw, list):
            return {"relays": list(raw), "auto_publish": True, "kind": 31240}
        if not isinstance(raw, dict):
            return {"relays": [], "auto_publish": True, "kind": 31240}
        return {
            "relays": list(raw.get("relays") or []),
            "auto_publish": bool(raw.get("auto_publish", True)),
            "kind": int(raw.get("kind") or 31240),
        }
