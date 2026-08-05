"""Read-only dashboard data helpers over Registry.

Pure functions so unit tests can assert structure without HTTP or a browser.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ..forensic.chain import verify_chain, verify_seal
from ..models import Canary, TriggerEvent
from ..registry import Registry


def list_canary_rows(registry: Registry) -> list[dict[str, Any]]:
    """Serialize planted canaries for the dashboard."""
    rows: list[dict[str, Any]] = []
    for c in registry.list_canaries():
        rows.append(_canary_row(c, registry))
    # Stable order: active first, then by created_at desc, then id
    rows.sort(key=lambda r: (not r["active"], r.get("created_at") or "", r["id"]), reverse=False)
    rows.sort(key=lambda r: (0 if r["active"] else 1, r["id"]))
    return rows


def _canary_row(c: Canary, registry: Registry) -> dict[str, Any]:
    trigger_n = registry.trigger_count(c.id)
    return {
        "id": c.id,
        "vector": c.vector.value if hasattr(c.vector, "value") else str(c.vector),
        "name": c.name,
        "path_or_url": c.path_or_url,
        "template": c.template,
        "active": bool(c.active),
        "notice_mode": c.notice_mode or "off",
        "access_count": int(c.access_count or 0),
        "created_at": c.created_at or "",
        "trigger_count": trigger_n,
    }


def list_trigger_rows(registry: Registry, *, limit: int = 100) -> list[dict[str, Any]]:
    """Serialize recent triggers including forensic seal fields when present."""
    canary_by_id = {c.id: c for c in registry.list_canaries()}
    events = registry.get_triggers(limit=limit)
    return [_trigger_row(e, canary_by_id=canary_by_id) for e in events]


def _target_info(
    event: TriggerEvent,
    *,
    canary_by_id: dict[str, Canary] | None = None,
) -> dict[str, str | None]:
    """Human-facing target: file name/path, tool name, or API route."""
    raw = event.raw_request or {}
    args = (event.forensic_chain.raw_args if event.forensic_chain else {}) or {}
    canary = (canary_by_id or {}).get(event.canary_id)
    vector = event.vector.value if hasattr(event.vector, "value") else str(event.vector)

    path: str | None = None
    name: str | None = None
    kind: str | None = None

    if vector == "file":
        kind = "file"
        path = (
            raw.get("file_path")
            or args.get("file_path")
            or args.get("path")
            or (canary.path_or_url if canary else None)
        )
        if path:
            name = Path(str(path)).name
        elif canary:
            name = canary.name
            path = canary.path_or_url
    elif vector == "mcp_tool":
        kind = "tool"
        name = (
            raw.get("tool")
            or (canary.name if canary else None)
            or event.canary_id
        )
        path = canary.path_or_url if canary else (f"mcp://{name}" if name else None)
    elif vector == "api_endpoint":
        kind = "endpoint"
        path = (
            raw.get("path")
            or args.get("path")
            or (canary.path_or_url if canary else None)
        )
        method = raw.get("method") or args.get("method") or ""
        if path and method:
            name = f"{method} {path}"
        else:
            name = path or (canary.name if canary else None)
    else:
        kind = vector
        name = canary.name if canary else None
        path = canary.path_or_url if canary else None

    return {
        "target_kind": kind,
        "target_name": str(name) if name else None,
        "target_path": str(path) if path else None,
    }


def _trigger_row(
    event: TriggerEvent,
    *,
    canary_by_id: dict[str, Canary] | None = None,
) -> dict[str, Any]:
    seal = event.chain_seal
    seal_errors = verify_seal(event) if seal is not None else ["missing chain_seal"]
    signed = bool(
        seal
        and seal.signature
        and seal.algorithm == "sha256-bip340"
    )
    target = _target_info(event, canary_by_id=canary_by_id)
    return {
        "id": event.id,
        "canary_id": event.canary_id,
        "vector": event.vector.value if hasattr(event.vector, "value") else str(event.vector),
        "triggered_at": event.triggered_at,
        "severity": (
            event.classification.severity.value
            if event.classification and hasattr(event.classification, "severity")
            else "medium"
        ),
        "raw_request": event.raw_request or {},
        "scope_notice": event.scope_notice,
        "forensic_args": (
            event.forensic_chain.raw_args if event.forensic_chain else {}
        ),
        "target_kind": target["target_kind"],
        "target_name": target["target_name"],
        "target_path": target["target_path"],
        "seal": {
            "present": seal is not None,
            "seq": seal.seq if seal else None,
            "content_hash": seal.content_hash if seal else None,
            "prev_hash": seal.prev_hash if seal else None,
            "algorithm": seal.algorithm if seal else None,
            "signed": signed,
            "pubkey": seal.pubkey if seal else None,
            "signature": seal.signature if seal else None,
            "nostr_event_id": seal.nostr_event_id if seal else None,
            "valid": len(seal_errors) == 0,
            "errors": seal_errors,
        },
    }


def summary_stats(registry: Registry, *, trigger_limit: int = 500) -> dict[str, Any]:
    """High-level counts from live registry data (never hard-coded demo values)."""
    canaries = registry.list_canaries()
    by_vector: dict[str, int] = {}
    active = 0
    for c in canaries:
        v = c.vector.value if hasattr(c.vector, "value") else str(c.vector)
        by_vector[v] = by_vector.get(v, 0) + 1
        if c.active:
            active += 1

    events = registry.get_triggers(limit=trigger_limit)
    triggers_by_vector: dict[str, int] = {}
    sealed = 0
    signed = 0
    for e in events:
        v = e.vector.value if hasattr(e.vector, "value") else str(e.vector)
        triggers_by_vector[v] = triggers_by_vector.get(v, 0) + 1
        if e.chain_seal is not None:
            sealed += 1
            if e.chain_seal.signature:
                signed += 1

    tip_hash, tip_seq = registry.get_chain_tip()
    chain_report = verify_chain(events)

    nostr = registry.get_nostr_config()
    return {
        "root": str(registry.root),
        "canary_total": len(canaries),
        "canary_active": active,
        "canaries_by_vector": by_vector,
        "trigger_total": len(events),
        "triggers_by_vector": triggers_by_vector,
        "sealed_triggers": sealed,
        "signed_triggers": signed,
        "chain_tip_seq": tip_seq,
        "chain_tip_hash": tip_hash,
        "chain_ok": bool(chain_report.get("ok")),
        "chain_checked": int(chain_report.get("checked") or 0),
        "nostr_relays": list(nostr.get("relays") or []),
        "nostr_auto_publish": bool(nostr.get("auto_publish", True)),
    }


def forensic_chain_view(registry: Registry, *, limit: int = 200) -> dict[str, Any]:
    """Append-only forensic chain for UI timeline (oldest → newest).

    Links each sealed event by prev_hash / content_hash so operators can see
    the hash spine, signature status, and verify result end-to-end.
    """
    canary_by_id = {c.id: c for c in registry.list_canaries()}
    events = registry.get_triggers(limit=limit)
    report = verify_chain(events)
    # Timeline ordered by seal seq ascending (chain direction)
    sealed = [e for e in events if e.chain_seal is not None]
    sealed.sort(key=lambda e: e.chain_seal.seq if e.chain_seal else 0)

    links: list[dict[str, Any]] = []
    for e in sealed:
        row = _trigger_row(e, canary_by_id=canary_by_id)
        seal = row["seal"]
        links.append(
            {
                "seq": seal.get("seq"),
                "event_id": row["id"],
                "canary_id": row["canary_id"],
                "vector": row["vector"],
                "triggered_at": row["triggered_at"],
                "target_kind": row.get("target_kind"),
                "target_name": row.get("target_name"),
                "target_path": row.get("target_path"),
                "prev_hash": seal.get("prev_hash"),
                "content_hash": seal.get("content_hash"),
                "algorithm": seal.get("algorithm"),
                "signed": seal.get("signed"),
                "valid": seal.get("valid"),
                "pubkey": seal.get("pubkey"),
                "signature": seal.get("signature"),
                "nostr_event_id": seal.get("nostr_event_id"),
                "errors": seal.get("errors") or [],
                "forensic_args": row.get("forensic_args") or {},
                "raw_request": row.get("raw_request") or {},
            }
        )

    tip_hash, tip_seq = registry.get_chain_tip()
    return {
        "ok": bool(report.get("ok")),
        "empty": bool(report.get("empty")),
        "checked": int(report.get("checked") or 0),
        "unsigned": int(report.get("unsigned") or 0),
        "tip_seq": tip_seq,
        "tip_hash": tip_hash,
        "errors": report.get("errors") or [],
        "links": links,
        "length": len(links),
    }


def dashboard_payload(registry: Registry, *, trigger_limit: int = 100) -> dict[str, Any]:
    """Full payload for the dashboard page and /api/dashboard."""
    return {
        "summary": summary_stats(registry, trigger_limit=max(trigger_limit, 500)),
        "canaries": list_canary_rows(registry),
        "triggers": list_trigger_rows(registry, limit=trigger_limit),
        "chain": forensic_chain_view(registry, limit=max(trigger_limit, 200)),
    }
