"""Alert routing — sends trigger notifications to configured destinations."""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import TYPE_CHECKING

import httpx

from .models import TriggerEvent

if TYPE_CHECKING:
    from .registry import Registry

logger = logging.getLogger("agent_canary.alerts")


async def send_webhook(url: str, event: TriggerEvent) -> bool:
    """Send a trigger event to a generic webhook URL."""
    payload = {
        "text": f"Agent Canary triggered: {event.canary_id}",
        "event": event.to_dict(),
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(url, json=payload)
            return r.status_code < 400
    except httpx.HTTPError:
        return False


async def send_slack(webhook_url: str, event: TriggerEvent) -> bool:
    """Send a trigger event to Slack via incoming webhook."""
    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "Agent Canary Triggered"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Canary:*\n`{event.canary_id}`"},
                    {"type": "mrkdwn", "text": f"*Vector:*\n{event.vector.value}"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n{event.classification.severity.value}"},
                    {"type": "mrkdwn", "text": f"*Time:*\n{event.triggered_at}"},
                ],
            },
        ],
    }

    if event.chain_seal is not None:
        seal = event.chain_seal
        ch = getattr(seal, "content_hash", "") or ""
        payload["blocks"].append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*Forensic seal:* seq={getattr(seal, 'seq', '?')} "
                    f"`{ch[:16]}…` alg={getattr(seal, 'algorithm', '?')}"
                ),
            },
        })

    if event.forensic_chain.trigger_prompt:
        payload["blocks"].append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Trigger prompt:*\n```{event.forensic_chain.trigger_prompt[:500]}```",
            },
        })

    if event.agent_fingerprint.model:
        payload["blocks"].append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": (
                f"Model: {event.agent_fingerprint.model} "
                f"({event.agent_fingerprint.model_confidence:.0%}) | "
                f"Framework: {event.agent_fingerprint.framework or 'unknown'}"
            )}],
        })

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(webhook_url, json=payload)
            return r.status_code < 400
    except httpx.HTTPError:
        return False


async def send_discord(webhook_url: str, event: TriggerEvent) -> bool:
    """Send a trigger event to Discord via webhook."""
    embed = {
        "title": "Agent Canary Triggered",
        "color": 0xFF4444,
        "fields": [
            {"name": "Canary", "value": f"`{event.canary_id}`", "inline": True},
            {"name": "Vector", "value": event.vector.value, "inline": True},
            {"name": "Severity", "value": event.classification.severity.value, "inline": True},
        ],
        "timestamp": event.triggered_at,
    }

    if event.chain_seal is not None:
        seal = event.chain_seal
        ch = getattr(seal, "content_hash", "") or ""
        nostr_id = getattr(seal, "nostr_event_id", None) or "local-only"
        embed["fields"].append({
            "name": "Forensic seal",
            "value": f"seq={getattr(seal, 'seq', '?')} `{ch[:16]}…`\nnostr=`{nostr_id[:16]}…`",
        })

    if event.forensic_chain.trigger_prompt:
        prompt = event.forensic_chain.trigger_prompt[:400]
        embed["fields"].append({"name": "Trigger Prompt", "value": f"```{prompt}```"})

    if event.agent_fingerprint.model:
        embed["fields"].append({
            "name": "Agent",
            "value": f"{event.agent_fingerprint.model} via {event.agent_fingerprint.framework or 'unknown'}",
        })

    payload = {"embeds": [embed]}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(webhook_url, json=payload)
            return r.status_code < 400
    except httpx.HTTPError:
        return False


async def send_nostr(
    event: TriggerEvent,
    relays: list[str],
    private_key_hex: str,
    *,
    kind: int = 31240,
) -> bool:
    """Sign and publish the sealed trigger to Nostr relays. True if any relay OK."""
    if not relays or not private_key_hex:
        return False
    try:
        from .nostr.client import publish_trigger
    except ImportError:
        logger.error("Nostr client unavailable")
        return False

    try:
        _nostr_event, results = await publish_trigger(
            event, private_key_hex, relays, kind=kind
        )
        return any(results.values()) if results else False
    except Exception:
        logger.exception("Nostr publish failed for event %s", event.id)
        return False


async def dispatch_alerts(
    alert_config: dict,
    event: TriggerEvent,
    *,
    registry: Registry | None = None,
    root: Path | None = None,
) -> dict[str, list[bool]]:
    """Send alerts to all configured destinations in parallel."""
    tasks: list[tuple[str, asyncio.Task]] = []

    for url in alert_config.get("webhooks", []) or []:
        tasks.append(("webhooks", asyncio.ensure_future(send_webhook(url, event))))
    for url in alert_config.get("slack", []) or []:
        tasks.append(("slack", asyncio.ensure_future(send_slack(url, event))))
    for url in alert_config.get("discord", []) or []:
        tasks.append(("discord", asyncio.ensure_future(send_discord(url, event))))

    # Nostr: relays under alerts.nostr.relays (or legacy list)
    nostr_cfg = alert_config.get("nostr")
    relays: list[str] = []
    kind = 31240
    auto_publish = True
    if isinstance(nostr_cfg, list):
        relays = list(nostr_cfg)
    elif isinstance(nostr_cfg, dict):
        relays = list(nostr_cfg.get("relays") or [])
        kind = int(nostr_cfg.get("kind") or 31240)
        auto_publish = bool(nostr_cfg.get("auto_publish", True))

    if relays and auto_publish:
        key = None
        key_root = root
        if registry is not None:
            key_root = registry.root
            try:
                key = registry._load_signing_key()
            except Exception:
                key = None
        if key is None and key_root is not None:
            try:
                from .nostr.keys import load_private_key

                key = load_private_key(key_root)
            except Exception:
                key = None
        if key:
            tasks.append(
                ("nostr", asyncio.ensure_future(
                    send_nostr(event, relays, key, kind=kind)
                ))
            )
        else:
            logger.warning(
                "Nostr relays configured but no nsec found; skip publish. "
                "Run: agent-canary nostr init"
            )

    if not tasks:
        return {}

    raw_results = await asyncio.gather(*(t for _, t in tasks), return_exceptions=True)

    results: dict[str, list[bool]] = {}
    for (alert_type, _), result in zip(tasks, raw_results):
        success = result is True if not isinstance(result, BaseException) else False
        results.setdefault(alert_type, []).append(success)

    # Persist Nostr event id back into the trigger row after publish
    if registry is not None and event.chain_seal is not None:
        if getattr(event.chain_seal, "nostr_event_id", None):
            try:
                registry.update_trigger_event(event)
            except Exception:
                logger.exception("Failed to persist Nostr event id for %s", event.id)

    return results


def fire_alerts(
    event: TriggerEvent,
    *,
    registry: Registry | None = None,
    alert_config: dict | None = None,
) -> dict[str, list[bool]]:
    """Dispatch alerts from sync or async contexts (CLI watch / vector callbacks).

    Returns empty dict when no destinations are configured.
    """
    config = alert_config
    if config is None and registry is not None:
        config = registry.get_alert_config()
    config = config or {}

    # Fast path: nothing to send
    has_any = bool(config.get("webhooks") or config.get("slack") or config.get("discord"))
    nostr = config.get("nostr")
    if isinstance(nostr, list):
        has_any = has_any or bool(nostr)
    elif isinstance(nostr, dict):
        has_any = has_any or bool(nostr.get("relays"))
    if not has_any:
        return {}

    async def _run() -> dict[str, list[bool]]:
        return await dispatch_alerts(config, event, registry=registry)

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_run())

    # Already inside an event loop: schedule and return empty (fire-and-forget)
    loop.create_task(_run())
    return {}
