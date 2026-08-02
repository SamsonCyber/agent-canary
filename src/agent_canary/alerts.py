"""Alert routing — sends trigger notifications to configured destinations."""
from __future__ import annotations

import asyncio

import httpx

from .models import TriggerEvent


async def send_webhook(url: str, event: TriggerEvent) -> bool:
    """Send a trigger event to a generic webhook URL."""
    payload = {
        "text": f"🐦 Agent Canary triggered: {event.canary_id}",
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


async def dispatch_alerts(alert_config: dict, event: TriggerEvent) -> dict[str, list[bool]]:
    """Send alerts to all configured destinations in parallel."""
    tasks: list[tuple[str, asyncio.Task]] = []

    for url in alert_config.get("webhooks", []):
        tasks.append(("webhooks", asyncio.ensure_future(send_webhook(url, event))))
    for url in alert_config.get("slack", []):
        tasks.append(("slack", asyncio.ensure_future(send_slack(url, event))))
    for url in alert_config.get("discord", []):
        tasks.append(("discord", asyncio.ensure_future(send_discord(url, event))))

    if not tasks:
        return {}

    raw_results = await asyncio.gather(*(t for _, t in tasks), return_exceptions=True)

    results: dict[str, list[bool]] = {}
    for (alert_type, _), result in zip(tasks, raw_results):
        success = result is True if not isinstance(result, BaseException) else False
        results.setdefault(alert_type, []).append(success)

    return results
