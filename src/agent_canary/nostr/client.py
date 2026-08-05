"""Relay client: publish signed events over WebSocket (NIP-01)."""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, TYPE_CHECKING

logger = logging.getLogger("agent_canary.nostr.client")

if TYPE_CHECKING:
    from ..models import TriggerEvent
    from .nip01 import NostrEvent


async def _publish_one(relay_url: str, event: dict[str, Any], timeout: float = 10.0) -> bool:
    """Send EVENT to one relay and wait for OK or timeout."""
    try:
        import websockets
    except ImportError:
        logger.error("websockets not installed; cannot publish to relays")
        return False

    payload = json.dumps(["EVENT", event], separators=(",", ":"), ensure_ascii=False)
    try:
        async with websockets.connect(
            relay_url,
            open_timeout=timeout,
            close_timeout=5,
            ping_interval=None,
        ) as ws:
            await ws.send(payload)
            deadline = asyncio.get_event_loop().time() + timeout
            while True:
                remaining = deadline - asyncio.get_event_loop().time()
                if remaining <= 0:
                    logger.warning("relay %s: timeout waiting for OK", relay_url)
                    return False
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=remaining)
                except asyncio.TimeoutError:
                    logger.warning("relay %s: recv timeout", relay_url)
                    return False
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if not isinstance(msg, list) or not msg:
                    continue
                if msg[0] == "OK" and len(msg) >= 3:
                    event_id = msg[1]
                    accepted = bool(msg[2])
                    if event_id == event.get("id"):
                        if not accepted:
                            reason = msg[3] if len(msg) > 3 else "rejected"
                            logger.warning("relay %s rejected event: %s", relay_url, reason)
                        return accepted
                if msg[0] == "NOTICE":
                    logger.info("relay %s NOTICE: %s", relay_url, msg[1] if len(msg) > 1 else "")
    except Exception as exc:
        logger.warning("relay %s publish failed: %s", relay_url, exc)
        return False


async def publish_event(
    event: NostrEvent | dict[str, Any],
    relays: list[str],
    *,
    timeout: float = 10.0,
) -> dict[str, bool]:
    """Publish to many relays in parallel. Returns {relay_url: ok}."""
    if hasattr(event, "to_dict"):
        event_dict = event.to_dict()  # type: ignore[union-attr]
    else:
        event_dict = dict(event)

    if not relays:
        return {}

    results = await asyncio.gather(
        *[_publish_one(url, event_dict, timeout=timeout) for url in relays],
        return_exceptions=True,
    )
    out: dict[str, bool] = {}
    for url, result in zip(relays, results):
        out[url] = result is True if not isinstance(result, BaseException) else False
    return out


async def publish_trigger(
    trigger: TriggerEvent,
    private_key_hex: str,
    relays: list[str],
    *,
    kind: int = 31240,
    timeout: float = 10.0,
) -> tuple[NostrEvent, dict[str, bool]]:
    """Sign a trigger as NIP-01 and publish. Updates trigger.chain_seal fields."""
    from .nip01 import build_trigger_event

    nostr_event = build_trigger_event(trigger, private_key_hex, kind=kind)
    results = await publish_event(nostr_event, relays, timeout=timeout)

    ok_relays = [url for url, ok in results.items() if ok]
    if trigger.chain_seal is not None:
        trigger.chain_seal.nostr_event_id = nostr_event.id
        # Merge successful relays into seal record
        existing = list(trigger.chain_seal.nostr_relays or [])
        for r in ok_relays:
            if r not in existing:
                existing.append(r)
        trigger.chain_seal.nostr_relays = existing

    return nostr_event, results


def publish_trigger_sync(
    trigger: TriggerEvent,
    private_key_hex: str,
    relays: list[str],
    **kwargs: Any,
) -> tuple[Any, dict[str, bool]]:
    """Sync wrapper for CLI and non-async call sites."""
    return asyncio.run(publish_trigger(trigger, private_key_hex, relays, **kwargs))
