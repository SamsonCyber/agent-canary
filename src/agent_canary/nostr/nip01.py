"""NIP-01 event construction, signing, and verification."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

from .keys import sign_message, verify_message, xonly_pubkey_hex

if TYPE_CHECKING:
    from ..models import TriggerEvent

# Custom regular kind for Agent Canary forensic seals (not replaceable).
DEFAULT_KIND = 31240


@dataclass
class NostrEvent:
    """Signed Nostr event (NIP-01)."""

    pubkey: str
    created_at: int
    kind: int
    tags: list[list[str]]
    content: str
    id: str = ""
    sig: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "pubkey": self.pubkey,
            "created_at": self.created_at,
            "kind": self.kind,
            "tags": self.tags,
            "content": self.content,
            "sig": self.sig,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> NostrEvent:
        return cls(
            id=str(data.get("id") or ""),
            pubkey=str(data["pubkey"]),
            created_at=int(data["created_at"]),
            kind=int(data["kind"]),
            tags=list(data.get("tags") or []),
            content=str(data.get("content") or ""),
            sig=str(data.get("sig") or ""),
        )


def _serialize_event(
    pubkey: str,
    created_at: int,
    kind: int,
    tags: list[list[str]],
    content: str,
) -> str:
    """NIP-01 serialization array as compact JSON."""
    return json.dumps(
        [0, pubkey, created_at, kind, tags, content],
        separators=(",", ":"),
        ensure_ascii=False,
    )


def compute_event_id(
    pubkey: str,
    created_at: int,
    kind: int,
    tags: list[list[str]],
    content: str,
) -> str:
    import hashlib

    serialized = _serialize_event(pubkey, created_at, kind, tags, content)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def sign_event(private_key_hex: str, event: NostrEvent) -> NostrEvent:
    """Fill pubkey, id, and sig on *event* (mutates and returns it)."""
    key = private_key_hex.strip().lower().removeprefix("0x")
    event.pubkey = xonly_pubkey_hex(key)
    event.id = compute_event_id(
        event.pubkey, event.created_at, event.kind, event.tags, event.content
    )
    event.sig = sign_message(key, bytes.fromhex(event.id))
    return event


def verify_event(event: NostrEvent | dict[str, Any]) -> bool:
    """Verify id binding and BIP-340 signature."""
    if isinstance(event, dict):
        event = NostrEvent.from_dict(event)
    expected = compute_event_id(
        event.pubkey, event.created_at, event.kind, event.tags, event.content
    )
    if event.id != expected:
        return False
    return verify_message(event.pubkey, event.sig, bytes.fromhex(event.id))


def build_trigger_event(
    trigger: TriggerEvent,
    private_key_hex: str,
    *,
    kind: int = DEFAULT_KIND,
    created_at: int | None = None,
    extra_tags: list[list[str]] | None = None,
) -> NostrEvent:
    """Build and sign a Nostr event from a sealed TriggerEvent.

    content is compact JSON of the full trigger dict (includes chain_seal).
    Tags carry machine-readable chain metadata for relay filters.
    """
    seal = trigger.chain_seal
    tags: list[list[str]] = [
        ["t", "agent-canary"],
        ["canary", trigger.canary_id],
        ["vector", trigger.vector.value if hasattr(trigger.vector, "value") else str(trigger.vector)],
        ["event", trigger.id],
    ]
    if seal is not None:
        tags.extend(
            [
                ["seq", str(seal.seq)],
                ["ch", seal.content_hash],
                ["prev", seal.prev_hash],
                ["alg", seal.algorithm],
            ]
        )
        if seal.nostr_event_id:
            # Link to prior Nostr event when re-publishing chain
            tags.append(["e", seal.nostr_event_id, "", "prev"])
        if trigger.classification and hasattr(trigger.classification, "severity"):
            tags.append(["severity", trigger.classification.severity.value])

    if extra_tags:
        tags.extend(extra_tags)

    content = json.dumps(trigger.to_dict(), separators=(",", ":"), ensure_ascii=False)
    ev = NostrEvent(
        pubkey="",
        created_at=created_at if created_at is not None else int(time.time()),
        kind=kind,
        tags=tags,
        content=content,
    )
    return sign_event(private_key_hex, ev)
