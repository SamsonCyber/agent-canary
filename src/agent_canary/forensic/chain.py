"""Hash-linked, optionally Schnorr-signed forensic seals.

Each TriggerEvent gets a ChainSeal:

1. content_hash — SHA-256 of the canonical event payload (no seal field)
2. prev_hash — content_hash of the previous sealed event (or GENESIS)
3. seq — append-only index starting at 1
4. signature — BIP-340 Schnorr over the link digest when a Nostr key is present

Verification recomputes hashes and checks signatures. Tampering any prior
event breaks every later link.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, TYPE_CHECKING

from .canonical import canonical_json, sha256_hex

if TYPE_CHECKING:
    from ..models import TriggerEvent

GENESIS_HASH = "0" * 64


class SealError(Exception):
    """Raised when a seal cannot be created or verified."""


@dataclass
class ChainSeal:
    """Cryptographic seal for one forensic event in an append-only chain."""

    seq: int
    content_hash: str
    prev_hash: str
    sealed_at: str
    algorithm: str = "sha256"  # sha256 | sha256-bip340
    pubkey: str | None = None  # 64-char hex x-only
    signature: str | None = None  # 128-char hex Schnorr
    nostr_event_id: str | None = None
    nostr_relays: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> ChainSeal | None:
        if not data:
            return None
        return cls(
            seq=int(data["seq"]),
            content_hash=str(data["content_hash"]),
            prev_hash=str(data["prev_hash"]),
            sealed_at=str(data["sealed_at"]),
            algorithm=str(data.get("algorithm") or "sha256"),
            pubkey=data.get("pubkey"),
            signature=data.get("signature"),
            nostr_event_id=data.get("nostr_event_id"),
            nostr_relays=list(data.get("nostr_relays") or []),
        )


def _jsonable(obj: Any) -> Any:
    """Recursively convert dataclasses/enums to plain JSON types."""
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, Enum):
        return obj.value
    if is_dataclass(obj) and not isinstance(obj, type):
        return {k: _jsonable(v) for k, v in asdict(obj).items()}
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    return obj


def payload_for_hash(event: TriggerEvent) -> dict[str, Any]:
    """Event fields that enter content_hash (everything except chain_seal)."""
    return {
        "id": event.id,
        "canary_id": event.canary_id,
        "triggered_at": event.triggered_at,
        "vector": event.vector.value if isinstance(event.vector, Enum) else event.vector,
        "agent_fingerprint": _jsonable(event.agent_fingerprint),
        "forensic_chain": _jsonable(event.forensic_chain),
        "classification": _jsonable(event.classification),
        "raw_request": _jsonable(event.raw_request),
        "scope_notice": _jsonable(event.scope_notice),
    }


def content_hash_for(event: TriggerEvent) -> str:
    return sha256_hex(canonical_json(payload_for_hash(event)))


def link_digest(seq: int, prev_hash: str, content_hash: str, sealed_at: str) -> bytes:
    """32-byte message signed for the chain link (BIP-340 message length)."""
    preimage = f"{seq}|{prev_hash}|{content_hash}|{sealed_at}"
    return bytes.fromhex(sha256_hex(preimage))


def seal_event(
    event: TriggerEvent,
    *,
    prev_hash: str = GENESIS_HASH,
    seq: int = 1,
    private_key_hex: str | None = None,
) -> ChainSeal:
    """Seal *event* into the chain. Mutates event.chain_seal.

    If private_key_hex is set, signs the link digest with BIP-340 Schnorr
    (requires coincurve). Without a key, stores an unsigned SHA-256 link.
    """
    if seq < 1:
        raise SealError("seq must be >= 1")
    if len(prev_hash) != 64 or any(c not in "0123456789abcdef" for c in prev_hash.lower()):
        raise SealError("prev_hash must be 64 lowercase hex chars")

    sealed_at = datetime.now(timezone.utc).isoformat()
    ch = content_hash_for(event)
    digest = link_digest(seq, prev_hash.lower(), ch, sealed_at)

    pubkey: str | None = None
    signature: str | None = None
    algorithm = "sha256"

    if private_key_hex:
        try:
            from ..nostr.keys import sign_message, xonly_pubkey_hex
        except ImportError as exc:
            raise SealError(
                "Nostr crypto unavailable. Install: pip install agent-canary[nostr]"
            ) from exc
        key = private_key_hex.strip().lower().removeprefix("0x")
        if len(key) != 64:
            raise SealError("private key must be 32-byte hex (64 chars)")
        pubkey = xonly_pubkey_hex(key)
        signature = sign_message(key, digest)
        algorithm = "sha256-bip340"

    seal = ChainSeal(
        seq=seq,
        content_hash=ch,
        prev_hash=prev_hash.lower(),
        sealed_at=sealed_at,
        algorithm=algorithm,
        pubkey=pubkey,
        signature=signature,
    )
    event.chain_seal = seal
    return seal


def verify_seal(event: TriggerEvent, *, require_signature: bool = False) -> list[str]:
    """Verify one event's seal. Returns a list of error strings (empty = ok)."""
    errors: list[str] = []
    seal = event.chain_seal
    if seal is None:
        errors.append("missing chain_seal")
        return errors

    expected = content_hash_for(event)
    if seal.content_hash != expected:
        errors.append(
            f"content_hash mismatch: stored={seal.content_hash[:16]}… "
            f"computed={expected[:16]}…"
        )

    if seal.algorithm == "sha256-bip340" or seal.signature:
        if not seal.signature or not seal.pubkey:
            errors.append("signed algorithm but missing signature or pubkey")
        else:
            try:
                from ..nostr.keys import verify_message
            except ImportError:
                errors.append("cannot verify signature: coincurve not installed")
            else:
                digest = link_digest(
                    seal.seq, seal.prev_hash, seal.content_hash, seal.sealed_at
                )
                if not verify_message(seal.pubkey, seal.signature, digest):
                    errors.append("BIP-340 signature invalid")
    elif require_signature:
        errors.append("signature required but seal is unsigned (sha256 only)")

    return errors


def verify_chain(
    events: list[TriggerEvent],
    *,
    require_signature: bool = False,
    expected_pubkey: str | None = None,
) -> dict[str, Any]:
    """Verify an ordered list of sealed events as a single chain.

    *events* should be sorted by chain_seal.seq ascending.
    Returns a report dict with ok, errors, checked count, tip hash.
    """
    errors: list[dict[str, Any]] = []
    checked = 0
    tip = GENESIS_HASH
    prev_hash = GENESIS_HASH
    prev_seq = 0

    ordered = sorted(
        [e for e in events if e.chain_seal is not None],
        key=lambda e: e.chain_seal.seq if e.chain_seal else 0,
    )
    unsigned = [e.id for e in events if e.chain_seal is None]
    if unsigned:
        for eid in unsigned:
            errors.append({"event_id": eid, "errors": ["missing chain_seal"]})

    for event in ordered:
        seal = event.chain_seal
        assert seal is not None
        checked += 1
        local = verify_seal(event, require_signature=require_signature)

        if seal.seq != prev_seq + 1 and not (prev_seq == 0 and seal.seq >= 1):
            # Allow first event to start at any seq only if chain empty;
            # after that, require strict +1.
            if prev_seq != 0:
                local.append(f"seq gap: expected {prev_seq + 1}, got {seal.seq}")
        if prev_seq != 0 and seal.prev_hash != prev_hash:
            local.append(
                f"prev_hash break: expected {prev_hash[:16]}…, got {seal.prev_hash[:16]}…"
            )
        if prev_seq == 0 and seal.seq == 1 and seal.prev_hash != GENESIS_HASH:
            local.append("genesis event prev_hash is not GENESIS")

        if expected_pubkey and seal.pubkey and seal.pubkey != expected_pubkey.lower():
            local.append(
                f"pubkey mismatch: expected {expected_pubkey[:16]}…, got {seal.pubkey[:16]}…"
            )

        if local:
            errors.append({"event_id": event.id, "seq": seal.seq, "errors": local})

        prev_hash = seal.content_hash
        prev_seq = seal.seq
        tip = seal.content_hash

    return {
        # Empty chain is valid (no events to forge yet).
        "ok": len(errors) == 0,
        "checked": checked,
        "unsigned": len(unsigned),
        "tip_hash": tip,
        "errors": errors,
        "empty": checked == 0 and len(unsigned) == 0,
    }
