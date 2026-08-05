"""Crypto-verified forensic chains for Agent Canary."""

from .chain import (
    GENESIS_HASH,
    ChainSeal,
    SealError,
    payload_for_hash,
    seal_event,
    verify_chain,
    verify_seal,
)

__all__ = [
    "GENESIS_HASH",
    "ChainSeal",
    "SealError",
    "payload_for_hash",
    "seal_event",
    "verify_chain",
    "verify_seal",
]
