"""Nostr NIP-01 / NIP-19 / key tests."""
from __future__ import annotations

import json

import pytest

coincurve = pytest.importorskip("coincurve")

from agent_canary.forensic.chain import GENESIS_HASH, seal_event
from agent_canary.models import ForensicChain, TriggerEvent, Vector
from agent_canary.nostr.keys import (
    generate_keypair,
    sign_message,
    verify_message,
    xonly_pubkey_hex,
)
from agent_canary.nostr.nip01 import (
    build_trigger_event,
    compute_event_id,
    sign_event,
    verify_event,
    NostrEvent,
)
from agent_canary.nostr.nip19 import decode_bech32_key, npub_encode, nsec_encode


def test_nip19_roundtrip():
    sk, pk = generate_keypair()
    nsec = nsec_encode(sk)
    npub = npub_encode(pk)
    assert nsec.startswith("nsec1")
    assert npub.startswith("npub1")
    hrp_s, raw_s = decode_bech32_key(nsec)
    hrp_p, raw_p = decode_bech32_key(npub)
    assert hrp_s == "nsec" and raw_s.hex() == sk
    assert hrp_p == "npub" and raw_p.hex() == pk


def test_schnorr_sign_verify():
    sk, pk = generate_keypair()
    msg = bytes.fromhex("ab" * 32)
    sig = sign_message(sk, msg)
    assert verify_message(pk, sig, msg) is True
    assert verify_message(pk, sig, bytes.fromhex("cd" * 32)) is False


def test_nip01_event_sign_verify():
    sk, pk = generate_keypair()
    ev = NostrEvent(
        pubkey="",
        created_at=1_700_000_000,
        kind=1,
        tags=[["t", "agent-canary"]],
        content="hello canary",
    )
    sign_event(sk, ev)
    assert ev.pubkey == pk
    assert len(ev.id) == 64
    assert len(ev.sig) == 128
    assert verify_event(ev) is True

    # Tamper content → id mismatch
    bad = NostrEvent.from_dict(ev.to_dict())
    bad.content = "tampered"
    assert verify_event(bad) is False

    # Correct id for tampered content but old sig → sig fail
    bad.id = compute_event_id(bad.pubkey, bad.created_at, bad.kind, bad.tags, bad.content)
    assert verify_event(bad) is False


def test_build_trigger_event_includes_chain_tags():
    sk, pk = generate_keypair()
    trigger = TriggerEvent(
        canary_id="file:abcd1234",
        vector=Vector.MCP_TOOL,
        forensic_chain=ForensicChain(raw_args={"query": "DROP TABLE users"}),
    )
    seal_event(trigger, prev_hash=GENESIS_HASH, seq=1, private_key_hex=sk)
    ev = build_trigger_event(trigger, sk, kind=31240, created_at=1_700_000_001)
    assert verify_event(ev) is True
    assert ev.kind == 31240
    tag_map = {t[0]: t[1] for t in ev.tags if len(t) >= 2}
    assert tag_map["t"] == "agent-canary"
    assert tag_map["canary"] == "file:abcd1234"
    assert tag_map["seq"] == "1"
    assert tag_map["ch"] == trigger.chain_seal.content_hash
    body = json.loads(ev.content)
    assert body["id"] == trigger.id
    assert body["chain_seal"]["signature"] is not None
