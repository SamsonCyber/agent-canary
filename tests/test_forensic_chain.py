"""Crypto-verified forensic chain tests."""
from __future__ import annotations

import pytest

from agent_canary.forensic.chain import (
    GENESIS_HASH,
    content_hash_for,
    seal_event,
    verify_chain,
    verify_seal,
)
from agent_canary.models import ForensicChain, TriggerEvent, Vector
from agent_canary.registry import Registry

coincurve = pytest.importorskip("coincurve")


@pytest.fixture
def reg(tmp_path):
    r = Registry(root=tmp_path)
    r.init()
    yield r
    r.close()


@pytest.fixture
def nsec(tmp_path, reg):
    from agent_canary.nostr.keys import generate_keypair, save_private_key

    sk, pk = generate_keypair()
    save_private_key(reg.root, sk)
    return sk, pk


def _event(canary_id: str = "file:deadbeef", **kwargs) -> TriggerEvent:
    return TriggerEvent(
        canary_id=canary_id,
        vector=Vector.FILE,
        forensic_chain=ForensicChain(raw_args={"path": "/tmp/x"}),
        raw_request={"file_path": "/tmp/x"},
        **kwargs,
    )


def test_unsigned_seal_hash_chain(reg):
    e1 = _event()
    seal_event(e1, prev_hash=GENESIS_HASH, seq=1, private_key_hex=None)
    assert e1.chain_seal is not None
    assert e1.chain_seal.seq == 1
    assert e1.chain_seal.prev_hash == GENESIS_HASH
    assert e1.chain_seal.signature is None
    assert e1.chain_seal.algorithm == "sha256"
    assert e1.chain_seal.content_hash == content_hash_for(e1)
    assert verify_seal(e1) == []

    e2 = _event(canary_id="file:cafebabe")
    seal_event(e2, prev_hash=e1.chain_seal.content_hash, seq=2)
    assert e2.chain_seal.prev_hash == e1.chain_seal.content_hash
    report = verify_chain([e1, e2])
    assert report["ok"] is True
    assert report["checked"] == 2


def test_signed_seal_bip340(nsec):
    sk, pk = nsec
    e = _event()
    seal_event(e, prev_hash=GENESIS_HASH, seq=1, private_key_hex=sk)
    assert e.chain_seal.algorithm == "sha256-bip340"
    assert e.chain_seal.pubkey == pk
    assert e.chain_seal.signature is not None
    assert len(e.chain_seal.signature) == 128
    assert verify_seal(e) == []


def test_tamper_breaks_content_hash(nsec):
    sk, _ = nsec
    e = _event()
    seal_event(e, prev_hash=GENESIS_HASH, seq=1, private_key_hex=sk)
    e.raw_request["file_path"] = "/tmp/TAMPERED"
    errs = verify_seal(e)
    assert any("content_hash mismatch" in x for x in errs)


def test_tamper_breaks_signature(nsec):
    sk, _ = nsec
    e = _event()
    seal_event(e, prev_hash=GENESIS_HASH, seq=1, private_key_hex=sk)
    # flip a nibble in the signature without changing content
    sig = e.chain_seal.signature
    flip = "0" if sig[0] != "0" else "1"
    e.chain_seal.signature = flip + sig[1:]
    errs = verify_seal(e)
    assert any("signature invalid" in x for x in errs)


def test_registry_auto_seals_with_key(reg, nsec):
    sk, pk = nsec
    e1 = _event()
    reg.log_trigger(e1, publish=False)
    assert e1.chain_seal is not None
    assert e1.chain_seal.seq == 1
    assert e1.chain_seal.pubkey == pk

    e2 = _event(canary_id="mcp_tool:x")
    e2.vector = Vector.MCP_TOOL
    reg.log_trigger(e2, publish=False)
    assert e2.chain_seal.seq == 2
    assert e2.chain_seal.prev_hash == e1.chain_seal.content_hash

    loaded = reg.get_triggers(limit=10)
    # newest first
    assert loaded[0].chain_seal.seq == 2
    report = verify_chain(loaded, require_signature=True, expected_pubkey=pk)
    assert report["ok"] is True


def test_chain_break_detected(reg, nsec):
    sk, pk = nsec
    events = []
    prev = GENESIS_HASH
    for i in range(3):
        e = _event(canary_id=f"file:{i:08x}")
        seal_event(e, prev_hash=prev, seq=i + 1, private_key_hex=sk)
        prev = e.chain_seal.content_hash
        events.append(e)

    # break middle link
    events[1].chain_seal.prev_hash = "a" * 64
    report = verify_chain(events, require_signature=True)
    assert report["ok"] is False
    assert any(
        "prev_hash break" in err
        for item in report["errors"]
        for err in item["errors"]
    )
