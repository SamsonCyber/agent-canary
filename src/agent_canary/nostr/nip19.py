"""Minimal NIP-19 bech32 encode/decode for nsec / npub only."""
from __future__ import annotations

# Bech32 charset (BIP-173)
_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


class Bech32Error(ValueError):
    pass


def _polymod(values: list[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _create_checksum(hrp: str, data: list[int]) -> list[int]:
    values = _hrp_expand(hrp) + data
    polymod = _polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _verify_checksum(hrp: str, data: list[int]) -> bool:
    return _polymod(_hrp_expand(hrp) + data) == 1


def _convertbits(data: bytes | list[int], frombits: int, tobits: int, pad: bool = True) -> list[int]:
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            raise Bech32Error("invalid convertbits value")
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise Bech32Error("invalid padding in convertbits")
    return ret


def bech32_encode(hrp: str, data: list[int]) -> str:
    combined = data + _create_checksum(hrp, data)
    return hrp + "1" + "".join(_CHARSET[d] for d in combined)


def bech32_decode(bech: str) -> tuple[str, list[int]]:
    if any(ord(x) < 33 or ord(x) > 126 for x in bech):
        raise Bech32Error("invalid bech32 character")
    if bech.lower() != bech and bech.upper() != bech:
        raise Bech32Error("mixed case bech32")
    bech = bech.lower()
    pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        # NIP-19 note/nevent can exceed 90; nsec/npub are short
        if pos < 1 or pos + 7 > len(bech):
            raise Bech32Error("invalid bech32 string")
    hrp = bech[:pos]
    data_part = bech[pos + 1 :]
    try:
        data = [_CHARSET.index(c) for c in data_part]
    except ValueError as exc:
        raise Bech32Error("invalid bech32 character") from exc
    if not _verify_checksum(hrp, data):
        raise Bech32Error("invalid bech32 checksum")
    return hrp, data[:-6]


def nsec_encode(private_key_hex: str) -> str:
    key = bytes.fromhex(private_key_hex.strip().lower().removeprefix("0x"))
    if len(key) != 32:
        raise Bech32Error("private key must be 32 bytes")
    return bech32_encode("nsec", _convertbits(key, 8, 5))


def npub_encode(pubkey_hex: str) -> str:
    key = bytes.fromhex(pubkey_hex.strip().lower().removeprefix("0x"))
    if len(key) != 32:
        raise Bech32Error("pubkey must be 32 bytes (x-only)")
    return bech32_encode("npub", _convertbits(key, 8, 5))


def decode_bech32_key(encoded: str) -> tuple[str, bytes]:
    """Decode nsec1… or npub1… to (hrp, raw_32_bytes)."""
    hrp, data = bech32_decode(encoded.strip())
    if hrp not in ("nsec", "npub"):
        raise Bech32Error(f"unsupported hrp: {hrp}")
    raw = bytes(_convertbits(data, 5, 8, pad=False))
    if len(raw) != 32:
        raise Bech32Error(f"decoded length {len(raw)} != 32")
    return hrp, raw
