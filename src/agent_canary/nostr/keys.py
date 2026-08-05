"""Secp256k1 / BIP-340 key helpers for Nostr (via coincurve)."""
from __future__ import annotations

import os
import secrets
from pathlib import Path

KEY_DIR_NAME = "nostr"
NSEC_FILE = "nsec"


class NostrCryptoError(Exception):
    """Missing dependency or invalid key material."""


def _require_coincurve():
    try:
        from coincurve import PrivateKey, PublicKeyXOnly
    except ImportError as exc:
        raise NostrCryptoError(
            "coincurve is required for Nostr signing. "
            "Install with: pip install agent-canary[nostr]"
        ) from exc
    return PrivateKey, PublicKeyXOnly


def generate_private_key_hex() -> str:
    """Return a fresh 32-byte private key as lowercase hex."""
    return secrets.token_hex(32)


def generate_keypair() -> tuple[str, str]:
    """Return (private_key_hex, xonly_pubkey_hex)."""
    sk = generate_private_key_hex()
    return sk, xonly_pubkey_hex(sk)


def xonly_pubkey_hex(private_key_hex: str) -> str:
    PrivateKey, PublicKeyXOnly = _require_coincurve()
    key = private_key_hex.strip().lower().removeprefix("0x")
    pk = PrivateKey(bytes.fromhex(key))
    xonly = PublicKeyXOnly.from_valid_secret(pk.secret)
    return xonly.format().hex()


def sign_message(private_key_hex: str, message32: bytes) -> str:
    """BIP-340 Schnorr sign a 32-byte message. Returns 64-byte sig as hex."""
    if len(message32) != 32:
        raise NostrCryptoError("message must be exactly 32 bytes")
    PrivateKey, _ = _require_coincurve()
    key = private_key_hex.strip().lower().removeprefix("0x")
    pk = PrivateKey(bytes.fromhex(key))
    return pk.sign_schnorr(message32).hex()


def verify_message(pubkey_hex: str, signature_hex: str, message32: bytes) -> bool:
    """Verify a BIP-340 Schnorr signature. Returns False on any failure."""
    if len(message32) != 32:
        return False
    try:
        _, PublicKeyXOnly = _require_coincurve()
        pub = PublicKeyXOnly(bytes.fromhex(pubkey_hex.strip().lower()))
        sig = bytes.fromhex(signature_hex.strip().lower())
        if len(sig) != 64:
            return False
        return bool(pub.verify(sig, message32))
    except Exception:
        return False


def key_dir(root: Path) -> Path:
    return root / ".agent-canary" / KEY_DIR_NAME


def nsec_path(root: Path) -> Path:
    return key_dir(root) / NSEC_FILE


def save_private_key(root: Path, private_key_hex: str) -> Path:
    """Write hex private key to .agent-canary/nostr/nsec (best-effort 0600)."""
    key = private_key_hex.strip().lower().removeprefix("0x")
    if len(key) != 64:
        raise NostrCryptoError("private key must be 32-byte hex")
    # Validate key material
    xonly_pubkey_hex(key)

    path = nsec_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(key + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # Windows may ignore mode bits
    # Cache npub for humans
    npub_file = path.parent / "npub"
    npub_file.write_text(xonly_pubkey_hex(key) + "\n", encoding="utf-8")
    try:
        os.chmod(npub_file, 0o644)
    except OSError:
        pass
    return path


def load_private_key(root: Path) -> str | None:
    """Load hex private key from disk. Accepts raw hex or nsec bech32."""
    path = nsec_path(root)
    if not path.exists():
        return None
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return None
    if raw.startswith("nsec1"):
        from .nip19 import decode_bech32_key

        hrp, data = decode_bech32_key(raw)
        if hrp != "nsec":
            raise NostrCryptoError(f"expected nsec, got {hrp}")
        return data.hex()
    key = raw.lower().removeprefix("0x")
    if len(key) != 64:
        raise NostrCryptoError("invalid nsec file contents")
    return key
