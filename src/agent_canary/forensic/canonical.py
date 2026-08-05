"""Canonical JSON for content-addressed forensic payloads."""
from __future__ import annotations

import json
from typing import Any


def canonical_json(obj: Any) -> str:
    """Serialize *obj* for hashing: sorted keys, no whitespace, UTF-8 safe.

    Matches the spirit of NIP-01 serialization (compact separators) so the
    same bytes hash the same way on every host.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: str | bytes) -> str:
    import hashlib

    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()
