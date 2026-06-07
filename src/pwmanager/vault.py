from __future__ import annotations

import json
import secrets
from typing import Any

from .aes_gcm import open_sealed, seal


def empty_vault() -> dict[str, Any]:
    return {"version": 1, "entries": []}


def encrypt_vault(master_key: bytes, vault: dict[str, Any]) -> tuple[bytes, bytes]:
    nonce = secrets.token_bytes(12)
    plaintext = json.dumps(vault, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return nonce, seal(master_key, nonce, plaintext)


def decrypt_vault(master_key: bytes, nonce: bytes, blob: bytes) -> dict[str, Any]:
    plaintext = open_sealed(master_key, nonce, blob)
    data = json.loads(plaintext.decode("utf-8"))
    if data.get("version") != 1 or not isinstance(data.get("entries"), list):
        raise ValueError("unsupported vault format")
    return data
