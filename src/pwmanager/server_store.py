from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class ServerStore:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS vaults (
                    user_id TEXT PRIMARY KEY,
                    server_share TEXT NOT NULL,
                    vault_blob BLOB NOT NULL,
                    vault_nonce BLOB NOT NULL,
                    metadata TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )

    def create_user(self, user_id: str, server_share: str, vault_blob: bytes, vault_nonce: bytes, metadata: dict) -> None:
        now = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO vaults (user_id, server_share, vault_blob, vault_nonce, metadata, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (user_id, server_share, vault_blob, vault_nonce, json.dumps(metadata), now, now),
            )

    def load_user(self, user_id: str) -> dict:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM vaults WHERE user_id = ?", (user_id,)).fetchone()
        if row is None:
            raise KeyError(f"user {user_id!r} is not registered on the server")
        return dict(row)

    def update_vault(self, user_id: str, vault_blob: bytes, vault_nonce: bytes) -> None:
        with self._connect() as conn:
            result = conn.execute(
                "UPDATE vaults SET vault_blob = ?, vault_nonce = ?, updated_at = ? WHERE user_id = ?",
                (vault_blob, vault_nonce, _now(), user_id),
            )
            if result.rowcount != 1:
                raise KeyError(f"user {user_id!r} is not registered on the server")

    def inspect_user(self, user_id: str) -> dict:
        row = self.load_user(user_id)
        return {
            "user_id": row["user_id"],
            "server_share": row["server_share"],
            "vault_blob_type": "BLOB",
            "vault_blob_bytes": len(row["vault_blob"]),
            "vault_nonce_hex": row["vault_nonce"].hex(),
            "metadata": json.loads(row["metadata"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
