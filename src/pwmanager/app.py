from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Any

from . import __version__
from .aes_gcm import open_sealed, seal
from .client_store import LocalStore
from .encoding import b64d, b64e
from .kdf import KdfParams, derive_key, new_params
from .passwords import generate_password
from .server_store import ServerStore
from .shamir import Share, format_share, format_share_token, parse_share, recover_secret, split_secret
from .vault import decrypt_vault, empty_vault, encrypt_vault


class PasswordManager:
    def __init__(self, local_dir: Path, server_db: Path):
        self.local = LocalStore(local_dir)
        self.server = ServerStore(server_db)

    def init_user(self, user_id: str, master_password: str) -> dict[str, Any]:
        if self.local.exists(user_id):
            raise ValueError(f"local vault for {user_id!r} already exists")

        master_key = secrets.token_bytes(16)
        local_share, server_share, recovery_share = split_secret(master_key, threshold=2, total=3)

        kdf_params = new_params()
        wrap_key = derive_key(master_password, kdf_params)
        local_share_nonce = secrets.token_bytes(12)
        local_share_blob = seal(wrap_key, local_share_nonce, format_share(local_share, "local").encode("utf-8"))

        vault = empty_vault()
        vault_nonce, vault_blob = encrypt_vault(master_key, vault)
        backup_nonce, backup_blob = encrypt_vault(master_key, vault)

        self.server.create_user(
            user_id=user_id,
            server_share=format_share(server_share, "server"),
            vault_blob=vault_blob,
            vault_nonce=vault_nonce,
            metadata={"app": "Vault That Password!", "version": __version__},
        )

        local_data = {
            "user_id": user_id,
            "kdf": kdf_params.to_json(),
            "local_share": {
                "nonce": b64e(local_share_nonce),
                "blob": b64e(local_share_blob),
            },
            "backup_vault": {
                "nonce": b64e(backup_nonce),
                "blob": b64e(backup_blob),
            },
        }
        self.local.save(user_id, local_data)
        return {
            "recovery_share_json": format_share(recovery_share, "recovery"),
            "recovery_share_token": format_share_token(recovery_share, "recovery"),
            "master_key_hex": master_key.hex(),
            "local_share": format_share(local_share, "local"),
            "server_share": format_share(server_share, "server"),
        }

    def _load_local_share(self, user_id: str, master_password: str) -> Share:
        local_data = self.local.load(user_id)
        params = KdfParams.from_json(local_data["kdf"])
        wrap_key = derive_key(master_password, params)
        sealed = b64d(local_data["local_share"]["blob"])
        nonce = b64d(local_data["local_share"]["nonce"])
        share_text = open_sealed(wrap_key, nonce, sealed).decode("utf-8")
        return parse_share(share_text)

    def _open_normal(self, user_id: str, master_password: str) -> tuple[bytes, dict[str, Any]]:
        local_share = self._load_local_share(user_id, master_password)
        server_row = self.server.load_user(user_id)
        server_share = parse_share(server_row["server_share"])
        master_key = recover_secret([local_share, server_share], length=16)
        vault = decrypt_vault(master_key, server_row["vault_nonce"], server_row["vault_blob"])
        return master_key, vault

    def open_normal(self, user_id: str, master_password: str) -> dict[str, Any]:
        _, vault = self._open_normal(user_id, master_password)
        return vault

    def open_backup(self, user_id: str, master_password: str, recovery_share_text: str) -> dict[str, Any]:
        local_share = self._load_local_share(user_id, master_password)
        recovery_share = parse_share(recovery_share_text)
        master_key = recover_secret([local_share, recovery_share], length=16)
        local_data = self.local.load(user_id)
        return decrypt_vault(
            master_key,
            b64d(local_data["backup_vault"]["nonce"]),
            b64d(local_data["backup_vault"]["blob"]),
        )

    def _save_normal(self, user_id: str, master_key: bytes, vault: dict[str, Any]) -> None:
        vault_nonce, vault_blob = encrypt_vault(master_key, vault)
        backup_nonce, backup_blob = encrypt_vault(master_key, vault)
        self.server.update_vault(user_id, vault_blob, vault_nonce)

        local_data = self.local.load(user_id)
        local_data["backup_vault"] = {"nonce": b64e(backup_nonce), "blob": b64e(backup_blob)}
        self.local.save(user_id, local_data)

    def list_entries(self, user_id: str, master_password: str, backup: bool = False, recovery_share_text: str | None = None) -> list[dict]:
        if backup:
            if not recovery_share_text:
                raise ValueError("backup mode requires a recovery share")
            vault = self.open_backup(user_id, master_password, recovery_share_text)
        else:
            vault = self.open_normal(user_id, master_password)
        return vault["entries"]

    def add_entry(
        self,
        user_id: str,
        master_password: str,
        service: str,
        username: str,
        password: str | None,
        generated_length: int | None,
        note: str,
    ) -> dict:
        master_key, vault = self._open_normal(user_id, master_password)
        final_password = generate_password(generated_length) if generated_length else password
        if not final_password:
            raise ValueError("password must be provided or generated")
        entry = {
            "id": secrets.token_hex(4),
            "nama_layanan": service,
            "username": username,
            "password": final_password,
            "catatan": note,
        }
        vault["entries"].append(entry)
        self._save_normal(user_id, master_key, vault)
        return entry

    def update_entry(
        self,
        user_id: str,
        master_password: str,
        entry_id: str,
        updates: dict[str, str | None],
        generated_length: int | None,
    ) -> dict:
        master_key, vault = self._open_normal(user_id, master_password)
        for entry in vault["entries"]:
            if entry["id"] == entry_id:
                if generated_length:
                    entry["password"] = generate_password(generated_length)
                for key, value in updates.items():
                    if value is not None:
                        entry[key] = value
                self._save_normal(user_id, master_key, vault)
                return entry
        raise KeyError(f"entry {entry_id!r} was not found")

    def delete_entry(self, user_id: str, master_password: str, entry_id: str) -> bool:
        master_key, vault = self._open_normal(user_id, master_password)
        before = len(vault["entries"])
        vault["entries"] = [entry for entry in vault["entries"] if entry["id"] != entry_id]
        if len(vault["entries"]) == before:
            raise KeyError(f"entry {entry_id!r} was not found")
        self._save_normal(user_id, master_key, vault)
        return True

    def inspect_server(self, user_id: str) -> dict:
        return self.server.inspect_user(user_id)

    def inspect_local(self, user_id: str) -> dict:
        data = self.local.load(user_id)
        return {
            "user_id": data["user_id"],
            "kdf": {key: value for key, value in data["kdf"].items() if key != "salt"} | {"salt": "<base64>"},
            "local_share_blob_bytes": len(b64d(data["local_share"]["blob"])),
            "local_share_nonce_hex": b64d(data["local_share"]["nonce"]).hex(),
            "backup_vault_blob_bytes": len(b64d(data["backup_vault"]["blob"])),
            "backup_vault_nonce_hex": b64d(data["backup_vault"]["nonce"]).hex(),
        }

    @staticmethod
    def to_pretty_json(data: Any) -> str:
        return json.dumps(data, indent=2, ensure_ascii=False)
