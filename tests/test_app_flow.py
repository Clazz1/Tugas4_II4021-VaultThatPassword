from pathlib import Path

from pwmanager.aes_gcm import InvalidTag
from pwmanager.app import PasswordManager


def test_normal_and_backup_flow(tmp_path: Path):
    manager = PasswordManager(tmp_path / "client", tmp_path / "server.sqlite3")
    init = manager.init_user("raka", "master-benar")

    entry = manager.add_entry(
        user_id="raka",
        master_password="master-benar",
        service="GitHub",
        username="raka@example.com",
        password="manual-pass",
        generated_length=None,
        note="akun utama",
    )
    entries = manager.list_entries("raka", "master-benar")
    assert entries[0]["id"] == entry["id"]

    backup_entries = manager.list_entries(
        "raka",
        "master-benar",
        backup=True,
        recovery_share_text=init["recovery_share_json"],
    )
    assert backup_entries[0]["nama_layanan"] == "GitHub"

    server_view = manager.inspect_server("raka")
    assert server_view["vault_blob_type"] == "BLOB"
    assert "manual-pass" not in str(server_view)


def test_wrong_master_password_is_rejected(tmp_path: Path):
    manager = PasswordManager(tmp_path / "client", tmp_path / "server.sqlite3")
    manager.init_user("raka", "master-benar")
    try:
        manager.list_entries("raka", "master-salah")
    except InvalidTag:
        pass
    else:
        raise AssertionError("wrong master password should not unlock local share")
