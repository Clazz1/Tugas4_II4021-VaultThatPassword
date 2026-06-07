"""Automated demonstration flow for the assignment video."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from pwmanager.app import PasswordManager
from pwmanager.visual_crypto import create_visual_recovery_share


DEMO_DIR = ROOT / "demo_workspace"


def show(title: str, value) -> None:
    print(f"\n=== {title} ===")
    if isinstance(value, (dict, list)):
        print(json.dumps(value, indent=2, ensure_ascii=False))
    else:
        print(value)


def main() -> None:
    if DEMO_DIR.exists():
        shutil.rmtree(DEMO_DIR)
    manager = PasswordManager(DEMO_DIR / "client", DEMO_DIR / "server.sqlite3")

    init = manager.init_user("raka", "master-benar")
    show("Vault dibuat dan recovery share ditampilkan sekali", {
        "master_key_hex_untuk_pengujian": init["master_key_hex"],
        "local_share": init["local_share"],
        "server_share": init["server_share"],
        "recovery_share_json": init["recovery_share_json"],
    })

    show("Server hanya menyimpan ciphertext, nonce, metadata, dan server share", manager.inspect_server("raka"))
    show("Local share dan backup vault tersimpan terenkripsi di klien", manager.inspect_local("raka"))

    try:
        manager.list_entries("raka", "master-salah")
    except Exception as exc:
        show("Master password salah ditolak", type(exc).__name__)

    entry_1 = manager.add_entry("raka", "master-benar", "GitHub", "raka@example.com", "manual-pass", None, "akun utama")
    show("Tambah password manual", entry_1)

    entry_2 = manager.add_entry("raka", "master-benar", "Portal Kampus", "18222000", None, 16, "dibangkitkan CSPRNG")
    show("Tambah password otomatis CSPRNG", entry_2)
    show("Isi vault mode normal", manager.list_entries("raka", "master-benar"))

    updated = manager.update_entry("raka", "master-benar", entry_1["id"], {"catatan": "akun utama diperbarui"}, None)
    show("Ubah data password", updated)

    manager.delete_entry("raka", "master-benar", entry_2["id"])
    show("Hapus data password", manager.list_entries("raka", "master-benar"))

    show(
        "Mode backup memakai local share + recovery share",
        manager.list_entries("raka", "master-benar", backup=True, recovery_share_text=init["recovery_share_json"]),
    )

    visual = create_visual_recovery_share(
        recovery_share_text=init["recovery_share_token"],
        out_dir=DEMO_DIR / "visual_crypto",
    )
    show("Bonus kriptografi visual recovery share", visual.to_json())

    bad_recovery = init["recovery_share_json"].replace('"x":3', '"x":99')
    try:
        manager.list_entries("raka", "master-benar", backup=True, recovery_share_text=bad_recovery)
    except Exception as exc:
        show("Recovery share salah ditolak", type(exc).__name__)


if __name__ == "__main__":
    main()
