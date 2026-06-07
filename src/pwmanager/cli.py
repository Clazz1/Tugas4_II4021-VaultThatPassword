"""Command-line interface for the distributed password manager."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from .app import PasswordManager


def _manager(args: argparse.Namespace) -> PasswordManager:
    return PasswordManager(local_dir=Path(args.local_dir), server_db=Path(args.server_db))


def _password(args: argparse.Namespace) -> str:
    if args.master_password is not None:
        return args.master_password
    return getpass.getpass("Master password: ")


def _print_entries(entries: list[dict]) -> None:
    if not entries:
        print("Vault kosong.")
        return
    for entry in entries:
        print(f"[{entry['id']}] {entry['nama_layanan']} | {entry['username']} | {entry['password']} | {entry.get('catatan', '')}")


def cmd_init(args: argparse.Namespace) -> int:
    result = _manager(args).init_user(args.user, _password(args))
    print("Vault berhasil dibuat.")
    print("Recovery share JSON, simpan aman dan jangan unggah ke server:")
    print(result["recovery_share_json"])
    print("Recovery share token:")
    print(result["recovery_share_token"])
    if args.show_debug:
        print("DEBUG master_key_hex:", result["master_key_hex"])
        print("DEBUG local_share:", result["local_share"])
        print("DEBUG server_share:", result["server_share"])
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    entries = _manager(args).list_entries(args.user, _password(args), args.backup, args.recovery_share)
    _print_entries(entries)
    return 0


def cmd_add(args: argparse.Namespace) -> int:
    entry = _manager(args).add_entry(
        user_id=args.user,
        master_password=_password(args),
        service=args.service,
        username=args.username,
        password=args.password,
        generated_length=args.generate,
        note=args.note or "",
    )
    print("Entry berhasil ditambahkan:")
    print(json.dumps(entry, indent=2, ensure_ascii=False))
    return 0


def cmd_update(args: argparse.Namespace) -> int:
    entry = _manager(args).update_entry(
        user_id=args.user,
        master_password=_password(args),
        entry_id=args.id,
        updates={
            "nama_layanan": args.service,
            "username": args.username,
            "password": args.password,
            "catatan": args.note,
        },
        generated_length=args.generate,
    )
    print("Entry berhasil diperbarui:")
    print(json.dumps(entry, indent=2, ensure_ascii=False))
    return 0


def cmd_delete(args: argparse.Namespace) -> int:
    _manager(args).delete_entry(args.user, _password(args), args.id)
    print("Entry berhasil dihapus.")
    return 0


def cmd_inspect_server(args: argparse.Namespace) -> int:
    print(_manager(args).to_pretty_json(_manager(args).inspect_server(args.user)))
    return 0


def cmd_inspect_local(args: argparse.Namespace) -> int:
    print(_manager(args).to_pretty_json(_manager(args).inspect_local(args.user)))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Password manager terdistribusi berbasis Shamir Secret Sharing.")
    parser.add_argument("--local-dir", default="client_data", help="direktori penyimpanan data lokal klien")
    parser.add_argument("--server-db", default="server_data/server.sqlite3", help="path SQLite server")

    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="buat vault baru")
    init.add_argument("--user", required=True)
    init.add_argument("--master-password")
    init.add_argument("--show-debug", action="store_true", help="tampilkan master key dan share untuk kebutuhan pengujian")
    init.set_defaults(func=cmd_init)

    list_cmd = sub.add_parser("list", help="lihat isi vault")
    list_cmd.add_argument("--user", required=True)
    list_cmd.add_argument("--master-password")
    list_cmd.add_argument("--backup", action="store_true", help="gunakan mode backup/local-only")
    list_cmd.add_argument("--recovery-share", help="recovery share JSON atau token untuk mode backup")
    list_cmd.set_defaults(func=cmd_list)

    add = sub.add_parser("add", help="tambah data password pada mode normal")
    add.add_argument("--user", required=True)
    add.add_argument("--master-password")
    add.add_argument("--service", required=True)
    add.add_argument("--username", required=True)
    add.add_argument("--password")
    add.add_argument("--generate", type=int, help="panjang password otomatis")
    add.add_argument("--note", default="")
    add.set_defaults(func=cmd_add)

    update = sub.add_parser("update", help="ubah data password pada mode normal")
    update.add_argument("--user", required=True)
    update.add_argument("--master-password")
    update.add_argument("--id", required=True)
    update.add_argument("--service")
    update.add_argument("--username")
    update.add_argument("--password")
    update.add_argument("--generate", type=int)
    update.add_argument("--note")
    update.set_defaults(func=cmd_update)

    delete = sub.add_parser("delete", help="hapus data password pada mode normal")
    delete.add_argument("--user", required=True)
    delete.add_argument("--master-password")
    delete.add_argument("--id", required=True)
    delete.set_defaults(func=cmd_delete)

    inspect_server = sub.add_parser("inspect-server", help="lihat data yang disimpan server")
    inspect_server.add_argument("--user", required=True)
    inspect_server.set_defaults(func=cmd_inspect_server)

    inspect_local = sub.add_parser("inspect-local", help="lihat ringkasan data lokal klien")
    inspect_local.add_argument("--user", required=True)
    inspect_local.set_defaults(func=cmd_inspect_local)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
