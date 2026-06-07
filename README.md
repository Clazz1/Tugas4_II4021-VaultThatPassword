# Vault That Password!

**Vault That Password!** adalah aplikasi CLI password manager terdistribusi untuk menyimpan data akun di dalam vault terenkripsi. Aplikasi ini dibuat untuk Tugas 4 II4021 Kriptografi dan menggabungkan AES-128-GCM, Shamir Secret Sharing `(2, 3)`, KDF `scrypt`, CSPRNG, SQLite, serta bonus kriptografi visual untuk recovery share.

Server hanya menyimpan ciphertext, nonce, metadata, dan satu server share. Proses kriptografi sensitif tetap dilakukan di sisi klien, sehingga kompromi server saja tidak cukup untuk membuka vault.

## Pembuat

| Nama | NIM | Kontak |
| --- | --- | --- |
| Muhammad Rafly Fauzan | 18223132 | 18223132@std.stei.itb.ac.id |
| M. Rakha Rabbani K. A. | 18223130 | 18223130@std.stei.itb.ac.id |

## Fitur Utama

- Vault password terenkripsi dengan AES-128-GCM.
- Master key dibagi menjadi `local share`, `server share`, dan `recovery share` menggunakan Shamir Secret Sharing `(2, 3)`.
- Local share dienkripsi menggunakan kunci hasil `scrypt(master_password, salt)`.
- Server SQLite hanya menyimpan data terenkripsi dan satu share.
- Mode normal: membuka vault dengan local share + server share.
- Mode backup: membuka vault lokal read-only dengan local share + recovery share.
- Tambah, ubah, hapus, dan lihat entry password.
- Pembangkitan password otomatis menggunakan CSPRNG.
- Bonus: recovery share dapat diubah menjadi QR code dan dibagi menjadi dua visual share `(2, 2)`.

## Tech Stack

| Komponen | Teknologi |
| --- | --- |
| Bahasa | Python 3.11+ |
| Penyimpanan server | SQLite via `sqlite3` |
| Enkripsi vault | AES-128-GCM pure Python |
| Secret sharing | Shamir Secret Sharing pada field `2^521 - 1` |
| KDF | `hashlib.scrypt` |
| Randomness | `secrets` |
| Bonus visual | `qrcode` + `Pillow` |
| Testing | `pytest` |

## Struktur Proyek

```text
.
|-- src/pwmanager/
|   |-- aes_gcm.py          # AES-128-GCM dan autentikasi tag
|   |-- app.py              # Alur utama aplikasi
|   |-- cli.py              # Command-line interface
|   |-- client_store.py     # Penyimpanan lokal klien
|   |-- kdf.py              # KDF scrypt
|   |-- passwords.py        # Generator password CSPRNG
|   |-- server_store.py     # Penyimpanan server SQLite
|   |-- shamir.py           # Shamir Secret Sharing
|   |-- vault.py            # Enkripsi/dekripsi vault
|   `-- visual_crypto.py    # Visual cryptography
|-- docs/
|   `-- 18223130_18223132_Tugas4_II4021.pdf
|-- tests/
|-- demo_flow.py
|-- pyproject.toml
`-- requirements.txt
```

## Instalasi

Dari root proyek, install dependency yang diperlukan:

```powershell
pip install -r requirements.txt
```

Aktifkan path source sebelum menjalankan command:

```powershell
$env:PYTHONPATH="src"
```

## Quick Start

Buat vault baru:

```powershell
python -m pwmanager init --user <user> --master-password "<password>" --show-debug
```

Simpan `Recovery share JSON` atau `Recovery share token` yang muncul. Recovery share dibutuhkan untuk mode backup.

Tambah password manual:

```powershell
python -m pwmanager add --user <user> --master-password "<password>" --service GitHub --username raka@example.com --password "<password>" --note "manual password"
```

Tambah password otomatis dengan CSPRNG:

```powershell
python -m pwmanager add --user <user> --master-password "<password>" --service "Portal Kampus" --username 18223130 --generate 16 --note "password otomatis"
```

Lihat isi vault mode normal:

```powershell
python -m pwmanager list --user <user> --master-password "<password>"
```

## Command Penting

Inspect data server:

```powershell
python -m pwmanager inspect-server --user <user>
```

Inspect data lokal:

```powershell
python -m pwmanager inspect-local --user <user>
```

Update entry:

```powershell
python -m pwmanager update --user <user> --master-password "<password>" --id <entry_id> --note "catatan baru"
```

Delete entry:

```powershell
python -m pwmanager delete --user <user> --master-password "<password>" --id <entry_id>
```

Mode backup:

```powershell
python -m pwmanager list --user <user> --master-password "<password>" --backup --recovery-share "<recovery_share_json_atau_token>"
```

Catatan PowerShell: jika memakai recovery share JSON inline, escape tanda kutip ganda dengan `\"`. Cara paling mudah adalah memakai recovery share token `SSS1...`.

## Kriptografi Visual

Buat QR recovery share dan dua visual share:

```powershell
python -m pwmanager visual-split --recovery-share "<recovery_share_token>" --out-dir docs/visual_demo
```

Output yang dihasilkan:

- `recovery_share_qr.png`
- `recovery_share_visual_share_1.png`
- `recovery_share_visual_share_2.png`
- `recovery_share_combined_overlay.png`
- `recovery_share_combined_qr.png`

Gabungkan dua visual share secara manual:

```powershell
python -m pwmanager visual-combine --share-1 docs/visual_demo/recovery_share_visual_share_1.png --share-2 docs/visual_demo/recovery_share_visual_share_2.png --overlay-out docs/visual_demo/manual_overlay.png --qr-out docs/visual_demo/manual_qr.png
```

Jika input berupa token `SSS1...`, QR hasil scan akan berisi recovery share JSON yang ekuivalen dan tetap dapat dipakai pada mode backup.

## Demo

Jalankan skenario demo end-to-end:

```powershell
python demo_flow.py
```

Demo mencakup pembuatan vault, pembagian share, inspeksi server/lokal, penolakan master password salah, tambah password manual, tambah password CSPRNG, update, delete, mode backup, bonus kriptografi visual, dan kegagalan pemulihan.

## Testing

```powershell
python -m pytest -q
```

Test yang tersedia:

- AES-128 block test vector.
- AES-GCM test vector untuk plaintext kosong dan satu blok.
- Deteksi modifikasi ciphertext melalui tag GCM.
- Rekonstruksi Shamir dari kombinasi dua share.
- Flow normal dan backup.
- Penolakan master password salah.
- Pembuatan visual share `(2, 2)` dan QR hasil gabungan yang dapat didecode.

## Model Keamanan

Server tidak pernah menerima atau menyimpan:

- Master key utuh.
- Local share.
- Recovery share.
- Isi vault plaintext.
- Password pengguna plaintext.
- Kunci turunan master password.

Server hanya menyimpan:

- `server_share`
- `vault_blob` sebagai BLOB SQLite
- `vault_nonce`
- metadata aplikasi

Local share disimpan di klien setelah dienkripsi menggunakan kunci hasil `scrypt`. Backup vault lokal juga tetap berupa ciphertext AES-128-GCM.
