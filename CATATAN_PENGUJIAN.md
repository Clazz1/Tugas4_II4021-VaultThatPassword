# Catatan Pengujian Tugas 4 II4021

Dokumen ini membantu menjalankan dan merekam pengujian dari uji pembuatan vault sampai uji kegagalan pemulihan. Semua command dijalankan dari folder proyek:

```powershell
cd C:\Users\USER\Documents\Codex\2026-06-07\files-mentioned-by-the-user-tugas4\outputs\tugas4_password_manager
```

Untuk pengujian manual yang bersih, gunakan folder khusus berikut:

```powershell
$env:PYTHONPATH="src"
$LOCAL="uji_manual/client"
$DB="uji_manual/server.sqlite3"
$USER="raka"
$PASS="master-benar"
```

Catatan penting:

- Simpan `recovery_share_json` yang muncul pada langkah 1 ke variabel atau file catatan sementara.
- Jangan pakai mode backup untuk tambah, ubah, atau hapus data. Mode backup memang read-only.
- Jika ingin demo otomatis, jalankan `python demo_flow.py`. Namun checklist di bawah lebih cocok untuk video karena setiap bukti bisa ditunjukkan satu per satu.

## 1. Uji Pembuatan Vault

Tujuan: membuktikan vault baru berhasil dibuat, master key dibangkitkan, vault kosong dienkripsi, dan master key dibagi menjadi tiga share.

Command:

```powershell
python -m pwmanager --local-dir $LOCAL --server-db $DB init --user $USER --master-password $PASS --show-debug
```

Yang perlu ditunjukkan:

- Output `Vault berhasil dibuat.`
- `DEBUG master_key_hex` muncul sebagai bukti master key dibangkitkan.
- `DEBUG local_share`, `DEBUG server_share`, dan `Recovery share JSON` muncul sebagai bukti skema Shamir `(2, 3)`.
- Recovery share memuat `x` dan `y`, misalnya `"x":3` dan `"y":"0x..."`.

Simpan recovery share dari output. Contoh:

```powershell
$RECOVERY='{"scheme":"SSS-P521","threshold":2,"label":"recovery","x":3,"y":"0x..."}'
```

## 2. Uji Penyimpanan Server

Tujuan: membuktikan server hanya menyimpan server share, vault terenkripsi, nonce vault, dan metadata.

Command:

```powershell
python -m pwmanager --local-dir $LOCAL --server-db $DB inspect-server --user $USER
```

Yang perlu ditunjukkan:

- Ada `server_share`.
- Ada `vault_blob_type` bernilai `BLOB`.
- Ada `vault_blob_bytes`, bukan isi vault plaintext.
- Ada `vault_nonce_hex`.
- Tidak ada nama layanan, username, password, atau catatan plaintext.

Analisis singkat untuk video:

Server tidak menyimpan master key, local share, recovery share, atau isi vault plaintext. Server hanya menyimpan ciphertext dan satu share, sehingga server saja tidak cukup untuk membuka vault.

## 3. Uji Penyimpanan dan Perlindungan Local Share

Tujuan: membuktikan local share tidak disimpan dalam bentuk asli dan dilindungi master password.

Command inspeksi lokal:

```powershell
python -m pwmanager --local-dir $LOCAL --server-db $DB inspect-local --user $USER
```

Yang perlu ditunjukkan:

- Ada parameter KDF `scrypt`.
- Ada `local_share_blob_bytes`, bukan local share plaintext.
- Ada `local_share_nonce_hex`.
- Ada `backup_vault_blob_bytes`.

Command master password benar:

```powershell
python -m pwmanager --local-dir $LOCAL --server-db $DB list --user $USER --master-password $PASS
```

Ekspektasi:

- Vault bisa dibuka.
- Jika belum ada entry, output `Vault kosong.`

Command master password salah:

```powershell
python -m pwmanager --local-dir $LOCAL --server-db $DB list --user $USER --master-password "master-salah"
```

Ekspektasi:

- Akses ditolak.
- Biasanya muncul error `AES-GCM authentication failed`.

## 4. Uji Akses Normal

Tujuan: membuktikan mode normal memakai local share dan server share untuk membuka vault.

Command:

```powershell
python -m pwmanager --local-dir $LOCAL --server-db $DB list --user $USER --master-password $PASS
```

Yang perlu ditunjukkan:

- Dengan master password benar, vault dapat dibuka.
- Pada mode normal, data vault diambil dari server SQLite.
- Jika password salah, local share gagal dibuka dan data password tidak ditampilkan.

Analisis singkat untuk video:

Mode normal merekonstruksi master key dari local share dan server share. Setelah master key valid, vault didekripsi memakai AES-128-GCM.

## 5. Uji Penambahan Data Password

Tujuan: membuktikan penambahan manual dan pembangkitan otomatis CSPRNG berhasil, serta vault dienkripsi ulang.

Tambahkan password manual:

```powershell
python -m pwmanager --local-dir $LOCAL --server-db $DB add --user $USER --master-password $PASS --service GitHub --username raka@example.com --password "manual-pass" --note "akun utama"
```

Tambahkan password otomatis:

```powershell
python -m pwmanager --local-dir $LOCAL --server-db $DB add --user $USER --master-password $PASS --service "Portal Kampus" --username 18222000 --generate 16 --note "password CSPRNG"
```

Lihat isi vault:

```powershell
python -m pwmanager --local-dir $LOCAL --server-db $DB list --user $USER --master-password $PASS
```

Yang perlu ditunjukkan:

- Entry GitHub muncul dengan password manual.
- Entry Portal Kampus muncul dengan password otomatis panjang 16 karakter.
- Password otomatis berisi karakter acak dari CSPRNG.

Bukti nonce berubah setelah update:

```powershell
python -m pwmanager --local-dir $LOCAL --server-db $DB inspect-server --user $USER
python -m pwmanager --local-dir $LOCAL --server-db $DB inspect-local --user $USER
```

Yang perlu ditunjukkan:

- `vault_blob_bytes` berubah setelah isi vault bertambah.
- `vault_nonce_hex` tersedia untuk enkripsi vault terbaru.
- `backup_vault_blob_bytes` menunjukkan backup lokal juga diperbarui.

## 6. Uji Pengubahan dan Penghapusan Data Password

Tujuan: membuktikan entry bisa diubah dan dihapus pada mode normal.

Ambil `entry_id` dari output `list`, misalnya:

```powershell
$ENTRY_ID="<id_entry_github>"
```

Ubah catatan entry:

```powershell
python -m pwmanager --local-dir $LOCAL --server-db $DB update --user $USER --master-password $PASS --id $ENTRY_ID --note "akun utama diperbarui"
```

Lihat hasil:

```powershell
python -m pwmanager --local-dir $LOCAL --server-db $DB list --user $USER --master-password $PASS
```

Yang perlu ditunjukkan:

- Catatan berubah menjadi `akun utama diperbarui`.

Hapus entry lain, misalnya entry Portal Kampus:

```powershell
$DELETE_ID="<id_entry_portal_kampus>"
python -m pwmanager --local-dir $LOCAL --server-db $DB delete --user $USER --master-password $PASS --id $DELETE_ID
```

Lihat hasil:

```powershell
python -m pwmanager --local-dir $LOCAL --server-db $DB list --user $USER --master-password $PASS
```

Yang perlu ditunjukkan:

- Entry yang dihapus tidak muncul lagi.
- Update dan delete hanya dilakukan pada mode normal.

## 7. Uji Penyimpanan Vault di Server

Tujuan: membuktikan server menyimpan vault sebagai BLOB dan tidak menyimpan data plaintext terpisah.

Command:

```powershell
python -m pwmanager --local-dir $LOCAL --server-db $DB inspect-server --user $USER
```

Yang perlu ditunjukkan:

- `vault_blob_type` bernilai `BLOB`.
- Tidak ada `GitHub`, `Portal Kampus`, `raka@example.com`, `manual-pass`, atau catatan plaintext pada output server.
- Server tidak menampilkan master key, local share, recovery share, atau kunci turunan master password.

Analisis singkat untuk video:

Data password hanya ada dalam vault plaintext setelah berhasil didekripsi di klien. Di SQLite server, vault tersimpan sebagai ciphertext.

## 8. Uji Mode Backup

Tujuan: membuktikan backup mode memakai local share dan recovery share, tidak mengambil vault dari server, dan hanya dapat melihat data.

Command:

```powershell
python -m pwmanager --local-dir $LOCAL --server-db $DB list --user $USER --master-password $PASS --backup --recovery-share $RECOVERY
```

Yang perlu ditunjukkan:

- Data password dapat dilihat.
- Mode backup memakai recovery share.
- Sumber vault adalah backup lokal terenkripsi.
- Tidak ada command add, update, atau delete dengan opsi `--backup`.

Analisis singkat untuk video:

Pada mode backup, master key direkonstruksi dari local share dan recovery share. Karena mode ini read-only, aplikasi tidak memperbarui server atau backup lokal untuk menghindari konflik versi.

## 9. Uji Kegagalan Pemulihan

Tujuan: membuktikan recovery share salah atau backup vault yang rusak tidak akan membuka data password.

### 9.1 Recovery Share Salah

Buat recovery share salah dengan mengubah nilai `x` atau `y` dari recovery share asli.

Contoh:

```powershell
$BAD_RECOVERY=$RECOVERY.Replace('"x":3','"x":99')
python -m pwmanager --local-dir $LOCAL --server-db $DB list --user $USER --master-password $PASS --backup --recovery-share $BAD_RECOVERY
```

Ekspektasi:

- Akses gagal.
- Data password tidak ditampilkan.
- Error dapat berupa kegagalan rekonstruksi secret atau kegagalan autentikasi AES-GCM.

### 9.2 Backup Vault Dimodifikasi

Untuk video, cukup jelaskan bahwa backup vault berisi ciphertext AES-GCM. Jika blob backup di file lokal diubah, authentication tag tidak cocok dan dekripsi gagal.

Cara menunjukkan tanpa merusak data utama:

1. Buka file lokal di folder `uji_manual/client`.
2. Tunjukkan field `backup_vault.blob`.
3. Jelaskan bahwa field itu adalah ciphertext dan tag.
4. Jika satu karakter blob diubah, AES-GCM akan menolak dekripsi karena tag tidak valid.

Ekspektasi:

- Vault tidak terbuka.
- Password tidak ditampilkan.

## Ringkasan Urutan Video Demo

1. Jalankan `init --show-debug`.
2. Simpan recovery share.
3. Jalankan `inspect-server`.
4. Jalankan `inspect-local`.
5. Jalankan `list` dengan password benar.
6. Jalankan `list` dengan password salah.
7. Jalankan `add` manual.
8. Jalankan `add --generate 16`.
9. Jalankan `list`.
10. Jalankan `update`.
11. Jalankan `delete`.
12. Jalankan `inspect-server` lagi.
13. Jalankan `list --backup --recovery-share $RECOVERY`.
14. Jalankan backup dengan recovery share salah.

Kalimat penutup yang bisa dipakai:

Implementasi memenuhi prinsip zero-knowledge karena server hanya menyimpan server share, nonce, metadata, dan vault ciphertext. Master key direkonstruksi di sisi klien dari dua share valid, sedangkan AES-128-GCM memastikan vault yang salah kunci atau sudah dimodifikasi tidak dapat dibuka.
