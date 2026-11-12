"""Utility to synchronize USB hardware dongle auth.key with CipherChat storage and database."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import psutil

from backend.config import DB_PATH, DEFAULT_DONGLE_FILENAME, STORAGE_DIR, _ensure_env_loaded
from backend.core.dongle_auth import compute_dongle_token_hash
from backend.database import get_connection
from scripts.generate_dongle_key import generate_dongle_key


def get_removable_drives() -> list[Path]:
    """Find all mounted drives detected as removable by the operating system."""
    removable: list[Path] = []
    try:
        for part in psutil.disk_partitions(all=False):
            if not part.mountpoint:
                continue
            opts = (part.opts or "").lower()
            if "removable" in opts:
                removable.append(Path(part.mountpoint))
    except Exception:
        pass
    return removable


def update_env_bootstrap_hash(token_hash: str) -> None:
    """Update CIPHERCHAT_DONGLE_BOOTSTRAP_HASH_HEX in .env file."""
    env_path = PROJECT_ROOT / ".env"
    if not env_path.is_file():
        return
    text = env_path.read_text(encoding="utf-8")
    new_text = re.sub(
        r"^CIPHERCHAT_DONGLE_BOOTSTRAP_HASH_HEX=.*$",
        f"CIPHERCHAT_DONGLE_BOOTSTRAP_HASH_HEX={token_hash}",
        text,
        flags=re.MULTILINE,
    )
    env_path.write_text(new_text, encoding="utf-8")


def update_demo_users_dongle_hash(token_hash: str, usernames: tuple[str, ...] = ("alice", "bob")) -> int:
    """Update dongle_token_hash_hex for specified users in SQLite database."""
    if not DB_PATH.is_file():
        return 0
    conn = get_connection()
    try:
        with conn:
            cursor = conn.execute(
                f"UPDATE users SET dongle_token_hash_hex = ? WHERE username IN ({','.join('?' for _ in usernames)})",
                (token_hash, *usernames),
            )
            return cursor.rowcount
    finally:
        conn.close()


def sync_dongle(
    target_drive: str | None = None,
    action: str = "status",
) -> int:
    """Synchronize or report status of auth.key between mock storage and USB flash drive."""
    _ensure_env_loaded()
    mock_dir = STORAGE_DIR / "mock_usb"
    mock_dir.mkdir(parents=True, exist_ok=True)
    mock_key = mock_dir / DEFAULT_DONGLE_FILENAME

    removable_drives = get_removable_drives()

    # Determine effective target drive
    target_path: Path | None = None
    if target_drive:
        clean_drive = target_drive.strip().rstrip("\\/")
        target_path = Path(clean_drive + "\\")
    elif removable_drives:
        target_path = removable_drives[0]

    # Read mock key if present
    mock_token: str | None = None
    mock_hash: str | None = None
    if mock_key.is_file():
        content = mock_key.read_text(encoding="utf-8").strip()
        if content:
            mock_token = content
            mock_hash = compute_dongle_token_hash(content)

    print("=== Status Sinkronisasi USB Dongle CipherChat ===")
    print(f"File Kunci Lokal : {mock_key}")
    print(f"Token Hash Lokal : {mock_hash or '(Belum ada)'}")

    if target_path:
        usb_key = target_path / DEFAULT_DONGLE_FILENAME
        print(f"Drive USB Target : {target_path}")
        print(f"File Kunci USB   : {usb_key}")
        usb_token: str | None = None
        usb_hash: str | None = None
        usb_file_accessible = False
        try:
            if usb_key.is_file():
                usb_file_accessible = True
                ucontent = usb_key.read_text(encoding="utf-8").strip()
                if ucontent:
                    usb_token = ucontent
                    usb_hash = compute_dongle_token_hash(ucontent)
        except (OSError, ValueError) as err:
            print(f"Peringatan: Drive/file USB tidak dapat diakses ({err})")
        print(f"Token Hash USB   : {usb_hash or '(Belum ada / tidak dapat diakses)'}")
    else:
        usb_key = None
        print("Drive USB Target : Tidak ada drive removable terdeteksi otomatis.")
        print("Petunjuk: Anda dapat menyertakan opsi --drive X: (contoh: --drive D: atau --drive E:).")

    if action == "to-usb":
        if not mock_token or not mock_hash:
            print("Error: File lokal storage/mock_usb/auth.key belum ada. Buat atau reset terlebih dahulu.")
            return 1
        if not target_path or not usb_key:
            print("Error: Drive USB target belum ditentukan atau tidak ditemukan.")
            return 1
        try:
            usb_key.write_text(mock_token + "\n", encoding="utf-8")
            print(f"Sukses: Kunci auth.key berhasil disalin ke USB drive ({usb_key}).")
            print(f"Token Hash: {mock_hash}")
        except OSError as exc:
            print(f"Error: Gagal menulis auth.key ke USB drive: {exc}")
            return 1
        return 0

    if action == "from-usb":
        if not target_path or not usb_key:
            print("Error: Drive USB target belum ditentukan atau tidak ditemukan.")
            return 1
        try:
            if not usb_key.is_file():
                print(f"Error: File auth.key pada USB target ({usb_key}) tidak ditemukan.")
                return 1
            raw = usb_key.read_text(encoding="utf-8").strip()
            if not raw:
                print("Error: File auth.key pada USB kosong.")
                return 1
            thash = compute_dongle_token_hash(raw)
            mock_key.write_text(raw + "\n", encoding="utf-8")
            update_env_bootstrap_hash(thash)
            updated_count = update_demo_users_dongle_hash(thash)
            print(f"Sukses: Kunci USB berhasil disinkronkan ke storage/mock_usb/auth.key.")
            print(f"Token Hash: {thash}")
            print(f"Bootstrap .env diperbarui.")
            print(f"Akun demo di database diperbarui: {updated_count} akun.")
        except (OSError, ValueError) as exc:
            print(f"Error: Gagal memproses file USB: {exc}")
            return 1
        return 0

    if action == "generate":
        # Generate new key in mock_dir and write to USB if available
        mock_key, raw_token, thash = generate_dongle_key(mock_dir)
        update_env_bootstrap_hash(thash)
        updated_count = update_demo_users_dongle_hash(thash)
        print(f"Kunci baru berhasil dibuat: {thash}")
        print(f"File lokal diperbarui: {mock_key}")
        print(f"Bootstrap .env diperbarui.")
        print(f"Akun demo di database diperbarui: {updated_count} akun.")
        if target_path and usb_key:
            try:
                usb_key.write_text(raw_token + "\n", encoding="utf-8")
                print(f"Kunci baru juga disalin ke USB drive: {usb_key}")
            except OSError as exc:
                print(f"Peringatan: Gagal menyalin ke USB drive: {exc}")
        return 0

    # Default action: status
    env_bootstrap = os.environ.get("CIPHERCHAT_DONGLE_BOOTSTRAP_HASH_HEX", "").strip().lower()
    print(f".env Bootstrap   : {env_bootstrap or '(Kosong)'}")

    if target_path and usb_key and usb_file_accessible:
        if usb_hash and mock_hash and usb_hash.lower() == mock_hash.lower():
            print("Status Kecocokan : Sesuai (Flashdisk dan lokal memiliki token yang sama).")
        else:
            print("Status Kecocokan : BERBEDA! Flashdisk dan lokal memiliki token yang berbeda.")
            print("Solusi:")
            print(f"  - Untuk menyalin kunci lokal ke Flashdisk: python scripts/sync_dongle.py --to-usb --drive {target_path}")
            print(f"  - Untuk menyalin kunci Flashdisk ke aplikasi: python scripts/sync_dongle.py --from-usb --drive {target_path}")
    elif target_path:
        print("Status Flashdisk : File auth.key belum ada atau tidak dapat diakses di Flashdisk.")
        print(f"Solusi: Colokkan Flashdisk yang valid dan jalankan 'python scripts/sync_dongle.py --to-usb --drive {target_path}'")

    return 0


def main() -> int:
    """CLI entry point for dongle sync utility."""
    parser = argparse.ArgumentParser(
        description="Sinkronisasi kunci USB Dongle (auth.key) antara Flashdisk dan CipherChat."
    )
    parser.add_argument(
        "--drive",
        help="Drive letter Flashdisk USB (misal: D: atau E:).",
        default=None,
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--to-usb",
        action="store_true",
        help="Salin auth.key dari storage/mock_usb ke Flashdisk.",
    )
    group.add_argument(
        "--from-usb",
        action="store_true",
        help="Gunakan auth.key yang sudah ada di Flashdisk dan sinkronkan ke aplikasi/database.",
    )
    group.add_argument(
        "--generate",
        action="store_true",
        help="Buat token acak baru, simpan ke lokal dan Flashdisk, lalu perbarui database.",
    )
    args = parser.parse_args()

    action = "status"
    if args.to_usb:
        action = "to-usb"
    elif args.from_usb:
        action = "from-usb"
    elif args.generate:
        action = "generate"

    return sync_dongle(target_drive=args.drive, action=action)


if __name__ == "__main__":
    raise SystemExit(main())
