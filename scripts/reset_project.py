"""Reset CipherChat Crypto storage, database, files, and blockchain to initial state."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.config import (
    BIOMETRICS_DIR,
    DB_PATH,
    ENCRYPTED_FILES_DIR,
    STEGO_IMAGES_DIR,
    STORAGE_DIR,
)
from backend.database import ensure_storage_directories, init_db


def reset_environment(
    include_demo_users: bool = False,
    target_usb_drive: str | None = None,
) -> None:
    """Clear database, uploaded biometrics, encrypted files, and stego images."""
    ensure_storage_directories()

    # 1. Remove database file and journal/WAL files if present
    for db_file in [
        DB_PATH,
        STORAGE_DIR / "cipherchat.db-wal",
        STORAGE_DIR / "cipherchat.db-shm",
        STORAGE_DIR / "cipherchat.db-journal",
    ]:
        if db_file.exists():
            try:
                db_file.unlink()
                print(f"Dihapus: {db_file.name}")
            except OSError as exc:
                print(f"Peringatan: Gagal menghapus {db_file.name}: {exc}")

    # 2. Clean biometrics directory (preserve .gitkeep)
    if BIOMETRICS_DIR.is_dir():
        for file in BIOMETRICS_DIR.iterdir():
            if file.is_file() and file.name != ".gitkeep":
                try:
                    file.unlink()
                except OSError:
                    pass
        print("Direktori storage/biometrics/ dibersihkan.")

    # 3. Clean encrypted files directory (preserve .gitkeep)
    if ENCRYPTED_FILES_DIR.is_dir():
        for file in ENCRYPTED_FILES_DIR.iterdir():
            if file.is_file() and file.name != ".gitkeep":
                try:
                    file.unlink()
                except OSError:
                    pass
        print("Direktori storage/encrypted_files/ dibersihkan.")

    # 4. Clean stego images directory (preserve .gitkeep)
    if STEGO_IMAGES_DIR.is_dir():
        for file in STEGO_IMAGES_DIR.iterdir():
            if file.is_file() and file.name != ".gitkeep":
                try:
                    file.unlink()
                except OSError:
                    pass
        print("Direktori storage/stego_images/ dibersihkan.")

    # 5. Reinitialize fresh database schema with Genesis block (block_index = 0)
    init_db(db_path=DB_PATH)
    print("Basis data cipherchat.db berhasil diinisialisasi ulang (Genesis Block #0 siap).")

    # 6. Optionally load clean demo accounts (alice and bob)
    if include_demo_users:
        from scripts.prepare_demo import prepare_demo_environment

        info = prepare_demo_environment(
            base_storage_dir=STORAGE_DIR,
            db_path=DB_PATH,
            update_dotenv=True,
            target_usb_drive=target_usb_drive,
        )
        print("Akun demo bawaan (alice dan bob) berhasil disiapkan.")
        print(f"  Token Hash Dongle : {info['dongle_token_hash']}")
        print(f"  File Kunci Lokal  : {info['dongle_key_path']}")
        if "active_usb_path" in info:
            print(f"  File Kunci USB    : {info['active_usb_path']}")


def main(argv: list[str] | None = None) -> int:
    """Entry point for the reset script CLI."""
    parser = argparse.ArgumentParser(
        description="Reset CipherChat storage, database, files, and blockchain to initial state."
    )
    parser.add_argument(
        "--with-demo-users",
        action="store_true",
        help="Also register fresh demo users (alice & bob) with sample files.",
    )
    parser.add_argument(
        "--usb-drive",
        default=None,
        help="Target drive letter for USB flash drive (e.g. D: or E:) to sync auth.key.",
    )
    args = parser.parse_args(argv)

    print("Memulai reset lingkungan CipherChat Crypto...")
    reset_environment(
        include_demo_users=args.with_demo_users,
        target_usb_drive=args.usb_drive,
    )
    print("Reset selesai. Aplikasi kembali ke kondisi awal.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

