"""CLI utility to update a user's dongle_token_hash_hex from the currently mounted USB auth.key."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.database import init_db
from backend.repositories.user_repo import update_user_dongle_hash


def main(argv: list[str] | None = None) -> int:
    """Prompt for password confirmation and update the user's USB dongle token hash in SQLite."""
    parser = argparse.ArgumentParser(
        description="Perbarui dongle_token_hash_hex pengguna dari auth.key yang sedang terpasang."
    )
    parser.add_argument(
        "--username",
        default=None,
        help="Username akun yang akan diperbarui dongle-nya.",
    )
    parser.add_argument(
        "--password",
        default=None,
        help="Kata sandi pengguna untuk konfirmasi (jika dikosongkan akan diminta secara interaktif).",
    )
    parser.add_argument(
        "--db-path",
        default=None,
        help="Lokasi file database SQLite opsional.",
    )
    parser.add_argument(
        "--mock-dir",
        default=None,
        help="Direktori dongle opsional (kosongkan untuk memindai flashdisk USB asli).",
    )
    args = parser.parse_args(argv)

    username = (args.username or "").strip()
    if not username:
        username = input("Masukkan username: ").strip()

    password = args.password
    if password is None:
        password = getpass.getpass(
            f"Masukkan kata sandi untuk pengguna '{username}': "
        )

    db_path = Path(args.db_path) if args.db_path else None
    init_db(db_path=db_path)

    try:
        result = update_user_dongle_hash(
            username=username,
            password=password,
            db_path=db_path,
            mock_dongle_dir=args.mock_dir,
        )
    except (ValueError, PermissionError) as exc:
        print(f"Gagal memperbarui dongle pengguna: {exc}")
        return 1

    print(
        f"Dongle untuk pengguna '{result['user']['username']}' berhasil diperbarui."
    )
    print(f"Lokasi USB terdeteksi : {result['mountpoint']}")
    print(f"SHA-256 Token Hash    : {result['dongle_token_hash_hex']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

