"""CLI utility to generate a USB hardware dongle key (auth.key) and print its SHA-256 hash."""

from __future__ import annotations

import argparse
import secrets
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.config import DEFAULT_DONGLE_FILENAME
from backend.core.dongle_auth import compute_dongle_token_hash


def generate_dongle_key(
    target_dir: str | Path,
    filename: str = DEFAULT_DONGLE_FILENAME,
) -> tuple[Path, str, str]:
    """Generate a 32-byte random hex token, write it to target_dir/filename, and return its SHA-256."""
    mount_path = Path(target_dir).resolve()
    mount_path.mkdir(parents=True, exist_ok=True)
    key_path = mount_path / filename

    raw_token = secrets.token_hex(32)
    key_path.write_text(raw_token + "\n", encoding="utf-8")
    token_hash_hex = compute_dongle_token_hash(raw_token)
    return key_path, raw_token, token_hash_hex


def main() -> int:
    """Parse CLI arguments and write auth.key to the target USB mountpoint."""
    parser = argparse.ArgumentParser(
        description="Generate a USB dongle auth.key file and print its SHA-256 hash."
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target USB flash drive mountpoint or directory path.",
    )
    parser.add_argument(
        "--filename",
        default=DEFAULT_DONGLE_FILENAME,
        help=f"Dongle key filename (default: {DEFAULT_DONGLE_FILENAME}).",
    )
    args = parser.parse_args()

    key_path, _, token_hash_hex = generate_dongle_key(
        target_dir=args.target,
        filename=args.filename,
    )
    print(f"Dongle key written to: {key_path}")
    print(f"SHA-256 Hash (dongle_token_hash_hex): {token_hash_hex}")
    print(
        f"For first-run bootstrap, set in .env:\n"
        f"CIPHERCHAT_DONGLE_BOOTSTRAP_HASH_HEX={token_hash_hex}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
