"""Gated application launcher for CipherChat Crypto (enforces Gate 0 USB Dongle check)."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.config import load_config
from backend.core.dongle_auth import enforce_startup_dongle_gate
from backend.database import init_db
from backend.repositories.user_repo import get_all_dongle_hashes


def verify_gate_before_launch(
    mock_dir: str | Path | None = None,
    db_path: Path | None = None,
) -> None:
    """Verify that a valid USB dongle is present before starting any server process."""
    cfg = load_config()
    init_db(db_path=db_path)
    registered_hashes = get_all_dongle_hashes(db_path=db_path)
    enforce_startup_dongle_gate(
        expected_hashes=registered_hashes if registered_hashes else None,
        bootstrap_hash_hex=cfg.dongle_bootstrap_hash_hex,
        dongle_filename=cfg.dongle_filename,
        mock_dir=mock_dir,
    )


def main(argv: list[str] | None = None) -> int:
    """Run the gated launcher: exit with code 1 if no valid USB dongle is mounted."""
    parser = argparse.ArgumentParser(description="Gated launcher for CipherChat Crypto.")
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Verify dongle gate and exit without spawning server processes.",
    )
    parser.add_argument(
        "--backend-only",
        action="store_true",
        help="Launch only the FastAPI Uvicorn server.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8501,
        help="Port for the Streamlit UI (default: 8501).",
    )
    parser.add_argument(
        "--db-path",
        default=None,
        help="Optional override path for SQLite database.",
    )
    args = parser.parse_args(argv)

    try:
        verify_gate_before_launch(
            db_path=Path(args.db_path) if args.db_path else None
        )
    except PermissionError as exc:
        print(str(exc))
        return 1
    except Exception as exc:
        print(f"Gagal memulai aplikasi: {exc}")
        return 1

    print("USB Dongle (auth.key) terdeteksi. Memulai CipherChat Crypto...")
    if args.check_only:
        return 0

    if args.backend_only:
        cmd = [
            sys.executable,
            "-m",
            "uvicorn",
            "backend.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            "8000",
        ]
    else:
        streamlit_script = PROJECT_ROOT / "frontend_streamlit" / "app.py"
        cmd = [
            sys.executable,
            "-m",
            "streamlit",
            "run",
            str(streamlit_script),
            "--server.port",
            str(args.port),
        ]

    return subprocess.call(cmd, cwd=str(PROJECT_ROOT))


if __name__ == "__main__":
    raise SystemExit(main())
