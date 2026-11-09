"""Prepare sample files, mock USB dongle, .env keys, and demo users for the Lecturer Demo."""

from __future__ import annotations

import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
from PIL import Image

from backend.core.dongle_auth import compute_dongle_token_hash
from backend.database import ensure_storage_directories, init_db
from backend.repositories.user_repo import get_user_by_username, register_user
from scripts.generate_dongle_key import generate_dongle_key


def _make_synthetic_face_png(seed: int, output_path: Path) -> bytes:
    """Create a deterministic 200x200 RGB PNG face pattern for OpenCV biometric demo."""
    rng = np.random.default_rng(seed)
    base = rng.integers(35, 215, size=(200, 200, 3), dtype=np.uint8)
    base[60:80, 50:80] = 20
    base[60:80, 120:150] = 20
    base[130:145, 70:130] = 40
    output_path.parent.mkdir(parents=True, exist_ok=True)
    Image.fromarray(base, mode="RGB").save(output_path, format="PNG")
    return output_path.read_bytes()


def _make_sample_cover_png(output_path: Path) -> bytes:
    """Create a lossless 256x256 RGB PNG cover image for LSB steganography demo."""
    rng = np.random.default_rng(303)
    arr = rng.integers(20, 235, size=(256, 256, 3), dtype=np.uint8)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    Image.fromarray(arr, mode="RGB").save(output_path, format="PNG")
    return output_path.read_bytes()


def _make_sample_pdf(output_path: Path) -> bytes:
    """Create a valid minimal PDF file (laporan.pdf) for ChaCha20 file encryption demo."""
    pdf_bytes = (
        b"%PDF-1.4\n"
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 300 144] /Contents 4 0 R >> endobj\n"
        b"4 0 obj << /Length 55 >> stream\n"
        b"BT /F1 14 Tf 20 100 Td (Laporan Rahasia CipherChat 2026) Tj ET\n"
        b"endstream endobj\n"
        b"xref\n0 5\n0000000000 65535 f \n"
        b"trailer << /Root 1 0 R /Size 5 >>\nstartxref\n250\n%%EOF\n"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(pdf_bytes)
    return pdf_bytes


def _update_env_file(env_path: Path, bootstrap_hash: str, mock_dir_rel: str) -> None:
    """Update CIPHERCHAT_DONGLE_BOOTSTRAP_HASH_HEX and CIPHERCHAT_DONGLE_MOCK_DIR in .env."""
    if not env_path.is_file():
        return
    text = env_path.read_text(encoding="utf-8")
    text = re.sub(
        r"^CIPHERCHAT_DONGLE_BOOTSTRAP_HASH_HEX=.*$",
        f"CIPHERCHAT_DONGLE_BOOTSTRAP_HASH_HEX={bootstrap_hash}",
        text,
        flags=re.MULTILINE,
    )
    text = re.sub(
        r"^CIPHERCHAT_DONGLE_MOCK_DIR=.*$",
        f"CIPHERCHAT_DONGLE_MOCK_DIR={mock_dir_rel}",
        text,
        flags=re.MULTILINE,
    )
    env_path.write_text(text, encoding="utf-8")


def prepare_demo_environment(
    base_storage_dir: Path | None = None,
    db_path: Path | None = None,
    update_dotenv: bool = True,
) -> dict[str, str]:
    """Set up USB dongle, sample files, SQLite tables, and demo accounts (alice & bob)."""
    storage_root = Path(base_storage_dir) if base_storage_dir is not None else (PROJECT_ROOT / "storage")
    demo_dir = storage_root / "demo_samples"
    usb_dir = storage_root / "mock_usb"
    bio_dir = storage_root / "biometrics"

    ensure_storage_directories()
    demo_dir.mkdir(parents=True, exist_ok=True)
    usb_dir.mkdir(parents=True, exist_ok=True)
    bio_dir.mkdir(parents=True, exist_ok=True)

    # 1. Create or reuse USB dongle auth.key
    key_file = usb_dir / "auth.key"
    if key_file.is_file() and key_file.read_text(encoding="utf-8").strip():
        raw_token = key_file.read_text(encoding="utf-8").strip()
        token_hash = compute_dongle_token_hash(raw_token)
    else:
        key_file, raw_token, token_hash = generate_dongle_key(usb_dir)

    if update_dotenv:
        _update_env_file(
            PROJECT_ROOT / ".env",
            bootstrap_hash=token_hash,
            mock_dir_rel="",
        )

    # 2. Create sample files for the 5 demo steps
    alice_face_path = demo_dir / "face_alice.png"
    bob_face_path = demo_dir / "face_bob.png"
    cover_png_path = demo_dir / "cover_demo.png"
    pdf_path = demo_dir / "laporan.pdf"

    alice_face_bytes = _make_synthetic_face_png(101, alice_face_path)
    bob_face_bytes = _make_synthetic_face_png(202, bob_face_path)
    _make_sample_cover_png(cover_png_path)
    _make_sample_pdf(pdf_path)

    # 3. Initialize SQLite database and register demo users alice and bob
    init_db(db_path=db_path)

    if get_user_by_username("alice", db_path=db_path) is None:
        register_user(
            username="alice",
            password="AlicePassword123!",
            face_image_bytes=alice_face_bytes,
            db_path=db_path,
            biometrics_dir=bio_dir,
            mock_dongle_dir=usb_dir,
        )

    if get_user_by_username("bob", db_path=db_path) is None:
        register_user(
            username="bob",
            password="BobPassword123!",
            face_image_bytes=bob_face_bytes,
            db_path=db_path,
            biometrics_dir=bio_dir,
            mock_dongle_dir=usb_dir,
        )

    return {
        "dongle_key_path": str(key_file),
        "dongle_token_hash": token_hash,
        "face_alice_path": str(alice_face_path),
        "face_bob_path": str(bob_face_path),
        "cover_png_path": str(cover_png_path),
        "pdf_path": str(pdf_path),
    }


if __name__ == "__main__":
    info = prepare_demo_environment()
    print("=== Lingkup Demo CipherChat Crypto Siap ===")
    for k, v in info.items():
        print(f"  {k}: {v}")
