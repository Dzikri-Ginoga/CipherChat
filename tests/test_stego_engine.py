"""Unit tests for Phase 3 PNG LSB Steganography (stego_engine.py and IMAGE messages)."""

from __future__ import annotations

import io
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import pytest
from PIL import Image

from backend.core.stego_engine import embed_lsb, extract_lsb
from backend.database import init_db
from backend.repositories.message_repo import reveal_image_message, send_image_message
from backend.repositories.user_repo import register_user
from scripts.generate_dongle_key import generate_dongle_key


def _create_synthetic_rgb_png(
    width: int = 256, height: int = 256, seed: int = 123
) -> tuple[bytes, np.ndarray]:
    """Create a synthetic RGB PNG image in memory and return its bytes and uint8 array."""
    rng = np.random.default_rng(seed)
    pixels = rng.integers(10, 245, size=(height, width, 3), dtype=np.uint8)
    buf = io.BytesIO()
    Image.fromarray(pixels, mode="RGB").save(buf, format="PNG")
    return buf.getvalue(), pixels


def test_embed_and_extract_500_char_message_and_pixel_delta(tmp_path: Path) -> None:
    """Create 256x256 RGB PNG, embed 500-char message, reload, verify extract_lsb() and max pixel delta <= 1."""
    png_bytes, orig_pixels = _create_synthetic_rgb_png(256, 256, seed=42)
    base_phrase = "Rahasia Kriptografi Steganografi LSB Citra PNG Lossless 2026 - "
    secret_500 = (base_phrase * 9)[:500]
    assert len(secret_500) == 500

    stego_path = tmp_path / "stego_256x256.png"
    metrics = embed_lsb(png_bytes, secret_500, stego_path)

    assert stego_path.is_file()
    assert metrics["width"] == 256
    assert metrics["height"] == 256
    assert metrics["capacity_bits"] == 256 * 256 * 3
    assert metrics["max_pixel_delta"] <= 1
    assert metrics["psnr_db"] > 50.0

    # Reload from disk and verify pixel delta <= 1 directly on arrays
    reloaded_pixels = np.asarray(Image.open(stego_path).convert("RGB"), dtype=np.uint8)
    max_diff = int(
        np.max(np.abs(reloaded_pixels.astype(np.int16) - orig_pixels.astype(np.int16)))
    )
    assert max_diff <= 1

    # Verify exact round-trip extraction
    extracted = extract_lsb(stego_path)
    assert extracted == secret_500


def test_embed_capacity_overflow_raises_value_error(tmp_path: Path) -> None:
    """Verify embedding a payload larger than width * height * 3 bits raises ValueError."""
    # 8x8 RGB image has only 8 * 8 * 3 = 192 sub-pixels (24 bytes total capacity)
    tiny_png_bytes, _ = _create_synthetic_rgb_png(width=8, height=8, seed=7)
    oversized_message = "Pesan ini jauh melebihi kapasitas 24 byte dari citra 8x8 piksel."

    with pytest.raises(
        ValueError, match="Kapasitas citra PNG tidak mencukupi untuk panjang pesan ini."
    ):
        embed_lsb(tiny_png_bytes, oversized_message, tmp_path / "overflow.png")


def test_extract_from_clean_image_raises_value_error(tmp_path: Path) -> None:
    """Verify extraction from a clean image (no stego payload) raises ValueError."""
    clean_png_bytes, _ = _create_synthetic_rgb_png(width=64, height=64, seed=99)
    clean_path = tmp_path / "clean.png"
    clean_path.write_bytes(clean_png_bytes)

    with pytest.raises(
        ValueError,
        match="Tidak ditemukan payload steganografi CipherChat pada citra ini.",
    ):
        extract_lsb(clean_path)


def test_jpeg_output_extension_rejected_and_message_repo_image_flow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify non-PNG output is rejected and IMAGE message repository round-trip works per DEC-09."""
    png_bytes, _ = _create_synthetic_rgb_png(128, 128, seed=55)

    with pytest.raises(ValueError, match="lossless .png"):
        embed_lsb(png_bytes, "Pesan", tmp_path / "bad_output.jpg")

    test_db = tmp_path / "stego_repo.db"
    bio_dir = tmp_path / "biometrics"
    stego_dir = tmp_path / "stego_images"
    usb_dir = tmp_path / "usb_drive"
    init_db(test_db)

    generate_dongle_key(usb_dir)
    monkeypatch.setenv("CIPHERCHAT_DONGLE_MOCK_DIR", str(usb_dir))

    alice = register_user(
        "alice", "Pass123!", png_bytes, db_path=test_db, biometrics_dir=bio_dir, mock_dongle_dir=usb_dir
    )
    bob = register_user(
        "bob", "Pass123!", png_bytes, db_path=test_db, biometrics_dir=bio_dir, mock_dongle_dir=usb_dir
    )
    charlie = register_user(
        "charlie", "Pass123!", png_bytes, db_path=test_db, biometrics_dir=bio_dir, mock_dongle_dir=usb_dir
    )

    secret = "Titik kumpul darurat berada di Gedung Kriptografi Lantai 3."
    sent_img = send_image_message(
        sender_id=alice["id"],
        recipient_id=bob["id"],
        cover_image=png_bytes,
        secret_message=secret,
        db_path=test_db,
        stego_images_dir=stego_dir,
    )
    assert sent_img["msg_type"] == "IMAGE"
    assert sent_img["storage_layers"] == "STEGO"
    assert sent_img["max_pixel_delta"] <= 1

    revealed = reveal_image_message(
        sent_img["id"], requesting_user_id=bob["id"], db_path=test_db
    )
    assert revealed["secret_message"] == secret

    # Unauthorized user (charlie) cannot reveal Alice->Bob image message
    with pytest.raises(PermissionError):
        reveal_image_message(
            sent_img["id"], requesting_user_id=charlie["id"], db_path=test_db
        )
