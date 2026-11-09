"""Lossless PNG Least Significant Bit (LSB) steganography engine for CipherChat Crypto.

Covers lecturer criterion 6 (image messages secured with steganography) and DEC-09 Option A
(plaintext secret message embedded into RGB LSB of lossless PNG).
"""

from __future__ import annotations

import io
import math
from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image

STEGO_DELIMITER: str = "$$CIPHERCHAT_EOF$$"
_DELIMITER_BYTES: bytes = STEGO_DELIMITER.encode("utf-8")


def _load_rgb_pixels(image_source: bytes | str | Path) -> np.ndarray:
    """Open an image from bytes or path, convert to RGB, and return a uint8 numpy array."""
    if isinstance(image_source, (str, Path)):
        src_path = Path(image_source)
        if not src_path.is_file():
            raise FileNotFoundError(f"Citra sumber tidak ditemukan: {src_path}")
        pil_img = Image.open(src_path).convert("RGB")
    elif isinstance(image_source, (bytes, bytearray)):
        if len(image_source) == 0:
            raise ValueError("Data citra kosong.")
        try:
            pil_img = Image.open(io.BytesIO(image_source)).convert("RGB")
        except Exception as exc:
            raise ValueError("Format citra tidak valid.") from exc
    else:
        raise ValueError("Tipe input citra tidak didukung.")

    return np.asarray(pil_img, dtype=np.uint8)


def _compute_image_metrics(
    orig_pixels: np.ndarray, stego_pixels: np.ndarray
) -> tuple[float, int]:
    """Calculate PSNR (in dB) and maximum absolute pixel delta between original and stego RGB arrays."""
    diff = stego_pixels.astype(np.int16) - orig_pixels.astype(np.int16)
    max_delta = int(np.max(np.abs(diff))) if diff.size > 0 else 0
    mse = float(np.mean(diff.astype(np.float64) ** 2))
    if mse == 0.0:
        psnr_db = 100.0
    else:
        psnr_db = round(float(10.0 * math.log10((255.0**2) / mse)), 2)
    return psnr_db, max_delta


def embed_lsb(
    input_image: bytes | str | Path,
    secret_text: str,
    output_path: str | Path,
) -> dict[str, Any]:
    """Embed a UTF-8 secret message into the Least Significant Bits of an RGB image and save as PNG.

    Args:
        input_image: Source image path or raw image bytes.
        secret_text: Secret text message to hide (DEC-09 Option A: plaintext).
        output_path: Destination file path; MUST have a .png extension.

    Returns:
        Dictionary containing output_path, capacity_bits, used_bits, psnr_db, max_pixel_delta,
        width, and height.
    """
    if not isinstance(secret_text, str) or not secret_text:
        raise ValueError("Pesan rahasia untuk steganografi tidak boleh kosong.")

    out_path = Path(output_path)
    if out_path.suffix.lower() != ".png":
        raise ValueError(
            "Output steganografi wajib menggunakan format lossless .png (bukan JPEG)."
        )

    orig_pixels = _load_rgb_pixels(input_image)
    height, width, channels = orig_pixels.shape

    full_text = secret_text + STEGO_DELIMITER
    payload_bytes = full_text.encode("utf-8")
    payload_uint8 = np.frombuffer(payload_bytes, dtype=np.uint8)
    binary_bits = np.unpackbits(payload_uint8)

    flat_pixels = orig_pixels.flatten().copy()
    capacity_bits = int(flat_pixels.size)
    used_bits = int(binary_bits.size)

    if used_bits > capacity_bits:
        raise ValueError(
            "Kapasitas citra PNG tidak mencukupi untuk panjang pesan ini."
        )

    # Modify the Least Significant Bit of the first N sub-pixels:
    # flat_pixels[i] = (flat_pixels[i] & 0xFE) | int(bit)
    flat_pixels[:used_bits] = (flat_pixels[:used_bits] & 0xFE) | binary_bits

    stego_pixels = flat_pixels.reshape((height, width, channels))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    Image.fromarray(stego_pixels, mode="RGB").save(
        out_path, format="PNG", compress_level=6
    )

    psnr_db, max_pixel_delta = _compute_image_metrics(orig_pixels, stego_pixels)

    return {
        "output_path": str(out_path),
        "width": int(width),
        "height": int(height),
        "capacity_bits": capacity_bits,
        "used_bits": used_bits,
        "psnr_db": psnr_db,
        "max_pixel_delta": max_pixel_delta,
    }


def extract_lsb(stego_image: bytes | str | Path) -> str:
    """Extract a UTF-8 secret message hidden in the LSBs of a lossless PNG image."""
    stego_pixels = _load_rgb_pixels(stego_image)
    flat_pixels = stego_pixels.flatten()

    num_Complete_bytes = int(flat_pixels.size // 8)
    if num_Complete_bytes < len(_DELIMITER_BYTES):
        raise ValueError(
            "Tidak ditemukan payload steganografi CipherChat pada citra ini."
        )

    lsb_bits = flat_pixels[: num_Complete_bytes * 8] & 1
    packed_bytes = np.packbits(lsb_bits).tobytes()

    delimiter_index = packed_bytes.find(_DELIMITER_BYTES)
    if delimiter_index == -1:
        raise ValueError(
            "Tidak ditemukan payload steganografi CipherChat pada citra ini."
        )

    secret_bytes = packed_bytes[:delimiter_index]
    try:
        return secret_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(
            "Tidak ditemukan payload steganografi CipherChat pada citra ini."
        ) from exc
