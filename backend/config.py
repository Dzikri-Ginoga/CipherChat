"""Configuration loader for CipherChat Crypto."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
ENV_FILE_PATH: Path = PROJECT_ROOT / ".env"
ENV_EXAMPLE_PATH: Path = PROJECT_ROOT / ".env.example"

STORAGE_DIR: Path = PROJECT_ROOT / "storage"
DB_PATH: Path = STORAGE_DIR / "cipherchat.db"
BIOMETRICS_DIR: Path = STORAGE_DIR / "biometrics"
ENCRYPTED_FILES_DIR: Path = STORAGE_DIR / "encrypted_files"
STEGO_IMAGES_DIR: Path = STORAGE_DIR / "stego_images"

MAX_UPLOAD_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB

DEFAULT_TEXT_AES128_KEY_HEX: str = "00112233445566778899aabbccddeeff"
DEFAULT_VIGENERE_KEY: str = "CIPHERCHATKEY"
DEFAULT_DB_COLUMN_KEY_HEX: str = "ffeeddccbbaa99887766554433221100"
DEFAULT_CHACHA20_KEY_HEX: str = (
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
)
DEFAULT_DONGLE_FILENAME: str = "auth.key"
DEFAULT_FACE_MATCH_THRESHOLD: float = 0.75
DEFAULT_POW_DIFFICULTY: int = 0


def _parse_env_file_fallback(env_path: Path) -> None:
    """Load key=value pairs from .env if python-dotenv is not installed."""
    if not env_path.exists():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _ensure_env_loaded() -> None:
    """Load environment variables from .env or .env.example."""
    target_path = ENV_FILE_PATH if ENV_FILE_PATH.exists() else ENV_EXAMPLE_PATH
    in_pytest = "PYTEST_CURRENT_TEST" in os.environ
    if load_dotenv is not None and target_path.exists():
        load_dotenv(dotenv_path=target_path, override=not in_pytest)
    elif target_path.exists():
        _parse_env_file_fallback(target_path)


@dataclass(frozen=True)
class AppConfig:
    """Validated runtime configuration for CipherChat Crypto."""

    text_aes128_key: bytes
    vigenere_key: str
    db_column_key: bytes
    chacha20_key: bytes
    dongle_filename: str
    dongle_bootstrap_hash_hex: str
    dongle_mock_dir: str
    face_match_threshold: float
    pow_difficulty: int
    max_upload_size_bytes: int


def _decode_hex_key(raw_hex: str, key_name: str, allowed_byte_lengths: tuple[int, ...]) -> bytes:
    """Decode and validate a hexadecimal key string."""
    cleaned = raw_hex.strip()
    try:
        key_bytes = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"{key_name} must be a valid hexadecimal string.") from exc
    if len(key_bytes) not in allowed_byte_lengths:
        expected_str = " or ".join(str(length) for length in allowed_byte_lengths)
        raise ValueError(
            f"{key_name} must be {expected_str} bytes long (got {len(key_bytes)} bytes)."
        )
    return key_bytes


def load_config() -> AppConfig:
    """Load and validate all keys and settings from environment variables."""
    _ensure_env_loaded()

    text_aes_hex = os.environ.get(
        "CIPHERCHAT_TEXT_AES128_KEY_HEX", DEFAULT_TEXT_AES128_KEY_HEX
    )
    vigenere_key = os.environ.get(
        "CIPHERCHAT_VIGENERE_KEY", DEFAULT_VIGENERE_KEY
    ).strip().upper()
    db_col_hex = os.environ.get(
        "CIPHERCHAT_DB_COLUMN_KEY_HEX", DEFAULT_DB_COLUMN_KEY_HEX
    )
    chacha20_hex = os.environ.get(
        "CIPHERCHAT_CHACHA20_KEY_HEX", DEFAULT_CHACHA20_KEY_HEX
    )

    text_aes128_key = _decode_hex_key(
        text_aes_hex, "CIPHERCHAT_TEXT_AES128_KEY_HEX", (16,)
    )
    db_column_key = _decode_hex_key(
        db_col_hex, "CIPHERCHAT_DB_COLUMN_KEY_HEX", (16, 32)
    )
    chacha20_key = _decode_hex_key(
        chacha20_hex, "CIPHERCHAT_CHACHA20_KEY_HEX", (32,)
    )

    if not vigenere_key or not vigenere_key.isalpha():
        raise ValueError(
            "CIPHERCHAT_VIGENERE_KEY must be a non-empty alphabetic string (A-Z)."
        )

    if (
        text_aes128_key == db_column_key
        or text_aes128_key == chacha20_key
        or db_column_key == chacha20_key
        or text_aes_hex.strip().lower() == db_col_hex.strip().lower()
        or text_aes_hex.strip().lower() == chacha20_hex.strip().lower()
        or db_col_hex.strip().lower() == chacha20_hex.strip().lower()
    ):
        raise ValueError(
            "Text AES key, database column key, and file ChaCha20 key must be distinct."
        )

    dongle_filename = (
        os.environ.get("CIPHERCHAT_DONGLE_FILENAME", DEFAULT_DONGLE_FILENAME).strip()
        or DEFAULT_DONGLE_FILENAME
    )
    dongle_bootstrap_hash_hex = (
        os.environ.get("CIPHERCHAT_DONGLE_BOOTSTRAP_HASH_HEX", "").strip().lower()
    )
    dongle_mock_dir = os.environ.get("CIPHERCHAT_DONGLE_MOCK_DIR", "").strip()

    raw_threshold = os.environ.get(
        "CIPHERCHAT_FACE_MATCH_THRESHOLD", str(DEFAULT_FACE_MATCH_THRESHOLD)
    ).strip()
    try:
        face_match_threshold = float(raw_threshold)
    except ValueError as exc:
        raise ValueError(
            "CIPHERCHAT_FACE_MATCH_THRESHOLD must be a float between 0.0 and 1.0."
        ) from exc
    if not (0.0 <= face_match_threshold <= 1.0):
        raise ValueError(
            "CIPHERCHAT_FACE_MATCH_THRESHOLD must be between 0.0 and 1.0."
        )

    raw_pow = os.environ.get(
        "CIPHERCHAT_POW_DIFFICULTY", str(DEFAULT_POW_DIFFICULTY)
    ).strip()
    try:
        pow_difficulty = int(raw_pow)
    except ValueError as exc:
        raise ValueError("CIPHERCHAT_POW_DIFFICULTY must be a non-negative integer.") from exc
    if pow_difficulty < 0:
        raise ValueError("CIPHERCHAT_POW_DIFFICULTY must be >= 0.")

    return AppConfig(
        text_aes128_key=text_aes128_key,
        vigenere_key=vigenere_key,
        db_column_key=db_column_key,
        chacha20_key=chacha20_key,
        dongle_filename=dongle_filename,
        dongle_bootstrap_hash_hex=dongle_bootstrap_hash_hex,
        dongle_mock_dir=dongle_mock_dir,
        face_match_threshold=face_match_threshold,
        pow_difficulty=pow_difficulty,
        max_upload_size_bytes=MAX_UPLOAD_SIZE_BYTES,
    )
