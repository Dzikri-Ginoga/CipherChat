"""Core cryptographic primitives for CipherChat Crypto (Phase 1 and Phase 2).

Implements:
- Salted PBKDF2-HMAC-SHA256 password hashing (Criterion 2)
- Classical Vigenere Cipher (alphabetic A-Z, a-z, DEC-03 Option A)
- Modern AES-128-GCM primitive (DEC-02 Option A)
- Text Super Encryption: Plaintext -> Vigenere -> AES-128-GCM -> Base64 (Criterion 3)
- File Vault Encryption: ChaCha20Poly1305 with a separate 32-byte key (Criterion 4)
- Database Column Encryption: AES-GCM with a separate DB column key (Criterion 5)
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from backend.config import MAX_UPLOAD_SIZE_BYTES, load_config

PBKDF2_ITERATIONS: int = 100_000
SALT_BYTE_LENGTH: int = 16
AES_GCM_NONCE_LENGTH: int = 12
AES_GCM_MIN_CIPHERTEXT_LENGTH: int = 12 + 16  # 12-byte nonce + 16-byte GCM tag
CHACHA20_NONCE_LENGTH: int = 12
CHACHA20_MIN_CIPHERTEXT_LENGTH: int = 12 + 16  # 12-byte nonce + 16-byte Poly1305 tag


# ---------------------------------------------------------------------------
# Phase 1: Salted SHA-256 Password Hashing (Criterion 2)
# ---------------------------------------------------------------------------


def generate_salt_hex() -> str:
    """Generate a random 16-byte salt encoded as a 32-character hexadecimal string."""
    return os.urandom(SALT_BYTE_LENGTH).hex()


def hash_password(password: str, salt_hex: str | None = None) -> tuple[str, str]:
    """Compute a salted PBKDF2-HMAC-SHA256 password hash.

    Returns:
        tuple[str, str]: (password_hash_hex, password_salt_hex)
    """
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string.")

    effective_salt_hex = (
        salt_hex.strip().lower() if salt_hex is not None else generate_salt_hex()
    )
    try:
        salt_bytes = bytes.fromhex(effective_salt_hex)
    except ValueError as exc:
        raise ValueError("Salt must be a valid hexadecimal string.") from exc

    if len(salt_bytes) < 8:
        raise ValueError("Salt must be at least 8 bytes long.")

    derived_bytes = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt_bytes,
        PBKDF2_ITERATIONS,
    )
    return derived_bytes.hex(), effective_salt_hex


def verify_password(password: str, stored_hash_hex: str, salt_hex: str) -> bool:
    """Verify a plaintext password against its stored hex hash and salt in constant time."""
    if (
        not isinstance(password, str)
        or not password
        or not isinstance(stored_hash_hex, str)
        or not stored_hash_hex
        or not isinstance(salt_hex, str)
        or not salt_hex
    ):
        return False

    try:
        computed_hash_hex, _ = hash_password(password, salt_hex=salt_hex)
    except ValueError:
        return False

    return hmac.compare_digest(
        computed_hash_hex.lower(), stored_hash_hex.strip().lower()
    )


# ---------------------------------------------------------------------------
# Phase 2.1: AES-128-GCM Primitive (DEC-02 Option A)
# ---------------------------------------------------------------------------


def _resolve_aes128_key(key: bytes | None = None) -> bytes:
    """Resolve and validate the 16-byte (128-bit) AES key for text encryption."""
    effective_key = key if key is not None else load_config().text_aes128_key
    if not isinstance(effective_key, (bytes, bytearray)) or len(effective_key) != 16:
        raise ValueError(
            f"AES-128 key must be strictly 16 bytes (128 bits), got {len(effective_key) if isinstance(effective_key, (bytes, bytearray)) else 'invalid type'}."
        )
    return bytes(effective_key)


def encrypt_aes128(plaintext: str, key: bytes | None = None) -> str:
    """Encrypt a UTF-8 plaintext string using AES-128-GCM and return Base64(nonce + ciphertext_with_tag)."""
    if not isinstance(plaintext, str):
        raise ValueError("Plaintext for AES-128 encryption must be a string.")
    aes_key = _resolve_aes128_key(key)
    nonce = os.urandom(AES_GCM_NONCE_LENGTH)
    ciphertext_with_tag = AESGCM(aes_key).encrypt(
        nonce, plaintext.encode("utf-8"), None
    )
    return base64.b64encode(nonce + ciphertext_with_tag).decode("ascii")


def decrypt_aes128(b64_ciphertext: str, key: bytes | None = None) -> str:
    """Decrypt a Base64(nonce + ciphertext_with_tag) string using AES-128-GCM."""
    if not isinstance(b64_ciphertext, str) or not b64_ciphertext.strip():
        raise ValueError("Ciphertext for AES-128 decryption must be a non-empty string.")
    aes_key = _resolve_aes128_key(key)

    try:
        raw = base64.b64decode(b64_ciphertext.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Invalid Base64 ciphertext for AES-128 decryption.") from exc

    if len(raw) < AES_GCM_MIN_CIPHERTEXT_LENGTH:
        raise ValueError("Ciphertext is too short to contain a valid AES-128-GCM payload.")

    nonce = raw[:AES_GCM_NONCE_LENGTH]
    ciphertext_with_tag = raw[AES_GCM_NONCE_LENGTH:]

    try:
        decrypted_bytes = AESGCM(aes_key).decrypt(nonce, ciphertext_with_tag, None)
    except InvalidTag as exc:
        raise ValueError(
            "AES-128-GCM decryption failed: wrong key or tampered ciphertext."
        ) from exc

    try:
        return decrypted_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Decrypted AES-128 payload is not valid UTF-8 text.") from exc


# ---------------------------------------------------------------------------
# Phase 2.1: Classical Vigenere Cipher (DEC-03 Option A: Alphabetic A-Z, a-z)
# ---------------------------------------------------------------------------


def _resolve_vigenere_key(vigenere_key: str | None = None) -> str:
    """Resolve and validate the uppercase alphabetic Vigenere key."""
    raw_key = (
        vigenere_key.strip().upper()
        if vigenere_key is not None
        else load_config().vigenere_key
    )
    if not raw_key or not raw_key.isascii() or not raw_key.isalpha():
        raise ValueError(
            "Vigenere key must be a non-empty ASCII alphabetic string (A-Z)."
        )
    return raw_key


def vigenere_encrypt(plaintext: str, vigenere_key: str | None = None) -> str:
    """Shift ASCII letters (A-Z, a-z) forward modulo 26 while preserving digits, spaces, and symbols."""
    if not isinstance(plaintext, str):
        raise ValueError("Plaintext for Vigenere encryption must be a string.")
    key = _resolve_vigenere_key(vigenere_key)
    key_len = len(key)
    k_idx = 0
    result_chars: list[str] = []

    for ch in plaintext:
        if "A" <= ch <= "Z":
            shift = ord(key[k_idx % key_len]) - ord("A")
            shifted = chr((ord(ch) - ord("A") + shift) % 26 + ord("A"))
            result_chars.append(shifted)
            k_idx += 1
        elif "a" <= ch <= "z":
            shift = ord(key[k_idx % key_len]) - ord("A")
            shifted = chr((ord(ch) - ord("a") + shift) % 26 + ord("a"))
            result_chars.append(shifted)
            k_idx += 1
        else:
            result_chars.append(ch)

    return "".join(result_chars)


def vigenere_decrypt(ciphertext: str, vigenere_key: str | None = None) -> str:
    """Reverse the alphabetic Vigenere shift modulo 26 while preserving digits, spaces, and symbols."""
    if not isinstance(ciphertext, str):
        raise ValueError("Ciphertext for Vigenere decryption must be a string.")
    key = _resolve_vigenere_key(vigenere_key)
    key_len = len(key)
    k_idx = 0
    result_chars: list[str] = []

    for ch in ciphertext:
        if "A" <= ch <= "Z":
            shift = ord(key[k_idx % key_len]) - ord("A")
            restored = chr((ord(ch) - ord("A") - shift) % 26 + ord("A"))
            result_chars.append(restored)
            k_idx += 1
        elif "a" <= ch <= "z":
            shift = ord(key[k_idx % key_len]) - ord("A")
            restored = chr((ord(ch) - ord("a") - shift) % 26 + ord("a"))
            result_chars.append(restored)
            k_idx += 1
        else:
            result_chars.append(ch)

    return "".join(result_chars)


# ---------------------------------------------------------------------------
# Phase 2.1: Text Super Encryption Pipeline (Vigenere + AES-128-GCM)
# ---------------------------------------------------------------------------


def super_encrypt(
    plaintext: str,
    vigenere_key: str | None = None,
    aes_key: bytes | None = None,
) -> str:
    """Super-encrypt chat text: Plaintext -> Vigenere Cipher -> AES-128-GCM -> Base64."""
    step1_vigenere = vigenere_encrypt(plaintext, vigenere_key=vigenere_key)
    return encrypt_aes128(step1_vigenere, key=aes_key)


def super_decrypt(
    b64_ciphertext: str,
    vigenere_key: str | None = None,
    aes_key: bytes | None = None,
) -> str:
    """Decrypt super-encrypted chat text: Base64 -> AES-128-GCM -> Vigenere Decrypt -> Plaintext."""
    step1_vigenere = decrypt_aes128(b64_ciphertext, key=aes_key)
    return vigenere_decrypt(step1_vigenere, vigenere_key=vigenere_key)


def inspect_super_encryption(
    plaintext: str,
    vigenere_key: str | None = None,
    aes_key: bytes | None = None,
) -> dict[str, str]:
    """Return intermediate transformations of text super encryption for lecturer inspection."""
    step1_vigenere = vigenere_encrypt(plaintext, vigenere_key=vigenere_key)
    step2_aes128_b64 = encrypt_aes128(step1_vigenere, key=aes_key)
    decrypted_back = super_decrypt(
        step2_aes128_b64, vigenere_key=vigenere_key, aes_key=aes_key
    )
    return {
        "plaintext": plaintext,
        "step1_vigenere": step1_vigenere,
        "step2_aes128_b64": step2_aes128_b64,
        "decrypted_back": decrypted_back,
    }


# ---------------------------------------------------------------------------
# Phase 2.2: File Vault Encryption (ChaCha20Poly1305, Criterion 4)
# ---------------------------------------------------------------------------


def _resolve_chacha20_key(key: bytes | None = None) -> bytes:
    """Resolve and validate the 32-byte (256-bit) ChaCha20 key for file encryption."""
    effective_key = key if key is not None else load_config().chacha20_key
    if not isinstance(effective_key, (bytes, bytearray)) or len(effective_key) != 32:
        raise ValueError(
            "ChaCha20 key must be strictly 32 bytes (256 bits)."
        )
    return bytes(effective_key)


def encrypt_file_chacha20(file_bytes: bytes, key: bytes | None = None) -> bytes:
    """Encrypt binary file bytes using ChaCha20Poly1305 and return (12-byte nonce + ciphertext_with_tag)."""
    if not isinstance(file_bytes, (bytes, bytearray)):
        raise ValueError("File payload for ChaCha20 encryption must be bytes.")
    if len(file_bytes) > MAX_UPLOAD_SIZE_BYTES:
        raise ValueError(
            f"Ukuran file melebihi batas maksimum ({MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)} MB)."
        )

    chacha_key = _resolve_chacha20_key(key)
    nonce = os.urandom(CHACHA20_NONCE_LENGTH)
    ciphertext_with_tag = ChaCha20Poly1305(chacha_key).encrypt(
        nonce, bytes(file_bytes), None
    )
    return nonce + ciphertext_with_tag


def decrypt_file_chacha20(encrypted_payload: bytes, key: bytes | None = None) -> bytes:
    """Decrypt binary (12-byte nonce + ciphertext_with_tag) using ChaCha20Poly1305."""
    if not isinstance(encrypted_payload, (bytes, bytearray)):
        raise ValueError("Encrypted file payload must be bytes.")
    if len(encrypted_payload) < CHACHA20_MIN_CIPHERTEXT_LENGTH:
        raise ValueError(
            "Encrypted file payload is too short to contain a valid ChaCha20Poly1305 stream."
        )

    chacha_key = _resolve_chacha20_key(key)
    nonce = bytes(encrypted_payload[:CHACHA20_NONCE_LENGTH])
    ciphertext_with_tag = bytes(encrypted_payload[CHACHA20_NONCE_LENGTH:])

    try:
        return ChaCha20Poly1305(chacha_key).decrypt(nonce, ciphertext_with_tag, None)
    except InvalidTag as exc:
        raise ValueError(
            "ChaCha20Poly1305 file decryption failed: wrong key or corrupted .enc file."
        ) from exc


# ---------------------------------------------------------------------------
# Phase 2.3: Database Column Encryption for Important Messages (Criterion 5)
# ---------------------------------------------------------------------------


def _resolve_db_column_key(key: bytes | None = None) -> bytes:
    """Resolve and validate the separate AES key for SQLite column encryption."""
    cfg = load_config()
    effective_key = key if key is not None else cfg.db_column_key
    if not isinstance(effective_key, (bytes, bytearray)) or len(effective_key) not in (16, 32):
        raise ValueError("Database column AES key must be 16 or 32 bytes long.")
    if bytes(effective_key) == cfg.text_aes128_key:
        raise ValueError(
            "Database column key must be distinct from the text AES-128 key."
        )
    return bytes(effective_key)


def encrypt_db_column(value: str, key: bytes | None = None) -> str:
    """Encrypt a database column string value using AES-GCM with the dedicated DB column key."""
    if not isinstance(value, str):
        raise ValueError("Database column value to encrypt must be a string.")
    db_key = _resolve_db_column_key(key)
    nonce = os.urandom(AES_GCM_NONCE_LENGTH)
    ciphertext_with_tag = AESGCM(db_key).encrypt(nonce, value.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext_with_tag).decode("ascii")


def decrypt_db_column(b64_ciphertext: str, key: bytes | None = None) -> str:
    """Decrypt a Base64-encoded database column value using AES-GCM with the dedicated DB column key."""
    if not isinstance(b64_ciphertext, str) or not b64_ciphertext.strip():
        raise ValueError("Encrypted database column value must be a non-empty string.")
    db_key = _resolve_db_column_key(key)

    try:
        raw = base64.b64decode(b64_ciphertext.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Invalid Base64 in encrypted database column.") from exc

    if len(raw) < AES_GCM_MIN_CIPHERTEXT_LENGTH:
        raise ValueError("Encrypted database column payload is too short.")

    nonce = raw[:AES_GCM_NONCE_LENGTH]
    ciphertext_with_tag = raw[AES_GCM_NONCE_LENGTH:]

    try:
        decrypted_bytes = AESGCM(db_key).decrypt(nonce, ciphertext_with_tag, None)
    except InvalidTag as exc:
        raise ValueError(
            "Database column decryption failed: wrong DB column key or tampered ciphertext."
        ) from exc

    try:
        return decrypted_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Decrypted database column value is not valid UTF-8.") from exc
