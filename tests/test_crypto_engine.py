"""Unit tests for Phase 1 & Phase 2 cryptographic primitives and message_repo.py."""

from __future__ import annotations

import io
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import pytest
from PIL import Image

from backend.config import load_config
from backend.core.crypto_engine import (
    decrypt_aes128,
    decrypt_db_column,
    decrypt_file_chacha20,
    encrypt_aes128,
    encrypt_db_column,
    encrypt_file_chacha20,
    generate_salt_hex,
    hash_password,
    inspect_super_encryption,
    super_decrypt,
    super_encrypt,
    verify_password,
    vigenere_decrypt,
    vigenere_encrypt,
)
from backend.database import init_db
from backend.repositories.message_repo import (
    download_decrypted_file_message,
    get_decrypted_message,
    get_file_raw_preview,
    get_raw_ciphertext_message,
    inspect_stored_text_message,
    send_file_message,
    send_text_message,
)
from backend.repositories.user_repo import register_user
from scripts.generate_dongle_key import generate_dongle_key


def test_verify_password_correct_wrong_and_altered_salt() -> None:
    """Verify verify_password() returns True for correct password and False for wrong password or altered salt."""
    password = "KriptografiSemester5!#2026"
    hash_hex, salt_hex = hash_password(password)

    assert len(salt_hex) == 32
    assert len(hash_hex) == 64

    assert verify_password(password, hash_hex, salt_hex) is True
    assert verify_password("SalahPassword123", hash_hex, salt_hex) is False

    altered_salt = ("f" if salt_hex[0] != "f" else "0") + salt_hex[1:]
    assert verify_password(password, hash_hex, altered_salt) is False

    hash_hex_2, salt_hex_2 = hash_password(password)
    assert salt_hex != salt_hex_2
    assert hash_hex != hash_hex_2
    assert len(generate_salt_hex()) == 32


def test_aes128_roundtrip_indonesian_punctuation_and_multiline() -> None:
    """Verify decrypt_aes128(encrypt_aes128(text)) == text for Indonesian sentences, punctuation, and multiline."""
    samples = [
        "Rapat proyek besok jam 09.30 di ruang B2.",
        "Pengujian tanda baca: !@#$%^&*()_+-=[]{};':\",./<>?`~\\|",
        "Baris pertama laporan kriptografi\nBaris kedua: 12345/ABC-DEF\nBaris ketiga: selesai.",
    ]
    for sample in samples:
        ct1 = encrypt_aes128(sample)
        ct2 = encrypt_aes128(sample)
        # Nonce is random per encryption
        assert ct1 != ct2
        assert decrypt_aes128(ct1) == sample
        assert decrypt_aes128(ct2) == sample


def test_vigenere_roundtrip_and_manual_lecturer_example() -> None:
    """Verify vigenere_decrypt(vigenere_encrypt(text)) == text and check known manual calculation."""
    # Manual calculation check:
    # Plaintext: "XYZ 123 abc!", Key: "ABC" (shifts: A=0, B=1, C=2)
    # 'X' + 0 -> 'X'
    # 'Y' + 1 -> 'Z'
    # 'Z' + 2 -> 'B'
    # ' 123 ' -> unchanged, key index does not advance on non-letters
    # 'a' + 0 -> 'a'
    # 'b' + 1 -> 'c'
    # 'c' + 2 -> 'e'
    # '!' -> '!'
    manual_plain = "XYZ 123 abc!"
    manual_cipher = vigenere_encrypt(manual_plain, vigenere_key="ABC")
    assert manual_cipher == "XZB 123 ace!"
    assert vigenere_decrypt(manual_cipher, vigenere_key="ABC") == manual_plain

    # Second manual check with default key "CIPHERCHATKEY" on "Rapat 09.30"
    # 'R'(17) + 'C'(2) = 19 ('T')
    # 'a'(0)  + 'I'(8) = 8  ('i')
    # 'p'(15) + 'P'(15)= 4  ('e')
    # 'a'(0)  + 'H'(7) = 7  ('h')
    # 't'(19) + 'E'(4) = 23 ('x')
    assert vigenere_encrypt("Rapat 09.30", vigenere_key="CIPHERCHATKEY") == "Tiehx 09.30"
    assert vigenere_decrypt("Tiehx 09.30", vigenere_key="CIPHERCHATKEY") == "Rapat 09.30"

    complex_text = "Rapat Proyek Kriptografi: 09/11/2026 pukul 14:30 WIB (Ruang B-204)!"
    enc = vigenere_encrypt(complex_text)
    assert enc != complex_text
    assert vigenere_decrypt(enc) == complex_text


def test_super_encryption_roundtrip_and_inspection() -> None:
    """Verify super_decrypt(super_encrypt(text)) == text with mixed case, digits, slashes, and punctuation."""
    text = "Jadwal Sidang Akhir: 15/12/2026 @ Ruang Lab-03 (Kode: KRIPTO-99) & Status: Siap!"
    cipher_b64 = super_encrypt(text)
    assert cipher_b64 != text
    assert super_decrypt(cipher_b64) == text

    inspection = inspect_super_encryption(text)
    assert inspection["plaintext"] == text
    assert inspection["step1_vigenere"] == vigenere_encrypt(text)
    assert inspection["decrypted_back"] == text
    assert decrypt_aes128(inspection["step2_aes128_b64"]) == inspection["step1_vigenere"]


def test_file_chacha20_roundtrip_binary_and_tamper_detection() -> None:
    """Verify decrypt_file_chacha20(encrypt_file_chacha20(file_bytes)) == file_bytes for PDF and random binary."""
    pdf_like_bytes = (
        b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        + os.urandom(4096)
        + b"\n%%EOF\n"
    )
    encrypted_pdf = encrypt_file_chacha20(pdf_like_bytes)
    assert encrypted_pdf != pdf_like_bytes
    assert len(encrypted_pdf) == 12 + len(pdf_like_bytes) + 16
    assert decrypt_file_chacha20(encrypted_pdf) == pdf_like_bytes

    random_bytes = os.urandom(8192)
    assert decrypt_file_chacha20(encrypt_file_chacha20(random_bytes)) == random_bytes

    # Tampering with encrypted file bytes must raise ValueError
    tampered = bytearray(encrypted_pdf)
    tampered[-1] ^= 0xFF
    with pytest.raises(ValueError, match="ChaCha20Poly1305"):
        decrypt_file_chacha20(bytes(tampered))

    # Wrong 32-byte key must raise ValueError
    wrong_chacha_key = b"\xff" * 32
    with pytest.raises(ValueError, match="ChaCha20Poly1305"):
        decrypt_file_chacha20(encrypted_pdf, key=wrong_chacha_key)


def test_db_column_encryption_roundtrip_and_random_nonce() -> None:
    """Verify decrypt_db_column(encrypt_db_column(text)) == text and nonces produce distinct ciphertexts."""
    secret_col_text = "Pesan sangat rahasia untuk disimpan pada kolom body_stored SQLite."
    c1 = encrypt_db_column(secret_col_text)
    c2 = encrypt_db_column(secret_col_text)

    assert c1 != c2
    assert decrypt_db_column(c1) == secret_col_text
    assert decrypt_db_column(c2) == secret_col_text


def test_distinct_keys_at_config_load_and_wrong_key_raises_value_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify keys are distinct at config load and decrypting with the wrong key raises ValueError."""
    cfg = load_config()
    assert cfg.text_aes128_key != cfg.db_column_key
    assert cfg.text_aes128_key != cfg.chacha20_key
    assert cfg.db_column_key != cfg.chacha20_key

    # Encrypt text with text_aes128_key, attempt to decrypt with db_column_key -> ValueError
    ciphertext = encrypt_aes128("Pesan uji kunci salah")
    with pytest.raises(ValueError, match="AES-128-GCM decryption failed"):
        decrypt_aes128(ciphertext, key=cfg.db_column_key)

    # Encrypt DB column with db_column_key, attempt to decrypt with a wrong 16-byte key -> ValueError
    col_cipher = encrypt_db_column("Data kolom penting")
    wrong_db_key = bytes.fromhex("11223344556677889900aabbccddeeff")
    with pytest.raises(ValueError, match="Database column decryption failed"):
        decrypt_db_column(col_cipher, key=wrong_db_key)

    # Setting identical text and DB column keys in env must raise ValueError at config load
    same_key_hex = "00112233445566778899aabbccddeeff"
    monkeypatch.setenv("CIPHERCHAT_TEXT_AES128_KEY_HEX", same_key_hex)
    monkeypatch.setenv("CIPHERCHAT_DB_COLUMN_KEY_HEX", same_key_hex)
    with pytest.raises(ValueError, match="distinct"):
        load_config()


def test_message_repo_text_important_and_file_messages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify message_repo stores and reads TEXT, Important TEXT (SUPER+DBCOL), and FILE (CHACHA20)."""
    test_db = tmp_path / "repo_messages.db"
    bio_dir = tmp_path / "biometrics"
    enc_files_dir = tmp_path / "encrypted_files"
    usb_dir = tmp_path / "usb_drive"
    init_db(test_db)

    generate_dongle_key(usb_dir)
    monkeypatch.setenv("CIPHERCHAT_DONGLE_MOCK_DIR", str(usb_dir))

    rng = np.random.default_rng(77)
    arr = rng.integers(30, 220, size=(200, 200, 3), dtype=np.uint8)
    buf = io.BytesIO()
    Image.fromarray(arr, mode="RGB").save(buf, format="PNG")
    face_bytes = buf.getvalue()

    alice = register_user(
        "alice", "PassAlice123!", face_bytes, db_path=test_db, biometrics_dir=bio_dir, mock_dongle_dir=usb_dir
    )
    bob = register_user(
        "bob", "PassBob123!", face_bytes, db_path=test_db, biometrics_dir=bio_dir, mock_dongle_dir=usb_dir
    )

    # 1. Normal TEXT message (storage_layers == 'SUPER')
    normal_plain = "Halo Bob, rapat jam 09.30 di ruang B2."
    normal_sent = send_text_message(
        sender_id=alice["id"],
        recipient_id=bob["id"],
        plaintext=normal_plain,
        is_important=False,
        db_path=test_db,
    )
    assert normal_sent["storage_layers"] == "SUPER"
    assert normal_sent["is_important"] is False

    raw_normal = get_raw_ciphertext_message(normal_sent["id"], db_path=test_db)
    assert raw_normal["body_stored"] != normal_plain
    assert super_decrypt(raw_normal["body_stored"]) == normal_plain

    dec_normal = get_decrypted_message(normal_sent["id"], requesting_user_id=bob["id"], db_path=test_db)
    assert dec_normal["decrypted_text"] == normal_plain

    # 2. Important TEXT message (is_important = 1 -> storage_layers == 'SUPER+DBCOL')
    important_plain = "Kode akses brankas utama: 9988-7766-ABCD!"
    important_sent = send_text_message(
        sender_id=alice["id"],
        recipient_id=bob["id"],
        plaintext=important_plain,
        is_important=True,
        db_path=test_db,
    )
    assert important_sent["storage_layers"] == "SUPER+DBCOL"
    assert important_sent["is_important"] is True

    raw_important = get_raw_ciphertext_message(important_sent["id"], db_path=test_db)
    # Direct super_decrypt on raw SQLite value MUST fail because it is wrapped with DB column key
    with pytest.raises(ValueError):
        super_decrypt(raw_important["body_stored"])

    # Unwrapping DB column layer first yields valid super-encrypted text
    unwrapped_super = decrypt_db_column(raw_important["body_stored"])
    assert super_decrypt(unwrapped_super) == important_plain

    dec_important = get_decrypted_message(
        important_sent["id"],
        requesting_user_id=bob["id"],
        db_path=test_db,
        mock_dongle_dir=usb_dir,
        enforce_dongle_for_important=True,
    )
    assert dec_important["decrypted_text"] == important_plain

    inspected = inspect_stored_text_message(
        important_sent["id"],
        db_path=test_db,
        mock_dongle_dir=usb_dir,
        enforce_dongle_for_important=True,
    )
    assert inspected["storage_layers"] == "SUPER+DBCOL"
    assert inspected["raw_sqlite_body_stored"] == raw_important["body_stored"]
    assert inspected["step2_aes128_b64"] != inspected["raw_sqlite_body_stored"]
    assert inspected["decrypted_back"] == important_plain

    # 3. FILE message (storage_layers == 'CHACHA20')
    sample_pdf = b"%PDF-1.4\nLaporan Keuangan Rahasia 2026\n%%EOF"
    file_sent = send_file_message(
        sender_id=alice["id"],
        recipient_id=bob["id"],
        file_bytes=sample_pdf,
        original_filename="laporan.pdf",
        mime_type="application/pdf",
        db_path=test_db,
        encrypted_files_dir=enc_files_dir,
    )
    assert file_sent["storage_layers"] == "CHACHA20"

    preview = get_file_raw_preview(file_sent["id"], db_path=test_db)
    assert preview["encrypted_size_bytes"] == 12 + len(sample_pdf) + 16
    assert len(preview["hex_preview"]) > 0

    downloaded = download_decrypted_file_message(
        file_sent["id"],
        requesting_user_id=bob["id"],
        db_path=test_db,
        mock_dongle_dir=usb_dir,
        enforce_dongle=True,
    )
    assert downloaded["file_bytes"] == sample_pdf
    assert downloaded["file_original_filename"] == "laporan.pdf"
