"""Message repository for TEXT, FILE, and Important Messages (Phase 2)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.config import ENCRYPTED_FILES_DIR, PROJECT_ROOT, STEGO_IMAGES_DIR, load_config
from backend.core.crypto_engine import (
    decrypt_aes128,
    decrypt_db_column,
    decrypt_file_chacha20,
    encrypt_db_column,
    encrypt_file_chacha20,
    super_decrypt,
    super_encrypt,
    vigenere_decrypt,
)
from backend.core.dongle_auth import verify_usb_dongle
from backend.core.stego_engine import embed_lsb, extract_lsb
from backend.database import get_connection
from backend.repositories.user_repo import get_all_dongle_hashes

_SELECT_MESSAGE_SQL = """
SELECT
    m.id,
    m.sender_id,
    s.username AS sender_username,
    m.recipient_id,
    r.username AS recipient_username,
    m.msg_type,
    m.is_important,
    m.storage_layers,
    m.body_stored,
    m.file_path,
    m.file_original_filename,
    m.file_mime_type,
    m.stego_image_path,
    m.created_at
FROM messages m
JOIN users s ON s.id = m.sender_id
JOIN users r ON r.id = m.recipient_id
"""


def _ensure_dongle_present_for_sensitive_action(
    db_path: Path | None = None,
    mock_dongle_dir: str | Path | None = None,
) -> None:
    """Re-verify USB dongle presence for sensitive actions (important messages / file downloads)."""
    cfg = load_config()
    registered_hashes = get_all_dongle_hashes(db_path=db_path)
    status = verify_usb_dongle(
        expected_hashes=registered_hashes if registered_hashes else None,
        bootstrap_hash_hex=cfg.dongle_bootstrap_hash_hex,
        dongle_filename=cfg.dongle_filename,
        mock_dir=mock_dongle_dir,
    )
    if not status.detected:
        raise PermissionError(status.message)


def send_text_message(
    sender_id: int,
    recipient_id: int,
    plaintext: str,
    is_important: bool = False,
    db_path: Path | None = None,
) -> dict[str, Any]:
    """Encrypt and store a TEXT message (with optional DB column encryption for important messages)."""
    if not isinstance(plaintext, str) or not plaintext.strip():
        raise ValueError("Isi pesan teks tidak boleh kosong.")

    # Step 1: Text Super Encryption (Vigenere + AES-128-GCM -> Base64)
    super_ciphertext_b64 = super_encrypt(plaintext)

    # Step 2: Optional Database Column Encryption (DEC-05 Option A: SUPER+DBCOL)
    if is_important:
        body_stored = encrypt_db_column(super_ciphertext_b64)
        storage_layers = "SUPER+DBCOL"
        important_int = 1
    else:
        body_stored = super_ciphertext_b64
        storage_layers = "SUPER"
        important_int = 0

    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    conn = get_connection(db_path)
    try:
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO messages (
                    sender_id, recipient_id, msg_type, is_important,
                    storage_layers, body_stored, file_path,
                    file_original_filename, file_mime_type,
                    stego_image_path, created_at
                ) VALUES (?, ?, 'TEXT', ?, ?, ?, NULL, NULL, NULL, NULL, ?)
                """,
                (
                    int(sender_id),
                    int(recipient_id),
                    important_int,
                    storage_layers,
                    body_stored,
                    created_at,
                ),
            )
            message_id = int(cursor.lastrowid)
    finally:
        conn.close()

    return {
        "id": message_id,
        "sender_id": int(sender_id),
        "recipient_id": int(recipient_id),
        "msg_type": "TEXT",
        "is_important": bool(important_int),
        "storage_layers": storage_layers,
        "created_at": created_at,
    }


def send_file_message(
    sender_id: int,
    recipient_id: int,
    file_bytes: bytes,
    original_filename: str,
    mime_type: str = "application/octet-stream",
    is_important: bool = False,
    db_path: Path | None = None,
    encrypted_files_dir: Path | None = None,
) -> dict[str, Any]:
    """Encrypt a file using ChaCha20Poly1305, save as .enc on disk, and record in SQLite."""
    if is_important:
        raise ValueError("Flag is_important hanya valid untuk pesan bertipe TEXT.")
    if not isinstance(file_bytes, (bytes, bytearray)) or len(file_bytes) == 0:
        raise ValueError("File yang dikirim tidak boleh kosong.")
    clean_filename = Path(original_filename).name.strip()
    if not clean_filename:
        raise ValueError("Nama file asli tidak valid.")

    # Encrypt using the dedicated ChaCha20 file pipeline (never uses text pipeline)
    encrypted_payload = encrypt_file_chacha20(bytes(file_bytes))

    target_dir = (
        Path(encrypted_files_dir)
        if encrypted_files_dir is not None
        else ENCRYPTED_FILES_DIR
    )
    target_dir.mkdir(parents=True, exist_ok=True)
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    conn = get_connection(db_path)
    try:
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO messages (
                    sender_id, recipient_id, msg_type, is_important,
                    storage_layers, body_stored, file_path,
                    file_original_filename, file_mime_type,
                    stego_image_path, created_at
                ) VALUES (?, ?, 'FILE', 0, 'CHACHA20', NULL, '', ?, ?, NULL, ?)
                """,
                (
                    int(sender_id),
                    int(recipient_id),
                    clean_filename,
                    mime_type.strip() or "application/octet-stream",
                    created_at,
                ),
            )
            message_id = int(cursor.lastrowid)
            enc_filename = f"{message_id}_{uuid.uuid4().hex[:12]}.enc"
            enc_file_path = target_dir / enc_filename
            enc_file_path.write_bytes(encrypted_payload)

            try:
                rel_path = (
                    enc_file_path.resolve()
                    .relative_to(PROJECT_ROOT.resolve())
                    .as_posix()
                )
            except ValueError:
                rel_path = str(enc_file_path.resolve())

            conn.execute(
                "UPDATE messages SET file_path = ? WHERE id = ?",
                (rel_path, message_id),
            )
    finally:
        conn.close()

    return {
        "id": message_id,
        "sender_id": int(sender_id),
        "recipient_id": int(recipient_id),
        "msg_type": "FILE",
        "is_important": False,
        "storage_layers": "CHACHA20",
        "file_path": rel_path,
        "file_original_filename": clean_filename,
        "file_mime_type": mime_type.strip() or "application/octet-stream",
        "created_at": created_at,
    }


def send_image_message(
    sender_id: int,
    recipient_id: int,
    cover_image: bytes | str | Path,
    secret_message: str,
    is_important: bool = False,
    db_path: Path | None = None,
    stego_images_dir: Path | None = None,
) -> dict[str, Any]:
    """Embed a plaintext secret message into a lossless PNG via LSB (DEC-09 Option A) and record in SQLite."""
    if is_important:
        raise ValueError("Flag is_important hanya valid untuk pesan bertipe TEXT.")
    if not isinstance(secret_message, str) or not secret_message.strip():
        raise ValueError("Pesan rahasia untuk steganografi tidak boleh kosong.")

    target_dir = (
        Path(stego_images_dir)
        if stego_images_dir is not None
        else STEGO_IMAGES_DIR
    )
    target_dir.mkdir(parents=True, exist_ok=True)
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    conn = get_connection(db_path)
    try:
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO messages (
                    sender_id, recipient_id, msg_type, is_important,
                    storage_layers, body_stored, file_path,
                    file_original_filename, file_mime_type,
                    stego_image_path, created_at
                ) VALUES (?, ?, 'IMAGE', 0, 'STEGO', NULL, NULL, NULL, 'image/png', '', ?)
                """,
                (
                    int(sender_id),
                    int(recipient_id),
                    created_at,
                ),
            )
            message_id = int(cursor.lastrowid)
            stego_filename = f"{message_id}_{uuid.uuid4().hex[:12]}.png"
            stego_file_path = target_dir / stego_filename

            stego_metrics = embed_lsb(
                input_image=cover_image,
                secret_text=secret_message,
                output_path=stego_file_path,
            )

            try:
                rel_path = (
                    stego_file_path.resolve()
                    .relative_to(PROJECT_ROOT.resolve())
                    .as_posix()
                )
            except ValueError:
                rel_path = str(stego_file_path.resolve())

            conn.execute(
                "UPDATE messages SET stego_image_path = ? WHERE id = ?",
                (rel_path, message_id),
            )
    finally:
        conn.close()

    return {
        "id": message_id,
        "sender_id": int(sender_id),
        "recipient_id": int(recipient_id),
        "msg_type": "IMAGE",
        "is_important": False,
        "storage_layers": "STEGO",
        "stego_image_path": rel_path,
        "width": stego_metrics["width"],
        "height": stego_metrics["height"],
        "capacity_bits": stego_metrics["capacity_bits"],
        "used_bits": stego_metrics["used_bits"],
        "psnr_db": stego_metrics["psnr_db"],
        "max_pixel_delta": stego_metrics["max_pixel_delta"],
        "created_at": created_at,
    }


def reveal_image_message(
    message_id: int,
    requesting_user_id: int | None = None,
    db_path: Path | None = None,
) -> dict[str, Any]:
    """Extract and return the hidden LSB message from an IMAGE message for sender or recipient."""
    raw_msg = get_raw_ciphertext_message(message_id, db_path=db_path)
    if raw_msg["msg_type"] != "IMAGE":
        raise ValueError("Pesan ini bukan pesan bertipe IMAGE.")

    if requesting_user_id is not None and int(requesting_user_id) not in (
        raw_msg["sender_id"],
        raw_msg["recipient_id"],
    ):
        raise PermissionError(
            "Hanya pengirim atau penerima yang dapat mengekstrak pesan gambar ini."
        )

    stego_path = Path(raw_msg["stego_image_path"])
    if not stego_path.is_absolute():
        stego_path = PROJECT_ROOT / stego_path
    if not stego_path.is_file():
        raise FileNotFoundError(f"Citra steganografi tidak ditemukan: {stego_path}")

    secret_message = extract_lsb(stego_path)
    return {
        "message_id": raw_msg["id"],
        "sender_id": raw_msg["sender_id"],
        "sender_username": raw_msg["sender_username"],
        "recipient_id": raw_msg["recipient_id"],
        "recipient_username": raw_msg["recipient_username"],
        "stego_image_path": raw_msg["stego_image_path"],
        "storage_layers": raw_msg["storage_layers"],
        "secret_message": secret_message,
        "created_at": raw_msg["created_at"],
    }


def get_raw_ciphertext_message(
    message_id: int,
    db_path: Path | None = None,
) -> dict[str, Any]:
    """Return the exact raw record stored inside SQLite without decrypting body_stored."""
    conn = get_connection(db_path)
    try:
        row = conn.execute(
            _SELECT_MESSAGE_SQL + " WHERE m.id = ?",
            (int(message_id),),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        raise ValueError(f"Pesan dengan ID {message_id} tidak ditemukan.")

    return {
        "id": int(row["id"]),
        "sender_id": int(row["sender_id"]),
        "sender_username": str(row["sender_username"]),
        "recipient_id": int(row["recipient_id"]),
        "recipient_username": str(row["recipient_username"]),
        "msg_type": str(row["msg_type"]),
        "is_important": bool(row["is_important"]),
        "storage_layers": str(row["storage_layers"]),
        "body_stored": row["body_stored"],
        "file_path": row["file_path"],
        "file_original_filename": row["file_original_filename"],
        "file_mime_type": row["file_mime_type"],
        "stego_image_path": row["stego_image_path"],
        "created_at": str(row["created_at"]),
    }


def _decrypt_text_row_body(body_stored: str, is_important: bool, storage_layers: str) -> str:
    """Decrypt a TEXT message body in Python after SELECT according to its storage layers."""
    if is_important or storage_layers == "SUPER+DBCOL":
        inner_super_b64 = decrypt_db_column(body_stored)
        return super_decrypt(inner_super_b64)
    return super_decrypt(body_stored)


def get_decrypted_message(
    message_id: int,
    requesting_user_id: int | None = None,
    db_path: Path | None = None,
    mock_dongle_dir: str | Path | None = None,
    enforce_dongle_for_important: bool = True,
) -> dict[str, Any]:
    """Fetch a message from SQLite and decrypt its payload in Python for normal chat usage."""
    raw_msg = get_raw_ciphertext_message(message_id, db_path=db_path)

    if requesting_user_id is not None and int(requesting_user_id) not in (
        raw_msg["sender_id"],
        raw_msg["recipient_id"],
    ):
        raise PermissionError("Anda tidak memiliki akses ke pesan ini.")

    msg_type = raw_msg["msg_type"]
    is_important = raw_msg["is_important"]
    storage_layers = raw_msg["storage_layers"]

    result: dict[str, Any] = {
        "id": raw_msg["id"],
        "sender_id": raw_msg["sender_id"],
        "sender_username": raw_msg["sender_username"],
        "recipient_id": raw_msg["recipient_id"],
        "recipient_username": raw_msg["recipient_username"],
        "msg_type": msg_type,
        "is_important": is_important,
        "storage_layers": storage_layers,
        "created_at": raw_msg["created_at"],
    }

    if msg_type == "TEXT":
        if is_important and enforce_dongle_for_important:
            _ensure_dongle_present_for_sensitive_action(
                db_path=db_path, mock_dongle_dir=mock_dongle_dir
            )
        if not raw_msg["body_stored"]:
            raise ValueError("Kolom body_stored kosong untuk pesan TEXT.")
        decrypted_text = _decrypt_text_row_body(
            raw_msg["body_stored"], is_important, storage_layers
        )
        result["decrypted_text"] = decrypted_text
    elif msg_type == "FILE":
        result["file_path"] = raw_msg["file_path"]
        result["file_original_filename"] = raw_msg["file_original_filename"]
        result["file_mime_type"] = raw_msg["file_mime_type"]
    elif msg_type == "IMAGE":
        result["stego_image_path"] = raw_msg["stego_image_path"]

    return result


def download_decrypted_file_message(
    message_id: int,
    requesting_user_id: int | None = None,
    db_path: Path | None = None,
    mock_dongle_dir: str | Path | None = None,
    enforce_dongle: bool = True,
) -> dict[str, Any]:
    """Read a ChaCha20 .enc file from disk and decrypt its binary content for the sender/recipient."""
    raw_msg = get_raw_ciphertext_message(message_id, db_path=db_path)
    if raw_msg["msg_type"] != "FILE":
        raise ValueError("Pesan ini bukan pesan bertipe FILE.")

    if requesting_user_id is not None and int(requesting_user_id) not in (
        raw_msg["sender_id"],
        raw_msg["recipient_id"],
    ):
        raise PermissionError("Hanya pengirim atau penerima yang dapat mengunduh file ini.")

    if enforce_dongle:
        _ensure_dongle_present_for_sensitive_action(
            db_path=db_path, mock_dongle_dir=mock_dongle_dir
        )

    enc_path = Path(raw_msg["file_path"])
    if not enc_path.is_absolute():
        enc_path = PROJECT_ROOT / enc_path
    if not enc_path.is_file():
        raise FileNotFoundError(f"File terenkripsi tidak ditemukan: {enc_path}")

    encrypted_bytes = enc_path.read_bytes()
    decrypted_bytes = decrypt_file_chacha20(encrypted_bytes)
    return {
        "message_id": raw_msg["id"],
        "file_bytes": decrypted_bytes,
        "file_original_filename": raw_msg["file_original_filename"],
        "file_mime_type": raw_msg["file_mime_type"],
        "file_path": raw_msg["file_path"],
        "storage_layers": raw_msg["storage_layers"],
    }


def get_file_raw_preview(
    message_id: int,
    preview_bytes: int = 64,
    db_path: Path | None = None,
) -> dict[str, Any]:
    """Return path and hex preview of the first N bytes of a ChaCha20 .enc file."""
    raw_msg = get_raw_ciphertext_message(message_id, db_path=db_path)
    if raw_msg["msg_type"] != "FILE":
        raise ValueError("Pesan ini bukan pesan bertipe FILE.")

    enc_path = Path(raw_msg["file_path"])
    if not enc_path.is_absolute():
        enc_path = PROJECT_ROOT / enc_path
    if not enc_path.is_file():
        raise FileNotFoundError(f"File terenkripsi tidak ditemukan: {enc_path}")

    raw_data = enc_path.read_bytes()
    return {
        "message_id": raw_msg["id"],
        "file_path": raw_msg["file_path"],
        "file_original_filename": raw_msg["file_original_filename"],
        "encrypted_size_bytes": len(raw_data),
        "hex_preview": raw_data[:preview_bytes].hex(),
        "storage_layers": raw_msg["storage_layers"],
    }


def inspect_stored_text_message(
    message_id: int,
    db_path: Path | None = None,
    mock_dongle_dir: str | Path | None = None,
    enforce_dongle_for_important: bool = True,
) -> dict[str, Any]:
    """Return side-by-side cryptographic layers of a stored TEXT message for lecturer demo."""
    raw_msg = get_raw_ciphertext_message(message_id, db_path=db_path)
    if raw_msg["msg_type"] != "TEXT":
        raise ValueError("Inspeksi super enkripsi teks hanya berlaku untuk pesan TEXT.")

    is_important = raw_msg["is_important"]
    storage_layers = raw_msg["storage_layers"]
    body_stored = str(raw_msg["body_stored"] or "")

    if is_important and enforce_dongle_for_important:
        _ensure_dongle_present_for_sensitive_action(
            db_path=db_path, mock_dongle_dir=mock_dongle_dir
        )

    if is_important or storage_layers == "SUPER+DBCOL":
        step2_aes128_b64 = decrypt_db_column(body_stored)
    else:
        step2_aes128_b64 = body_stored

    step1_vigenere = decrypt_aes128(step2_aes128_b64)
    plaintext = vigenere_decrypt(step1_vigenere)

    return {
        "message_id": raw_msg["id"],
        "is_important": is_important,
        "storage_layers": storage_layers,
        "plaintext": plaintext,
        "step1_vigenere": step1_vigenere,
        "step2_aes128_b64": step2_aes128_b64,
        "raw_sqlite_body_stored": body_stored,
        "decrypted_back": plaintext,
    }


def list_inbox_messages(
    user_id: int,
    db_path: Path | None = None,
    mock_dongle_dir: str | Path | None = None,
    enforce_dongle_for_important: bool = True,
) -> list[dict[str, Any]]:
    """List all messages involving user_id (as sender or recipient) with decrypted TEXT bodies."""
    conn = get_connection(db_path)
    try:
        rows = conn.execute(
            _SELECT_MESSAGE_SQL
            + " WHERE m.recipient_id = ? OR m.sender_id = ? ORDER BY m.id DESC",
            (int(user_id), int(user_id)),
        ).fetchall()
    finally:
        conn.close()

    results: list[dict[str, Any]] = []
    for row in rows:
        msg_id = int(row["id"])
        results.append(
            get_decrypted_message(
                msg_id,
                requesting_user_id=user_id,
                db_path=db_path,
                mock_dongle_dir=mock_dongle_dir,
                enforce_dongle_for_important=enforce_dongle_for_important,
            )
        )
    return results
