"""User repository for registration, lookup, and 3-factor login verification."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

from backend.config import BIOMETRICS_DIR, PROJECT_ROOT
from backend.core.crypto_engine import hash_password, verify_password
from backend.core.dongle_auth import scan_dongle_token, verify_user_dongle
from backend.core.face_auth import enroll_face_image, verify_face
from backend.database import get_connection


def _row_to_public_user(row: Any) -> dict[str, Any]:
    """Convert a SQLite user row to a public dictionary without password secrets."""
    return {
        "id": int(row["id"]),
        "username": str(row["username"]),
        "dongle_token_hash_hex": str(row["dongle_token_hash_hex"]),
        "face_reference_path": str(row["face_reference_path"]),
        "created_at": str(row["created_at"]),
    }


def get_all_dongle_hashes(db_path: Path | None = None) -> list[str]:
    """Return all registered dongle token SHA-256 hashes from the users table."""
    conn = get_connection(db_path)
    try:
        rows = conn.execute("SELECT dongle_token_hash_hex FROM users").fetchall()
        return [str(r["dongle_token_hash_hex"]) for r in rows]
    finally:
        conn.close()


def get_user_by_username(
    username: str,
    db_path: Path | None = None,
    include_secrets: bool = False,
) -> dict[str, Any] | None:
    """Fetch a user record by username."""
    cleaned = username.strip()
    if not cleaned:
        return None
    conn = get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (cleaned,)
        ).fetchone()
        if row is None:
            return None
        if include_secrets:
            return dict(row)
        return _row_to_public_user(row)
    finally:
        conn.close()


def get_user_by_id(user_id: int, db_path: Path | None = None) -> dict[str, Any] | None:
    """Fetch a user record by primary key ID."""
    conn = get_connection(db_path)
    try:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (int(user_id),)).fetchone()
        if row is None:
            return None
        return _row_to_public_user(row)
    finally:
        conn.close()


def list_users(db_path: Path | None = None) -> list[dict[str, Any]]:
    """List all registered users ordered by username."""
    conn = get_connection(db_path)
    try:
        rows = conn.execute("SELECT * FROM users ORDER BY username ASC").fetchall()
        return [_row_to_public_user(r) for r in rows]
    finally:
        conn.close()


def register_user(
    username: str,
    password: str,
    face_image_bytes: bytes,
    dongle_token_hash_hex: str | None = None,
    db_path: Path | None = None,
    biometrics_dir: Path | None = None,
    mock_dongle_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Register a new user with salted SHA-256 password hash, dongle hash, and reference face."""
    clean_username = username.strip()
    if not clean_username:
        raise ValueError("Username tidak boleh kosong.")
    if not password:
        raise ValueError("Kata sandi tidak boleh kosong.")

    existing = get_user_by_username(clean_username, db_path=db_path)
    if existing is not None:
        raise ValueError(f"Username '{clean_username}' sudah terdaftar.")

    if dongle_token_hash_hex is None:
        dongle_status = scan_dongle_token(mock_dir=mock_dongle_dir)
        if not dongle_status.detected or dongle_status.token_hash_hex is None:
            raise PermissionError("USB Dongle (auth.key) tidak terdeteksi")
        effective_dongle_hash = dongle_status.token_hash_hex
    else:
        effective_dongle_hash = dongle_token_hash_hex.strip().lower()

    target_bio_dir = Path(biometrics_dir) if biometrics_dir is not None else BIOMETRICS_DIR
    face_file_path = target_bio_dir / f"{clean_username}.png"
    enroll_face_image(face_image_bytes, face_file_path)

    try:
        rel_face_path = face_file_path.resolve().relative_to(PROJECT_ROOT.resolve()).as_posix()
    except ValueError:
        rel_face_path = str(face_file_path.resolve())

    password_hash_hex, password_salt_hex = hash_password(password)
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    conn = get_connection(db_path)
    try:
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO users (
                    username, password_hash_hex, password_salt_hex,
                    dongle_token_hash_hex, face_reference_path, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    clean_username,
                    password_hash_hex,
                    password_salt_hex,
                    effective_dongle_hash,
                    rel_face_path,
                    created_at,
                ),
            )
            user_id = int(cursor.lastrowid)
    finally:
        conn.close()

    return {
        "id": user_id,
        "username": clean_username,
        "dongle_token_hash_hex": effective_dongle_hash,
        "face_reference_path": rel_face_path,
        "created_at": created_at,
    }


def authenticate_user(
    username: str,
    password: str,
    webcam_frame: bytes | str | Path | np.ndarray,
    db_path: Path | None = None,
    mock_dongle_dir: str | Path | None = None,
    face_threshold: float | None = None,
) -> dict[str, Any]:
    """Authenticate a user across all three factors (Dongle, Password Hash, Face Biometrics)."""
    user = get_user_by_username(username, db_path=db_path, include_secrets=True)
    if user is None:
        dongle_scan = scan_dongle_token(mock_dir=mock_dongle_dir)
        return {
            "authenticated": False,
            "factors": {
                "dongle": False,
                "password": False,
                "biometric": False,
                "face_score": 0.0,
            },
            "message": (
                "USB Dongle (auth.key) tidak terdeteksi"
                if not dongle_scan.detected
                else "Kata sandi salah"
            ),
        }

    # Factor 1 (Possession): USB Dongle match for this user
    dongle_status = verify_user_dongle(
        user["dongle_token_hash_hex"], mock_dir=mock_dongle_dir
    )
    dongle_ok = dongle_status.detected

    # Factor 2 (Knowledge): Salted SHA-256 password verification
    password_ok = verify_password(
        password=password,
        stored_hash_hex=user["password_hash_hex"],
        salt_hex=user["password_salt_hex"],
    )

    # Factor 3 (Inherence): OpenCV webcam face match
    ref_path = Path(user["face_reference_path"])
    if not ref_path.is_absolute():
        ref_path = PROJECT_ROOT / ref_path

    biometric_ok, face_score, bio_message = verify_face(
        reference_image_path=ref_path,
        live_image_input=webcam_frame,
        threshold=face_threshold,
    )

    authenticated = bool(dongle_ok and password_ok and biometric_ok)

    if authenticated:
        final_message = "Login berhasil. Seluruh faktor keamanan terverifikasi."
    elif not dongle_ok:
        final_message = dongle_status.message
    elif not password_ok:
        final_message = "Kata sandi salah"
    else:
        final_message = bio_message

    return {
        "authenticated": authenticated,
        "user": _row_to_public_user(user) if authenticated else None,
        "factors": {
            "dongle": dongle_ok,
            "password": password_ok,
            "biometric": biometric_ok,
            "face_score": float(face_score),
        },
        "message": final_message,
    }


def update_user_dongle_hash(
    username: str,
    password: str,
    db_path: Path | None = None,
    mock_dongle_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Update a user's dongle_token_hash_hex from the currently mounted auth.key after password check."""
    clean_username = username.strip()
    if not clean_username:
        raise ValueError("Username tidak boleh kosong.")

    user = get_user_by_username(clean_username, db_path=db_path, include_secrets=True)
    if user is None:
        raise ValueError(f"Pengguna '{clean_username}' tidak ditemukan.")

    if not verify_password(
        password=password,
        stored_hash_hex=user["password_hash_hex"],
        salt_hex=user["password_salt_hex"],
    ):
        raise PermissionError("Kata sandi salah")

    dongle_status = scan_dongle_token(mock_dir=mock_dongle_dir)
    if not dongle_status.detected or dongle_status.token_hash_hex is None:
        raise PermissionError("USB Dongle (auth.key) tidak terdeteksi")

    new_hash = dongle_status.token_hash_hex.lower()
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute(
                "UPDATE users SET dongle_token_hash_hex = ? WHERE id = ?",
                (new_hash, int(user["id"])),
            )
    finally:
        conn.close()

    updated = get_user_by_username(clean_username, db_path=db_path)
    assert updated is not None
    return {
        "user": updated,
        "mountpoint": dongle_status.mountpoint,
        "dongle_token_hash_hex": new_hash,
    }

