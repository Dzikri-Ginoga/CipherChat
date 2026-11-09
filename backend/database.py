"""SQLite connection helper and schema initializer for CipherChat Crypto."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from backend.config import (
    BIOMETRICS_DIR,
    DB_PATH,
    ENCRYPTED_FILES_DIR,
    STEGO_IMAGES_DIR,
    STORAGE_DIR,
)

DDL_USERS: str = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash_hex TEXT NOT NULL,
    password_salt_hex TEXT NOT NULL,
    dongle_token_hash_hex TEXT NOT NULL,
    face_reference_path TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""

DDL_MESSAGES: str = """
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    recipient_id INTEGER NOT NULL,
    msg_type TEXT NOT NULL,
    is_important INTEGER NOT NULL DEFAULT 0,
    storage_layers TEXT NOT NULL,
    body_stored TEXT,
    file_path TEXT,
    file_original_filename TEXT,
    file_mime_type TEXT,
    stego_image_path TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (sender_id) REFERENCES users(id),
    FOREIGN KEY (recipient_id) REFERENCES users(id)
);
"""

DDL_ASSETS: str = """
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_code TEXT UNIQUE NOT NULL,
    asset_name TEXT NOT NULL,
    description TEXT,
    owner_username TEXT NOT NULL,
    content_fingerprint_sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

DDL_ASSET_BLOCKS: str = """
CREATE TABLE IF NOT EXISTS asset_blocks (
    block_index INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    actor_username TEXT NOT NULL,
    action_type TEXT NOT NULL,
    target_asset_id INTEGER,
    data_summary TEXT NOT NULL,
    nonce INTEGER NOT NULL DEFAULT 0,
    previous_hash TEXT NOT NULL,
    current_hash TEXT UNIQUE NOT NULL
);
"""


def ensure_storage_directories() -> None:
    """Create all local runtime storage directories if they do not exist."""
    for directory in (
        STORAGE_DIR,
        BIOMETRICS_DIR,
        ENCRYPTED_FILES_DIR,
        STEGO_IMAGES_DIR,
    ):
        directory.mkdir(parents=True, exist_ok=True)


def get_connection(db_path: Path | None = None) -> sqlite3.Connection:
    """Open a configured SQLite connection with foreign keys enabled."""
    target_path = Path(db_path) if db_path is not None else DB_PATH
    target_path.parent.mkdir(parents=True, exist_ok=True)
    if target_path.exists():
        try:
            raw = target_path.read_bytes()
            if 0 < len(raw) < 100 and not raw.startswith(b"SQLite format 3"):
                target_path.write_bytes(b"")
            elif len(raw) >= 100 and raw.startswith(b"SQLite format 3") and (raw[18] == 2 or raw[19] == 2):
                patched = bytearray(raw)
                patched[18] = 1
                patched[19] = 1
                target_path.write_bytes(bytes(patched))
        except OSError:
            pass
    conn = sqlite3.connect(str(target_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = MEMORY;")
    return conn


def _compute_genesis_hash(
    timestamp: str,
    actor_username: str,
    action_type: str,
    target_asset_id: int | None,
    data_summary: str,
    nonce: int,
    previous_hash: str,
) -> str:
    """Compute canonical SHA-256 block hash for the Genesis block."""
    payload = json.dumps(
        {
            "block_index": 0,
            "timestamp": timestamp,
            "actor_username": actor_username,
            "action_type": action_type,
            "target_asset_id": target_asset_id,
            "data_summary": data_summary,
            "nonce": nonce,
            "previous_hash": previous_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def init_db(db_path: Path | None = None) -> None:
    """Initialize SQLite schema and create the Genesis block if absent."""
    ensure_storage_directories()
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute(DDL_USERS)
            conn.execute(DDL_MESSAGES)
            conn.execute(DDL_ASSETS)
            conn.execute(DDL_ASSET_BLOCKS)

            row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM asset_blocks WHERE block_index = 0"
            ).fetchone()
            if row is not None and int(row["cnt"]) == 0:
                timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                actor_username = "SYSTEM"
                action_type = "GENESIS"
                target_asset_id = None
                data_summary = "CipherChat Asset Ledger Genesis Block"
                nonce = 0
                previous_hash = "0" * 64
                current_hash = _compute_genesis_hash(
                    timestamp=timestamp,
                    actor_username=actor_username,
                    action_type=action_type,
                    target_asset_id=target_asset_id,
                    data_summary=data_summary,
                    nonce=nonce,
                    previous_hash=previous_hash,
                )
                conn.execute(
                    """
                    INSERT INTO asset_blocks (
                        block_index, timestamp, actor_username, action_type,
                        target_asset_id, data_summary, nonce, previous_hash, current_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        0,
                        timestamp,
                        actor_username,
                        action_type,
                        target_asset_id,
                        data_summary,
                        nonce,
                        previous_hash,
                        current_hash,
                    ),
                )
    finally:
        conn.close()
