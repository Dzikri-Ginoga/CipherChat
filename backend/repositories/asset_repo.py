"""Asset repository for registering and transferring important assets on the SHA-256 blockchain ledger."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.core.blockchain import Blockchain
from backend.database import get_connection


def compute_content_fingerprint(content: bytes | str) -> str:
    """Compute the 64-character SHA-256 hexadecimal fingerprint of an asset's content."""
    if isinstance(content, str):
        raw_bytes = content.encode("utf-8")
    elif isinstance(content, (bytes, bytearray)):
        raw_bytes = bytes(content)
    else:
        raise ValueError("Content for fingerprinting must be bytes or str.")
    return hashlib.sha256(raw_bytes).hexdigest()


def _row_to_asset_dict(row: Any) -> dict[str, Any]:
    """Convert a SQLite row from the assets table to a dictionary."""
    return {
        "id": int(row["id"]),
        "asset_code": str(row["asset_code"]),
        "asset_name": str(row["asset_name"]),
        "description": str(row["description"] or ""),
        "owner_username": str(row["owner_username"]),
        "content_fingerprint_sha256": str(row["content_fingerprint_sha256"]),
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
    }


def register_asset(
    owner_username: str,
    asset_name: str,
    description: str = "",
    content_bytes: bytes | None = None,
    asset_code: str | None = None,
    db_path: Path | None = None,
    pow_difficulty: int | None = None,
) -> dict[str, Any]:
    """Register a new important asset and append a REGISTER_ASSET block in the same SQLite transaction."""
    clean_owner = owner_username.strip()
    clean_name = asset_name.strip()
    clean_desc = (description or "").strip()

    if not clean_owner:
        raise ValueError("Username pemilik aset tidak boleh kosong.")
    if not clean_name:
        raise ValueError("Nama aset penting tidak boleh kosong.")

    if content_bytes is not None and len(content_bytes) > 0:
        fingerprint = compute_content_fingerprint(content_bytes)
    else:
        fingerprint = compute_content_fingerprint(f"{clean_name}|{clean_desc}")

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ledger = Blockchain(db_path=db_path, pow_difficulty=pow_difficulty)

    conn = get_connection(db_path)
    try:
        with conn:
            ledger.ensure_genesis_block(conn=conn)

            if asset_code and asset_code.strip():
                effective_code = asset_code.strip()
            else:
                count_row = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM assets"
                ).fetchone()
                next_num = (int(count_row["cnt"]) if count_row is not None else 0) + 1
                effective_code = f"AST-2026-{next_num:04d}"

            cursor = conn.execute(
                """
                INSERT INTO assets (
                    asset_code, asset_name, description, owner_username,
                    content_fingerprint_sha256, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    effective_code,
                    clean_name,
                    clean_desc,
                    clean_owner,
                    fingerprint,
                    now_iso,
                    now_iso,
                ),
            )
            asset_id = int(cursor.lastrowid)

            data_summary = (
                f"asset_code={effective_code};fingerprint={fingerprint};"
                f"from=GENESIS;to={clean_owner}"
            )
            new_block = ledger.add_block(
                actor_username=clean_owner,
                action_type="REGISTER_ASSET",
                target_asset_id=asset_id,
                data_summary=data_summary,
                conn=conn,
                timestamp=now_iso,
            )
    finally:
        conn.close()

    return {
        "asset": {
            "id": asset_id,
            "asset_code": effective_code,
            "asset_name": clean_name,
            "description": clean_desc,
            "owner_username": clean_owner,
            "content_fingerprint_sha256": fingerprint,
            "created_at": now_iso,
            "updated_at": now_iso,
        },
        "block": new_block.to_dict(),
    }


def transfer_asset(
    asset_id: int,
    actor_username: str,
    new_owner_username: str,
    db_path: Path | None = None,
    pow_difficulty: int | None = None,
) -> dict[str, Any]:
    """Transfer ownership of an existing asset and append a TRANSFER_ASSET block in the same transaction."""
    clean_actor = actor_username.strip()
    clean_new_owner = new_owner_username.strip()

    if not clean_actor:
        raise ValueError("Username pelaku transfer tidak boleh kosong.")
    if not clean_new_owner:
        raise ValueError("Username pemilik baru tidak boleh kosong.")
    if clean_actor == clean_new_owner:
        raise ValueError("Pemilik baru harus berbeda dari pemilik saat ini.")

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ledger = Blockchain(db_path=db_path, pow_difficulty=pow_difficulty)

    conn = get_connection(db_path)
    try:
        with conn:
            row = conn.execute(
                "SELECT * FROM assets WHERE id = ?", (int(asset_id),)
            ).fetchone()
            if row is None:
                raise ValueError(f"Aset dengan ID {asset_id} tidak ditemukan.")

            current_owner = str(row["owner_username"])
            if current_owner != clean_actor:
                raise PermissionError(
                    "Hanya pemilik aset saat ini yang dapat mentransfer kepemilikan."
                )

            asset_code = str(row["asset_code"])
            fingerprint = str(row["content_fingerprint_sha256"])

            conn.execute(
                "UPDATE assets SET owner_username = ?, updated_at = ? WHERE id = ?",
                (clean_new_owner, now_iso, int(asset_id)),
            )

            data_summary = (
                f"asset_code={asset_code};fingerprint={fingerprint};"
                f"from={current_owner};to={clean_new_owner}"
            )
            new_block = ledger.add_block(
                actor_username=clean_actor,
                action_type="TRANSFER_ASSET",
                target_asset_id=int(asset_id),
                data_summary=data_summary,
                conn=conn,
                timestamp=now_iso,
            )

            updated_row = conn.execute(
                "SELECT * FROM assets WHERE id = ?", (int(asset_id),)
            ).fetchone()
    finally:
        conn.close()

    return {
        "asset": _row_to_asset_dict(updated_row),
        "block": new_block.to_dict(),
    }


def list_assets(db_path: Path | None = None) -> list[dict[str, Any]]:
    """Return all registered assets ordered by ID ascending."""
    conn = get_connection(db_path)
    try:
        rows = conn.execute("SELECT * FROM assets ORDER BY id ASC").fetchall()
        return [_row_to_asset_dict(r) for r in rows]
    finally:
        conn.close()


def get_asset_by_id(
    asset_id: int, db_path: Path | None = None
) -> dict[str, Any] | None:
    """Return a single asset by ID, or None if not found."""
    conn = get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM assets WHERE id = ?", (int(asset_id),)
        ).fetchone()
        return _row_to_asset_dict(row) if row is not None else None
    finally:
        conn.close()


def get_chain_with_verification(
    db_path: Path | None = None,
    pow_difficulty: int | None = None,
) -> dict[str, Any]:
    """Return the full ordered list of blocks and the live verify_chain() integrity report."""
    ledger = Blockchain(db_path=db_path, pow_difficulty=pow_difficulty)
    blocks = [b.to_dict() for b in ledger.get_all_blocks()]
    verification = ledger.verify_chain()
    return {
        "blocks": blocks,
        "verification": verification,
    }
