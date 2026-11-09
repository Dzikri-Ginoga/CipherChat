"""SHA-256 hash-chained Blockchain Asset Ledger for CipherChat Crypto.

Covers lecturer criterion 7 (important assets secured with simple blockchain)
and DEC-06 Option A (registered digital asset with SHA-256 fingerprint, REGISTER_ASSET
and TRANSFER_ASSET actions, optional proof-of-work via CIPHERCHAT_POW_DIFFICULTY).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.config import load_config
from backend.database import get_connection

GENESIS_PREVIOUS_HASH: str = "0" * 64
ALLOWED_ACTION_TYPES: tuple[str, ...] = ("GENESIS", "REGISTER_ASSET", "TRANSFER_ASSET")


@dataclass(frozen=True)
class Block:
    """Immutable ledger entry stored in the asset_blocks SQLite table."""

    block_index: int
    timestamp: str
    actor_username: str
    action_type: str
    target_asset_id: int | None
    data_summary: str
    nonce: int
    previous_hash: str
    current_hash: str

    def to_dict(self) -> dict[str, Any]:
        """Convert the Block dataclass to a plain dictionary."""
        return asdict(self)


def compute_block_hash(
    block_index: int,
    timestamp: str,
    actor_username: str,
    action_type: str,
    target_asset_id: int | None,
    data_summary: str,
    nonce: int,
    previous_hash: str,
) -> str:
    """Compute a deterministic SHA-256 hex digest over canonical sorted JSON block fields."""
    payload = json.dumps(
        {
            "block_index": int(block_index),
            "timestamp": str(timestamp),
            "actor_username": str(actor_username),
            "action_type": str(action_type),
            "target_asset_id": int(target_asset_id) if target_asset_id is not None else None,
            "data_summary": str(data_summary),
            "nonce": int(nonce),
            "previous_hash": str(previous_hash),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def mine_block_hash(
    block_index: int,
    timestamp: str,
    actor_username: str,
    action_type: str,
    target_asset_id: int | None,
    data_summary: str,
    previous_hash: str,
    pow_difficulty: int = 0,
) -> tuple[int, str]:
    """Compute (or mine if pow_difficulty > 0) a valid nonce and current_hash for a block."""
    if pow_difficulty < 0:
        raise ValueError("Proof-of-work difficulty must be >= 0.")

    nonce = 0
    required_prefix = "0" * pow_difficulty
    while True:
        candidate_hash = compute_block_hash(
            block_index=block_index,
            timestamp=timestamp,
            actor_username=actor_username,
            action_type=action_type,
            target_asset_id=target_asset_id,
            data_summary=data_summary,
            nonce=nonce,
            previous_hash=previous_hash,
        )
        if pow_difficulty == 0 or candidate_hash.startswith(required_prefix):
            return nonce, candidate_hash
        nonce += 1


def _row_to_block(row: sqlite3.Row | dict[str, Any]) -> Block:
    """Convert a SQLite row from asset_blocks into a Block instance."""
    return Block(
        block_index=int(row["block_index"]),
        timestamp=str(row["timestamp"]),
        actor_username=str(row["actor_username"]),
        action_type=str(row["action_type"]),
        target_asset_id=(
            int(row["target_asset_id"])
            if row["target_asset_id"] is not None
            else None
        ),
        data_summary=str(row["data_summary"]),
        nonce=int(row["nonce"]),
        previous_hash=str(row["previous_hash"]),
        current_hash=str(row["current_hash"]),
    )


def _parse_summary_kv(data_summary: str) -> dict[str, str]:
    """Parse semicolon-delimited key=value pairs from data_summary."""
    parsed: dict[str, str] = {}
    for part in data_summary.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            parsed[k.strip()] = v.strip()
    return parsed


class Blockchain:
    """Manages the SHA-256 hash-chained asset ledger stored in SQLite."""

    def __init__(
        self,
        db_path: Path | None = None,
        pow_difficulty: int | None = None,
    ) -> None:
        self.db_path = db_path
        self._pow_difficulty_override = pow_difficulty

    @property
    def pow_difficulty(self) -> int:
        """Return effective proof-of-work difficulty (0 by default per DEC-06 Option A)."""
        if self._pow_difficulty_override is not None:
            return int(self._pow_difficulty_override)
        return load_config().pow_difficulty

    def ensure_genesis_block(
        self, conn: sqlite3.Connection | None = None
    ) -> Block:
        """Create Block #0 (GENESIS) if asset_blocks is empty, and return Block #0."""
        owns_conn = conn is None
        active_conn = conn if conn is not None else get_connection(self.db_path)
        try:
            row = active_conn.execute(
                "SELECT * FROM asset_blocks WHERE block_index = 0"
            ).fetchone()
            if row is not None:
                return _row_to_block(row)

            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            actor_username = "SYSTEM"
            action_type = "GENESIS"
            target_asset_id = None
            data_summary = "CipherChat Asset Ledger Genesis Block"
            previous_hash = GENESIS_PREVIOUS_HASH
            nonce, current_hash = mine_block_hash(
                block_index=0,
                timestamp=timestamp,
                actor_username=actor_username,
                action_type=action_type,
                target_asset_id=target_asset_id,
                data_summary=data_summary,
                previous_hash=previous_hash,
                pow_difficulty=self.pow_difficulty,
            )

            active_conn.execute(
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
            if owns_conn:
                active_conn.commit()

            return Block(
                block_index=0,
                timestamp=timestamp,
                actor_username=actor_username,
                action_type=action_type,
                target_asset_id=target_asset_id,
                data_summary=data_summary,
                nonce=nonce,
                previous_hash=previous_hash,
                current_hash=current_hash,
            )
        finally:
            if owns_conn:
                active_conn.close()

    def get_latest_block(
        self, conn: sqlite3.Connection | None = None
    ) -> Block | None:
        """Return the block with the highest block_index, or None if the table is empty."""
        owns_conn = conn is None
        active_conn = conn if conn is not None else get_connection(self.db_path)
        try:
            row = active_conn.execute(
                "SELECT * FROM asset_blocks ORDER BY block_index DESC LIMIT 1"
            ).fetchone()
            return _row_to_block(row) if row is not None else None
        finally:
            if owns_conn:
                active_conn.close()

    def get_all_blocks(
        self, conn: sqlite3.Connection | None = None
    ) -> list[Block]:
        """Return all blocks in ascending order of block_index."""
        owns_conn = conn is None
        active_conn = conn if conn is not None else get_connection(self.db_path)
        try:
            rows = active_conn.execute(
                "SELECT * FROM asset_blocks ORDER BY block_index ASC"
            ).fetchall()
            return [_row_to_block(r) for r in rows]
        finally:
            if owns_conn:
                active_conn.close()

    def add_block(
        self,
        actor_username: str,
        action_type: str,
        target_asset_id: int | None,
        data_summary: str,
        conn: sqlite3.Connection | None = None,
        timestamp: str | None = None,
    ) -> Block:
        """Append a new hash-chained block to asset_blocks."""
        if action_type not in ALLOWED_ACTION_TYPES:
            raise ValueError(f"Unsupported action_type: {action_type}")
        clean_actor = actor_username.strip()
        if not clean_actor:
            raise ValueError("actor_username cannot be empty.")
        if not data_summary or not data_summary.strip():
            raise ValueError("data_summary cannot be empty.")

        owns_conn = conn is None
        active_conn = conn if conn is not None else get_connection(self.db_path)
        try:
            latest = self.get_latest_block(conn=active_conn)
            if latest is None:
                latest = self.ensure_genesis_block(conn=active_conn)

            next_index = latest.block_index + 1
            previous_hash = latest.current_hash
            effective_ts = (
                timestamp
                if timestamp is not None
                else datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            )
            nonce, current_hash = mine_block_hash(
                block_index=next_index,
                timestamp=effective_ts,
                actor_username=clean_actor,
                action_type=action_type,
                target_asset_id=target_asset_id,
                data_summary=data_summary.strip(),
                previous_hash=previous_hash,
                pow_difficulty=self.pow_difficulty,
            )

            active_conn.execute(
                """
                INSERT INTO asset_blocks (
                    block_index, timestamp, actor_username, action_type,
                    target_asset_id, data_summary, nonce, previous_hash, current_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    next_index,
                    effective_ts,
                    clean_actor,
                    action_type,
                    target_asset_id,
                    data_summary.strip(),
                    nonce,
                    previous_hash,
                    current_hash,
                ),
            )
            if owns_conn:
                active_conn.commit()

            return Block(
                block_index=next_index,
                timestamp=effective_ts,
                actor_username=clean_actor,
                action_type=action_type,
                target_asset_id=target_asset_id,
                data_summary=data_summary.strip(),
                nonce=nonce,
                previous_hash=previous_hash,
                current_hash=current_hash,
            )
        finally:
            if owns_conn:
                active_conn.close()

    def verify_chain(
        self,
        conn: sqlite3.Connection | None = None,
        check_assets_table: bool = True,
    ) -> dict[str, Any]:
        """Verify the cryptographic integrity of the entire asset_blocks chain."""
        owns_conn = conn is None
        active_conn = conn if conn is not None else get_connection(self.db_path)
        try:
            blocks = self.get_all_blocks(conn=active_conn)
            total_blocks = len(blocks)

            if total_blocks == 0:
                return {
                    "is_valid": False,
                    "total_blocks": 0,
                    "broken_at_index": 0,
                    "error_detail": "Genesis block (#0) tidak ditemukan.",
                }

            difficulty = self.pow_difficulty
            required_prefix = "0" * difficulty if difficulty > 0 else ""

            # Track the latest block per asset for optional cross-table verification
            latest_asset_block: dict[int, Block] = {}

            for idx, blk in enumerate(blocks):
                if blk.block_index != idx:
                    return {
                        "is_valid": False,
                        "total_blocks": total_blocks,
                        "broken_at_index": blk.block_index,
                        "error_detail": (
                            f"Urutan indeks blok tidak berurutan pada blok #{blk.block_index}."
                        ),
                    }

                if idx == 0 and blk.previous_hash != GENESIS_PREVIOUS_HASH:
                    return {
                        "is_valid": False,
                        "total_blocks": total_blocks,
                        "broken_at_index": 0,
                        "error_detail": "previous_hash pada Genesis Block (#0) tidak valid.",
                    }

                if idx > 0 and blk.previous_hash != blocks[idx - 1].current_hash:
                    return {
                        "is_valid": False,
                        "total_blocks": total_blocks,
                        "broken_at_index": idx,
                        "error_detail": (
                            f"previous_hash pada blok #{idx} tidak cocok dengan current_hash blok #{idx - 1}."
                        ),
                    }

                expected_hash = compute_block_hash(
                    block_index=blk.block_index,
                    timestamp=blk.timestamp,
                    actor_username=blk.actor_username,
                    action_type=blk.action_type,
                    target_asset_id=blk.target_asset_id,
                    data_summary=blk.data_summary,
                    nonce=blk.nonce,
                    previous_hash=blk.previous_hash,
                )
                if blk.current_hash != expected_hash:
                    return {
                        "is_valid": False,
                        "total_blocks": total_blocks,
                        "broken_at_index": idx,
                        "error_detail": (
                            f"Hash blok #{idx} tidak sesuai dengan isi datanya (data_summary atau atribut dimodifikasi)."
                        ),
                    }

                if difficulty > 0 and not blk.current_hash.startswith(required_prefix):
                    return {
                        "is_valid": False,
                        "total_blocks": total_blocks,
                        "broken_at_index": idx,
                        "error_detail": (
                            f"Hash blok #{idx} tidak memenuhi syarat proof-of-work ('{required_prefix}')."
                        ),
                    }

                if blk.target_asset_id is not None:
                    latest_asset_block[blk.target_asset_id] = blk

            if check_assets_table and latest_asset_block:
                for asset_id, last_blk in latest_asset_block.items():
                    asset_row = active_conn.execute(
                        "SELECT * FROM assets WHERE id = ?", (asset_id,)
                    ).fetchone()
                    if asset_row is None:
                        return {
                            "is_valid": False,
                            "total_blocks": total_blocks,
                            "broken_at_index": last_blk.block_index,
                            "error_detail": (
                                f"Aset ID {asset_id} pada blok #{last_blk.block_index} telah dihapus dari tabel assets."
                            ),
                        }
                    kv = _parse_summary_kv(last_blk.data_summary)
                    expected_owner = kv.get("to")
                    expected_fp = kv.get("fingerprint")
                    if (
                        expected_owner
                        and str(asset_row["owner_username"]) != expected_owner
                    ) or (
                        expected_fp
                        and str(asset_row["content_fingerprint_sha256"]) != expected_fp
                    ):
                        return {
                            "is_valid": False,
                            "total_blocks": total_blocks,
                            "broken_at_index": last_blk.block_index,
                            "error_detail": (
                                f"Data tabel assets untuk ID {asset_id} tidak sinkron dengan blok terakhir #{last_blk.block_index}."
                            ),
                        }

            return {
                "is_valid": True,
                "total_blocks": total_blocks,
                "broken_at_index": None,
                "error_detail": None,
            }
        finally:
            if owns_conn:
                active_conn.close()
