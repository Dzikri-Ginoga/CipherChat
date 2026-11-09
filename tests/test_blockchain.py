"""Unit tests for Phase 3 SHA-256 Blockchain Asset Ledger (blockchain.py and asset_repo.py)."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from backend.core.blockchain import Blockchain, compute_block_hash
from backend.database import get_connection, init_db
from backend.repositories.asset_repo import (
    get_chain_with_verification,
    list_assets,
    register_asset,
    transfer_asset,
)


def test_genesis_plus_three_asset_blocks_valid_chain(tmp_path: Path) -> None:
    """Initialize Genesis block + 3 asset blocks (1 register, 2 transfers) and assert verify_chain() is True."""
    test_db = tmp_path / "blockchain_valid.db"
    init_db(test_db)

    # Block #1: Register asset by alice
    reg_res = register_asset(
        owner_username="alice",
        asset_name="Sertifikat Kunci Root CA",
        description="Dokumen otoritas sertifikat utama",
        content_bytes=b"ROOT-CA-CONTENT-2026-SHA256",
        asset_code="AST-2026-0001",
        db_path=test_db,
    )
    asset_id = reg_res["asset"]["id"]
    assert reg_res["block"]["block_index"] == 1
    assert reg_res["block"]["action_type"] == "REGISTER_ASSET"

    # Block #2: Transfer from alice to bob
    tx1_res = transfer_asset(
        asset_id=asset_id,
        actor_username="alice",
        new_owner_username="bob",
        db_path=test_db,
    )
    assert tx1_res["block"]["block_index"] == 2
    assert tx1_res["block"]["action_type"] == "TRANSFER_ASSET"
    assert tx1_res["asset"]["owner_username"] == "bob"

    # Block #3: Transfer from bob to charlie
    tx2_res = transfer_asset(
        asset_id=asset_id,
        actor_username="bob",
        new_owner_username="charlie",
        db_path=test_db,
    )
    assert tx2_res["block"]["block_index"] == 3
    assert tx2_res["block"]["action_type"] == "TRANSFER_ASSET"
    assert tx2_res["asset"]["owner_username"] == "charlie"

    # Non-owner (alice) attempting to transfer again must raise PermissionError
    with pytest.raises(PermissionError):
        transfer_asset(
            asset_id=asset_id,
            actor_username="alice",
            new_owner_username="david",
            db_path=test_db,
        )

    chain_report = get_chain_with_verification(db_path=test_db)
    verification = chain_report["verification"]
    assert verification["is_valid"] is True
    assert verification["total_blocks"] == 4
    assert verification["broken_at_index"] is None
    assert len(list_assets(db_path=test_db)) == 1


def test_tamper_data_summary_detected_at_block_1(tmp_path: Path) -> None:
    """Modify data_summary of Block #1 directly in SQLite and assert broken_at_index == 1."""
    test_db = tmp_path / "blockchain_tamper_b1.db"
    init_db(test_db)

    reg = register_asset(
        owner_username="alice",
        asset_name="Dokumen Paten Algoritma",
        content_bytes=b"PATENT-DATA-001",
        db_path=test_db,
    )
    asset_id = reg["asset"]["id"]
    transfer_asset(asset_id, "alice", "bob", db_path=test_db)
    transfer_asset(asset_id, "bob", "charlie", db_path=test_db)

    # Tamper with Block #1 data_summary in SQLite without recomputing hashes
    conn = get_connection(test_db)
    try:
        with conn:
            conn.execute(
                "UPDATE asset_blocks SET data_summary = ? WHERE block_index = 1",
                ("asset_code=AST-2026-0001;fingerprint=TAMPERED;from=GENESIS;to=mallory",),
            )
    finally:
        conn.close()

    ledger = Blockchain(db_path=test_db)
    report = ledger.verify_chain()
    assert report["is_valid"] is False
    assert report["broken_at_index"] == 1
    assert isinstance(report["error_detail"], str) and "blok #1" in report["error_detail"]


def test_relinked_tampered_block_fails_on_next_block_previous_hash(
    tmp_path: Path,
) -> None:
    """Recompute only the tampered Block #1 hash and assert Block #2 fails on previous_hash."""
    test_db = tmp_path / "blockchain_relink.db"
    init_db(test_db)

    reg = register_asset(
        owner_username="alice",
        asset_name="Kontrak Lisensi Kriptografi",
        content_bytes=b"LICENSE-2026",
        db_path=test_db,
    )
    asset_id = reg["asset"]["id"]
    transfer_asset(asset_id, "alice", "bob", db_path=test_db)
    transfer_asset(asset_id, "bob", "charlie", db_path=test_db)

    # Modify Block #1 data_summary AND recompute Block #1's current_hash
    conn = get_connection(test_db)
    try:
        row1 = conn.execute(
            "SELECT * FROM asset_blocks WHERE block_index = 1"
        ).fetchone()
        tampered_summary = "asset_code=AST-2026-0001;fingerprint=FORGED;from=GENESIS;to=eve"
        forged_hash_1 = compute_block_hash(
            block_index=int(row1["block_index"]),
            timestamp=str(row1["timestamp"]),
            actor_username=str(row1["actor_username"]),
            action_type=str(row1["action_type"]),
            target_asset_id=int(row1["target_asset_id"]),
            data_summary=tampered_summary,
            nonce=int(row1["nonce"]),
            previous_hash=str(row1["previous_hash"]),
        )
        with conn:
            conn.execute(
                "UPDATE asset_blocks SET data_summary = ?, current_hash = ? WHERE block_index = 1",
                (tampered_summary, forged_hash_1),
            )
    finally:
        conn.close()

    ledger = Blockchain(db_path=test_db)
    report = ledger.verify_chain()
    assert report["is_valid"] is False
    # Block #1 hash matches its own tampered fields, so Block #2 detects previous_hash mismatch!
    assert report["broken_at_index"] == 2
    assert "previous_hash" in (report["error_detail"] or "")


def test_optional_proof_of_work_leading_zeros(tmp_path: Path) -> None:
    """Verify that when PoW difficulty > 0 is enabled, every block current_hash starts with required zeros."""
    test_db = tmp_path / "blockchain_pow.db"
    # Initialize tables without non-PoW genesis so Blockchain creates Genesis with PoW difficulty=2
    conn = get_connection(test_db)
    try:
        from backend.database import DDL_ASSET_BLOCKS, DDL_ASSETS, DDL_MESSAGES, DDL_USERS

        with conn:
            conn.execute(DDL_USERS)
            conn.execute(DDL_MESSAGES)
            conn.execute(DDL_ASSETS)
            conn.execute(DDL_ASSET_BLOCKS)
    finally:
        conn.close()

    difficulty = 2
    reg = register_asset(
        owner_username="alice",
        asset_name="Aset PoW",
        content_bytes=b"POW-CONTENT",
        db_path=test_db,
        pow_difficulty=difficulty,
    )
    transfer_asset(
        asset_id=reg["asset"]["id"],
        actor_username="alice",
        new_owner_username="bob",
        db_path=test_db,
        pow_difficulty=difficulty,
    )

    ledger = Blockchain(db_path=test_db, pow_difficulty=difficulty)
    blocks = ledger.get_all_blocks()
    assert len(blocks) == 3
    for blk in blocks:
        assert blk.current_hash.startswith("0" * difficulty)

    report = ledger.verify_chain()
    assert report["is_valid"] is True


def test_verify_chain_contract_keys_valid_and_tampered(tmp_path: Path) -> None:
    """Verify verify_chain() returns strictly the 4 contract keys from context/004 Section 2.6."""
    expected_keys = {"is_valid", "total_blocks", "broken_at_index", "error_detail"}

    test_db = tmp_path / "blockchain_contract_keys.db"
    init_db(test_db)

    reg = register_asset(
        owner_username="alice",
        asset_name="Dokumen Kontrak Integritas",
        content_bytes=b"CONTRACT-BYTES-2026",
        db_path=test_db,
    )
    transfer_asset(reg["asset"]["id"], "alice", "bob", db_path=test_db)

    # 1. Valid chain case
    valid_chain_data = get_chain_with_verification(db_path=test_db)
    valid_report = valid_chain_data["verification"]
    assert set(valid_report.keys()) == expected_keys
    assert valid_report["is_valid"] is True
    assert valid_report["total_blocks"] == 3
    assert valid_report["broken_at_index"] is None
    assert valid_report["error_detail"] is None

    # 2. Tampered chain case (modify 1 character in Block #1 data_summary)
    conn = get_connection(test_db)
    try:
        with conn:
            conn.execute(
                "UPDATE asset_blocks SET data_summary = data_summary || 'X' WHERE block_index = 1"
            )
    finally:
        conn.close()

    tampered_chain_data = get_chain_with_verification(db_path=test_db)
    tampered_report = tampered_chain_data["verification"]
    assert set(tampered_report.keys()) == expected_keys
    assert tampered_report["is_valid"] is False
    assert tampered_report["total_blocks"] == 3
    assert tampered_report["broken_at_index"] == 1
    assert isinstance(tampered_report["error_detail"], str)
    assert len(tampered_report["error_detail"]) > 0

