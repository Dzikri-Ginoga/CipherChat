"""Unit tests for Phase 1 USB dongle gate, SQLite schema, and 3-factor biometric login."""

from __future__ import annotations

import io
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import pytest
from PIL import Image

from backend.core.dongle_auth import (
    compute_dongle_token_hash,
    enforce_startup_dongle_gate,
    scan_dongle_token,
    verify_usb_dongle,
    verify_user_dongle,
)
from backend.database import get_connection, init_db
from backend.repositories.user_repo import authenticate_user, register_user
from scripts.generate_dongle_key import generate_dongle_key
from scripts.run_app import main as run_app_main


def _make_synthetic_face_png_bytes(seed: int = 42) -> bytes:
    """Create a deterministic patterned 200x200 RGB PNG image for biometric tests."""
    rng = np.random.default_rng(seed)
    base = rng.integers(30, 220, size=(200, 200, 3), dtype=np.uint8)
    # Draw symmetric eye/mouth-like features so histogram & template correlation are realistic
    base[60:80, 50:80] = 20
    base[60:80, 120:150] = 20
    base[130:145, 70:130] = 40
    buf = io.BytesIO()
    Image.fromarray(base, mode="RGB").save(buf, format="PNG")
    return buf.getvalue()


def test_valid_dongle_detection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify valid auth.key in CIPHERCHAT_DONGLE_MOCK_DIR succeeds."""
    key_path, raw_token, expected_hash = generate_dongle_key(tmp_path)
    assert key_path.is_file()
    assert compute_dongle_token_hash(raw_token) == expected_hash

    monkeypatch.setenv("CIPHERCHAT_DONGLE_MOCK_DIR", str(tmp_path))
    monkeypatch.setenv("CIPHERCHAT_DONGLE_BOOTSTRAP_HASH_HEX", expected_hash)

    status = verify_usb_dongle()
    assert status.detected is True
    assert status.token_hash_hex == expected_hash
    assert status.mountpoint == str(tmp_path)


def test_missing_empty_and_wrong_dongle_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify missing file, empty file, and wrong token each return detected == False."""
    monkeypatch.setenv("CIPHERCHAT_DONGLE_MOCK_DIR", str(tmp_path))

    # 1. Missing auth.key file
    missing_status = verify_usb_dongle()
    assert missing_status.detected is False
    assert missing_status.message == "USB Dongle (auth.key) tidak terdeteksi"

    # 2. Empty auth.key file
    key_file = tmp_path / "auth.key"
    key_file.write_text("   \n", encoding="utf-8")
    empty_status = scan_dongle_token()
    assert empty_status.detected is False
    assert empty_status.message == "USB Dongle (auth.key) tidak terdeteksi"

    # 3. Wrong token hash mismatch against expected user hash
    key_file.write_text("valid_raw_token_value_12345\n", encoding="utf-8")
    wrong_expected_hash = "a" * 64
    mismatch_status = verify_usb_dongle(expected_hashes=[wrong_expected_hash])
    assert mismatch_status.detected is False
    assert mismatch_status.message == "USB Dongle tidak cocok dengan akun ini"

    user_mismatch = verify_user_dongle(wrong_expected_hash)
    assert user_mismatch.detected is False
    assert user_mismatch.message == "USB Dongle tidak cocok dengan akun ini"


def test_startup_gate_raises_and_launcher_exits_without_dongle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify startup gate raises PermissionError and launcher exits with code 1 when missing."""
    empty_usb = tmp_path / "empty_usb"
    empty_usb.mkdir()
    monkeypatch.setenv("CIPHERCHAT_DONGLE_MOCK_DIR", str(empty_usb))

    with pytest.raises(PermissionError) as exc_info:
        enforce_startup_dongle_gate()
    assert "USB Dongle (auth.key) tidak terdeteksi" in str(exc_info.value)

    exit_code = run_app_main(["--check-only", "--db-path", str(tmp_path / "gate_test.db")])
    assert exit_code == 1


def test_database_init_and_three_factor_authentication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify SQLite schema creation, user registration, and 3-factor biometric login."""
    test_db = tmp_path / "test_cipherchat.db"
    bio_dir = tmp_path / "biometrics"
    usb_dir = tmp_path / "usb_drive"
    init_db(test_db)

    # Confirm all 4 tables and Genesis block exist
    conn = get_connection(test_db)
    try:
        tables = {
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert {"users", "messages", "assets", "asset_blocks"}.issubset(tables)
        genesis = conn.execute(
            "SELECT * FROM asset_blocks WHERE block_index = 0"
        ).fetchone()
        assert genesis is not None
        assert genesis["action_type"] == "GENESIS"
        assert genesis["previous_hash"] == "0" * 64
    finally:
        conn.close()

    _, _, token_hash = generate_dongle_key(usb_dir)
    monkeypatch.setenv("CIPHERCHAT_DONGLE_MOCK_DIR", str(usb_dir))
    monkeypatch.setenv("CIPHERCHAT_FACE_MATCH_THRESHOLD", "0.75")

    face_bytes_alice = _make_synthetic_face_png_bytes(seed=101)
    face_bytes_stranger = _make_synthetic_face_png_bytes(seed=999)

    user = register_user(
        username="alice",
        password="SecretPassword123!",
        face_image_bytes=face_bytes_alice,
        db_path=test_db,
        biometrics_dir=bio_dir,
        mock_dongle_dir=usb_dir,
    )
    assert user["username"] == "alice"
    assert user["dongle_token_hash_hex"] == token_hash

    # 1. All 3 factors valid -> Login succeeds
    ok_res = authenticate_user(
        username="alice",
        password="SecretPassword123!",
        webcam_frame=face_bytes_alice,
        db_path=test_db,
        mock_dongle_dir=usb_dir,
    )
    assert ok_res["authenticated"] is True
    assert ok_res["factors"]["dongle"] is True
    assert ok_res["factors"]["password"] is True
    assert ok_res["factors"]["biometric"] is True
    assert ok_res["factors"]["face_score"] >= 0.75

    # 2a. Dongle factor failure: wrong dongle token mounted
    wrong_usb_dir = tmp_path / "wrong_usb_drive"
    generate_dongle_key(wrong_usb_dir)
    bad_dongle_res = authenticate_user(
        username="alice",
        password="SecretPassword123!",
        webcam_frame=face_bytes_alice,
        db_path=test_db,
        mock_dongle_dir=wrong_usb_dir,
    )
    assert bad_dongle_res["authenticated"] is False
    assert bad_dongle_res["factors"]["dongle"] is False
    assert bad_dongle_res["factors"]["password"] is True
    assert bad_dongle_res["factors"]["biometric"] is True
    assert bad_dongle_res["message"] == "USB Dongle tidak cocok dengan akun ini"

    # 2b. Dongle factor failure: dongle unplugged (missing auth.key)
    unplugged_usb_dir = tmp_path / "unplugged_usb_drive"
    unplugged_usb_dir.mkdir()
    missing_dongle_res = authenticate_user(
        username="alice",
        password="SecretPassword123!",
        webcam_frame=face_bytes_alice,
        db_path=test_db,
        mock_dongle_dir=unplugged_usb_dir,
    )
    assert missing_dongle_res["authenticated"] is False
    assert missing_dongle_res["factors"]["dongle"] is False
    assert missing_dongle_res["factors"]["password"] is True
    assert missing_dongle_res["factors"]["biometric"] is True
    assert missing_dongle_res["message"] == "USB Dongle (auth.key) tidak terdeteksi"

    # 3. Password factor failure: wrong password
    bad_pw_res = authenticate_user(
        username="alice",
        password="WrongPassword",
        webcam_frame=face_bytes_alice,
        db_path=test_db,
        mock_dongle_dir=usb_dir,
    )
    assert bad_pw_res["authenticated"] is False
    assert bad_pw_res["factors"]["dongle"] is True
    assert bad_pw_res["factors"]["password"] is False
    assert bad_pw_res["factors"]["biometric"] is True
    assert bad_pw_res["message"] == "Kata sandi salah"

    # 4a. Biometric factor failure: no face in camera frame (blank image)
    blank_buf = io.BytesIO()
    Image.fromarray(np.zeros((200, 200, 3), dtype=np.uint8), mode="RGB").save(
        blank_buf, format="PNG"
    )
    no_face_res = authenticate_user(
        username="alice",
        password="SecretPassword123!",
        webcam_frame=blank_buf.getvalue(),
        db_path=test_db,
        mock_dongle_dir=usb_dir,
    )
    assert no_face_res["authenticated"] is False
    assert no_face_res["factors"]["dongle"] is True
    assert no_face_res["factors"]["password"] is True
    assert no_face_res["factors"]["biometric"] is False
    assert no_face_res["factors"]["face_score"] == 0.0
    assert no_face_res["message"] == "Wajah tidak terdeteksi pada kamera"

    # 4b. Biometric factor failure: different person's face below threshold
    bad_face_res = authenticate_user(
        username="alice",
        password="SecretPassword123!",
        webcam_frame=face_bytes_stranger,
        db_path=test_db,
        mock_dongle_dir=usb_dir,
    )
    assert bad_face_res["authenticated"] is False
    assert bad_face_res["factors"]["dongle"] is True
    assert bad_face_res["factors"]["password"] is True
    assert bad_face_res["factors"]["biometric"] is False
    assert bad_face_res["message"] == "Verifikasi wajah gagal"


def test_fastapi_routers_session_and_startup_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify FastAPI startup dongle gate, public endpoints, and session-protected routers."""
    from fastapi import HTTPException, UploadFile

    import backend.config as cfg_mod
    import backend.database as db_mod
    import backend.repositories.user_repo as urepo_mod
    from backend.main import app, reset_dongle_middleware_cache, verify_startup_gate
    from backend.routers.asset_router import get_asset_chain_endpoint, list_assets_endpoint
    from backend.routers.auth_router import (
        clear_all_sessions,
        create_session_for_user,
        get_dongle_status,
        require_authenticated_user,
    )
    from backend.routers.message_router import (
        SendTextMessageRequest,
        inspect_message_endpoint,
        post_text_message,
    )

    test_db = tmp_path / "api_cipherchat.db"
    bio_dir = tmp_path / "api_biometrics"
    usb_dir = tmp_path / "api_usb"
    empty_usb = tmp_path / "empty_usb"
    empty_usb.mkdir()

    monkeypatch.setattr(cfg_mod, "DB_PATH", test_db)
    monkeypatch.setattr(db_mod, "DB_PATH", test_db)
    monkeypatch.setattr(urepo_mod, "BIOMETRICS_DIR", bio_dir)

    # 1. Startup gate refuses to start when USB dongle is missing
    monkeypatch.setenv("CIPHERCHAT_DONGLE_MOCK_DIR", str(empty_usb))
    reset_dongle_middleware_cache()
    with pytest.raises(RuntimeError) as exc_info:
        verify_startup_gate()
    assert "USB Dongle (auth.key) tidak terdeteksi" in str(exc_info.value)

    # 2. Mount valid USB dongle and verify startup gate succeeds
    _, _, token_hash = generate_dongle_key(usb_dir)
    monkeypatch.setenv("CIPHERCHAT_DONGLE_MOCK_DIR", str(usb_dir))
    monkeypatch.setenv("CIPHERCHAT_FACE_MATCH_THRESHOLD", "0.75")
    monkeypatch.setenv("CIPHERCHAT_DONGLE_BOOTSTRAP_HASH_HEX", token_hash)
    reset_dongle_middleware_cache()
    clear_all_sessions()
    verify_startup_gate()

    # 3. Verify all expected route paths are registered on the FastAPI app
    registered_paths = set(app.openapi()["paths"].keys())
    expected_paths = {
        "/api/v1/auth/dongle-status",
        "/api/v1/auth/register",
        "/api/v1/auth/login",
        "/api/v1/messages/text",
        "/api/v1/messages/inbox",
        "/api/v1/messages/{message_id}/inspect",
        "/api/v1/files/send",
        "/api/v1/files/{message_id}/download",
        "/api/v1/files/{message_id}/raw-preview",
        "/api/v1/stego/send",
        "/api/v1/stego/{message_id}/reveal",
        "/api/v1/stego/extract",
        "/api/v1/assets",
        "/api/v1/assets/{asset_id}/transfer",
        "/api/v1/assets/chain",
    }
    assert expected_paths.issubset(registered_paths)

    # 4. Public endpoint: dongle-status works without session
    status_data = get_dongle_status()
    assert status_data["detected"] is True

    # 5. Protected endpoints reject missing/invalid session token with HTTP 401
    with pytest.raises(HTTPException) as auth_exc:
        require_authenticated_user(authorization=None, x_session_token=None)
    assert auth_exc.value.status_code == 401

    # 6. Register user, create session, and verify protected router handlers
    face_bytes = _make_synthetic_face_png_bytes(seed=77)
    user = register_user(
        username="dosen_tester",
        password="StrongPassword!1",
        face_image_bytes=face_bytes,
        db_path=test_db,
        biometrics_dir=bio_dir,
        mock_dongle_dir=usb_dir,
    )
    token = create_session_for_user(user)
    auth_user = require_authenticated_user(authorization=f"Bearer {token}")
    assert auth_user["username"] == "dosen_tester"

    sent_msg = post_text_message(
        payload=SendTextMessageRequest(
            recipient_username="dosen_tester",
            text="Pesan uji coba REST API",
            is_important=True,
        ),
        current_user=auth_user,
    )
    inspected = inspect_message_endpoint(
        message_id=sent_msg["id"], current_user=auth_user
    )
    assert inspected["plaintext"] == "Pesan uji coba REST API"
    assert inspected["storage_layers"] == "SUPER+DBCOL"

    assert isinstance(list_assets_endpoint(current_user=auth_user), list)
    chain_report = get_asset_chain_endpoint(current_user=auth_user)
    assert chain_report["verification"]["is_valid"] is True


def test_end_to_end_lecturer_demo_5_steps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Execute all 5 steps of the End-to-End Lecturer Demo Script (context/006 Section 2)."""
    from backend.repositories.asset_repo import (
        get_chain_with_verification,
        register_asset,
        transfer_asset,
    )
    from backend.repositories.message_repo import (
        download_decrypted_file_message,
        get_decrypted_message,
        get_file_raw_preview,
        get_raw_ciphertext_message,
        inspect_stored_text_message,
        reveal_image_message,
        send_file_message,
        send_image_message,
        send_text_message,
    )
    from backend.repositories.user_repo import get_user_by_username
    from scripts.prepare_demo import prepare_demo_environment

    test_db = tmp_path / "demo_e2e.db"
    info = prepare_demo_environment(
        base_storage_dir=tmp_path, db_path=test_db, update_dotenv=False
    )
    usb_dir = Path(info["dongle_key_path"]).parent

    # Demo Step 1: Dongle Gate and Biometric Login [Criteria 1 and 2]
    empty_usb = tmp_path / "unplugged_usb"
    empty_usb.mkdir()
    with pytest.raises(PermissionError) as gate_exc:
        enforce_startup_dongle_gate(mock_dir=empty_usb)
    assert "USB Dongle (auth.key) tidak terdeteksi" in str(gate_exc.value)

    alice_face_bytes = Path(info["face_alice_path"]).read_bytes()
    login_res = authenticate_user(
        username="alice",
        password="AlicePassword123!",
        webcam_frame=alice_face_bytes,
        db_path=test_db,
        mock_dongle_dir=usb_dir,
    )
    assert login_res["authenticated"] is True
    assert login_res["user"]["username"] == "alice"

    alice_row = get_user_by_username("alice", db_path=test_db, include_secrets=True)
    bob_row = get_user_by_username("bob", db_path=test_db)
    assert alice_row is not None and bob_row is not None
    assert alice_row["password_hash_hex"] != "AlicePassword123!"
    assert len(alice_row["password_salt_hex"]) == 32

    # Demo Step 2: Text Super Encryption and Important Message [Criteria 3 and 5]
    normal_msg = send_text_message(
        sender_id=alice_row["id"],
        recipient_id=bob_row["id"],
        plaintext="Rapat proyek besok jam 09.30 di ruang B2",
        is_important=False,
        db_path=test_db,
    )
    insp_normal = inspect_stored_text_message(normal_msg["id"], db_path=test_db)
    assert insp_normal["storage_layers"] == "SUPER"
    assert insp_normal["step1_vigenere"] != insp_normal["plaintext"]
    assert insp_normal["decrypted_back"] == "Rapat proyek besok jam 09.30 di ruang B2"

    important_msg = send_text_message(
        sender_id=alice_row["id"],
        recipient_id=bob_row["id"],
        plaintext="Pesan sangat penting rahasia negara",
        is_important=True,
        db_path=test_db,
    )
    raw_imp = get_raw_ciphertext_message(important_msg["id"], db_path=test_db)
    dec_imp = get_decrypted_message(
        important_msg["id"],
        requesting_user_id=bob_row["id"],
        db_path=test_db,
        mock_dongle_dir=usb_dir,
        enforce_dongle_for_important=True,
    )
    assert raw_imp["storage_layers"] == "SUPER+DBCOL"
    assert "Pesan sangat penting" not in raw_imp["body_stored"]
    assert dec_imp["decrypted_text"] == "Pesan sangat penting rahasia negara"

    # Demo Step 3: ChaCha20 File Message [Criterion 4]
    pdf_bytes = Path(info["pdf_path"]).read_bytes()
    file_msg = send_file_message(
        sender_id=alice_row["id"],
        recipient_id=bob_row["id"],
        file_bytes=pdf_bytes,
        original_filename="laporan.pdf",
        mime_type="application/pdf",
        db_path=test_db,
        encrypted_files_dir=tmp_path / "encrypted_files",
    )
    preview = get_file_raw_preview(file_msg["id"], db_path=test_db)
    assert not bytes.fromhex(preview["hex_preview"]).startswith(b"%PDF")
    restored = download_decrypted_file_message(
        file_msg["id"],
        requesting_user_id=bob_row["id"],
        db_path=test_db,
        mock_dongle_dir=usb_dir,
        enforce_dongle=True,
    )
    assert restored["file_bytes"] == pdf_bytes

    # Demo Step 4: Image Message with LSB Steganography [Criterion 6]
    cover_bytes = Path(info["cover_png_path"]).read_bytes()
    img_msg = send_image_message(
        sender_id=alice_row["id"],
        recipient_id=bob_row["id"],
        cover_image=cover_bytes,
        secret_message="Pesan tersembunyi di piksel PNG untuk demo dosen",
        db_path=test_db,
        stego_images_dir=tmp_path / "stego_images",
    )
    assert img_msg["max_pixel_delta"] <= 1
    assert img_msg["psnr_db"] > 50.0
    revealed = reveal_image_message(
        img_msg["id"], requesting_user_id=bob_row["id"], db_path=test_db
    )
    assert (
        revealed["secret_message"]
        == "Pesan tersembunyi di piksel PNG untuk demo dosen"
    )

    # Demo Step 5: Asset Blockchain and Tamper Detection [Criterion 7]
    reg_res = register_asset(
        owner_username="alice",
        asset_name="Sertifikat Kunci Master 2026",
        description="Dokumen aset penting",
        content_bytes=pdf_bytes,
        asset_code="AST-DEMO-001",
        db_path=test_db,
    )
    transfer_asset(
        asset_id=reg_res["asset"]["id"],
        actor_username="alice",
        new_owner_username="bob",
        db_path=test_db,
    )
    chain_valid = get_chain_with_verification(db_path=test_db)
    assert chain_valid["verification"]["is_valid"] is True
    assert len(chain_valid["blocks"]) == 3

    conn = get_connection(test_db)
    try:
        with conn:
            conn.execute(
                "UPDATE asset_blocks SET data_summary = 'TAMPERED_SUMMARY' WHERE block_index = 1"
            )
    finally:
        conn.close()

    chain_tampered = get_chain_with_verification(db_path=test_db)
    assert chain_tampered["verification"]["is_valid"] is False
    assert chain_tampered["verification"]["broken_at_index"] == 1


def test_real_usb_partitions_wrong_hash_gate_sensitive_actions_and_update_script(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify psutil USB detection when MOCK_DIR is empty, startup rejection on wrong hash, mid-session unplug blocking, and update_user_dongle.py."""
    from collections import namedtuple
    import psutil
    from backend.repositories.message_repo import (
        download_decrypted_file_message,
        get_decrypted_message,
        inspect_stored_text_message,
        send_file_message,
        send_text_message,
    )
    from backend.repositories.user_repo import get_user_by_username
    from scripts.update_user_dongle import main as update_dongle_cli_main

    FakePartition = namedtuple("FakePartition", ["device", "mountpoint", "fstype", "opts"])

    usb_mount = tmp_path / "physical_usb_drive"
    usb_mount.mkdir()

    # Ensure CIPHERCHAT_DONGLE_MOCK_DIR is empty so only psutil.disk_partitions is used
    monkeypatch.setenv("CIPHERCHAT_DONGLE_MOCK_DIR", "")
    monkeypatch.setattr(
        psutil,
        "disk_partitions",
        lambda all=False: [
            FakePartition("E:\\", str(usb_mount), "FAT32", "rw,removable"),
        ],
    )

    # 1. File hilang (missing auth.key on physical USB) -> detected == False
    st_missing = verify_usb_dongle()
    assert st_missing.detected is False
    assert st_missing.message == "USB Dongle (auth.key) tidak terdeteksi"
    assert "mock_usb" not in str(st_missing.mountpoint or "")

    # 2. File kosong (empty auth.key on physical USB) -> detected == False
    auth_key_file = usb_mount / "auth.key"
    auth_key_file.write_text("   \n", encoding="utf-8")
    st_empty = verify_usb_dongle()
    assert st_empty.detected is False
    assert st_empty.message == "USB Dongle (auth.key) tidak terdeteksi"

    # 3. Token salah (wrong token in auth.key vs expected/bootstrap hash) -> detected == False & startup gate refuses
    _, _, valid_hash = generate_dongle_key(usb_mount)
    wrong_hash = "f" * 64
    st_wrong = verify_usb_dongle(expected_hashes=[wrong_hash])
    assert st_wrong.detected is False
    assert st_wrong.message == "USB Dongle tidak cocok dengan akun ini"

    with pytest.raises(PermissionError) as gate_wrong_exc:
        enforce_startup_dongle_gate(expected_hashes=[wrong_hash])
    assert "USB Dongle tidak cocok dengan akun ini" in str(gate_wrong_exc.value)

    # 4. Token benar (matching token in auth.key) -> detected == True & startup gate passes
    st_valid = verify_usb_dongle(expected_hashes=[valid_hash])
    assert st_valid.detected is True
    assert st_valid.token_hash_hex == valid_hash
    assert st_valid.mountpoint == str(usb_mount)
    gate_ok = enforce_startup_dongle_gate(expected_hashes=[valid_hash])
    assert gate_ok.detected is True

    # 5. Mid-session USB unplug blocks reading important messages and downloading files
    test_db = tmp_path / "usb_mid_session.db"
    bio_dir = tmp_path / "usb_bio"
    init_db(test_db)
    face_bytes = _make_synthetic_face_png_bytes(seed=55)

    alice = register_user(
        username="alice",
        password="AliceSecretPassword!",
        face_image_bytes=face_bytes,
        db_path=test_db,
        biometrics_dir=bio_dir,
    )
    assert alice["dongle_token_hash_hex"] == valid_hash

    imp_msg = send_text_message(
        sender_id=alice["id"],
        recipient_id=alice["id"],
        plaintext="Pesan penting rahasia tingkat tinggi",
        is_important=True,
        db_path=test_db,
    )
    file_msg = send_file_message(
        sender_id=alice["id"],
        recipient_id=alice["id"],
        file_bytes=b"%PDF-1.4 Rahasia",
        original_filename="rahasia.pdf",
        mime_type="application/pdf",
        db_path=test_db,
        encrypted_files_dir=tmp_path / "enc_files",
    )

    # Simulate unplugging the physical USB flash drive mid-session
    monkeypatch.setattr(psutil, "disk_partitions", lambda all=False: [])

    with pytest.raises(PermissionError) as read_imp_exc:
        get_decrypted_message(imp_msg["id"], requesting_user_id=alice["id"], db_path=test_db)
    assert "USB Dongle (auth.key) tidak terdeteksi" in str(read_imp_exc.value)

    with pytest.raises(PermissionError) as insp_imp_exc:
        inspect_stored_text_message(imp_msg["id"], db_path=test_db)
    assert "USB Dongle (auth.key) tidak terdeteksi" in str(insp_imp_exc.value)

    with pytest.raises(PermissionError) as dl_file_exc:
        download_decrypted_file_message(file_msg["id"], requesting_user_id=alice["id"], db_path=test_db)
    assert "USB Dongle (auth.key) tidak terdeteksi" in str(dl_file_exc.value)

    # 6. Plug in a NEW physical USB flash drive and update user's dongle hash via scripts/update_user_dongle.py
    new_usb_mount = tmp_path / "new_physical_usb"
    _, _, new_usb_hash = generate_dongle_key(new_usb_mount)
    assert new_usb_hash != valid_hash

    monkeypatch.setattr(
        psutil,
        "disk_partitions",
        lambda all=False: [
            FakePartition("F:\\", str(new_usb_mount), "FAT32", "rw,removable"),
        ],
    )

    # Before updating, the new USB dongle does not match alice's old hash
    with pytest.raises(PermissionError) as mismatch_exc:
        get_decrypted_message(imp_msg["id"], requesting_user_id=alice["id"], db_path=test_db)
    assert "USB Dongle tidak cocok dengan akun ini" in str(mismatch_exc.value)

    # Wrong password in update_user_dongle.py must fail with exit code 1
    bad_code = update_dongle_cli_main(
        ["--username", "alice", "--password", "WrongPass", "--db-path", str(test_db)]
    )
    assert bad_code == 1

    # Correct password in update_user_dongle.py updates alice's dongle_token_hash_hex
    ok_code = update_dongle_cli_main(
        [
            "--username",
            "alice",
            "--password",
            "AliceSecretPassword!",
            "--db-path",
            str(test_db),
        ]
    )
    assert ok_code == 0

    updated_alice = get_user_by_username("alice", db_path=test_db)
    assert updated_alice is not None
    assert updated_alice["dongle_token_hash_hex"] == new_usb_hash

    # Now sensitive actions succeed with the new physical USB flash drive
    dec_after = get_decrypted_message(
        imp_msg["id"], requesting_user_id=alice["id"], db_path=test_db
    )
    assert dec_after["decrypted_text"] == "Pesan penting rahasia tingkat tinggi"


def test_empty_mock_dir_and_no_usb_flashdrive_returns_detected_false(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify that when CIPHERCHAT_DONGLE_MOCK_DIR is empty and no removable USB drive is mounted, detection is False even if fixed drives or mock_usb exist."""
    from collections import namedtuple
    import psutil

    FakePartition = namedtuple("FakePartition", ["device", "mountpoint", "fstype", "opts"])

    fixed_c = tmp_path / "fixed_c"
    fixed_d = tmp_path / "fixed_d"
    fixed_c.mkdir()
    fixed_d.mkdir()
    # Even if a fixed drive accidentally has an auth.key, fixed drives must be ignored
    generate_dongle_key(fixed_c)
    generate_dongle_key(fixed_d)

    monkeypatch.setenv("CIPHERCHAT_DONGLE_MOCK_DIR", "")
    monkeypatch.setattr(
        psutil,
        "disk_partitions",
        lambda all=False: [
            FakePartition("C:\\", str(fixed_c), "NTFS", "rw,fixed"),
            FakePartition("D:\\", str(fixed_d), "NTFS", "rw,fixed"),
        ],
    )

    status = verify_usb_dongle()
    assert status.detected is False
    assert status.mountpoint is None
    assert status.token_hash_hex is None
    assert status.message == "USB Dongle (auth.key) tidak terdeteksi"

    with pytest.raises(PermissionError) as gate_exc:
        enforce_startup_dongle_gate()
    assert "USB Dongle (auth.key) tidak terdeteksi" in str(gate_exc.value)

    exit_code = run_app_main(["--check-only", "--db-path", str(tmp_path / "no_usb.db")])
    assert exit_code == 1


def test_is_dongle_connected_detection_and_removal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify is_dongle_connected returns True when key exists and False when removed."""
    from backend.core.dongle_auth import is_dongle_connected
    from scripts.generate_dongle_key import generate_dongle_key

    usb_mock = tmp_path / "usb_removable"
    usb_mock.mkdir()
    empty_mock = tmp_path / "usb_empty"
    empty_mock.mkdir()

    # 1. Empty directory has no dongle
    monkeypatch.setenv("CIPHERCHAT_DONGLE_MOCK_DIR", str(empty_mock))
    assert is_dongle_connected() is False
    assert is_dongle_connected(mock_dir=empty_mock) is False

    # 2. Key generated in directory
    key_file, _, _ = generate_dongle_key(usb_mock)
    monkeypatch.setenv("CIPHERCHAT_DONGLE_MOCK_DIR", str(usb_mock))
    assert is_dongle_connected() is True
    assert is_dongle_connected(mock_dir=usb_mock) is True

    # 3. Key file removed (simulating USB dongle removal during operation)
    key_file.unlink()
    assert is_dongle_connected() is False
    assert is_dongle_connected(mock_dir=usb_mock) is False


def test_require_active_dongle_dependency(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify require_active_dongle passes when dongle is connected and raises 403 when removed."""
    from fastapi import HTTPException

    from backend.dependencies import require_active_dongle
    from scripts.generate_dongle_key import generate_dongle_key

    usb_mock = tmp_path / "usb_dependency_test"
    usb_mock.mkdir()
    key_file, _, _ = generate_dongle_key(usb_mock)
    monkeypatch.setenv("CIPHERCHAT_DONGLE_MOCK_DIR", str(usb_mock))

    # Connected: returns True
    assert require_active_dongle() is True

    # Dongle removed: raises HTTPException 403
    key_file.unlink()
    with pytest.raises(HTTPException) as exc_info:
        require_active_dongle()
    assert exc_info.value.status_code == 403
    assert "Security violation: Hardware dongle not detected." in exc_info.value.detail


def test_dongle_removal_guard_blocks_protected_api_routes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify router dependencies and endpoints enforce HTTP 403 when USB dongle is removed."""
    from fastapi import HTTPException

    from backend.dependencies import require_active_dongle
    from backend.routers.asset_router import router as asset_router
    from backend.routers.auth_router import get_dongle_status
    from backend.routers.file_router import router as file_router
    from backend.routers.message_router import router as message_router
    from backend.routers.stego_router import router as stego_router
    from scripts.generate_dongle_key import generate_dongle_key

    usb_dir = tmp_path / "guard_usb"
    usb_dir.mkdir()
    key_file, _, _ = generate_dongle_key(usb_dir)
    monkeypatch.setenv("CIPHERCHAT_DONGLE_MOCK_DIR", str(usb_dir))

    # 1. Verify require_active_dongle is attached as a security dependency to all protected routers
    for r in (message_router, file_router, stego_router, asset_router):
        deps = [d.dependency for d in r.dependencies]
        assert require_active_dongle in deps

    # 2. When dongle is plugged in, dongle-status returns connected=True
    status_attached = get_dongle_status()
    assert status_attached["connected"] is True
    assert status_attached["detected"] is True
    assert require_active_dongle() is True

    # 3. Simulate dongle removal by unlinking key file
    key_file.unlink()

    # 4. dongle-status immediately reports disconnected without reading file contents
    status_detached = get_dongle_status()
    assert status_detached["connected"] is False
    assert status_detached["detected"] is False

    # 5. Dependency immediately blocks access with HTTP 403 Forbidden
    with pytest.raises(HTTPException) as exc_info:
        require_active_dongle()
    assert exc_info.value.status_code == 403
    assert "Security violation: Hardware dongle not detected." in exc_info.value.detail





