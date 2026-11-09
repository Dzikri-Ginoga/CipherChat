"""Streamlit 5-page frontend for CipherChat Crypto."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st

from backend.config import load_config
from backend.core.dongle_auth import DongleStatus, verify_usb_dongle
from backend.core.stego_engine import extract_lsb
from backend.database import init_db
from backend.repositories.asset_repo import (
    get_chain_with_verification,
    list_assets,
    register_asset,
    transfer_asset,
)
from backend.repositories.message_repo import (
    download_decrypted_file_message,
    get_file_raw_preview,
    inspect_stored_text_message,
    list_inbox_messages,
    reveal_image_message,
    send_file_message,
    send_image_message,
    send_text_message,
)
from backend.repositories.user_repo import (
    authenticate_user,
    get_all_dongle_hashes,
    get_user_by_username,
    list_users,
    register_user,
)


def _check_live_dongle() -> DongleStatus:
    """Evaluate live USB dongle status on every Streamlit rerun without caching."""
    cfg = load_config()
    init_db()
    registered_hashes = get_all_dongle_hashes()
    return verify_usb_dongle(
        expected_hashes=registered_hashes if registered_hashes else None,
        bootstrap_hash_hex=cfg.dongle_bootstrap_hash_hex,
        dongle_filename=cfg.dongle_filename,
        mock_dir=cfg.dongle_mock_dir if cfg.dongle_mock_dir else None,
    )


def _format_dongle_location(dongle_status: DongleStatus) -> str:
    """Format the detected USB mountpoint label without exposing mock_usb when mock mode is off."""
    cfg = load_config()
    raw_mount = str(dongle_status.mountpoint or "").strip()
    if not cfg.dongle_mock_dir and "mock_usb" in raw_mount.lower():
        return "Perangkat USB"
    return raw_mount or "Perangkat USB"


def _init_session_state() -> None:
    """Initialize Streamlit session state keys."""
    if "authenticated" not in st.session_state:
        st.session_state["authenticated"] = False
    if "current_user" not in st.session_state:
        st.session_state["current_user"] = None
    if "last_auth_result" not in st.session_state:
        st.session_state["last_auth_result"] = None
    if "last_stego_send_result" not in st.session_state:
        st.session_state["last_stego_send_result"] = None
    if "chain_verification_result" not in st.session_state:
        st.session_state["chain_verification_result"] = None


def _require_login() -> dict:
    """Re-verify live USB dongle and active login session before rendering protected pages."""
    live_dongle = _check_live_dongle()
    if not live_dongle.detected:
        st.session_state["authenticated"] = False
        st.session_state["current_user"] = None
        st.error(live_dongle.message)
        st.stop()

    if not st.session_state.get("authenticated") or not st.session_state.get("current_user"):
        st.warning(
            "Akses ditolak: Silakan selesaikan autentikasi 3 faktor pada "
            "Halaman 1: Login Aman terlebih dahulu."
        )
        st.stop()
    return st.session_state["current_user"]


def render_page_1_auth(dongle_status: DongleStatus) -> None:
    """Render Halaman 1: Login Aman (Dongle Gate dan Biometrik)."""
    st.header("Halaman 1: Login Aman (Dongle Gate dan Biometrik)")

    if dongle_status.detected:
        mount_label = _format_dongle_location(dongle_status)
        st.success(
            f"Status Perangkat Keras: USB Dongle (auth.key) Terdeteksi pada {mount_label}"
        )
    else:
        st.error(dongle_status.message)
        st.stop()

    if st.session_state.get("authenticated") and st.session_state.get("current_user"):
        user = st.session_state["current_user"]
        st.info(f"Sesi aktif sebagai pengguna: **{user['username']}** (ID: {user['id']})")
        if st.button("Keluar (Logout)", key="btn_logout"):
            st.session_state["authenticated"] = False
            st.session_state["current_user"] = None
            st.session_state["last_auth_result"] = None
            st.rerun()

    tab_login, tab_register = st.tabs(
        ["Masuk (Autentikasi 3 Faktor)", "Registrasi Pengguna Baru"]
    )

    with tab_login:
        st.subheader("Formulir Masuk Multi-Faktor")
        login_username = st.text_input("Nama Pengguna (Username)", key="login_username")
        login_password = st.text_input(
            "Kata Sandi (Password)", type="password", key="login_password"
        )

        st.markdown("**Pengambilan Citra Wajah (Biometrik OpenCV):**")
        cam_photo = st.camera_input(
            "Ambil foto wajah melalui kamera web", key="login_camera"
        )
        fallback_photo = st.file_uploader(
            "Atau unggah file citra wajah (PNG/JPG) jika kamera perangkat keras tidak tersedia",
            type=["png", "jpg", "jpeg"],
            key="login_upload_fallback",
        )

        if st.button("Verifikasi dan Masuk", type="primary", key="btn_login"):
            snapshot_bytes: bytes | None = None
            if cam_photo is not None:
                snapshot_bytes = cam_photo.getvalue()
            elif fallback_photo is not None:
                snapshot_bytes = fallback_photo.getvalue()

            if not login_username.strip() or not login_password:
                st.error("Nama pengguna dan kata sandi wajib diisi.")
            elif snapshot_bytes is None:
                st.error("Wajah tidak terdeteksi pada kamera")
            else:
                result = authenticate_user(
                    username=login_username.strip(),
                    password=login_password,
                    webcam_frame=snapshot_bytes,
                )
                st.session_state["last_auth_result"] = result
                if result["authenticated"]:
                    st.session_state["authenticated"] = True
                    st.session_state["current_user"] = result["user"]
                    st.success(result["message"])
                else:
                    st.session_state["authenticated"] = False
                    st.session_state["current_user"] = None
                    st.error(result["message"])

        if st.session_state.get("last_auth_result") is not None:
            res = st.session_state["last_auth_result"]
            factors = res["factors"]
            st.markdown("---")
            st.subheader("Daftar Periksa Verifikasi 3 Faktor")
            col1, col2, col3 = st.columns(3)
            with col1:
                status_dongle = "LOLOS" if factors["dongle"] else "GAGAL"
                st.metric("Faktor 1: USB Dongle", status_dongle)
            with col2:
                status_pw = "LOLOS" if factors["password"] else "GAGAL"
                st.metric("Faktor 2: Password Hash (SHA-256)", status_pw)
            with col3:
                status_bio = "LOLOS" if factors["biometric"] else "GAGAL"
                st.metric(
                    "Faktor 3: Biometrik Wajah",
                    f"{status_bio} (Skor: {factors['face_score']:.4f})",
                )

    with tab_register:
        st.subheader("Pendaftaran Akun dan Enrolmen Wajah")
        st.caption(
            "Akun baru akan diikat dengan token USB Dongle (auth.key) yang sedang terpasang."
        )
        reg_username = st.text_input("Nama Pengguna Baru", key="reg_username")
        reg_password = st.text_input(
            "Kata Sandi Baru", type="password", key="reg_password"
        )
        reg_cam = st.camera_input(
            "Ambil foto wajah referensi untuk pendaftaran", key="reg_camera"
        )
        reg_upload = st.file_uploader(
            "Atau unggah citra wajah referensi (PNG/JPG)",
            type=["png", "jpg", "jpeg"],
            key="reg_upload_fallback",
        )

        if st.button("Daftarkan Akun", key="btn_register"):
            reg_face_bytes: bytes | None = None
            if reg_cam is not None:
                reg_face_bytes = reg_cam.getvalue()
            elif reg_upload is not None:
                reg_face_bytes = reg_upload.getvalue()

            if not reg_username.strip() or not reg_password:
                st.error("Nama pengguna dan kata sandi wajib diisi.")
            elif reg_face_bytes is None:
                st.error("Wajah tidak terdeteksi pada kamera")
            else:
                try:
                    created = register_user(
                        username=reg_username.strip(),
                        password=reg_password,
                        face_image_bytes=reg_face_bytes,
                    )
                    st.success(
                        f"Pengguna '{created['username']}' berhasil didaftarkan "
                        f"dengan ID {created['id']}."
                    )
                except (ValueError, PermissionError) as exc:
                    st.error(str(exc))


def render_page_2_text_messages() -> None:
    """Render Halaman 2: Pesan Teks (Super Enkripsi dan Pesan Penting)."""
    current_user = _require_login()
    st.header("Halaman 2: Pesan Teks (Super Enkripsi dan Pesan Penting)")

    users = list_users()
    usernames = [u["username"] for u in users]

    st.subheader("Kirim Pesan Teks Terenkripsi (Vigenere + AES-128)")
    with st.form("form_send_text"):
        recipient_username = st.selectbox(
            "Penerima Pesan",
            options=usernames if usernames else [current_user["username"]],
        )
        plaintext = st.text_area(
            "Isi Pesan Teks",
            placeholder="Ketik pesan rahasia Anda di sini...",
            height=100,
        )
        is_important = st.checkbox(
            "Tandai sebagai Pesan Penting (dienkripsi di basis data)"
        )
        submitted = st.form_submit_button("Enkripsi dan Kirim Pesan")
        if submitted:
            recipient_user = get_user_by_username(recipient_username)
            if recipient_user is None:
                st.error(f"Penerima '{recipient_username}' tidak ditemukan.")
            else:
                try:
                    sent = send_text_message(
                        sender_id=current_user["id"],
                        recipient_id=recipient_user["id"],
                        plaintext=plaintext,
                        is_important=is_important,
                    )
                    st.success(
                        f"Pesan berhasil dikirim (ID Pesan: #{sent['id']}, "
                        f"Lapisan Penyimpanan: {sent['storage_layers']})."
                    )
                except (ValueError, PermissionError) as exc:
                    st.error(str(exc))

    st.markdown("---")
    st.subheader("Kotak Masuk dan Riwayat Pesan Teks")
    try:
        all_messages = list_inbox_messages(
            user_id=current_user["id"], enforce_dongle_for_important=True
        )
    except PermissionError as exc:
        st.error(str(exc))
        return
    text_messages = [m for m in all_messages if m["msg_type"] == "TEXT"]

    if not text_messages:
        st.info("Belum ada pesan teks untuk pengguna ini.")
        return

    for msg in text_messages:
        badge = "[PESAN PENTING - SUPER+DBCOL]" if msg["is_important"] else "[STANDAR - SUPER]"
        with st.expander(
            f"Pesan #{msg['id']} | {badge} | Dari: {msg['sender_username']} -> "
            f"Ke: {msg['recipient_username']} | {msg['created_at']}",
            expanded=True,
        ):
            st.markdown(f"**Pesan Terdekripsi:** {msg.get('decrypted_text', '')}")
            st.caption(
                f"Lapisan Enkripsi: `{msg['storage_layers']}` | "
                f"Pesan Penting: `{'Ya' if msg['is_important'] else 'Tidak'}`"
            )

    st.markdown("---")
    inspect_enabled = st.toggle(
        "Mode Inspeksi Kriptografi (Demo Dosen)", value=False
    )
    if inspect_enabled:
        st.subheader("Panel Mode Inspeksi Kriptografi (Demo Dosen)")
        msg_options = {
            f"Pesan #{m['id']} ({m['storage_layers']}) - {m['sender_username']} -> {m['recipient_username']}": m["id"]
            for m in text_messages
        }
        selected_label = st.selectbox(
            "Pilih Pesan Teks untuk Diinspeksi", options=list(msg_options.keys())
        )
        selected_msg_id = msg_options[selected_label]

        try:
            inspection = inspect_stored_text_message(
                message_id=selected_msg_id,
                enforce_dongle_for_important=True,
            )
            st.markdown(
                f"**ID Pesan:** `#{inspection['message_id']}` | "
                f"**Status Penting:** `{'Ya' if inspection['is_important'] else 'Tidak'}` | "
                f"**Kolom `storage_layers` di SQLite:** `{inspection['storage_layers']}`"
            )
            st.markdown("**1. Plaintext Input:**")
            st.code(inspection["plaintext"], language="text")

            st.markdown("**2. Hasil Step 1: Vigenere Ciphertext:**")
            st.code(inspection["step1_vigenere"], language="text")

            st.markdown("**3. Hasil Step 2: AES-128 Base64:**")
            st.code(inspection["step2_aes128_b64"], language="text")

            st.markdown(
                "**4. Nilai Mentah di SQLite (untuk pesan penting: hasil enkripsi kolom basis data):**"
            )
            st.code(inspection["raw_sqlite_body_stored"], language="text")

            st.markdown("**5. Hasil Dekripsi Kembali:**")
            st.code(inspection["decrypted_back"], language="text")
        except (ValueError, PermissionError) as exc:
            st.error(str(exc))


def render_page_3_file_messages() -> None:
    """Render Halaman 3: Pesan File (ChaCha20)."""
    current_user = _require_login()
    st.header("Halaman 3: Pesan File (ChaCha20)")
    st.caption(
        "Pipeline enkripsi file menggunakan algoritma stream cipher ChaCha20-Poly1305 "
        "dengan kunci 256-bit terpisah dari pipeline pesan teks."
    )

    users = list_users()
    usernames = [u["username"] for u in users]

    st.subheader("Kirim dan Enkripsi File (ChaCha20)")
    with st.form("form_send_file"):
        recipient_username = st.selectbox(
            "Penerima File",
            options=usernames if usernames else [current_user["username"]],
            key="file_recipient",
        )
        uploaded_file = st.file_uploader(
            "Pilih File Dokumen / Arsip / PDF untuk Dienkripsi",
            key="file_uploader_chacha",
        )
        submitted = st.form_submit_button("Enkripsi ChaCha20 dan Kirim File")
        if submitted:
            if uploaded_file is None:
                st.error("Silakan pilih file yang akan dikirim.")
            else:
                recipient_user = get_user_by_username(recipient_username)
                if recipient_user is None:
                    st.error(f"Penerima '{recipient_username}' tidak ditemukan.")
                else:
                    try:
                        sent = send_file_message(
                            sender_id=current_user["id"],
                            recipient_id=recipient_user["id"],
                            file_bytes=uploaded_file.getvalue(),
                            original_filename=uploaded_file.name,
                            mime_type=uploaded_file.type or "application/octet-stream",
                        )
                        st.success(
                            f"File '{sent['file_original_filename']}' berhasil dienkripsi dengan ChaCha20 "
                            f"dan disimpan ke '{sent['file_path']}' (ID Pesan: #{sent['id']})."
                        )
                    except (ValueError, PermissionError) as exc:
                        st.error(str(exc))

    st.markdown("---")
    st.subheader("Daftar Pesan File Terenkripsi (.enc)")
    all_messages = list_inbox_messages(
        user_id=current_user["id"], enforce_dongle_for_important=True
    )
    file_messages = [m for m in all_messages if m["msg_type"] == "FILE"]

    if not file_messages:
        st.info("Belum ada pesan file untuk pengguna ini.")
        return

    for msg in file_messages:
        with st.expander(
            f"File #{msg['id']} | {msg['file_original_filename']} | "
            f"Dari: {msg['sender_username']} -> Ke: {msg['recipient_username']} | {msg['created_at']}",
            expanded=True,
        ):
            try:
                preview = get_file_raw_preview(
                    message_id=msg["id"],
                    preview_bytes=64,
                )
                st.markdown(f"**Nama File Asli:** `{preview['file_original_filename']}`")
                st.markdown(
                    f"**Lokasi File Terenkripsi di Disk (`.enc`):** `{preview['file_path']}`"
                )
                st.markdown(
                    f"**Ukuran File Terenkripsi:** `{preview['encrypted_size_bytes']} byte` | "
                    f"**Lapisan:** `{preview['storage_layers']}`"
                )
                st.markdown("**Hex Preview File `.enc` di Disk (64 Byte Pertama):**")
                st.code(preview["hex_preview"], language="text")

                decrypted = download_decrypted_file_message(
                    message_id=msg["id"],
                    requesting_user_id=current_user["id"],
                    enforce_dongle=True,
                )
                st.download_button(
                    label="Unduh dan Dekripsi File",
                    data=decrypted["file_bytes"],
                    file_name=decrypted["file_original_filename"],
                    mime=decrypted["file_mime_type"],
                    key=f"btn_download_file_{msg['id']}",
                )
            except (ValueError, PermissionError, FileNotFoundError) as exc:
                st.error(str(exc))


def render_page_4_stego_messages() -> None:
    """Render Halaman 4: Pesan Gambar (Steganografi LSB PNG)."""
    current_user = _require_login()
    st.header("Halaman 4: Pesan Gambar (Steganografi LSB PNG)")

    tab_send, tab_extract = st.tabs(
        ["Tab Kirim (Sisipkan Pesan ke LSB PNG)", "Tab Ekstrak (Baca Pesan dari PNG)"]
    )

    users = list_users()
    usernames = [u["username"] for u in users]

    with tab_send:
        st.subheader("Sisipkan Pesan Rahasia ke Citra PNG (Lossless LSB)")
        recipient_username = st.selectbox(
            "Penerima Citra Stego",
            options=usernames if usernames else [current_user["username"]],
            key="stego_recipient",
        )
        cover_file = st.file_uploader(
            "Unggah Citra Penampung (Format PNG)",
            type=["png"],
            key="stego_cover_uploader",
        )
        secret_message = st.text_area(
            "Pesan Rahasia yang Akan Disisipkan",
            placeholder="Ketik pesan rahasia yang akan disembunyikan di dalam piksel PNG...",
            height=100,
            key="stego_secret_text",
        )

        if st.button("Sisipkan ke LSB dan Kirim Gambar", type="primary", key="btn_send_stego"):
            if cover_file is None:
                st.error("Silakan unggah citra PNG terlebih dahulu.")
            elif not secret_message:
                st.error("Pesan rahasia tidak boleh kosong.")
            else:
                recipient_user = get_user_by_username(recipient_username)
                if recipient_user is None:
                    st.error(f"Penerima '{recipient_username}' tidak ditemukan.")
                else:
                    try:
                        cover_bytes = cover_file.getvalue()
                        sent = send_image_message(
                            sender_id=current_user["id"],
                            recipient_id=recipient_user["id"],
                            cover_image=cover_bytes,
                            secret_message=secret_message,
                        )
                        stego_disk_path = PROJECT_ROOT / sent["stego_image_path"]
                        stego_bytes = stego_disk_path.read_bytes()
                        st.session_state["last_stego_send_result"] = {
                            "meta": sent,
                            "cover_bytes": cover_bytes,
                            "stego_bytes": stego_bytes,
                        }
                        st.success(
                            f"Pesan berhasil disisipkan ke dalam citra PNG "
                            f"(ID Pesan: #{sent['id']}, Lokasi: {sent['stego_image_path']})."
                        )
                    except (ValueError, PermissionError) as exc:
                        st.error(str(exc))

        if st.session_state.get("last_stego_send_result") is not None:
            res = st.session_state["last_stego_send_result"]
            meta = res["meta"]
            st.markdown("---")
            st.subheader("Perbandingan Citra Asli vs Citra Steganografi LSB")
            col_orig, col_stego = st.columns(2)
            with col_orig:
                st.markdown("**Citra PNG Asli (Cover Image)**")
                st.image(res["cover_bytes"], use_container_width=True)
            with col_stego:
                st.markdown("**Citra PNG Steganografi (Stego Image)**")
                st.image(res["stego_bytes"], use_container_width=True)

            mcol1, mcol2, mcol3, mcol4 = st.columns(4)
            mcol1.metric("Kapasitas Maksimum (Bit)", f"{meta['capacity_bits']}")
            mcol2.metric("Bit Terpakai", f"{meta['used_bits']}")
            mcol3.metric("Selisih Piksel Maks", f"{meta['max_pixel_delta']}")
            psnr_str = (
                "Identik (Inf)"
                if meta["psnr_db"] == float("inf")
                else f"{meta['psnr_db']:.2f} dB"
            )
            mcol4.metric("Kualitas PSNR", psnr_str)

    with tab_extract:
        st.subheader("Ekstraksi Pesan Tersembunyi dari Citra Stego PNG")
        all_messages = list_inbox_messages(
            user_id=current_user["id"], enforce_dongle_for_important=True
        )
        image_messages = [m for m in all_messages if m["msg_type"] == "IMAGE"]

        st.markdown("**Opsi 1: Ekstrak dari Kotak Masuk Pesan Gambar**")
        if not image_messages:
            st.info("Belum ada pesan gambar steganografi di kotak masuk.")
        else:
            img_options = {
                f"Gambar #{m['id']} ({m['stego_image_path']}) - Dari: {m['sender_username']} -> Ke: {m['recipient_username']}": m["id"]
                for m in image_messages
            }
            selected_img_label = st.selectbox(
                "Pilih Pesan Gambar dari Kotak Masuk",
                options=list(img_options.keys()),
                key="select_inbox_stego",
            )
            selected_img_id = img_options[selected_img_label]
            if st.button("Ekstrak Pesan dari Kotak Masuk", key="btn_reveal_inbox_stego"):
                try:
                    revealed = reveal_image_message(
                        message_id=selected_img_id,
                        requesting_user_id=current_user["id"],
                    )
                    stego_path = PROJECT_ROOT / revealed["stego_image_path"]
                    if stego_path.is_file():
                        st.image(
                            stego_path.read_bytes(),
                            caption=revealed["stego_image_path"],
                            width=320,
                        )
                    st.success("Pesan rahasia berhasil diekstraksi dari LSB PNG:")
                    st.code(revealed["secret_message"], language="text")
                except (ValueError, PermissionError, FileNotFoundError) as exc:
                    st.error(str(exc))

        st.markdown("---")
        st.markdown("**Opsi 2: Unggah File Stego `.png` Secara Langsung (Alat Demo)**")
        uploaded_stego = st.file_uploader(
            "Pilih File PNG yang Mengandung Payload Steganografi",
            type=["png"],
            key="direct_stego_extract_uploader",
        )
        if uploaded_stego is not None:
            try:
                extracted_text = extract_lsb(uploaded_stego.getvalue())
                st.success("Payload steganografi berhasil ditemukan dan diekstraksi:")
                st.code(extracted_text, language="text")
            except ValueError as exc:
                st.error(str(exc))


def render_page_5_blockchain_assets() -> None:
    """Render Halaman 5: Aset Penting dan Blockchain."""
    current_user = _require_login()
    st.header("Halaman 5: Aset Penting dan Blockchain")

    users = list_users()
    usernames = [u["username"] for u in users]

    col_reg, col_transfer = st.columns(2)

    with col_reg:
        st.subheader("Daftarkan Aset Digital Penting")
        with st.form("form_register_asset"):
            asset_code = st.text_input(
                "Kode Aset Unik (Opsional)", placeholder="Misal: DOC-2026-001"
            )
            asset_name = st.text_input(
                "Nama Aset", placeholder="Misal: Sertifikat Kunci Root"
            )
            asset_desc = st.text_area(
                "Deskripsi Aset",
                placeholder="Penjelasan singkat mengenai dokumen atau aset penting...",
                height=80,
            )
            asset_file = st.file_uploader(
                "File Dokumen untuk Sidik Jari SHA-256 (Opsional)",
                key="asset_file_uploader",
            )
            reg_submitted = st.form_submit_button("Daftarkan Aset dan Tambah Blok")
            if reg_submitted:
                try:
                    file_bytes = asset_file.getvalue() if asset_file is not None else None
                    result = register_asset(
                        owner_username=current_user["username"],
                        asset_name=asset_name,
                        description=asset_desc,
                        content_bytes=file_bytes,
                        asset_code=asset_code if asset_code.strip() else None,
                    )
                    st.success(
                        f"Aset '{result['asset']['asset_code']}' berhasil didaftarkan "
                        f"dan dicatat pada Blok #{result['block']['block_index']}."
                    )
                except ValueError as exc:
                    st.error(str(exc))

    with col_transfer:
        st.subheader("Transfer Kepemilikan Aset")
        current_assets = list_assets()
        owned_assets = [
            a for a in current_assets if a["owner_username"] == current_user["username"]
        ]
        with st.form("form_transfer_asset"):
            if owned_assets:
                asset_map = {
                    f"{a['asset_code']} - {a['asset_name']}": a["id"]
                    for a in owned_assets
                }
                selected_asset_label = st.selectbox(
                    "Pilih Aset Milik Anda", options=list(asset_map.keys())
                )
            else:
                asset_map = {}
                selected_asset_label = st.selectbox(
                    "Pilih Aset Milik Anda",
                    options=["(Anda belum memiliki aset terdaftar)"],
                )

            new_owner = st.selectbox(
                "Pemilik Baru (Target Transfer)",
                options=usernames if usernames else [current_user["username"]],
            )
            transfer_submitted = st.form_submit_button("Transfer Aset dan Tambah Blok")
            if transfer_submitted:
                if not owned_assets:
                    st.error("Anda belum memiliki aset untuk ditransfer.")
                else:
                    try:
                        target_asset_id = asset_map[selected_asset_label]
                        res = transfer_asset(
                            asset_id=target_asset_id,
                            actor_username=current_user["username"],
                            new_owner_username=new_owner,
                        )
                        st.success(
                            f"Kepemilikan aset '{res['asset']['asset_code']}' berhasil "
                            f"ditransfer ke '{new_owner}' pada Blok #{res['block']['block_index']}."
                        )
                    except (ValueError, PermissionError) as exc:
                        st.error(str(exc))

    st.markdown("---")
    st.subheader("Daftar Aset Terdaftar")
    all_assets = list_assets()
    if not all_assets:
        st.info("Belum ada aset digital yang terdaftar.")
    else:
        st.dataframe(
            [
                {
                    "ID": a["id"],
                    "Kode Aset": a["asset_code"],
                    "Nama Aset": a["asset_name"],
                    "Pemilik Saat Ini": a["owner_username"],
                    "Sidik Jari SHA-256": a["content_fingerprint_sha256"],
                    "Waktu Dibuat": a["created_at"],
                }
                for a in all_assets
            ],
            use_container_width=True,
        )

    st.markdown("---")
    st.subheader("Buku Besar Rantai Blok (SHA-256 Hash-Chained Ledger)")

    chain_data = get_chain_with_verification()
    if st.button(
        "Verifikasi Integritas Rantai Blok",
        type="primary",
        key="btn_verify_chain",
    ):
        chain_data = get_chain_with_verification()
        st.session_state["chain_verification_result"] = chain_data["verification"]

    verification = chain_data["verification"]

    if verification["is_valid"]:
        st.success(
            f"Status Integritas Rantai Blok: VALID (Total Blok: {verification['total_blocks']})"
        )
    else:
        broken_idx = verification["broken_at_index"]
        error_detail = verification["error_detail"]
        st.error(
            f"TAMPER DETECTED pada blok #{broken_idx} - Detail: {error_detail}"
        )

    blocks = chain_data["blocks"]
    chain_labels = [
        f"Block #{b['block_index']} ({b['action_type']})" for b in blocks
    ]
    st.markdown("**Urutan Rantai Blok:** `" + " -> ".join(chain_labels) + "`")

    for blk in blocks:
        with st.container(border=True):
            st.markdown(
                f"#### Block #{blk['block_index']} | Aksi: `{blk['action_type']}` | "
                f"Aktor: `{blk['actor_username']}`"
            )
            bcol1, bcol2 = st.columns(2)
            with bcol1:
                st.markdown(f"**Block Index:** `{blk['block_index']}`")
                st.markdown(f"**Timestamp:** `{blk['timestamp']}`")
                st.markdown(f"**Actor Username:** `{blk['actor_username']}`")
                st.markdown(f"**Action Type:** `{blk['action_type']}`")
            with bcol2:
                st.markdown(f"**Target Asset ID:** `{blk['target_asset_id']}`")
                st.markdown(f"**Nonce:** `{blk['nonce']}`")
                st.markdown("**Data Summary:**")
                st.code(blk["data_summary"], language="text")

            st.markdown(f"**Previous Hash:** `{blk['previous_hash']}`")
            st.markdown(f"**Current Hash:** `{blk['current_hash']}`")


def main() -> None:
    """Main Streamlit entrypoint with Gate 0 USB Dongle check and 5-page navigation."""
    st.set_page_config(
        page_title="CipherChat Crypto",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    _init_session_state()

    dongle_status = _check_live_dongle()

    # Gate 0: Refuse to render navigation or other pages when USB Dongle is absent
    if not dongle_status.detected:
        st.session_state["authenticated"] = False
        st.session_state["current_user"] = None
        st.title("CipherChat Crypto - Sistem Terkunci (Gate 0)")
        st.error(dongle_status.message)
        st.warning(
            "Aplikasi menolak dijalankan karena USB Dongle (auth.key) yang valid tidak ditemukan. "
            "Silakan pasang USB flash drive yang berisi file auth.key lalu muat ulang halaman ini."
        )
        if st.button("Periksa Ulang USB Dongle"):
            st.rerun()
        st.stop()

    mount_label = _format_dongle_location(dongle_status)
    st.sidebar.title("CipherChat Crypto")
    st.sidebar.success(f"USB Dongle: Terdeteksi ({mount_label})")

    if st.session_state.get("authenticated") and st.session_state.get("current_user"):
        st.sidebar.info(
            f"Pengguna Aktif: {st.session_state['current_user']['username']}"
        )
    else:
        st.sidebar.warning("Status Sesi: Belum Masuk")

    pages = [
        "Halaman 1: Login Aman (Dongle Gate dan Biometrik)",
        "Halaman 2: Pesan Teks (Super Enkripsi dan Pesan Penting)",
        "Halaman 3: Pesan File (ChaCha20)",
        "Halaman 4: Pesan Gambar (Steganografi LSB PNG)",
        "Halaman 5: Aset Penting dan Blockchain",
    ]
    selected_page = st.sidebar.radio("Navigasi Halaman", options=pages)

    if selected_page == pages[0]:
        render_page_1_auth(dongle_status)
    elif selected_page == pages[1]:
        render_page_2_text_messages()
    elif selected_page == pages[2]:
        render_page_3_file_messages()
    elif selected_page == pages[3]:
        render_page_4_stego_messages()
    elif selected_page == pages[4]:
        render_page_5_blockchain_assets()


if __name__ == "__main__":
    main()
