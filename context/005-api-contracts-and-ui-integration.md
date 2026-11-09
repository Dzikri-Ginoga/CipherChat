# 005 - Phase 4: API Contracts and UI Integration

## 1. FastAPI REST Endpoint Contracts (`backend/routers/`)

Even if using Streamlit for the UI demo, maintaining clean service/router signatures ensures decoupled logic and allows instant testing via Swagger UI (`/docs`). All endpoints except `dongle-status` and `register` require an authenticated session.

### 1.1 Auth Endpoints (`/api/v1/auth`)
* `GET /api/v1/auth/dongle-status`
  * Checks whether a USB drive with `auth.key` is currently plugged in.
  * Response: `{"detected": bool, "mountpoint": str | None, "message": str}`
* `POST /api/v1/auth/register`
  * Multipart form: `username`, `password`, `face_image` (PNG/JPG). The dongle token hash is read from the currently mounted `auth.key`.
* `POST /api/v1/auth/login`
  * Multipart form: `username`, `password`, `webcam_snapshot` (PNG/JPG).
  * Executes the dongle match, salted SHA-256 password check, and OpenCV face match.
  * Response: `{"authenticated": bool, "factors": {"dongle": bool, "password": bool, "biometric": bool, "face_score": float}, "message": str}`

### 1.2 Text Message Endpoints (`/api/v1/messages`)
* `POST /api/v1/messages/text` - JSON: `recipient_username`, `text`, `is_important`. Super-encrypts (Vigenere + AES-128). If `is_important` is true, also applies the database column encryption.
* `GET /api/v1/messages/inbox` - Returns messages for the current user with decrypted text for `TEXT` messages.
* `GET /api/v1/messages/{message_id}/inspect` - Returns plaintext, intermediate Vigenere ciphertext, final AES-128 Base64 ciphertext, the raw SQLite stored value, and `storage_layers` for lecturer demonstration. Requires dongle presence for important messages.

### 1.3 File Message Endpoints (`/api/v1/files`)
* `POST /api/v1/files/send` - Multipart: `recipient_username`, `file`. Encrypts with ChaCha20, writes `.enc` to `storage/encrypted_files/`, inserts a `FILE` message.
* `GET /api/v1/files/{message_id}/download` - Verifies the user is sender or recipient and the dongle is present, reads `.enc`, decrypts with ChaCha20, and returns a binary file download stream with the original filename and MIME type.
* `GET /api/v1/files/{message_id}/raw-preview` - Returns path and a hex preview (first 64 bytes) of the encrypted file for the inspection panel.

### 1.4 Image Message Endpoints (`/api/v1/stego`)
* `POST /api/v1/stego/send` - Multipart: `recipient_username`, `cover_image` (PNG), `secret_message`. Embeds via LSB (payload per `DEC-09`), saves to `storage/stego_images/`, inserts an `IMAGE` message. Response includes capacity bits and PSNR.
* `GET /api/v1/stego/{message_id}/reveal` - Extracts and returns the hidden message for the sender or recipient.
* `POST /api/v1/stego/extract` - Uploads any stego PNG image and extracts the hidden LSB text (demo tool).

### 1.5 Asset Ledger Endpoints (`/api/v1/assets`)
* `POST /api/v1/assets` - Registers an asset (name, description, optional file for fingerprinting), computes the SHA-256 fingerprint, inserts the `assets` row, and appends a `REGISTER_ASSET` block.
* `POST /api/v1/assets/{asset_id}/transfer` - JSON: `new_owner_username`. Updates the owner and appends a `TRANSFER_ASSET` block. Only the current owner may transfer.
* `GET /api/v1/assets` - Lists assets with their current owner and fingerprint.
* `GET /api/v1/assets/chain` - Returns the full ordered list of blocks together with the live `verify_chain()` integrity status.

---

## 2. Five-Page UI Specification

Regardless of whether `DEC-01` is set to **Streamlit** or **Next.js**, the UI must organize the workflow into 5 intuitive tabs/pages. All labels are in Indonesian.

1. **Halaman 1: Login Aman (Dongle Gate dan Biometrik)**
   * Displays live status badge for USB Dongle (`auth.key` Terdeteksi / Tidak Terdeteksi). If not detected at app start, show only this blocked screen and nothing else.
   * Input fields for Username and Password.
   * Webcam capture widget (`st.camera_input` in Streamlit or HTML5 `<video>` canvas capture in Next.js).
   * Step-by-step verification checklist showing pass/fail status for USB Dongle, Password Hash, and Biometric Face Score.

2. **Halaman 2: Pesan Teks (Super Enkripsi dan Pesan Penting)**
   * Compose form with recipient, text, and a checkbox "Tandai sebagai Pesan Penting (dienkripsi di basis data)".
   * Inbox list with decrypted text.
   * **Toggle "Mode Inspeksi Kriptografi (Demo Dosen)":** Displays a comparison panel showing:
     * Plaintext Input
     * Hasil Step 1: Vigenere Ciphertext
     * Hasil Step 2: AES-128 Base64
     * Nilai Mentah di SQLite (untuk pesan penting: hasil enkripsi kolom basis data)
     * Hasil Dekripsi Kembali

3. **Halaman 3: Pesan File (ChaCha20)**
   * Upload a file and choose a recipient.
   * Shows the raw `.enc` file path and hex preview of the encrypted file on disk to prove the file cannot be opened directly.
   * Button **"Unduh dan Dekripsi File"** that decrypts the ChaCha20 bytes in memory and downloads the original file.

4. **Halaman 4: Pesan Gambar (Steganografi LSB PNG)**
   * Tab Kirim: Upload PNG, type the secret message, embed into LSB, compare Original vs Stego image side by side (with pixel capacity and PSNR info), and send.
   * Tab Ekstrak: Upload or select a stego `.png` and immediately display the extracted hidden text.

5. **Halaman 5: Aset Penting dan Blockchain**
   * Forms to register an asset and transfer ownership.
   * Visual chain of blocks (`Block #0 Genesis` -> `Block #1` -> `Block #2` ...).
   * Each card displays `block_index`, `timestamp`, `actor_username`, `action_type`, `data_summary`, `previous_hash`, and `current_hash`.
   * Button **"Verifikasi Integritas Rantai Blok"** showing `VALID` (green) or `TAMPER DETECTED` (red) with the exact broken block index.

---

## 3. Error Message Conventions (Indonesian, User Facing)

| Situation | Message |
| :--- | :--- |
| No dongle at startup or mid-session | `USB Dongle (auth.key) tidak terdeteksi` |
| Dongle token does not match user | `USB Dongle tidak cocok dengan akun ini` |
| Wrong password | `Kata sandi salah` |
| No face in camera frame | `Wajah tidak terdeteksi pada kamera` |
| Face score below threshold | `Verifikasi wajah gagal` |
| Image too small for message | `Kapasitas citra PNG tidak mencukupi untuk panjang pesan ini.` |
| No stego payload found | `Tidak ditemukan payload steganografi CipherChat pada citra ini.` |
| Chain broken | `TAMPER DETECTED pada blok #<index>` |

