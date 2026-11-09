# 000 - Project Overview and Architecture

## 1. System Summary

**CipherChat Crypto** is a secure messaging application prototype for a cryptography course. Each kind of data in the app is protected by a different cryptographic technique:
1. **Gated Biometric Login:** The application can only be started when a physical USB dongle (`auth.key`) is plugged in. Login then requires a salted SHA-256 password check and an OpenCV webcam face match.
2. **Text Super Encryption:** Chat text is protected by a classical Vigenere Cipher chained with modern AES-128, encoded as Base64.
3. **File Encryption with a Different Algorithm:** File messages are protected with ChaCha20, never with the text pipeline.
4. **Database Encryption of Important Messages:** Messages flagged as important are encrypted at the column level inside SQLite with a separate key.
5. **Image Steganography:** Image messages carry a hidden message inside the Least Significant Bits (LSB) of a lossless PNG.
6. **Blockchain Asset Ledger:** Important assets are registered and transferred through a simple SHA-256 hash-chained ledger that detects tampering.

---

## 2. Requirement Matrix (Source: Lecturer Criteria Screenshot)

Every item below is mandatory. The "Where" column points to the context file that specifies the implementation.

| No | Lecturer Criterion (Indonesian original, paraphrased) | Implementation Summary | Where |
| :--- | :--- | :--- | :--- |
| 1 | Aplikasi memiliki login biometric dan hanya dapat dihidupkan menggunakan bantuan dongle | USB dongle startup gate plus OpenCV webcam face login | `002` |
| 2 | Login aplikasi menggunakan algoritma kriptografi (hash atau lainnya seperti Jcrypto, AES) | Salted SHA-256 (or PBKDF2-HMAC-SHA256) password hashing | `002` |
| 3 | Pesan teks dienkripsi dengan super enkripsi (algoritma modern dan klasik) | Vigenere (classic) then AES-128 (modern) then Base64 | `003` |
| 4 | Pesan file dienkripsi dengan kriptografi yang berbeda dari teks | ChaCha20 file vault | `003` |
| 5 | Pesan penting dienkripsi pada basis data yang digunakan | AES column encryption of important messages in SQLite with a separate key | `001`, `003` |
| 6 | Pesan gambar diamankan dengan konsep steganografi | PNG LSB steganography | `004` |
| 7 | Aset penting diamankan dengan teknologi blockchain sederhana | SHA-256 hash-chained asset ledger | `004` |
| 8 | UNKNOWN: the last line of the source screenshot was cut off | Pending `DEC-07` in `INIT.md` | `INIT.md` |

Hard rules derived from the matrix:
* Text and file pipelines must use different algorithms and different keys.
* The dongle check must happen at application start, not only at login.
* Important-message encryption is a database-level concern and must be demonstrable by opening `storage/cipherchat.db` in a SQLite browser.

---

## 3. Technology Stack

* **Language:** Python 3.11+
* **Backend API:** FastAPI + Uvicorn (REST API with automatic OpenAPI docs at `/docs`)
* **Database:** SQLite3 (single local file `storage/cipherchat.db`, zero external DB server overhead)
* **Frontend UI (Selectable via `INIT.md`, `DEC-01`):**
  * **Option A (Rapid Demo):** Streamlit (`frontend_streamlit/app.py`) communicating with `backend/core/` or FastAPI endpoints.
  * **Option B (Modern Dashboard):** Next.js + React + Tailwind CSS (`frontend_nextjs/`) communicating with FastAPI over HTTP JSON/Multipart.
* **Key Python Libraries:**
  * `cryptography`: AES-128 (CBC or GCM), AES column encryption, ChaCha20, PBKDF2-HMAC-SHA256.
  * `opencv-contrib-python`: Webcam frame capture, Haar cascade face detection, and LBPH/histogram face recognition.
  * `psutil`: Cross-platform detection of mounted USB storage partitions.
  * `Pillow` and `numpy`: Pixel matrix manipulation for RGB LSB steganography on lossless `.png` files.

---

## 4. Intuitive Codebase Directory Structure

```text
cipherchat-crypto/
|-- AGENTS.md
|-- INIT.md
|-- context/
|   |-- 000-project-overview-and-architecture.md
|   |-- 001-database-and-storage-schema.md
|   |-- 002-auth-dongle-gate-and-biometrics.md
|   |-- 003-message-encryption-and-file-vault.md
|   |-- 004-steganography-and-blockchain-assets.md
|   |-- 005-api-contracts-and-ui-integration.md
|   `-- 006-testing-and-demo-scenarios.md
|-- .env.example
|-- requirements.txt
|-- backend/
|   |-- __init__.py
|   |-- config.py                # Loads keys, paths, and settings from .env
|   |-- database.py              # SQLite connection helper and schema initializer
|   |-- main.py                  # FastAPI entrypoint, CORS, and dongle startup gate
|   |-- core/                    # Pure, framework-independent security modules
|   |   |-- __init__.py
|   |   |-- crypto_engine.py     # SHA-256+Salt, AES-128, Vigenere, ChaCha20, DB column crypto
|   |   |-- dongle_auth.py       # USB partition scanner and auth.key verifier
|   |   |-- face_auth.py         # OpenCV webcam snapshot and face matcher
|   |   |-- stego_engine.py      # PNG LSB embed and extract routines
|   |   `-- blockchain.py        # Block, Blockchain, and SHA-256 chain verifier
|   |-- repositories/            # Data access layer handling DB read/write + encryption
|   |   |-- user_repo.py
|   |   |-- message_repo.py
|   |   `-- asset_repo.py
|   `-- routers/                 # FastAPI route handlers
|       |-- auth_router.py
|       |-- message_router.py
|       |-- file_router.py
|       |-- stego_router.py
|       `-- asset_router.py
|-- frontend_streamlit/          # If Option A is selected
|   `-- app.py
|-- scripts/
|   |-- init_project.py          # Creates storage folders, DB tables, and genesis block
|   |-- generate_dongle_key.py   # Writes auth.key to a target USB flash drive
|   `-- run_app.py               # Gated launcher: verifies dongle, then starts backend and UI
|-- storage/                     # Local runtime storage (gitignored except .gitkeep)
|   |-- cipherchat.db            # SQLite database file
|   |-- biometrics/              # Enrolled user reference face images
|   |-- encrypted_files/         # ChaCha20 encrypted .enc files
|   `-- stego_images/            # PNG images with embedded LSB payloads
`-- tests/
    |-- test_crypto_engine.py
    |-- test_stego_engine.py
    |-- test_blockchain.py
    `-- test_dongle_auth.py
```

---

## 5. Configuration and Environment Variables (`.env.example`)

Never hardcode secret keys inside source files. Load all configuration via `backend/config.py` from `.env`:

```ini
# Master 16-byte key for AES-128 (text super encryption) encoded as 32 hexadecimal characters
CIPHERCHAT_TEXT_AES128_KEY_HEX=00112233445566778899aabbccddeeff

# Default classical key for Vigenere Cipher (alphabetic uppercase)
CIPHERCHAT_VIGENERE_KEY=CIPHERCHATKEY

# Separate key for database column encryption of important messages (16 bytes as 32 hex chars, or 32 bytes as 64 hex chars)
CIPHERCHAT_DB_COLUMN_KEY_HEX=ffeeddccbbaa99887766554433221100

# Master 32-byte key for ChaCha20 file encryption encoded as 64 hexadecimal characters
CIPHERCHAT_CHACHA20_KEY_HEX=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff

# Expected filename on the USB hardware dongle
CIPHERCHAT_DONGLE_FILENAME=auth.key

# SHA-256 hex of the first dongle token, used only while the users table is empty (see DEC-08)
CIPHERCHAT_DONGLE_BOOTSTRAP_HASH_HEX=

# Optional local fallback path to simulate USB dongle during development if no physical USB port is available
CIPHERCHAT_DONGLE_MOCK_DIR=

# Minimum similarity score (0.0 to 1.0) required for OpenCV face verification
CIPHERCHAT_FACE_MATCH_THRESHOLD=0.75

# Optional proof-of-work difficulty (number of leading zero hex chars) for the asset ledger, 0 disables it (see DEC-06)
CIPHERCHAT_POW_DIFFICULTY=0
```

The three encryption keys (text, database column, file) MUST be distinct values in real use. The example values above are placeholders for local development only.

