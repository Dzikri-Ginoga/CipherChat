# 006 - Testing and Lecturer Demo Scenarios

## 1. Automated Unit Test Suite (`tests/`)

Before presenting the application, all unit tests in `pytest` must pass:

1. `tests/test_crypto_engine.py`:
   * Verify `verify_password()` returns `True` for correct password and `False` for wrong password or altered salt.
   * Verify `decrypt_aes128(encrypt_aes128(text)) == text` for Indonesian sentences, emoji-free punctuation, and multiline text.
   * Verify `vigenere_decrypt(vigenere_encrypt(text)) == text` for mixed uppercase, lowercase, digits, and punctuation, and verify one known manual example so the lecturer can check by hand.
   * Verify `super_decrypt(super_encrypt(text)) == text` with mixed uppercase, lowercase, digits, slashes, and punctuation.
   * Verify `decrypt_file_chacha20(encrypt_file_chacha20(file_bytes)) == file_bytes` for binary data (PDF-like bytes and random bytes).
   * Verify `decrypt_db_column(encrypt_db_column(text)) == text`, and that the ciphertext of two encryptions of the same text differs (random nonce).
   * Verify the text key, database column key, and ChaCha20 key are distinct at config load, and that decrypting a text ciphertext with the wrong key raises `ValueError`.

2. `tests/test_stego_engine.py`:
   * Create a synthetic `256x256` RGB PNG image in memory, embed a 500-character message, save as PNG, reload, and verify `extract_lsb()` returns the exact string.
   * Verify that embedding a payload larger than `width * height * 3` bits raises `ValueError`.
   * Verify the maximum absolute pixel difference between the original and the stego image is at most `1`.
   * Verify extraction from a clean image (no payload) raises `ValueError`.

3. `tests/test_blockchain.py`:
   * Initialize Genesis block + 3 asset blocks (one register, two transfers) and assert `verify_chain()["is_valid"] is True`.
   * Simulate database tampering by modifying `data_summary` of Block `#1` directly in SQLite and assert `verify_chain()` returns `is_valid == False` and `broken_at_index == 1`.
   * Simulate a relinked chain (recompute only the tampered block hash) and assert the next block fails on `previous_hash`.
   * If PoW is enabled, assert every `current_hash` starts with the required zeros.

4. `tests/test_dongle_auth.py`:
   * Use a temporary directory as `CIPHERCHAT_DONGLE_MOCK_DIR` with a valid `auth.key` and assert detection succeeds.
   * Assert a missing file, an empty file, and a wrong token each return `detected == False` or a hash mismatch with the right message.
   * Assert the startup gate function raises or exits when no dongle is present.

---

## 2. End-to-End Lecturer Demo Script (10 Minutes)

Use this exact sequence during the final presentation to demonstrate every requirement smoothly:

1. **Demo Step 1 - Dongle Gate and Biometric Login (2 mins) [Criteria 1 and 2]:**
   * Unplug the USB flash drive and run `python scripts/run_app.py`. Show that the application refuses to start with `"USB Dongle (auth.key) tidak terdeteksi"`.
   * Plug in the USB flash drive containing `auth.key`, start the app, capture the webcam face snapshot, enter the password, and log in successfully.
   * Briefly open `storage/cipherchat.db` to show `password_hash_hex` and `password_salt_hex` are not the plain password.

2. **Demo Step 2 - Text Super Encryption and Important Message (2.5 mins) [Criteria 3 and 5]:**
   * On Page 2, send a normal text message: `"Rapat proyek besok jam 09.30 di ruang B2"`. Open the **Inspeksi Kriptografi** panel to show the Vigenere result and then the AES-128 Base64 result.
   * Send a second message with "Pesan Penting" checked. Open `storage/cipherchat.db` in DB Browser for SQLite and show that its `body_stored` is unreadable and `storage_layers` is `SUPER+DBCOL`, while the app displays the decrypted text.

3. **Demo Step 3 - ChaCha20 File Message (1.5 mins) [Criterion 4]:**
   * On Page 3, send a sample PDF (`laporan.pdf`) to another user.
   * Show the generated `.enc` file inside `storage/encrypted_files/` and show that a standard PDF viewer cannot open it. State that the text pipeline used Vigenere + AES while files use ChaCha20.
   * Log in as the recipient, click **Unduh dan Dekripsi File**, and open the restored PDF.

4. **Demo Step 4 - Image Message with LSB Steganography (2 mins) [Criterion 6]:**
   * On Page 4, upload a `.png`, type a secret message, embed it, and show Original vs Stego side by side with PSNR.
   * As the recipient, reveal the hidden message. Optionally re-upload the stego PNG in the Extract tab.

5. **Demo Step 5 - Asset Blockchain and Tamper Detection (2 mins) [Criterion 7]:**
   * On Page 5, register an asset, then transfer it to another user. Show the chain of blocks.
   * Click **Verifikasi Integritas Rantai Blok** to show `VALID`.
   * (Optional Bonus) Edit one character of `data_summary` in `asset_blocks` via SQLite CLI and re-run verification to demonstrate instant tamper detection at the exact block index.

---

## 3. Requirement Traceability Checklist

Tick each item only after the demo step or test above passes.

- [x] Criterion 1: App refuses to start without dongle, biometric (face) login works
- [x] Criterion 2: Login uses salted SHA-256 (or PBKDF2-HMAC-SHA256), constant-time comparison
- [x] Criterion 3: Text messages use Vigenere + AES-128 super encryption
- [x] Criterion 4: File messages use ChaCha20, a different algorithm and key from text
- [x] Criterion 5: Important messages are encrypted at the database column level and shown as ciphertext in SQLite
- [x] Criterion 6: Image messages carry hidden messages via PNG LSB steganography
- [x] Criterion 7: Important assets are protected by a SHA-256 hash-chained ledger with tamper detection
- [x] Criterion 8: Resolved per `DEC-07` (either confirmed absent or implemented)
- [x] All `pytest` tests pass
- [x] No emojis or em/en dashes anywhere in the repository (see `AGENTS.md`)

