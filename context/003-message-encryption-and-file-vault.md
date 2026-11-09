# 003 - Phase 2: Text Super Encryption, File Vault, and Important Message Encryption

Covers lecturer criteria 3 (text super encryption), 4 (file encryption with a different algorithm) and 5 (important messages encrypted in the database).

## 1. Algorithm Allocation Summary

| Data Type | Algorithm | Key Variable | Output |
| :--- | :--- | :--- | :--- |
| Text message | Vigenere (classic) then AES-128 (modern) | `CIPHERCHAT_VIGENERE_KEY`, `CIPHERCHAT_TEXT_AES128_KEY_HEX` | Base64 string |
| File message | ChaCha20 (different from text) | `CIPHERCHAT_CHACHA20_KEY_HEX` | `.enc` file on disk |
| Important message (database level) | AES column encryption with a separate key | `CIPHERCHAT_DB_COLUMN_KEY_HEX` | Base64 string in SQLite column |

The three keys are separate. The file pipeline must never call any text pipeline function.

---

## 2. AES-128 Primitive (`encrypt_aes128` / `decrypt_aes128`)

### 2.1 Key Specification
* Key length: Strictly 16 bytes (128 bits), loaded from `CIPHERCHAT_TEXT_AES128_KEY_HEX` (32 hex characters).
* Validate `len(aes_key) == 16` at application startup; raise `ValueError` otherwise.

### 2.2 Cipher Implementation
* **Recommended Mode (AES-128-GCM, `DEC-02` Option A):**
  * Generate a random 12-byte nonce (`os.urandom(12)`).
  * Encrypt `plaintext.encode('utf-8')` using `AESGCM(key).encrypt(nonce, data, None)`.
  * Prepend `nonce` to `ciphertext_with_tag` and encode with `base64.b64encode(...)`.
* **Alternative Mode (AES-128-CBC, `DEC-02` Option B, if required by lecturer syllabus):**
  * Generate a random 16-byte IV (`os.urandom(16)`).
  * Apply PKCS7 padding (block size 128 bits) via `cryptography.hazmat.primitives.padding.PKCS7(128)`.
  * Encrypt with `Cipher(algorithms.AES(key), modes.CBC(iv))` and encode `iv + ciphertext` as Base64.
* On decryption failure (wrong key, tampered ciphertext), raise `ValueError` with a clear message. Never return partial plaintext.

---

## 3. Text Super Encryption for Chat Messages (Vigenere + AES-128)

Used for the stored body of every `TEXT` message.

### 3.1 Step-by-Step Encryption Pipeline (`super_encrypt`)
1. **Input:** Plaintext chat message string (for example: `"Rapat proyek besok jam 09.30 di ruang B2"`).
2. **Step 1 - Vigenere Cipher (`vigenere_encrypt`):**
   * Use `vigenere_key` (uppercase alphabetic string, e.g., `"CIPHERCHATKEY"`).
   * For each character in the input string:
     * If the character is an ASCII letter (`A-Z` or `a-z`), shift it forward by `ord(key[k_idx % len(key)]) - ord('A')` positions modulo 26, preserving uppercase/lowercase, and increment `k_idx`.
     * If the character is a digit, space, or punctuation, keep it unchanged and do NOT advance `k_idx` (unless `DEC-03` in `INIT.md` is set to Extended ASCII 32-126).
3. **Step 2 - AES-128 Encryption:**
   * Pass the Vigenere output string directly into `encrypt_aes128()`.
4. **Output:** Base64 string ready for SQLite storage.

### 3.2 Step-by-Step Decryption Pipeline (`super_decrypt`)
1. **Input:** Base64 super-encrypted string from SQLite.
2. **Step 1 - AES-128 Decryption:** Call `decrypt_aes128(b64_ciphertext)` to recover the intermediate Vigenere ciphertext string.
3. **Step 2 - Vigenere Decryption (`vigenere_decrypt`):** Reverse the alphabetic shift (`-shift % 26`) using the same `vigenere_key`.
4. **Output:** Original plaintext message string.

### 3.3 UI Inspection Helper
Provide `inspect_super_encryption(plaintext)` returning:

```python
{
    "plaintext": "...",
    "step1_vigenere": "...",
    "step2_aes128_b64": "...",
    "decrypted_back": "...",
}
```

so the UI can display each intermediate transformation during the lecturer demo.

---

## 4. File Messages (ChaCha20 Stream Cipher)

Used for encrypting uploaded file messages (PDF, JPG, PNG, DOCX, ZIP and others) before saving to `storage/encrypted_files/`. This is deliberately a different algorithm from the text pipeline (criterion 4).

### 4.1 Key and Nonce Specification
* Key length: 32 bytes (256 bits) from `CIPHERCHAT_CHACHA20_KEY_HEX`.
* Algorithm: `ChaCha20Poly1305` (12-byte random nonce) from `cryptography.hazmat.primitives.ciphers.aead`, or raw `algorithms.ChaCha20` (16-byte random nonce) from `cryptography.hazmat.primitives.ciphers`. Ask the developer if the lecturer expects raw ChaCha20 without authentication.

### 4.2 File Encryption and Decryption Workflow
1. **Send and Encrypt (`encrypt_file_chacha20`):**
   * Read uploaded file bytes in memory.
   * Generate random nonce and encrypt bytes.
   * Write `nonce + encrypted_bytes` to `storage/encrypted_files/<message_id>_<uuid>.enc`.
   * Insert a `messages` row with `msg_type = 'FILE'`, `storage_layers = 'CHACHA20'`, the `.enc` relative path, original filename, and MIME type.
2. **Receive and Decrypt (`decrypt_file_chacha20`):**
   * Verify the requesting user is the sender or recipient.
   * Read the `.enc` file from disk.
   * Slice the leading nonce bytes, decrypt the payload back into original file bytes, and stream the bytes to the user with the original filename and MIME type.
3. Set a maximum upload size (for example 10 MB) in `config.py` and reject larger files with `ValueError`.

---

## 5. Important Messages Encrypted in the Database (Criterion 5)

Messages with `is_important = 1` get protection at the database column level, in addition to the normal text pipeline (default `DEC-05` Option A).

### 5.1 Pipeline (`encrypt_db_column` / `decrypt_db_column`)
1. Compute `super_text = super_encrypt(plaintext)` (Section 3).
2. Compute `stored = encrypt_db_column(super_text)` using AES (GCM recommended) with `CIPHERCHAT_DB_COLUMN_KEY_HEX`, a key that is different from the text AES key.
3. Save `stored` into `messages.body_stored` and set `storage_layers = 'SUPER+DBCOL'`.
4. On read: `decrypt_db_column(stored)` then `super_decrypt(...)`. This happens in `message_repo.py` after `SELECT`, never inside SQL.

If `DEC-05` Option B is chosen, skip step 1 and store `encrypt_db_column(plaintext)` with `storage_layers = 'DBCOL'`.

### 5.2 Rules
* Never store the database column key inside SQLite or inside the repository.
* The repository must never return `body_stored` of an important message to the UI as if it were readable text. Use `get_raw_ciphertext_message()` for inspection views only.
* A sensitive read of an important message re-checks the dongle presence (see `002`, Section 3 step 6).

