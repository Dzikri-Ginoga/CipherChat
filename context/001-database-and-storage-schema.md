# 001 - Database and Storage Schema

## 1. SQLite Configuration Rules

* Database path: `storage/cipherchat.db`
* Enable Foreign Keys on every connection: `PRAGMA foreign_keys = ON;`
* Enable Write-Ahead Logging for concurrency safety: `PRAGMA journal_mode = WAL;`
* Return rows as dictionary-like objects using `conn.row_factory = sqlite3.Row`.

---

## 2. Table Definitions (DDL)

### 2.1 Table: `users` (Chat Users)
Stores credentials, USB dongle token hash, and reference biometric face path.

```sql
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash_hex TEXT NOT NULL,
    password_salt_hex TEXT NOT NULL,
    dongle_token_hash_hex TEXT NOT NULL,
    face_reference_path TEXT NOT NULL,
    created_at TEXT NOT NULL
);
```

### 2.2 Table: `messages` (Text, File, and Image Messages)
One table holds all three message types. The meaning of the columns depends on `msg_type`.

* `TEXT`: `body_stored` holds the super-encrypted text (Vigenere + AES-128, Base64). If `is_important = 1`, the stored value is additionally wrapped by database column encryption (see `DEC-05`).
* `FILE`: `body_stored` is NULL. The file is stored on disk as ChaCha20 `.enc`, referenced by `file_path`.
* `IMAGE`: `body_stored` is NULL. The PNG with the hidden message is stored on disk, referenced by `stego_image_path`.

```sql
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    recipient_id INTEGER NOT NULL,
    msg_type TEXT NOT NULL,                     -- TEXT, FILE, IMAGE
    is_important INTEGER NOT NULL DEFAULT 0,    -- 0 or 1
    storage_layers TEXT NOT NULL,               -- SUPER, SUPER+DBCOL, CHACHA20, STEGO, STEGO+AES
    body_stored TEXT,                           -- Base64 ciphertext for TEXT messages, else NULL
    file_path TEXT,                             -- Relative path to .enc file in storage/encrypted_files/
    file_original_filename TEXT,                -- Original filename, e.g., laporan.pdf
    file_mime_type TEXT,                        -- Original MIME type for download
    stego_image_path TEXT,                      -- Relative path to .png in storage/stego_images/
    created_at TEXT NOT NULL,
    FOREIGN KEY (sender_id) REFERENCES users(id),
    FOREIGN KEY (recipient_id) REFERENCES users(id)
);
```

Constraint rules enforced in `message_repo.py`:
* `is_important = 1` is only valid for `msg_type = 'TEXT'` unless the developer extends it.
* When `is_important = 1`, `storage_layers` MUST be `SUPER+DBCOL` (or `DBCOL` if `DEC-05` Option B is chosen).

### 2.3 Table: `assets` (Current State of Important Assets)
Holds the current, queryable state of each asset. The tamper-evident history lives in `asset_blocks`.

```sql
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_code TEXT UNIQUE NOT NULL,            -- Plaintext code, e.g., AST-2026-0001
    asset_name TEXT NOT NULL,
    description TEXT,
    owner_username TEXT NOT NULL,
    content_fingerprint_sha256 TEXT NOT NULL,   -- SHA-256 hex of the asset file or description content
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
```

### 2.4 Table: `asset_blocks` (Blockchain Ledger)
Stores the sequential hash chain of every asset registration and transfer.

```sql
CREATE TABLE IF NOT EXISTS asset_blocks (
    block_index INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    actor_username TEXT NOT NULL,
    action_type TEXT NOT NULL,                  -- GENESIS, REGISTER_ASSET, TRANSFER_ASSET
    target_asset_id INTEGER,
    data_summary TEXT NOT NULL,                 -- Deterministic description: asset code, fingerprint, from/to owner
    nonce INTEGER NOT NULL DEFAULT 0,           -- Used only when proof-of-work is enabled
    previous_hash TEXT NOT NULL,                -- 64-char SHA-256 hex of block (block_index - 1)
    current_hash TEXT UNIQUE NOT NULL           -- 64-char SHA-256 hex of this block
);
```

---

## 3. Disk Storage Layout

| Path | Content | Created By |
| :--- | :--- | :--- |
| `storage/cipherchat.db` | SQLite database | `scripts/init_project.py` |
| `storage/biometrics/<username>.png` | Enrolled reference face image | Registration endpoint |
| `storage/encrypted_files/<message_id>_<uuid>.enc` | `nonce + ChaCha20 ciphertext` of file messages | File message upload |
| `storage/stego_images/<message_id>_<uuid>.png` | Lossless PNG carrying the hidden message | Image message embed |

All files under `storage/` are runtime data and must be gitignored except `.gitkeep` placeholders.

---

## 4. Lecturer Inspection Requirement (Raw Ciphertext vs Decrypted View)

During academic evaluation, the lecturer will ask to see proof that data inside SQLite is genuinely encrypted, especially important messages (criterion 5). Therefore:
1. The repository layer (`message_repo.py`) must expose two read methods:
   * `get_decrypted_message()`: Returns decrypted plaintext for normal chat usage.
   * `get_raw_ciphertext_message()`: Returns the exact Base64 string stored inside SQLite so the UI can display a side-by-side comparison table ("Raw SQLite Ciphertext" vs "Decrypted Plaintext").
2. The inspection view must also show the `storage_layers` value so it is obvious which protections were applied.
3. Reading and decrypting an important message must be performed in Python after `SELECT`. SQLite itself never sees plaintext or keys.

