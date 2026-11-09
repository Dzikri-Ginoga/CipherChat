# INIT.md - Project Bootstrap and Execution Sequence

## 1. Initialization Protocol for the AI Agent

When starting work on this repository, execute the following steps in strict sequential order. Do not skip steps and do not assume missing configuration values.

### Step 1: Read Context Architecture
1. Read `AGENTS.md` to internalize formatting rules, coding standards, and stop-and-ask triggers.
2. Read `context/000-project-overview-and-architecture.md` to understand the requirement matrix, the target directory tree, and module boundaries.

### Step 2: Resolve Open Decision Gates (Do Not Assume)
Before scaffolding code, check whether the developer has confirmed the following choices. If any item below is still marked `PENDING`, ask the developer before proceeding:

| Decision ID | Topic | Options | Final Confirmed Choice | Status |
| :--- | :--- | :--- | :--- | :--- |
| `DEC-01` | Frontend UI Framework | Option A: Streamlit (Pure Python, 1-day setup)<br>Option B: Next.js + Tailwind CSS (Modern messaging dashboard) | **Option A:** Streamlit (`frontend_streamlit/app.py`, Pure Python) | `CONFIRMED` |
| `DEC-02` | AES Cipher Mode (text and database column) | Option A: AES-GCM (Authenticated, no padding oracle)<br>Option B: AES-CBC + PKCS7 Padding | **Option A:** AES-GCM (`AESGCM` via `cryptography`) | `CONFIRMED` |
| `DEC-03` | Vigenere Cipher Scope | Option A: Alphabetic (`A-Z`, `a-z`) while keeping digits/symbols intact<br>Option B: Extended ASCII (printable chars 32-126) | **Option A:** Alphabetic (`A-Z`, `a-z`), keeping digits/symbols intact | `CONFIRMED` |
| `DEC-04` | Webcam Biometric Method | Option A: OpenCV LBPH / Histogram Cosine Similarity (zero C++ build)<br>Option B: `face-recognition` (`dlib` C++ compilation) | **Option A:** OpenCV LBPH / Histogram Cosine Similarity (`opencv-contrib-python`) | `CONFIRMED` |
| `DEC-05` | Storage of "Important Messages" in the database | Option A: Important text messages get a second layer, AES column encryption with a separate DB key, on top of the Vigenere + AES super encryption<br>Option B: Important messages use only the AES column encryption (no Vigenere layer) | **Option A:** Second layer AES column encryption with separate DB key on top of Vigenere + AES-128 (`storage_layers = 'SUPER+DBCOL'`) | `CONFIRMED` |
| `DEC-06` | Definition of "Important Asset" and blockchain style | Option A: Asset = registered digital document or file (name, owner, SHA-256 fingerprint of content), ledger supports `REGISTER_ASSET` and `TRANSFER_ASSET`, no proof-of-work<br>Option B: Same as A plus simple proof-of-work (hash must start with `000`) | **Option A:** Registered digital document/file (name, owner, SHA-256 content fingerprint), supports `REGISTER_ASSET` and `TRANSFER_ASSET`, no mandatory proof-of-work | `CONFIRMED` |
| `DEC-07` | Eighth lecturer criterion | The source slide had a last line cut off in the screenshot. Developer must supply the full text, or confirm there are exactly 7 criteria | **Option A:** Confirmed there are exactly 7 lecturer criteria (no 8th criterion) | `CONFIRMED` |
| `DEC-08` | Dongle bootstrap on first run | Option A: `.env` holds `CIPHERCHAT_DONGLE_BOOTSTRAP_HASH_HEX` used only while the `users` table is empty<br>Option B: Startup gate accepts any `auth.key` whose hash matches any registered user, and a separate CLI script registers the first user | **Option A:** `.env` holds `CIPHERCHAT_DONGLE_BOOTSTRAP_HASH_HEX` used only while the `users` table is empty | `CONFIRMED` |
| `DEC-09` | Image message payload | Option A: Hide the plaintext secret message in the PNG<br>Option B: Encrypt the secret with AES first, then hide the Base64 ciphertext in the PNG | **Option A:** Hide the plaintext secret message directly in the PNG (`storage_layers = 'STEGO'`) | `CONFIRMED` |

Messaging transport is intentionally simple: users exchange messages through the shared SQLite inbox (poll or refresh). Do not build WebSocket or real-time networking unless the developer asks for it.

---

## 3. Environment Setup Commands

Once decision gates are confirmed, initialize the Python 3.11 environment:

```bash
# 1. Create and activate virtual environment
python3.11 -m venv .venv
# On Linux/macOS:
source .venv/bin/activate
# On Windows (PowerShell):
# .\.venv\Scripts\Activate.ps1

# 2. Install core dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 3. Initialize directories, SQLite database, and the genesis block of the asset ledger
python scripts/init_project.py

# 4. Prepare a USB flash drive as the dongle (writes auth.key, prints its SHA-256)
python scripts/generate_dongle_key.py --target <USB_MOUNTPOINT>

# 5. Start the application ONLY through the gated launcher
python scripts/run_app.py
```

---

## 4. Master Implementation Roadmap (10-14 Days)

Execute implementation phase by phase. After completing each phase, run its verification check from `context/006-testing-and-demo-scenarios.md` before moving to the next phase.

### Phase 1: Setup, Dongle Gate, and Authentication Foundation (Days 1 - 3)
* Criteria covered: 1 and 2
* Reference: `context/001-database-and-storage-schema.md`, `context/002-auth-dongle-gate-and-biometrics.md`
* Deliverables:
  1. SQLite database initialization (`users`, `messages`, `assets`, `asset_blocks`).
  2. Dongle startup gate: `scripts/run_app.py` and the backend startup hook refuse to run when no valid `auth.key` is mounted.
  3. User registration and login using SHA-256 + dynamic salt.
  4. Helper script `scripts/generate_dongle_key.py` to initialize a USB flash drive for testing.
  5. OpenCV webcam face capture and similarity comparison endpoint (biometric login).

### Phase 2: Message Encryption Modules (Days 4 - 6)
* Criteria covered: 3, 4, and 5
* Reference: `context/003-message-encryption-and-file-vault.md`
* Deliverables:
  1. Text super encryption pipeline for chat messages: Plaintext -> Vigenere Cipher -> AES-128 -> Base64.
  2. File message encryption using ChaCha20 (different algorithm from text), stored as `.enc` in `storage/encrypted_files/`, with on-demand decryption for the recipient.
  3. Important messages (`is_important = 1`) encrypted at the database column level with a separate key, plus automatic decryption in the repository layer.

### Phase 3: Steganography and Blockchain Asset Ledger (Days 7 - 9)
* Criteria covered: 6 and 7
* Reference: `context/004-steganography-and-blockchain-assets.md`
* Deliverables:
  1. LSB steganography module (`embed_lsb`, `extract_lsb`) on PNG images using `Pillow` and `numpy`, used for image messages.
  2. `Block` and `Blockchain` classes using SHA-256 hash chaining for important assets.
  3. Automatic block creation on every asset registration and transfer.
  4. Chain integrity verification function (`verify_chain()`) to detect database tampering.

### Phase 4: UI Integration and End-to-End Polishing (Days 10 - 12)
* Reference: `context/005-api-contracts-and-ui-integration.md`, `context/006-testing-and-demo-scenarios.md`
* Deliverables:
  1. Page 1: Gated Login (Dongle Status + Password + Webcam Face Scan).
  2. Page 2: Text Messages (compose, inbox, important flag, cryptography inspection panel).
  3. Page 3: File Messages (ChaCha20 `.enc` upload and decrypted download).
  4. Page 4: Image Messages (PNG upload, secret message embedding, extraction).
  5. Page 5: Asset Ledger Explorer (register, transfer, visual hash chain, tamper check indicator).

