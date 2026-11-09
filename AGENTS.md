# AGENTS.md - Master Operating Instructions for AI Coding Agent

## 1. Purpose and Role

You are the autonomous AI software engineer assigned to build and maintain the **CipherChat Crypto** repository (Secure Messaging Application with Multi-Layer Cryptography, Steganography, and Blockchain Asset Ledger). Your objective is to write clean, modular, deterministic, and easily verifiable code that satisfies all academic and engineering requirements without over-engineering.

The seven mandatory lecturer criteria are listed in `context/000-project-overview-and-architecture.md` (Section 2, Requirement Matrix). Every feature you build must trace back to one of those criteria. Never drop, merge, or weaken a criterion.

---

## 2. Strict Communication and Formatting Rules

1. **No Emojis:** Never use emojis in source code, comments, commit messages, documentation, logs, UI labels, or terminal outputs.
2. **No Em Dashes or En Dashes:** Never use em dashes or en dashes in documentation, comments, strings, or responses. Use standard ASCII hyphens (`-`), colons (`:`), or parentheses instead.
3. **Do Not Assume If Confused:** If any requirement, architectural choice, key derivation rule, cipher mode, or file path is ambiguous or underspecified, STOP immediately and ask the developer for clarification before writing or modifying code. Never silently guess.
4. **Language Convention:** Write all source code, variable names, function signatures, database schemas, code comments, and technical logs in **English**. Use **Indonesian** strictly for end-user UI labels and lecturer demo status messages.

---

## 3. Context Routing Table

Before implementing any feature or fixing any bug, read `INIT.md` first, then load the relevant numbered context file from the `context/` directory:

| File Path | Scope and Responsibility | When to Read |
| :--- | :--- | :--- |
| `INIT.md` | Project bootstrap, environment checks, unresolved decision gates, and Phase 1-4 execution order | First session or before starting a new phase |
| `context/000-project-overview-and-architecture.md` | Requirement matrix (7 criteria), tech stack, repository directory structure, architectural boundaries, module dependencies, `.env` keys | Project scaffolding and architectural refactoring |
| `context/001-database-and-storage-schema.md` | SQLite tables (`users`, `messages`, `assets`, `asset_blocks`), column encryption mapping, and disk storage | Writing SQL queries, models, or file storage logic |
| `context/002-auth-dongle-gate-and-biometrics.md` | Phase 1: USB dongle startup gate, salted SHA-256 login, and OpenCV webcam face verification | Implementing the app launch gate, authentication, and biometric checks |
| `context/003-message-encryption-and-file-vault.md` | Phase 2: Vigenere + AES-128 text super encryption, ChaCha20 file encryption, and AES column encryption of important messages in the database | Implementing `crypto_engine.py`, text messages, file messages, or important-message storage |
| `context/004-steganography-and-blockchain-assets.md` | Phase 3: PNG LSB steganography for image messages and the SHA-256 blockchain asset ledger | Implementing `stego_engine.py` or `blockchain.py` |
| `context/005-api-contracts-and-ui-integration.md` | Phase 4: FastAPI REST endpoints and UI screen specifications (Streamlit or Next.js) | Building API routes and connecting the 5 UI pages |
| `context/006-testing-and-demo-scenarios.md` | End-to-end test cases, cryptographic round-trip checks, tamper tests, and lecturer presentation flow | Validating implementation and preparing demo scripts |

---

## 4. Engineering Best Practices and Codebase Intuition

* **Pure Core Modules:** Keep all cryptographic, steganographic, blockchain, dongle, and biometric logic inside `backend/core/` as pure, framework-agnostic Python modules. They must not import FastAPI or Streamlit objects directly.
* **Explicit Inputs and Outputs:** Every function in `backend/core/` must use Python 3.11 type hints (`str`, `bytes`, `tuple`, `dict`, `dataclass`) and raise explicit, descriptive exceptions (`ValueError`, `PermissionError`, `FileNotFoundError`).
* **Round-Trip Verification:** Every encryption or embedding function (`encrypt_aes128`, `super_encrypt`, `encrypt_file_chacha20`, `encrypt_db_column`, `embed_lsb`) must have a paired inverse function (`decrypt_aes128`, `super_decrypt`, `decrypt_file_chacha20`, `decrypt_db_column`, `extract_lsb`) accompanied by an automated test proving `decrypt(encrypt(x)) == x`.
* **Inspectability for Lecturer Review:** Keep cryptographic algorithms readable and self-contained. Do not hide Vigenere shifts, nonce generation, LSB bitwise operations, or block hash concatenation behind convoluted abstractions or third-party wrappers.
* **Different Algorithms Per Data Type:** Text messages use Vigenere + AES-128. File messages MUST use a different algorithm (ChaCha20). Never reuse the text pipeline for files, and never share one key between the two pipelines.
* **One Key Per Purpose:** Text AES key, database column key, and file ChaCha20 key are three separate secrets loaded from `.env`. Never hardcode them and never store them in SQLite.
* **Deterministic File Paths:** Always resolve file system paths using `pathlib.Path` anchored to the project root so the application runs identically regardless of the current working directory.
* **Dongle Gate Is Not Only a Login Factor:** The application must refuse to start (not merely refuse login) when no valid dongle is present. See `context/002-auth-dongle-gate-and-biometrics.md`.

---

## 5. Escalation Protocol (When to Stop and Ask)

Halt execution and ask the user when encountering any of the following:
1. Unresolved stack selection (for example, whether to build the frontend in Streamlit or React/Next.js if not yet locked in `INIT.md`).
2. Ambiguity in Vigenere cipher character handling (whether only `A-Z`/`a-z` characters are shifted while preserving numbers/punctuation, or full printable ASCII 32-126 is shifted).
3. Ambiguity in AES operation mode (GCM authenticated encryption vs CBC with PKCS7 padding).
4. Hardware permissions or webcam device index issues (`cv2.VideoCapture(0)` vs external camera index).
5. Any attempt to define what an "important asset" is for the blockchain ledger before `DEC-06` is confirmed.
6. Any request that seems to add an eighth lecturer criterion before `DEC-07` is resolved (the source screenshot had a truncated last line).
7. Dongle behavior on first run when no user exists yet (bootstrap rule in `DEC-08`).

