# 004 - Phase 3: LSB Image Steganography and Blockchain Asset Ledger

Covers lecturer criteria 6 (image messages secured with steganography) and 7 (important assets secured with simple blockchain).

## 1. LSB Steganography for Image Messages (`backend/core/stego_engine.py`)

### 1.1 Concept for Image Messages
An image message is a PNG picture that the sender uploads together with a secret message. The secret message is hidden inside the pixels. The recipient receives the stego PNG (which looks like the normal picture) and extracts the hidden message with the extract function.

Payload depends on `DEC-09`:
* Option A: embed the plaintext secret message.
* Option B (recommended): embed `encrypt_aes128(secret)` Base64 output, so the hidden content is encrypted as well. Set `storage_layers = 'STEGO+AES'`.

### 1.2 Format Constraint (Strictly Lossless PNG)
* Input images may be PNG (or converted to RGB PNG on upload), but the output stego image MUST always be saved in **lossless `PNG` format**.
* Never save stego output as JPEG, because JPEG lossy compression destroys Least Significant Bit payloads.

### 1.3 Embedding Algorithm (`embed_lsb`)
1. Open the source image with `Image.open(input_path).convert("RGB")` and load pixel values into a `numpy.ndarray` of dtype `uint8`.
2. Append a unique end-of-message delimiter to the secret text: `full_text = secret_text + "$$CIPHERCHAT_EOF$$"`.
3. Convert `full_text.encode('utf-8')` into a contiguous string of binary bits (`'0'` and `'1'`), 8 bits per byte.
4. Flatten the 3D RGB numpy array into a 1D array `flat_pixels`.
5. **Capacity Check:** Verify `len(binary_bits) <= len(flat_pixels)`. If the message bits exceed available sub-pixels, raise `ValueError("Kapasitas citra PNG tidak mencukupi untuk panjang pesan ini.")`.
6. Modify the Least Significant Bit of the first `N` sub-pixels:
   `flat_pixels[i] = (flat_pixels[i] & 0xFE) | int(bit)`
7. Reshape `flat_pixels` back to the original `(height, width, 3)` shape and save as PNG to `storage/stego_images/`.
8. Calculate and return image quality metrics (`PSNR` or max pixel delta = 1) so the user can show the lecturer that visual distortion is imperceptible.

### 1.4 Extraction Algorithm (`extract_lsb`)
1. Load the stego PNG image with `Image.open(stego_path).convert("RGB")` and flatten the numpy array.
2. Extract the LSB (`pixel & 1`) of each sub-pixel, grouping every 8 bits into 1 byte.
3. Decode accumulated bytes and check if the trailing characters match `"$$CIPHERCHAT_EOF$$"`.
4. As soon as the delimiter is encountered, stop reading and return the UTF-8 decoded message prior to the delimiter.
5. If the image ends without finding the delimiter, raise `ValueError("Tidak ditemukan payload steganografi CipherChat pada citra ini.")`.

### 1.5 Access Rules
* Only the sender and the recipient of the message may extract its hidden content through the app.
* The generic extract tool (upload any PNG) is allowed for the lecturer demo, but it can only reveal what the payload mode allows (with `DEC-09` Option B it reveals ciphertext unless the user then decrypts it).

---

## 2. Blockchain Asset Ledger (`backend/core/blockchain.py`)

### 2.1 What Is an Important Asset
Defined by `DEC-06` (default Option A): an asset is a registered digital document or item with a code, a name, an owner, and a SHA-256 fingerprint of its content. The ledger records who registered it and every ownership transfer. The ledger does not store the asset content itself, only its fingerprint, so any later modification of the asset is detectable by recomputing the fingerprint.

Do not implement asset logic beyond this definition until `DEC-06` is confirmed.

### 2.2 Block Structure (`Block` Dataclass)
Each block represents an immutable ledger entry stored in the `asset_blocks` SQLite table:
* `block_index` (`int`): Sequential integer starting at `0` (Genesis Block).
* `timestamp` (`str`): UTC ISO-8601 timestamp (`YYYY-MM-DDTHH:MM:SSZ`).
* `actor_username` (`str`): Authenticated user who performed the action.
* `action_type` (`str`): One of `GENESIS`, `REGISTER_ASSET`, `TRANSFER_ASSET`.
* `target_asset_id` (`int | None`): ID of the affected row in `assets` (`None` for Genesis Block).
* `data_summary` (`str`): Deterministic summary, for example `"asset_code=AST-2026-0001;fingerprint=<sha256>;from=alice;to=bob"`.
* `nonce` (`int`): Proof-of-work counter, `0` when PoW is disabled.
* `previous_hash` (`str`): `current_hash` of block `block_index - 1` (`"0" * 64` for Genesis Block).
* `current_hash` (`str`): SHA-256 hex digest computed deterministically over the block fields.

### 2.3 Deterministic Hash Calculation (`compute_block_hash`)
Construct a canonical JSON string with sorted keys (excluding `current_hash`) and compute SHA-256:

```python
import hashlib
import json

def compute_block_hash(
    block_index: int,
    timestamp: str,
    actor_username: str,
    action_type: str,
    target_asset_id: int | None,
    data_summary: str,
    nonce: int,
    previous_hash: str,
) -> str:
    payload = json.dumps(
        {
            "block_index": block_index,
            "timestamp": timestamp,
            "actor_username": actor_username,
            "action_type": action_type,
            "target_asset_id": target_asset_id,
            "data_summary": data_summary,
            "nonce": nonce,
            "previous_hash": previous_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
```

### 2.4 Optional Proof-of-Work (`DEC-06` Option B)
When `CIPHERCHAT_POW_DIFFICULTY = d > 0`, `mine_block()` increments `nonce` from `0` until `current_hash` starts with `"0" * d`. `verify_chain()` must also check the prefix when `d > 0`. Keep `d` small (2 to 4) so the demo stays fast.

### 2.5 Appending Blocks
* `Blockchain.add_block(actor_username, action_type, target_asset_id, data_summary)` reads the latest block, sets `previous_hash`, computes (or mines) the hash, and inserts the row.
* Hook it into `asset_repo.py` so that `register_asset()` appends `REGISTER_ASSET` and `transfer_asset()` appends `TRANSFER_ASSET` inside the same SQLite transaction as the `assets` row change.
* `scripts/init_project.py` creates the Genesis block exactly once.

### 2.6 Chain Verification (`verify_chain`)
Iterate through all rows in `asset_blocks` ordered by `block_index ASC`:
1. Verify Block `0` has `previous_hash == "0" * 64`.
2. For every block `i`, recompute `expected_hash = compute_block_hash(...)` and verify `block.current_hash == expected_hash`.
3. For every block `i > 0`, verify `block[i].previous_hash == block[i - 1].current_hash`.
4. If PoW is enabled, verify the hash prefix.
5. Optionally cross-check each asset: the latest `data_summary` for an asset must agree with the `assets` row (owner and fingerprint).
6. Return a verification report dictionary:
   `{"is_valid": bool, "total_blocks": int, "broken_at_index": int | None, "error_detail": str | None}`.

