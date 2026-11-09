# 002 - Phase 1: Dongle Startup Gate, Hash Login, and Webcam Biometrics

Covers lecturer criteria 1 (biometric login, app only starts with dongle) and 2 (login uses a cryptographic algorithm).

## 1. Access Flow Overview

The lecturer criterion says the application "can only be started with the help of a dongle". Therefore the dongle is both a startup gate and a login factor:

1. **Gate 0 (Startup, Possession):** The application process refuses to start unless a valid USB dongle is mounted. No dongle means no backend, no UI, no login screen.
2. **Factor 1 (Knowledge):** Username + Password verified via salted SHA-256.
3. **Factor 2 (Possession, per user):** The mounted `auth.key` must match the logging-in user's `dongle_token_hash_hex`.
4. **Factor 3 (Inherence):** Live webcam face snapshot matching the enrolled reference image in `users.face_reference_path`.

If any step fails, login is rejected with a specific failure reason.

---

## 2. Gate 0: Dongle Startup Gate

### 2.1 Where the Gate Runs
* `scripts/run_app.py` (the only supported launcher): calls `verify_usb_dongle()` before spawning Uvicorn or Streamlit. On failure it prints `"USB Dongle (auth.key) tidak terdeteksi. Aplikasi tidak dapat dihidupkan."` and exits with a non-zero code.
* `backend/main.py`: FastAPI `lifespan` startup hook calls the same check and raises `RuntimeError` on failure, so starting Uvicorn directly is also blocked.
* UI entrypoint (`frontend_streamlit/app.py` if `DEC-01` is Streamlit): calls the check at the top of the script and calls `st.stop()` with an Indonesian error banner if the dongle is missing.
* Optional hardening: a lightweight FastAPI middleware re-checks the dongle every few seconds (cache the result for about 5 seconds) and returns HTTP 423 when the dongle is removed mid-session.

### 2.2 Which Token Is Accepted at Startup
At startup no user is logged in yet. Rule (see `DEC-08` in `INIT.md`):
* If the `users` table is empty, accept the token whose SHA-256 equals `CIPHERCHAT_DONGLE_BOOTSTRAP_HASH_HEX` (so the first user can be registered).
* Otherwise accept any `auth.key` whose SHA-256 equals the `dongle_token_hash_hex` of at least one registered user.

---

## 3. Dongle Detection Logic (`backend/core/dongle_auth.py`)

1. Call `psutil.disk_partitions(all=False)` to enumerate mounted storage volumes.
2. Optionally check `CIPHERCHAT_DONGLE_MOCK_DIR` if explicitly configured in `.env` for headless testing.
3. On each partition `mountpoint`, check if `<mountpoint>/auth.key` exists.
4. Read the file content as UTF-8, strip leading/trailing whitespace, compute `hashlib.sha256(raw_token.encode('utf-8')).hexdigest()`, and compare with the expected hash using `hmac.compare_digest`.
5. Return a dataclass such as `DongleStatus(detected: bool, mountpoint: str | None, token_hash_hex: str | None, message: str)`.
6. If the USB flash drive is unplugged mid-session, any subsequent sensitive action (decrypting an important message, downloading a file) re-invokes `verify_usb_dongle()` to enforce continuous hardware presence.

### 3.1 USB Key Generator Script (`scripts/generate_dongle_key.py`)
Provide a CLI utility that:
1. Generates a high-entropy random token (`secrets.token_hex(32)`).
2. Writes the raw token to `<target_usb_mountpoint>/auth.key`.
3. Prints the corresponding `SHA-256` hash so it can be registered into `users.dongle_token_hash_hex` (or placed in `CIPHERCHAT_DONGLE_BOOTSTRAP_HASH_HEX` for the first user).

---

## 4. Factor 1: Salted SHA-256 Password Hashing

Implement in `backend/core/crypto_engine.py`:
* **Salt Generation:** 16 random bytes via `os.urandom(16)`, stored as a 32-character hex string in `password_salt_hex`.
* **Hashing Algorithm:** Use `hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt_bytes, 100_000)` (or direct `hashlib.sha256(salt_bytes + password.encode('utf-8')).hexdigest()` if the course syllabus strictly requests single-round SHA-256 + salt; confirm with user if unsure).
* **Comparison:** Always use `hmac.compare_digest(computed_hex, stored_hex)` to prevent timing attacks.
* Never log or return the password, the hash, or the salt in API responses.

---

## 5. Factor 3: OpenCV Webcam Face Verification (`backend/core/face_auth.py`)

### 5.1 Why OpenCV Without `dlib`
Avoid `face-recognition` (`dlib`) unless explicitly requested by the developer (`DEC-04`), because `dlib` requires compiling C++ sources which frequently breaks on Windows laptops. Use `opencv-contrib-python` instead.

### 5.2 Face Detection and Verification Pipeline
1. **Face Detection:** Load OpenCV built-in Haar Cascade classifier:
   `cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")`
2. **Preprocessing:**
   * Convert frame to grayscale (`cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)`).
   * Detect the largest bounding box `(x, y, w, h)`. If no face is detected, return `(False, 0.0, "Wajah tidak terdeteksi pada kamera")`.
   * Crop the face region, resize to `200x200` pixels, and apply histogram equalization (`cv2.equalizeHist`) to normalize lighting differences.
3. **Comparison Method:**
   * **Primary Method (`cv2.face.LBPHFaceRecognizer_create()`):** Train on the user's enrolled face image(s) and compute prediction confidence distance on the live frame.
   * **Fallback Method (Normalized Cross-Correlation / Histogram Comparison):** Compute `cv2.matchTemplate(enrolled_face, live_face, cv2.TM_CCOEFF_NORMED)` combined with `cv2.compareHist`.
4. **Threshold Check:** Compare similarity score against `CIPHERCHAT_FACE_MATCH_THRESHOLD` (default `0.75`). Return `(is_match: bool, score: float, message: str)`.
5. Webcam device index defaults to `0`. If capture fails, stop and ask the developer (see escalation protocol in `AGENTS.md`).

---

## 6. Login Result Contract

`authenticate_user(username, password, webcam_frame)` returns:

```python
{
    "authenticated": bool,
    "factors": {
        "dongle": bool,
        "password": bool,
        "biometric": bool,
        "face_score": float,
    },
    "message": str,   # Indonesian, shown to the user and the lecturer
}
```

Evaluate all factors and report each one individually so the UI checklist can show exactly which factor failed. Authenticated is `True` only when all three are `True`.

