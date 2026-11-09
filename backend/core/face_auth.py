"""OpenCV webcam face detection and verification module for CipherChat Crypto."""

from __future__ import annotations

import io
from pathlib import Path

import numpy as np
from PIL import Image

from backend.config import DEFAULT_FACE_MATCH_THRESHOLD, load_config

try:
    import cv2

    if hasattr(cv2, "ocl"):
        cv2.ocl.setUseOpenCL(False)
except ImportError:
    cv2 = None  # type: ignore[assignment]

FACE_SIZE: tuple[int, int] = (200, 200)


def _load_bgr_image(image_input: bytes | str | Path | np.ndarray) -> np.ndarray:
    """Load an image from bytes, path, or numpy array into a 3-channel BGR uint8 array."""
    if isinstance(image_input, np.ndarray):
        if image_input.ndim == 2:
            if cv2 is not None:
                return cv2.cvtColor(image_input, cv2.COLOR_GRAY2BGR)
            return np.stack([image_input] * 3, axis=-1)
        if image_input.ndim == 3 and image_input.shape[2] == 3:
            return image_input.astype(np.uint8)
        raise ValueError("Unsupported numpy image array shape.")

    if isinstance(image_input, (str, Path)):
        path = Path(image_input)
        if not path.is_file():
            raise FileNotFoundError(f"Face image file not found: {path}")
        pil_img = Image.open(path).convert("RGB")
    elif isinstance(image_input, (bytes, bytearray)):
        if len(image_input) == 0:
            raise ValueError("Empty image bytes provided.")
        try:
            pil_img = Image.open(io.BytesIO(image_input)).convert("RGB")
        except Exception as exc:
            raise ValueError("Invalid image format.") from exc
    else:
        raise ValueError("Unsupported image input type.")

    rgb_arr = np.asarray(pil_img, dtype=np.uint8)
    # Convert RGB to BGR for OpenCV compatibility
    return rgb_arr[:, :, ::-1].copy()


def _to_grayscale(bgr_frame: np.ndarray) -> np.ndarray:
    """Convert BGR frame to 2D grayscale uint8 array."""
    if cv2 is not None:
        return cv2.cvtColor(bgr_frame, cv2.COLOR_BGR2GRAY)
    # Luminance conversion fallback if cv2 is unavailable
    b = bgr_frame[:, :, 0].astype(np.float32)
    g = bgr_frame[:, :, 1].astype(np.float32)
    r = bgr_frame[:, :, 2].astype(np.float32)
    gray = 0.114 * b + 0.587 * g + 0.299 * r
    return np.clip(gray, 0, 255).astype(np.uint8)


def _equalize_and_resize(gray_crop: np.ndarray) -> np.ndarray:
    """Resize grayscale face crop to 200x200 and apply histogram equalization."""
    if cv2 is not None:
        resized = cv2.resize(gray_crop, FACE_SIZE, interpolation=cv2.INTER_AREA)
        return cv2.equalizeHist(resized)

    pil_gray = Image.fromarray(gray_crop, mode="L").resize(FACE_SIZE)
    arr = np.asarray(pil_gray, dtype=np.uint8)
    hist, _ = np.histogram(arr.flatten(), 256, [0, 256])
    cdf = hist.cumsum()
    cdf_masked = np.ma.masked_equal(cdf, 0)
    if cdf_masked.max() == cdf_masked.min():
        return arr
    cdf_norm = (cdf_masked - cdf_masked.min()) * 255 / (cdf_masked.max() - cdf_masked.min())
    cdf_final = np.ma.filled(cdf_norm, 0).astype(np.uint8)
    return cdf_final[arr]


_CACHED_CLASSIFIER: object | None = None


def _get_haar_classifier():
    """Load and cache the OpenCV Haar Cascade frontal face classifier."""
    global _CACHED_CLASSIFIER
    if _CACHED_CLASSIFIER is not None:
        return _CACHED_CLASSIFIER
    if cv2 is None:
        return None

    import faulthandler
    import tempfile

    candidate_paths: list[Path] = []
    if getattr(cv2, "__file__", None):
        candidate_paths.append(
            Path(cv2.__file__).resolve().parent / "data" / "haarcascade_frontalface_default.xml"
        )
    if hasattr(cv2, "data"):
        candidate_paths.append(
            Path(cv2.data.haarcascades) / "haarcascade_frontalface_default.xml"
        )

    cascade_path: Path | None = None
    for path in candidate_paths:
        if path.is_file():
            cascade_path = path
            break

    if cascade_path is None:
        return None

    load_target = cascade_path
    tmp_xml = Path(tempfile.gettempdir()) / "cipherchat_haarcascade_frontalface_default.xml"
    if not tmp_xml.is_file():
        try:
            tmp_xml.write_bytes(cascade_path.read_bytes())
        except OSError:
            pass
    if tmp_xml.is_file():
        load_target = tmp_xml

    was_enabled = faulthandler.is_enabled()
    if was_enabled:
        faulthandler.disable()
    try:
        classifier = cv2.CascadeClassifier(str(load_target))
    finally:
        if was_enabled:
            faulthandler.enable()

    if not classifier.empty():
        _CACHED_CLASSIFIER = classifier
        return classifier
    return None


def preprocess_face(
    image_input: bytes | str | Path | np.ndarray,
    allow_full_frame_fallback: bool = False,
) -> np.ndarray | None:
    """Detect the largest frontal face, crop, resize to 200x200, and equalize histogram.

    Returns None when no face is detected (unless allow_full_frame_fallback is True).
    """
    bgr_frame = _load_bgr_image(image_input)
    gray = _to_grayscale(bgr_frame)
    if gray.size == 0 or int(np.max(gray)) - int(np.min(gray)) < 5:
        return None

    classifier = _get_haar_classifier()
    if classifier is not None:
        faces = classifier.detectMultiScale(
            gray,
            scaleFactor=1.1,
            minNeighbors=4,
            minSize=(30, 30),
        )
        if len(faces) > 0:
            largest = max(faces, key=lambda rect: int(rect[2]) * int(rect[3]))
            x, y, w, h = (int(v) for v in largest)
            crop = gray[y : y + h, x : x + w]
            return _equalize_and_resize(crop)

    if allow_full_frame_fallback:
        return _equalize_and_resize(gray)
    return None


def enroll_face_image(
    image_bytes: bytes,
    output_path: Path,
    require_haar_detection: bool = False,
) -> Path:
    """Validate and save an enrolled reference face image as lossless PNG."""
    bgr = _load_bgr_image(image_bytes)
    face_crop = preprocess_face(
        bgr, allow_full_frame_fallback=not require_haar_detection
    )
    if face_crop is None:
        raise ValueError("Wajah tidak terdeteksi pada kamera")

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    rgb_arr = bgr[:, :, ::-1]
    Image.fromarray(rgb_arr, mode="RGB").save(output_path, format="PNG")
    return output_path


def _compute_similarity_score(ref_face: np.ndarray, live_face: np.ndarray) -> float:
    """Compute similarity score in [0.0, 1.0] using LBPH and histogram/template correlation."""
    scores: list[float] = []

    if cv2 is not None:
        # 1. Primary Method: OpenCV LBPHFaceRecognizer
        if hasattr(cv2, "face") and hasattr(cv2.face, "LBPHFaceRecognizer_create"):
            try:
                recognizer = cv2.face.LBPHFaceRecognizer_create()
                recognizer.train([ref_face], np.array([0], dtype=np.int32))
                _, confidence_distance = recognizer.predict(live_face)
                # LBPH distance 0.0 is identical; map [0, 120] to [1.0, 0.0]
                lbph_score = max(0.0, min(1.0, 1.0 - (float(confidence_distance) / 120.0)))
                scores.append(lbph_score)
            except Exception:
                pass

        # 2. Fallback / Complementary Method: Template Matching + Histogram Correlation
        try:
            tmpl_res = cv2.matchTemplate(ref_face, live_face, cv2.TM_CCOEFF_NORMED)
            ncc_score = max(0.0, min(1.0, (float(tmpl_res[0][0]) + 1.0) / 2.0))
            scores.append(ncc_score)

            hist_ref = cv2.calcHist([ref_face], [0], None, [64], [0, 256])
            hist_live = cv2.calcHist([live_face], [0], None, [64], [0, 256])
            cv2.normalize(hist_ref, hist_ref)
            cv2.normalize(hist_live, hist_live)
            hist_corr = float(cv2.compareHist(hist_ref, hist_live, cv2.HISTCMP_CORREL))
            hist_score = max(0.0, min(1.0, (hist_corr + 1.0) / 2.0))
            scores.append(hist_score)
        except Exception:
            pass

    if not scores:
        # Pure numpy cosine similarity fallback
        v1 = ref_face.flatten().astype(np.float64)
        v2 = live_face.flatten().astype(np.float64)
        v1_centered = v1 - np.mean(v1)
        v2_centered = v2 - np.mean(v2)
        denom = float(np.linalg.norm(v1_centered) * np.linalg.norm(v2_centered))
        if denom == 0.0:
            return 0.0
        corr = float(np.dot(v1_centered, v2_centered) / denom)
        return max(0.0, min(1.0, (corr + 1.0) / 2.0))

    return float(sum(scores) / len(scores))


def verify_face(
    reference_image_path: str | Path,
    live_image_input: bytes | str | Path | np.ndarray,
    threshold: float | None = None,
) -> tuple[bool, float, str]:
    """Compare a live webcam frame against the enrolled reference face image.

    Returns:
        tuple[bool, float, str]: (is_match, similarity_score, message_indonesian)
    """
    ref_path = Path(reference_image_path)
    if not ref_path.is_file():
        raise FileNotFoundError(f"Reference face image not found: {ref_path}")

    effective_threshold = (
        float(threshold)
        if threshold is not None
        else load_config().face_match_threshold
        if threshold is None
        else DEFAULT_FACE_MATCH_THRESHOLD
    )

    try:
        live_bgr = _load_bgr_image(live_image_input)
    except ValueError:
        return False, 0.0, "Wajah tidak terdeteksi pada kamera"

    # Try strict Haar detection first; if both reference and live are synthetic/cropped portraits
    # where Haar does not trigger, use normalized full-frame face region unless image is blank.
    live_face = preprocess_face(live_bgr, allow_full_frame_fallback=False)
    ref_bgr = _load_bgr_image(ref_path)
    ref_face = preprocess_face(ref_bgr, allow_full_frame_fallback=False)

    if live_face is None:
        # Check if the live frame is uniform/empty (no face in camera frame)
        gray_live = _to_grayscale(live_bgr)
        if gray_live.size == 0 or float(np.std(gray_live)) < 8.0:
            return False, 0.0, "Wajah tidak terdeteksi pada kamera"
        live_face = preprocess_face(live_bgr, allow_full_frame_fallback=True)

    if ref_face is None:
        ref_face = preprocess_face(ref_bgr, allow_full_frame_fallback=True)

    if live_face is None or ref_face is None:
        return False, 0.0, "Wajah tidak terdeteksi pada kamera"

    score = round(_compute_similarity_score(ref_face, live_face), 4)
    if score >= effective_threshold:
        return True, score, "Verifikasi wajah berhasil"
    return False, score, "Verifikasi wajah gagal"


def capture_webcam_frame(device_index: int = 0) -> bytes:
    """Capture a single PNG-encoded frame from a local webcam via OpenCV."""
    if cv2 is None:
        raise RuntimeError("OpenCV (cv2) is not installed.")
    cap = cv2.VideoCapture(device_index)
    if not cap.isOpened():
        raise RuntimeError(f"Cannot open webcam at device index {device_index}.")
    try:
        ok, frame = cap.read()
        if not ok or frame is None:
            raise RuntimeError("Failed to read frame from webcam.")
        success, encoded = cv2.imencode(".png", frame)
        if not success:
            raise RuntimeError("Failed to encode webcam frame as PNG.")
        return encoded.tobytes()
    finally:
        cap.release()
