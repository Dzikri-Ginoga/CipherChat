"""USB hardware dongle scanner and startup gate for CipherChat Crypto."""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import psutil

from backend.config import DEFAULT_DONGLE_FILENAME, PROJECT_ROOT, _ensure_env_loaded


@dataclass(frozen=True)
class DongleStatus:
    """Represents the result of a USB hardware dongle verification check."""

    detected: bool
    mountpoint: str | None
    token_hash_hex: str | None
    message: str


def compute_dongle_token_hash(raw_token: str) -> str:
    """Compute the SHA-256 hex digest of a raw dongle key token."""
    if not isinstance(raw_token, str):
        raise ValueError("Dongle token must be a string.")
    cleaned = raw_token.strip()
    if not cleaned:
        raise ValueError("Dongle token cannot be empty.")
    return hashlib.sha256(cleaned.encode("utf-8")).hexdigest()


def _resolve_candidate_mountpoints(mock_dir: str | Path | None = None) -> list[Path]:
    """Return candidate directories to inspect for auth.key."""
    _ensure_env_loaded()
    candidates: list[Path] = []
    effective_mock = (
        str(mock_dir).strip()
        if mock_dir is not None
        else os.environ.get("CIPHERCHAT_DONGLE_MOCK_DIR", "").strip()
    )
    if effective_mock:
        mock_path = Path(effective_mock)
        if not mock_path.is_absolute():
            mock_path = PROJECT_ROOT / mock_path
        candidates.append(mock_path)
        # When a mock directory is explicitly set (including in unit tests),
        # restrict scanning to the mock directory so host drives do not interfere.
        return candidates

    try:
        partitions = psutil.disk_partitions(all=False)
    except Exception:
        partitions = []

    for part in partitions:
        if not part.mountpoint:
            continue
        opts_lower = (part.opts or "").lower()
        if "removable" in opts_lower:
            candidates.append(Path(part.mountpoint))

    return candidates


def scan_dongle_token(
    dongle_filename: str | None = None,
    mock_dir: str | Path | None = None,
) -> DongleStatus:
    """Scan mounted USB partitions (or mock_dir) for auth.key and compute its SHA-256 hash."""
    filename = (
        dongle_filename.strip()
        if dongle_filename and dongle_filename.strip()
        else os.environ.get("CIPHERCHAT_DONGLE_FILENAME", DEFAULT_DONGLE_FILENAME).strip()
        or DEFAULT_DONGLE_FILENAME
    )
    candidates = _resolve_candidate_mountpoints(mock_dir=mock_dir)

    for mountpoint in candidates:
        key_file = mountpoint / filename
        try:
            if not key_file.is_file():
                continue
            raw_content = key_file.read_text(encoding="utf-8").strip()
        except OSError:
            continue

        if not raw_content:
            return DongleStatus(
                detected=False,
                mountpoint=str(mountpoint),
                token_hash_hex=None,
                message="USB Dongle (auth.key) tidak terdeteksi",
            )

        token_hash = compute_dongle_token_hash(raw_content)
        return DongleStatus(
            detected=True,
            mountpoint=str(mountpoint),
            token_hash_hex=token_hash,
            message="USB Dongle (auth.key) terdeteksi",
        )

    return DongleStatus(
        detected=False,
        mountpoint=None,
        token_hash_hex=None,
        message="USB Dongle (auth.key) tidak terdeteksi",
    )


def verify_usb_dongle(
    expected_hashes: Iterable[str] | None = None,
    bootstrap_hash_hex: str | None = None,
    dongle_filename: str | None = None,
    mock_dir: str | Path | None = None,
) -> DongleStatus:
    """Verify that a valid USB dongle is mounted and matches registered or bootstrap hashes."""
    scanned = scan_dongle_token(dongle_filename=dongle_filename, mock_dir=mock_dir)
    if not scanned.detected or scanned.token_hash_hex is None:
        return scanned

    mounted_hash = scanned.token_hash_hex.lower()

    hash_list = (
        [h.strip().lower() for h in expected_hashes if h and h.strip()]
        if expected_hashes is not None
        else []
    )

    if hash_list:
        for candidate_hash in hash_list:
            if hmac.compare_digest(mounted_hash, candidate_hash):
                return DongleStatus(
                    detected=True,
                    mountpoint=scanned.mountpoint,
                    token_hash_hex=mounted_hash,
                    message="USB Dongle (auth.key) terdeteksi",
                )
        return DongleStatus(
            detected=False,
            mountpoint=scanned.mountpoint,
            token_hash_hex=mounted_hash,
            message="USB Dongle tidak cocok dengan akun ini",
        )

    effective_bootstrap = (
        bootstrap_hash_hex.strip().lower()
        if bootstrap_hash_hex is not None
        else os.environ.get("CIPHERCHAT_DONGLE_BOOTSTRAP_HASH_HEX", "").strip().lower()
    )
    if effective_bootstrap:
        if hmac.compare_digest(mounted_hash, effective_bootstrap):
            return DongleStatus(
                detected=True,
                mountpoint=scanned.mountpoint,
                token_hash_hex=mounted_hash,
                message="USB Dongle (auth.key) terdeteksi",
            )
        return DongleStatus(
            detected=False,
            mountpoint=scanned.mountpoint,
            token_hash_hex=mounted_hash,
            message="USB Dongle tidak cocok dengan akun ini",
        )

    return DongleStatus(
        detected=True,
        mountpoint=scanned.mountpoint,
        token_hash_hex=mounted_hash,
        message="USB Dongle (auth.key) terdeteksi",
    )


def verify_user_dongle(
    user_dongle_hash_hex: str,
    dongle_filename: str | None = None,
    mock_dir: str | Path | None = None,
) -> DongleStatus:
    """Verify that the currently mounted USB dongle matches a specific user's dongle hash."""
    scanned = scan_dongle_token(dongle_filename=dongle_filename, mock_dir=mock_dir)
    if not scanned.detected or scanned.token_hash_hex is None:
        return DongleStatus(
            detected=False,
            mountpoint=scanned.mountpoint,
            token_hash_hex=None,
            message="USB Dongle (auth.key) tidak terdeteksi",
        )

    expected = user_dongle_hash_hex.strip().lower()
    actual = scanned.token_hash_hex.lower()
    if not expected or not hmac.compare_digest(actual, expected):
        return DongleStatus(
            detected=False,
            mountpoint=scanned.mountpoint,
            token_hash_hex=actual,
            message="USB Dongle tidak cocok dengan akun ini",
        )

    return DongleStatus(
        detected=True,
        mountpoint=scanned.mountpoint,
        token_hash_hex=actual,
        message="USB Dongle (auth.key) terdeteksi",
    )


def enforce_startup_dongle_gate(
    expected_hashes: Iterable[str] | None = None,
    bootstrap_hash_hex: str | None = None,
    dongle_filename: str | None = None,
    mock_dir: str | Path | None = None,
) -> DongleStatus:
    """Gate 0 check: raise PermissionError if no valid USB dongle is present at startup."""
    status = verify_usb_dongle(
        expected_hashes=expected_hashes,
        bootstrap_hash_hex=bootstrap_hash_hex,
        dongle_filename=dongle_filename,
        mock_dir=mock_dir,
    )
    if not status.detected:
        raise PermissionError(
            f"{status.message}. Aplikasi tidak dapat dihidupkan."
        )
    return status
