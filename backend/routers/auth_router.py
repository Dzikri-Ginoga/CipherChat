"""FastAPI authentication router and session dependency for CipherChat Crypto."""

from __future__ import annotations

import secrets
from typing import Any

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, UploadFile, status

from backend.config import load_config
from backend.core.dongle_auth import is_dongle_connected, verify_usb_dongle
from backend.dependencies import require_active_dongle
from backend.repositories.user_repo import (
    authenticate_user,
    get_all_dongle_hashes,
    get_user_by_username,
    register_user,
)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

# In-memory session store mapping session_token -> user dictionary
_ACTIVE_SESSIONS: dict[str, dict[str, Any]] = {}


def create_session_for_user(user: dict[str, Any]) -> str:
    """Create and store a random session token for an authenticated user."""
    token = secrets.token_hex(24)
    _ACTIVE_SESSIONS[token] = user
    return token


def clear_all_sessions() -> None:
    """Clear all active in-memory sessions (helper for unit tests)."""
    _ACTIVE_SESSIONS.clear()


def require_authenticated_user(
    authorization: str | None = Header(default=None),
    x_session_token: str | None = Header(default=None),
) -> dict[str, Any]:
    """FastAPI dependency that enforces an active login session."""
    token: str | None = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    elif x_session_token:
        token = x_session_token.strip()

    if not token or token not in _ACTIVE_SESSIONS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sesi login tidak valid atau belum login.",
        )
    return _ACTIVE_SESSIONS[token]


@router.get("/dongle-status")
def get_dongle_status() -> dict[str, Any]:
    """Check whether a valid USB dongle with auth.key is currently plugged in."""
    connected = is_dongle_connected()
    return {
        "connected": connected,
        "detected": connected,
        "message": (
            "USB Dongle (auth.key) terdeteksi"
            if connected
            else "USB Dongle (auth.key) tidak terdeteksi"
        ),
    }


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register_endpoint(
    username: str = Form(...),
    password: str = Form(...),
    face_image: UploadFile = File(...),
) -> dict[str, Any]:
    """Register a new user using the currently mounted USB dongle and reference face image."""
    image_bytes = await face_image.read()
    try:
        user = register_user(
            username=username,
            password=password,
            face_image_bytes=image_bytes,
        )
        return {
            "status": "registered",
            "user": user,
            "message": f"Akun '{user['username']}' berhasil didaftarkan.",
        }
    except PermissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=str(exc),
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@router.post("/login")
async def login_endpoint(
    username: str = Form(...),
    password: str = Form(...),
    webcam_snapshot: UploadFile = File(...),
) -> dict[str, Any]:
    """Verify USB dongle, salted SHA-256 password hash, and OpenCV face biometrics."""
    snapshot_bytes = await webcam_snapshot.read()
    result = authenticate_user(
        username=username,
        password=password,
        webcam_frame=snapshot_bytes,
    )
    if result["authenticated"]:
        user = get_user_by_username(username)
        if user is not None:
            session_token = create_session_for_user(user)
            result["session_token"] = session_token
            result["user"] = user
    return result


@router.get("/me")
def get_current_session_user(
    current_user: dict[str, Any] = Depends(require_authenticated_user),
) -> dict[str, Any]:
    """Return the currently logged-in user profile."""
    return current_user
