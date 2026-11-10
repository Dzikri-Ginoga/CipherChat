"""FastAPI security dependencies for CipherChat Crypto."""

from __future__ import annotations

from fastapi import HTTPException, status

from backend.core.dongle_auth import is_dongle_connected


def require_active_dongle() -> bool:
    """FastAPI security dependency ensuring the physical USB dongle remains connected."""
    if not is_dongle_connected():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Security violation: Hardware dongle not detected.",
        )
    return True

