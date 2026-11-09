"""FastAPI router for PNG LSB steganography image messages (/api/v1/stego)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status

from backend.core.stego_engine import extract_lsb
from backend.repositories.message_repo import reveal_image_message, send_image_message
from backend.repositories.user_repo import get_user_by_username
from backend.routers.auth_router import require_authenticated_user

router = APIRouter(prefix="/api/v1/stego", tags=["stego"])


@router.post("/send", status_code=status.HTTP_201_CREATED)
async def send_stego_image_endpoint(
    recipient_username: str = Form(...),
    secret_message: str = Form(...),
    cover_image: UploadFile = File(...),
    current_user: dict[str, Any] = Depends(require_authenticated_user),
) -> dict[str, Any]:
    """Embed a secret message into a lossless PNG via LSB and send as an IMAGE message."""
    recipient = get_user_by_username(recipient_username)
    if recipient is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Penerima '{recipient_username}' tidak ditemukan.",
        )

    cover_bytes = await cover_image.read()
    try:
        return send_image_message(
            sender_id=current_user["id"],
            recipient_id=recipient["id"],
            cover_image=cover_bytes,
            secret_message=secret_message,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@router.get("/{message_id}/reveal")
def reveal_stego_message_endpoint(
    message_id: int,
    current_user: dict[str, Any] = Depends(require_authenticated_user),
) -> dict[str, Any]:
    """Extract and return the hidden LSB message for the sender or recipient."""
    try:
        return reveal_image_message(
            message_id=message_id,
            requesting_user_id=current_user["id"],
        )
    except PermissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@router.post("/extract")
async def generic_extract_stego_endpoint(
    stego_image: UploadFile = File(...),
    current_user: dict[str, Any] = Depends(require_authenticated_user),
) -> dict[str, Any]:
    """Upload any stego PNG image and extract the hidden LSB text (lecturer demo tool)."""
    image_bytes = await stego_image.read()
    try:
        secret_text = extract_lsb(image_bytes)
        return {
            "filename": stego_image.filename,
            "secret_message": secret_text,
            "storage_layers": "STEGO",
        }
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
