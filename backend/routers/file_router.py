"""FastAPI router for ChaCha20 encrypted file messages (/api/v1/files)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Response, UploadFile, status

from backend.dependencies import require_active_dongle
from backend.repositories.message_repo import (
    download_decrypted_file_message,
    get_file_raw_preview,
    send_file_message,
)
from backend.repositories.user_repo import get_user_by_username
from backend.routers.auth_router import require_authenticated_user

router = APIRouter(
    prefix="/api/v1/files",
    tags=["files"],
    dependencies=[Depends(require_active_dongle)],
)


@router.post("/send", status_code=status.HTTP_201_CREATED)
async def send_encrypted_file_endpoint(
    recipient_username: str = Form(...),
    file: UploadFile = File(...),
    current_user: dict[str, Any] = Depends(require_authenticated_user),
) -> dict[str, Any]:
    """Encrypt an uploaded file with ChaCha20Poly1305 and store as .enc in storage/encrypted_files/."""
    recipient = get_user_by_username(recipient_username)
    if recipient is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Penerima '{recipient_username}' tidak ditemukan.",
        )

    file_bytes = await file.read()
    try:
        return send_file_message(
            sender_id=current_user["id"],
            recipient_id=recipient["id"],
            file_bytes=file_bytes,
            original_filename=file.filename or "attachment.bin",
            mime_type=file.content_type or "application/octet-stream",
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@router.get("/{message_id}/download")
def download_file_endpoint(
    message_id: int,
    current_user: dict[str, Any] = Depends(require_authenticated_user),
) -> Response:
    """Verify user access and dongle presence, decrypt .enc with ChaCha20, and stream original file."""
    try:
        decrypted = download_decrypted_file_message(
            message_id=message_id,
            requesting_user_id=current_user["id"],
            enforce_dongle=True,
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

    filename = decrypted["file_original_filename"]
    mime_type = decrypted["file_mime_type"]
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return Response(
        content=decrypted["file_bytes"],
        media_type=mime_type,
        headers=headers,
    )


@router.get("/{message_id}/raw-preview")
def raw_preview_endpoint(
    message_id: int,
    current_user: dict[str, Any] = Depends(require_authenticated_user),
) -> dict[str, Any]:
    """Return path and hex preview (first 64 bytes) of the ChaCha20 .enc file."""
    try:
        return get_file_raw_preview(message_id=message_id, preview_bytes=64)
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
