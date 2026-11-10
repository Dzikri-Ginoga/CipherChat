"""FastAPI router for text messages and cryptographic inspection (/api/v1/messages)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from backend.dependencies import require_active_dongle
from backend.repositories.message_repo import (
    inspect_stored_text_message,
    list_inbox_messages,
    send_text_message,
)
from backend.repositories.user_repo import get_user_by_username
from backend.routers.auth_router import require_authenticated_user

router = APIRouter(
    prefix="/api/v1/messages",
    tags=["messages"],
    dependencies=[Depends(require_active_dongle)],
)


class SendTextMessageRequest(BaseModel):
    """JSON request payload for sending a super-encrypted text message."""

    recipient_username: str
    text: str
    is_important: bool = False


@router.post("/text", status_code=status.HTTP_201_CREATED)
def post_text_message(
    payload: SendTextMessageRequest,
    current_user: dict[str, Any] = Depends(require_authenticated_user),
) -> dict[str, Any]:
    """Encrypt a text message with Vigenere + AES-128 (and DB column AES if important)."""
    recipient = get_user_by_username(payload.recipient_username)
    if recipient is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Penerima '{payload.recipient_username}' tidak ditemukan.",
        )

    try:
        msg = send_text_message(
            sender_id=current_user["id"],
            recipient_id=recipient["id"],
            plaintext=payload.text,
            is_important=payload.is_important,
        )
        return msg
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@router.get("/inbox")
def get_inbox(
    current_user: dict[str, Any] = Depends(require_authenticated_user),
) -> list[dict[str, Any]]:
    """Return inbox and sent messages for the authenticated user with decrypted text."""
    try:
        return list_inbox_messages(
            user_id=current_user["id"],
            enforce_dongle_for_important=True,
        )
    except PermissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=str(exc),
        ) from exc


@router.get("/{message_id}/inspect")
def inspect_message_endpoint(
    message_id: int,
    current_user: dict[str, Any] = Depends(require_authenticated_user),
) -> dict[str, Any]:
    """Return intermediate Vigenere, AES-128 Base64, and raw SQLite ciphertext for lecturer demo."""
    try:
        return inspect_stored_text_message(
            message_id=message_id,
            enforce_dongle_for_important=True,
        )
    except PermissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=str(exc),
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
