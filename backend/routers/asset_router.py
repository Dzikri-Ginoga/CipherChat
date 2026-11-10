"""FastAPI router for the SHA-256 Blockchain Asset Ledger (/api/v1/assets)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from pydantic import BaseModel

from backend.dependencies import require_active_dongle
from backend.repositories.asset_repo import (
    get_chain_with_verification,
    list_assets,
    register_asset,
    transfer_asset,
)
from backend.routers.auth_router import require_authenticated_user

router = APIRouter(
    prefix="/api/v1/assets",
    tags=["assets"],
    dependencies=[Depends(require_active_dongle)],
)


class TransferAssetRequest(BaseModel):
    """JSON request body for transferring ownership of an important asset."""

    new_owner_username: str


@router.post("", status_code=status.HTTP_201_CREATED)
async def register_asset_endpoint(
    asset_name: str = Form(...),
    description: str = Form(default=""),
    asset_code: str | None = Form(default=None),
    file: UploadFile | None = File(default=None),
    current_user: dict[str, Any] = Depends(require_authenticated_user),
) -> dict[str, Any]:
    """Register an important asset, compute its SHA-256 fingerprint, and append REGISTER_ASSET block."""
    content_bytes = await file.read() if file is not None else None
    try:
        return register_asset(
            owner_username=current_user["username"],
            asset_name=asset_name,
            description=description,
            content_bytes=content_bytes,
            asset_code=asset_code,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@router.post("/{asset_id}/transfer")
def transfer_asset_endpoint(
    asset_id: int,
    payload: TransferAssetRequest,
    current_user: dict[str, Any] = Depends(require_authenticated_user),
) -> dict[str, Any]:
    """Transfer asset ownership to a new owner and append a TRANSFER_ASSET block."""
    try:
        return transfer_asset(
            asset_id=asset_id,
            actor_username=current_user["username"],
            new_owner_username=payload.new_owner_username,
        )
    except PermissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@router.get("")
def list_assets_endpoint(
    current_user: dict[str, Any] = Depends(require_authenticated_user),
) -> list[dict[str, Any]]:
    """List all registered assets with their current owner and SHA-256 fingerprint."""
    return list_assets()


@router.get("/chain")
def get_asset_chain_endpoint(
    current_user: dict[str, Any] = Depends(require_authenticated_user),
) -> dict[str, Any]:
    """Return the full ordered list of blocks together with the live verify_chain() integrity status."""
    return get_chain_with_verification()
