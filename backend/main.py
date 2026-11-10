"""FastAPI application entrypoint with USB dongle startup gate and all REST routers."""

from __future__ import annotations

import time
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.config import load_config
from backend.core.dongle_auth import enforce_startup_dongle_gate, verify_usb_dongle
from backend.database import init_db
from backend.repositories.user_repo import get_all_dongle_hashes
from backend.routers.asset_router import router as asset_router
from backend.routers.auth_router import router as auth_router
from backend.routers.file_router import router as file_router
from backend.routers.message_router import router as message_router
from backend.routers.stego_router import router as stego_router

_DONGLE_CACHE_TTL_SECONDS: float = 0.0
_last_dongle_check_ts: float = 0.0
_last_dongle_detected: bool = False
_last_dongle_message: str = "USB Dongle (auth.key) tidak terdeteksi"


def reset_dongle_middleware_cache() -> None:
    """Reset the cached dongle check timestamp (helper for tests)."""
    global _last_dongle_check_ts, _last_dongle_detected, _last_dongle_message
    _last_dongle_check_ts = 0.0
    _last_dongle_detected = False
    _last_dongle_message = "USB Dongle (auth.key) tidak terdeteksi"


def verify_startup_gate() -> None:
    """Verify configuration, initialize database, and enforce Gate 0 USB dongle presence."""
    cfg = load_config()
    init_db()
    registered_hashes = get_all_dongle_hashes()
    try:
        enforce_startup_dongle_gate(
            expected_hashes=registered_hashes if registered_hashes else None,
            bootstrap_hash_hex=cfg.dongle_bootstrap_hash_hex,
        )
    except PermissionError as exc:
        raise RuntimeError(str(exc)) from exc


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """FastAPI lifespan hook enforcing the USB dongle startup gate."""
    verify_startup_gate()
    yield


app = FastAPI(
    title="CipherChat Crypto API",
    version="1.0.0",
    description="Secure Messaging Application with Multi-Layer Cryptography, Steganography, and Blockchain Asset Ledger",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/auth/dongle-status", tags=["auth"])
def api_dongle_status_endpoint():
    """Lightweight endpoint returning boolean presence of USB dongle."""
    from backend.routers.auth_router import get_dongle_status
    return get_dongle_status()


app.include_router(auth_router)
app.include_router(message_router)
app.include_router(file_router)
app.include_router(stego_router)
app.include_router(asset_router)
