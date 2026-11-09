"""Initialize storage folders, .env configuration, SQLite tables, and Genesis block."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.config import ENV_EXAMPLE_PATH, ENV_FILE_PATH, load_config
from backend.database import ensure_storage_directories, init_db


def main() -> int:
    """Bootstrap project directories, .env file, SQLite schema, and Genesis block."""
    ensure_storage_directories()
    if not ENV_FILE_PATH.exists() and ENV_EXAMPLE_PATH.exists():
        shutil.copyfile(ENV_EXAMPLE_PATH, ENV_FILE_PATH)
        print(f"Created default .env from {ENV_EXAMPLE_PATH.name}")

    load_config()
    init_db()
    print("Project initialized: storage directories, SQLite tables, and Genesis block ready.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
