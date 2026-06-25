"""Delete legacy SQLite/GridFS storage after native MongoDB is verified.

Requires CONFIRM_DELETE_LEGACY_GRIDFS=yes and refuses to run unless the native
Mongo metadata marker exists.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import bot


def main() -> None:
    if os.getenv("CONFIRM_DELETE_LEGACY_GRIDFS", "").strip().lower() != "yes":
        raise SystemExit("Set CONFIRM_DELETE_LEGACY_GRIDFS=yes to confirm legacy snapshot deletion.")
    _client, database, _fs, _state = bot._mongo_objects()
    prefix = bot.MONGO_NATIVE_COLLECTION_PREFIX
    meta = database[f"{prefix}meta"].find_one(
        {"_id": "native_mongo_state", "initialized": True}
    )
    if not meta:
        raise SystemExit("Native MongoDB migration marker is missing. Nothing was deleted.")

    native_counts = {}
    for table in ("users", "wallets", "photos", "payment_deposits", "wallet_ledger"):
        native_counts[table] = database[f"{prefix}{table}"].count_documents({})
    if native_counts["users"] <= 0 or native_counts["photos"] <= 0:
        raise SystemExit(f"Native collections look incomplete: {native_counts}. Nothing was deleted.")

    files_result = database["sqlite_snapshots.files"].delete_many({})
    chunks_result = database["sqlite_snapshots.chunks"].delete_many({})
    state_result = database[bot.MONGO_STATE_COLLECTION].delete_many({})
    print(
        "Legacy GridFS cleanup complete:",
        {
            "native_counts": native_counts,
            "files_deleted": files_result.deleted_count,
            "chunks_deleted": chunks_result.deleted_count,
            "state_deleted": state_result.deleted_count,
        },
    )


if __name__ == "__main__":
    main()
