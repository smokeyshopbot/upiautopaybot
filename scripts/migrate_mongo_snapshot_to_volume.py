"""Copy the current MongoDB SQLite snapshot to a persistent Railway Volume.

MongoDB is read-only in this operation. The destination is written to a temporary
file, integrity-checked, and atomically renamed so a failed migration cannot leave
a partial production database.
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import bot


def snapshot_file_id():
    _client, database, _fs, state_collection = bot._mongo_objects()
    state = state_collection.find_one({"_id": bot.MONGO_SNAPSHOT_ID}) or {}
    file_id = state.get("file_id")
    if file_id:
        return file_id
    fallback = database["sqlite_snapshots.files"].find_one(
        {
            "$or": [
                {"metadata.snapshot_id": bot.MONGO_SNAPSHOT_ID},
                {"filename": f"{bot.MONGO_SNAPSHOT_ID}.sqlite3"},
            ]
        },
        sort=[("uploadDate", -1)],
    )
    return fallback.get("_id") if fallback else None


def inspect_database(path: Path) -> dict[str, str | int]:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        quick_check = str(conn.execute("PRAGMA quick_check").fetchone()[0])
        if quick_check.lower() != "ok":
            raise RuntimeError(f"SQLite integrity check failed: {quick_check}")
        result: dict[str, str | int] = {
            "bytes": path.stat().st_size,
            "quick_check": quick_check,
        }
        for table in ("photos", "payment_deposits", "wallet_ledger", "users"):
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (table,),
            ).fetchone()
            if exists:
                result[f"{table}_rows"] = int(conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
        return result
    finally:
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--target",
        default=os.getenv("SQLITE_VOLUME_DB_PATH", "/data/upi_autopay_bot.db"),
        help="Persistent destination path on the mounted Railway Volume.",
    )
    parser.add_argument(
        "--replace",
        action="store_true",
        default=os.getenv("SQLITE_VOLUME_MIGRATION_REPLACE", "false").lower() in {"1", "true", "yes", "on"},
        help="Back up and replace an existing target database.",
    )
    args = parser.parse_args()

    if not bot.MONGO_URI:
        raise SystemExit("MONGO_URI/MONGODB_URI is required for this one-time migration.")

    target = Path(args.target).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.migration_tmp")
    if temporary.exists():
        temporary.unlink()

    if target.exists() and not args.replace:
        existing = inspect_database(target)
        raise SystemExit(
            f"Target already exists and is valid: {target} {existing}. "
            "Set SQLITE_VOLUME_MIGRATION_REPLACE=true only if you intentionally want to replace it."
        )

    _client, _database, filesystem, _state_collection = bot._mongo_objects()
    file_id = snapshot_file_id()
    if not file_id:
        raise SystemExit(f"No MongoDB snapshot found for {bot.MONGO_SNAPSHOT_ID}.")

    print(f"Downloading MongoDB snapshot {file_id} to temporary volume file...")
    grid_out = filesystem.get(file_id)
    with temporary.open("wb") as handle:
        while True:
            block = grid_out.read(1024 * 1024)
            if not block:
                break
            handle.write(block)
        handle.flush()
        os.fsync(handle.fileno())

    migrated = inspect_database(temporary)
    if target.exists():
        backup = target.with_name(
            f"{target.name}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        os.replace(target, backup)
        print(f"Existing target backed up to {backup}")
    os.replace(temporary, target)
    print(f"Migration complete: target={target} details={migrated}")
    print("MongoDB was not changed. Next set STORAGE_BACKEND=sqlite and DB_PATH to this target.")


if __name__ == "__main__":
    main()
