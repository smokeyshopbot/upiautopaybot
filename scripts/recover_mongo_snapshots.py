"""Read-only MongoDB/GridFS snapshot inventory and SQLite recovery scanner.

This script never updates or deletes MongoDB data. It reconstructs every GridFS
file/chunk group into a temporary local file, runs SQLite integrity checks, and
reports the newest business-record timestamps found in each valid candidate.
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import gridfs
from pymongo import MongoClient

import bot


DATE_COLUMNS = {
    "photos": ["created_at", "status_at", "settled_at"],
    "payment_deposits": ["created_at", "confirmed_at", "credited_at", "manual_submitted_at"],
    "wallet_ledger": ["created_at"],
    "users": ["created_at", "updated_at"],
    "disputes": ["created_at", "resolved_at"],
    "message_events": ["created_at", "replied_at"],
}


def inspect_sqlite(path: Path) -> dict:
    result: dict = {"path": str(path), "bytes": path.stat().st_size, "valid": False}
    if path.stat().st_size < 100 or path.read_bytes()[:16] != b"SQLite format 3\x00":
        result["error"] = "not a SQLite file"
        return result
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            quick_check = str(conn.execute("PRAGMA quick_check").fetchone()[0])
            result["quick_check"] = quick_check
            result["valid"] = quick_check.lower() == "ok"
            tables = {
                str(row[0])
                for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            result["tables"] = len(tables)
            details = {}
            newest = ""
            for table, date_columns in DATE_COLUMNS.items():
                if table not in tables:
                    continue
                columns = {
                    str(row[1]) for row in conn.execute(f'PRAGMA table_info("{table}")')
                }
                count = int(conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
                table_info = {"rows": count}
                for column in date_columns:
                    if column not in columns:
                        continue
                    value = conn.execute(
                        f'SELECT MAX("{column}") FROM "{table}" WHERE "{column}" IS NOT NULL'
                    ).fetchone()[0]
                    if value:
                        text = str(value)
                        table_info[f"max_{column}"] = text
                        if text > newest:
                            newest = text
                details[table] = table_info
            result["details"] = details
            result["newest_record"] = newest or None
        finally:
            conn.close()
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def write_gridfs_file(fs: gridfs.GridFS, file_id, output: Path) -> None:
    grid_out = fs.get(file_id)
    with output.open("wb") as handle:
        while True:
            block = grid_out.read(1024 * 1024)
            if not block:
                break
            handle.write(block)


def write_chunk_group(chunks_collection, file_id, output: Path) -> tuple[int, bool]:
    expected_n = 0
    complete_sequence = True
    with output.open("wb") as handle:
        for chunk in chunks_collection.find({"files_id": file_id}).sort("n", 1):
            n = int(chunk.get("n", -1))
            if n != expected_n:
                complete_sequence = False
                expected_n = n
            handle.write(bytes(chunk.get("data") or b""))
            expected_n += 1
    return expected_n, complete_sequence


def main() -> None:
    if not bot.MONGO_URI:
        raise SystemExit("MONGO_URI/MONGODB_URI is not configured.")

    client = MongoClient(
        bot.MONGO_URI,
        serverSelectionTimeoutMS=15000,
        connectTimeoutMS=15000,
        socketTimeoutMS=120000,
        retryWrites=False,
    )
    client.admin.command("ping")
    try:
        database_names = client.list_database_names()
    except Exception:
        database_names = [bot.MONGO_DB_NAME]

    recovery_root = Path(tempfile.mkdtemp(prefix="upi_snapshot_recovery_"))
    print(f"recovery_directory={recovery_root}")
    found = 0

    for database_name in database_names:
        database = client[database_name]
        try:
            collections = set(database.list_collection_names())
        except Exception:
            continue
        if not ({"sqlite_snapshots.files", "sqlite_snapshots.chunks"} & collections):
            continue

        print(f"\nDATABASE {database_name}")
        state_rows = []
        if bot.MONGO_STATE_COLLECTION in collections:
            state_rows = list(database[bot.MONGO_STATE_COLLECTION].find({}))
        for state in state_rows:
            print(
                "STATE",
                f"id={state.get('_id')}",
                f"file_id={state.get('file_id')}",
                f"size={state.get('size_bytes')}",
                f"updated={state.get('updated_at')}",
            )

        files_collection = database["sqlite_snapshots.files"]
        chunks_collection = database["sqlite_snapshots.chunks"]
        fs = gridfs.GridFS(database, collection="sqlite_snapshots")
        file_docs = list(files_collection.find({}).sort("uploadDate", 1))
        known_ids = {doc["_id"] for doc in file_docs}

        chunk_stats: dict = defaultdict(lambda: {"count": 0, "bytes": 0, "max_n": -1})
        for row in chunks_collection.aggregate(
            [
                {
                    "$group": {
                        "_id": "$files_id",
                        "count": {"$sum": 1},
                        "bytes": {"$sum": {"$binarySize": "$data"}},
                        "max_n": {"$max": "$n"},
                    }
                }
            ],
            allowDiskUse=True,
        ):
            chunk_stats[row["_id"]] = {
                "count": int(row.get("count") or 0),
                "bytes": int(row.get("bytes") or 0),
                "max_n": int(row.get("max_n") or -1),
            }

        for index, doc in enumerate(file_docs, 1):
            found += 1
            file_id = doc["_id"]
            stamp = doc.get("uploadDate")
            safe_stamp = stamp.strftime("%Y%m%d_%H%M%S") if isinstance(stamp, datetime) else "unknown"
            output = recovery_root / f"{database_name}_file_{index}_{safe_stamp}_{file_id}.sqlite"
            try:
                write_gridfs_file(fs, file_id, output)
                inspection = inspect_sqlite(output)
            except Exception as exc:
                inspection = {"valid": False, "error": f"{type(exc).__name__}: {exc}"}
            print(
                "FILE",
                f"id={file_id}",
                f"upload={stamp}",
                f"declared_length={doc.get('length')}",
                f"chunks={chunk_stats[file_id]}",
                f"inspection={inspection}",
            )

        orphan_ids = [file_id for file_id in chunk_stats if file_id not in known_ids]
        for index, file_id in enumerate(orphan_ids, 1):
            found += 1
            output = recovery_root / f"{database_name}_orphan_{index}_{file_id}.sqlite"
            try:
                written_chunks, contiguous = write_chunk_group(chunks_collection, file_id, output)
                inspection = inspect_sqlite(output)
            except Exception as exc:
                written_chunks, contiguous = 0, False
                inspection = {"valid": False, "error": f"{type(exc).__name__}: {exc}"}
            print(
                "ORPHAN",
                f"id={file_id}",
                f"chunks={chunk_stats[file_id]}",
                f"written_chunks={written_chunks}",
                f"contiguous={contiguous}",
                f"inspection={inspection}",
            )

    print(f"\nscanned_candidates={found}")
    print("No MongoDB documents were changed or deleted.")


if __name__ == "__main__":
    main()
