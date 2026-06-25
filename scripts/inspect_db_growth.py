import os
import sqlite3

import bot


def main() -> None:
    if bot.MONGO_ENABLED:
        _client, _db, _fs, state_col = bot._mongo_objects()
        print("mongo_state:")
        for state in state_col.find({}, {"file_id": 1, "filename": 1, "size_bytes": 1, "updated_at": 1}):
            print(
                f"id={state.get('_id')} file_id={state.get('file_id')} "
                f"filename={state.get('filename')} size={state.get('size_bytes')} updated_at={state.get('updated_at')}"
            )
        print("gridfs_files:")
        for item in _db["sqlite_snapshots.files"].find(
            {}, {"filename": 1, "length": 1, "uploadDate": 1, "metadata": 1}
        ).sort("uploadDate", -1):
            print(
                f"id={item.get('_id')} filename={item.get('filename')} length={item.get('length')} "
                f"uploaded={item.get('uploadDate')} metadata={item.get('metadata')}"
            )
    bot.restore_mongo_snapshot_if_configured()
    path = os.path.abspath(bot.DB_PATH)
    conn = sqlite3.connect(path)
    try:
        page_size = int(conn.execute("PRAGMA page_size").fetchone()[0])
        page_count = int(conn.execute("PRAGMA page_count").fetchone()[0])
        freelist = int(conn.execute("PRAGMA freelist_count").fetchone()[0])
        print(f"snapshot={path}")
        print(f"bytes={os.path.getsize(path)} page_size={page_size} page_count={page_count} freelist={freelist}")
        try:
            print("largest_objects:")
            for name, size in conn.execute(
                "SELECT name, SUM(pgsize) FROM dbstat GROUP BY name ORDER BY SUM(pgsize) DESC LIMIT 20"
            ):
                print(f"{name}: {int(size)} bytes")
        except sqlite3.OperationalError:
            print("largest_objects: unavailable (SQLite dbstat module is not enabled)")
        print("approximate_table_payloads:")
        table_names = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
        table_sizes: list[tuple[int, int, str]] = []
        for table in table_names:
            columns = [str(row[1]) for row in conn.execute(f'PRAGMA table_info("{table}")')]
            byte_expr = " + ".join(f'COALESCE(LENGTH(CAST("{column}" AS BLOB)), 0)' for column in columns) or "0"
            count, payload_bytes = conn.execute(
                f'SELECT COUNT(*), COALESCE(SUM({byte_expr}), 0) FROM "{table}"'
            ).fetchone()
            table_sizes.append((int(payload_bytes), int(count), table))
        for payload_bytes, count, table in sorted(table_sizes, reverse=True)[:20]:
            print(f"{table}: rows={count} payload_bytes={payload_bytes}")
        print("important_counts:")
        for table in ("payment_verification_logs", "payment_deposits", "payment_tx_hashes", "photos", "wallet_ledger"):
            try:
                count = int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                print(f"{table}: {count}")
            except sqlite3.OperationalError:
                print(f"{table}: unavailable")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
