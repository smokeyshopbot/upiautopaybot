from __future__ import annotations

import json
import logging
import os
import sqlite3
import tempfile
import threading
import uuid
from pathlib import Path
from typing import Callable

from pymongo import DeleteOne, ReplaceOne


logger = logging.getLogger("upi_autopay_bot.native_mongo")


class NativeMongoConnection(sqlite3.Connection):
    _native_store: "NativeMongoStore | None" = None

    def commit(self) -> None:  # type: ignore[override]
        store = self._native_store
        if store is not None and not store.sync_suspended:
            store.persist_pending(self)
        super().commit()

    def __exit__(self, exc_type, exc, tb):  # type: ignore[override]
        if exc_type is not None:
            return super().__exit__(exc_type, exc, tb)
        store = self._native_store
        try:
            if store is not None and not store.sync_suspended:
                store.persist_pending(self)
        except Exception:
            super().rollback()
            raise
        return super().__exit__(exc_type, exc, tb)


class NativeMongoStore:
    """MongoDB persistence for the bot's existing relational logic.

    SQLite exists only as a shared in-memory query/transaction engine. Every
    committed row change is synchronously mirrored to one MongoDB document.
    There is no SQLite file and no GridFS snapshot.
    """

    META_ID = "native_mongo_state"
    CRITICAL_TABLES = (
        "users",
        "wallets",
        "wallet_ledger",
        "photos",
        "payment_deposits",
        "payment_tx_hashes",
        "payout_requests",
        "disputes",
        "dispute_messages",
    )

    def __init__(
        self,
        *,
        database,
        collection_prefix: str = "native_",
        on_persistence_error: Callable[[BaseException], None] | None = None,
        on_persistence_success: Callable[[], None] | None = None,
    ) -> None:
        self.database = database
        self.client = database.client
        self.collection_prefix = collection_prefix
        self.on_persistence_error = on_persistence_error
        self.on_persistence_success = on_persistence_success
        self.memory_uri = f"file:upi_native_{uuid.uuid4().hex}?mode=memory&cache=shared"
        self.sync_suspended = True
        self._sync_lock = threading.RLock()
        self._keeper = self._new_connection()
        self._keeper.execute("PRAGMA foreign_keys = ON")
        self._keeper.execute("PRAGMA journal_mode = MEMORY")

    @property
    def meta_collection(self):
        return self.database[f"{self.collection_prefix}meta"]

    def collection(self, table: str):
        return self.database[f"{self.collection_prefix}{table}"]

    def _new_connection(self) -> NativeMongoConnection:
        conn = sqlite3.connect(
            self.memory_uri,
            uri=True,
            timeout=20,
            check_same_thread=False,
            factory=NativeMongoConnection,
        )
        conn.row_factory = sqlite3.Row
        conn._native_store = self
        return conn

    def connection(self) -> NativeMongoConnection:
        conn = self._new_connection()
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def close(self) -> None:
        try:
            self._keeper.close()
        except Exception:
            pass

    def table_names(self, conn: sqlite3.Connection | None = None) -> list[str]:
        target = conn or self._keeper
        rows = target.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type = 'table'
              AND name NOT LIKE 'sqlite_%'
              AND name != '_native_changes'
            ORDER BY name
            """
        ).fetchall()
        return [str(row[0]) for row in rows]

    @staticmethod
    def table_columns(conn: sqlite3.Connection, table: str) -> list[str]:
        return [str(row[1]) for row in conn.execute(f'PRAGMA table_info("{table}")').fetchall()]

    @staticmethod
    def primary_key_columns(conn: sqlite3.Connection, table: str) -> list[str]:
        rows = conn.execute(f'PRAGMA table_info("{table}")').fetchall()
        keyed = sorted(
            ((int(row[5]), str(row[1])) for row in rows if int(row[5] or 0) > 0),
            key=lambda item: item[0],
        )
        return [name for _order, name in keyed]

    @staticmethod
    def document_id(values: list) -> str:
        return json.dumps(values, ensure_ascii=False, separators=(",", ":"), default=str)

    def document_id_for_row(self, conn: sqlite3.Connection, table: str, row: sqlite3.Row) -> str:
        keys = self.primary_key_columns(conn, table)
        if keys:
            return self.document_id([row[key] for key in keys])
        return self.document_id([row["_native_rowid"]])

    def create_change_tracking(self) -> None:
        conn = self._keeper
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS _native_changes (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                table_name TEXT NOT NULL,
                doc_id TEXT NOT NULL,
                rowid_value INTEGER,
                op TEXT NOT NULL
            )
            """
        )
        for table in self.table_names(conn):
            keys = self.primary_key_columns(conn, table)
            if keys:
                new_id = "json_array(" + ",".join(f'NEW."{key}"' for key in keys) + ")"
                old_id = "json_array(" + ",".join(f'OLD."{key}"' for key in keys) + ")"
            else:
                new_id = "json_array(NEW.rowid)"
                old_id = "json_array(OLD.rowid)"
            safe = "".join(ch if ch.isalnum() else "_" for ch in table)
            conn.executescript(
                f"""
                DROP TRIGGER IF EXISTS native_{safe}_insert;
                DROP TRIGGER IF EXISTS native_{safe}_update;
                DROP TRIGGER IF EXISTS native_{safe}_delete;

                CREATE TRIGGER native_{safe}_insert AFTER INSERT ON "{table}"
                BEGIN
                    INSERT INTO _native_changes(table_name, doc_id, rowid_value, op)
                    VALUES ('{table}', {new_id}, NEW.rowid, 'upsert');
                END;

                CREATE TRIGGER native_{safe}_update AFTER UPDATE ON "{table}"
                BEGIN
                    INSERT INTO _native_changes(table_name, doc_id, rowid_value, op)
                    SELECT '{table}', {old_id}, OLD.rowid, 'delete'
                    WHERE {old_id} != {new_id};
                    INSERT INTO _native_changes(table_name, doc_id, rowid_value, op)
                    VALUES ('{table}', {new_id}, NEW.rowid, 'upsert');
                END;

                CREATE TRIGGER native_{safe}_delete AFTER DELETE ON "{table}"
                BEGIN
                    INSERT INTO _native_changes(table_name, doc_id, rowid_value, op)
                    VALUES ('{table}', {old_id}, OLD.rowid, 'delete');
                END;
                """
            )
        conn.commit()

    def _row_document(self, table: str, row: sqlite3.Row, doc_id: str) -> dict:
        document = {key: row[key] for key in row.keys() if key != "_native_rowid"}
        document["_id"] = doc_id
        document["_native_rowid"] = int(row["_native_rowid"])
        return document

    def persist_pending(self, conn: sqlite3.Connection) -> None:
        changes = conn.execute(
            "SELECT seq, table_name, doc_id, rowid_value, op FROM _native_changes ORDER BY seq ASC"
        ).fetchall()
        if not changes:
            return

        final_changes: dict[tuple[str, str], sqlite3.Row] = {}
        for change in changes:
            final_changes[(str(change["table_name"]), str(change["doc_id"]))] = change

        operations: dict[str, list] = {}
        for (table, doc_id), change in final_changes.items():
            op = str(change["op"])
            if op == "delete":
                operations.setdefault(table, []).append(DeleteOne({"_id": doc_id}))
                continue
            row = conn.execute(
                f'SELECT rowid AS _native_rowid, * FROM "{table}" WHERE rowid = ?',
                (int(change["rowid_value"]),),
            ).fetchone()
            if row is None:
                operations.setdefault(table, []).append(DeleteOne({"_id": doc_id}))
            else:
                operations.setdefault(table, []).append(
                    ReplaceOne({"_id": doc_id}, self._row_document(table, row, doc_id), upsert=True)
                )

        with self._sync_lock:
            try:
                with self.client.start_session() as session:
                    with session.start_transaction():
                        for table, table_operations in operations.items():
                            if table_operations:
                                self.collection(table).bulk_write(
                                    table_operations,
                                    ordered=True,
                                    session=session,
                                )
                        changed_critical = {
                            table for table in operations if table in self.CRITICAL_TABLES
                        }
                        if changed_critical:
                            count_updates = {
                                f"table_counts.{table}": self.collection(table).count_documents(
                                    {}, session=session
                                )
                                for table in changed_critical
                            }
                            self.meta_collection.update_one(
                                {"_id": self.META_ID},
                                {"$set": count_updates},
                                session=session,
                            )
                conn.execute("DELETE FROM _native_changes")
                if self.on_persistence_success:
                    self.on_persistence_success()
            except Exception as exc:
                if self.on_persistence_error:
                    self.on_persistence_error(exc)
                raise

    def native_initialized(self) -> bool:
        return self.meta_collection.find_one({"_id": self.META_ID, "initialized": True}) is not None

    def collection_counts(self, tables: tuple[str, ...] | None = None) -> dict[str, int]:
        selected = tables or tuple(self.table_names(self._keeper))
        return {
            table: int(self.collection(table).count_documents({}))
            for table in selected
        }

    def memory_counts(self, tables: tuple[str, ...] | None = None) -> dict[str, int]:
        selected = tables or tuple(self.table_names(self._keeper))
        return {
            table: int(self._keeper.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
            for table in selected
        }

    def validate_critical_integrity(self) -> dict[str, dict[str, int]]:
        meta = self.meta_collection.find_one({"_id": self.META_ID, "initialized": True})
        if not meta:
            raise RuntimeError("Native MongoDB migration marker is missing.")
        expected = {
            str(table): int(count)
            for table, count in dict(meta.get("table_counts") or {}).items()
        }
        mongo_counts = self.collection_counts(self.CRITICAL_TABLES)
        memory_counts = self.memory_counts(self.CRITICAL_TABLES)
        errors: list[str] = []
        for table in self.CRITICAL_TABLES:
            mongo_count = mongo_counts.get(table, 0)
            memory_count = memory_counts.get(table, 0)
            if mongo_count != memory_count:
                errors.append(
                    f"{table}: MongoDB has {mongo_count}, memory loaded {memory_count}"
                )
            expected_count = expected.get(table)
            if expected_count is not None and mongo_count < expected_count:
                errors.append(
                    f"{table}: MongoDB has {mongo_count}, migration recorded {expected_count}"
                )
        if (
            mongo_counts.get("photos", 0) > 0
            or mongo_counts.get("wallet_ledger", 0) > 0
            or mongo_counts.get("payment_deposits", 0) > 0
        ) and (
            mongo_counts.get("users", 0) <= 0
            or mongo_counts.get("wallets", 0) <= 0
        ):
            errors.append("business records exist but users or wallets are missing")
        if errors:
            raise RuntimeError(
                "Critical native MongoDB integrity check failed: " + "; ".join(errors)
            )
        return {"mongo": mongo_counts, "memory": memory_counts}

    def _clear_memory_tables(self, conn: sqlite3.Connection) -> None:
        conn.execute("PRAGMA foreign_keys = OFF")
        for table in reversed(self.table_names(conn)):
            conn.execute(f'DELETE FROM "{table}"')
        changes_exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='_native_changes'"
        ).fetchone()
        if changes_exists:
            conn.execute("DELETE FROM _native_changes")
        conn.execute("PRAGMA foreign_keys = ON")

    def load_native_documents_into_memory(self) -> None:
        conn = self._keeper
        self.sync_suspended = True
        self._clear_memory_tables(conn)
        conn.execute("PRAGMA foreign_keys = OFF")
        for table in self.table_names(conn):
            columns = self.table_columns(conn, table)
            docs = list(self.collection(table).find({}).sort("_native_rowid", 1))
            if not docs:
                continue
            placeholders = ",".join("?" for _ in columns)
            column_sql = ",".join(f'"{column}"' for column in columns)
            values = [[doc.get(column) for column in columns] for doc in docs]
            conn.executemany(
                f'INSERT OR REPLACE INTO "{table}" ({column_sql}) VALUES ({placeholders})',
                values,
            )
        conn.execute("PRAGMA foreign_keys = ON")
        conn.commit()
        self.sync_suspended = False

    def import_sqlite_file(self, sqlite_path: str) -> dict[str, int]:
        source = sqlite3.connect(f"file:{Path(sqlite_path).resolve()}?mode=ro", uri=True)
        source.row_factory = sqlite3.Row
        counts: dict[str, int] = {}
        try:
            quick_check = str(source.execute("PRAGMA quick_check").fetchone()[0])
            if quick_check.lower() != "ok":
                raise RuntimeError(f"Legacy SQLite snapshot failed integrity check: {quick_check}")
            for table in self.table_names(self._keeper):
                exists = source.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                    (table,),
                ).fetchone()
                if not exists:
                    counts[table] = 0
                    continue
                target_columns = self.table_columns(self._keeper, table)
                source_columns = {
                    str(row[1]) for row in source.execute(f'PRAGMA table_info("{table}")').fetchall()
                }
                common = [column for column in target_columns if column in source_columns]
                if not common:
                    counts[table] = 0
                    continue
                rows = source.execute(
                    f'SELECT rowid AS _native_rowid, * FROM "{table}"'
                ).fetchall()
                documents = []
                pk_columns = self.primary_key_columns(self._keeper, table)
                for row in rows:
                    if pk_columns:
                        doc_id = self.document_id([row[key] for key in pk_columns])
                    else:
                        doc_id = self.document_id([row["_native_rowid"]])
                    document = {column: row[column] for column in common}
                    document["_id"] = doc_id
                    document["_native_rowid"] = int(row["_native_rowid"])
                    documents.append(document)
                collection = self.collection(table)
                collection.delete_many({})
                if documents:
                    collection.insert_many(documents, ordered=True)
                counts[table] = len(documents)
            self.meta_collection.replace_one(
                {"_id": self.META_ID},
                {
                    "_id": self.META_ID,
                    "initialized": True,
                    "schema_version": 1,
                    "source": "legacy_sqlite_snapshot",
                    "table_counts": counts,
                },
                upsert=True,
            )
        finally:
            source.close()
        return counts

    def initialize_from_memory(self) -> dict[str, int]:
        conn = self._keeper
        counts: dict[str, int] = {}
        for table in self.table_names(conn):
            rows = conn.execute(f'SELECT rowid AS _native_rowid, * FROM "{table}"').fetchall()
            documents = []
            for row in rows:
                doc_id = self.document_id_for_row(conn, table, row)
                documents.append(self._row_document(table, row, doc_id))
            collection = self.collection(table)
            collection.delete_many({})
            if documents:
                collection.insert_many(documents, ordered=True)
            counts[table] = len(documents)
        self.meta_collection.replace_one(
            {"_id": self.META_ID},
            {
                "_id": self.META_ID,
                "initialized": True,
                "schema_version": 1,
                "source": "empty_native_initialization",
                "table_counts": counts,
            },
            upsert=True,
        )
        return counts

    def download_legacy_gridfs_snapshot(self, fs, state_collection, snapshot_id: str) -> str | None:
        state = state_collection.find_one({"_id": snapshot_id}) or {}
        file_id = state.get("file_id")
        if not file_id:
            fallback = self.database["sqlite_snapshots.files"].find_one(
                {
                    "$or": [
                        {"metadata.snapshot_id": snapshot_id},
                        {"filename": f"{snapshot_id}.sqlite3"},
                    ]
                },
                sort=[("uploadDate", -1)],
            )
            file_id = fallback.get("_id") if fallback else None
        if not file_id:
            return None
        fd, path = tempfile.mkstemp(prefix="upi_native_import_", suffix=".sqlite")
        os.close(fd)
        grid_out = fs.get(file_id)
        with open(path, "wb") as handle:
            while True:
                block = grid_out.read(1024 * 1024)
                if not block:
                    break
                handle.write(block)
        return path
