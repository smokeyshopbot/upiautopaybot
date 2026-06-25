import sys
import os
import sqlite3
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from native_mongo_store import NativeMongoStore
import bot


class FakeCursor(list):
    def sort(self, key, direction):
        return FakeCursor(sorted(self, key=lambda row: row.get(key, 0), reverse=direction < 0))


class FakeCollection:
    def __init__(self):
        self.docs = {}

    def find(self, query=None):
        return FakeCursor([dict(doc) for doc in self.docs.values()])

    def find_one(self, query, sort=None):
        if "_id" in query:
            doc = self.docs.get(query["_id"])
            return dict(doc) if doc else None
        rows = list(self.docs.values())
        return dict(rows[0]) if rows else None

    def replace_one(self, query, document, upsert=False, session=None):
        self.docs[query["_id"]] = dict(document)

    def update_one(self, query, update, upsert=False, session=None):
        document = self.docs.setdefault(query["_id"], {"_id": query["_id"]})
        for key, value in update.get("$set", {}).items():
            target = document
            parts = key.split(".")
            for part in parts[:-1]:
                target = target.setdefault(part, {})
            target[parts[-1]] = value

    def count_documents(self, query, session=None):
        return len(self.docs)

    def delete_many(self, query, session=None):
        if not query:
            count = len(self.docs)
            self.docs.clear()
            return type("DeleteResult", (), {"deleted_count": count})()
        count = 0
        for key in list(self.docs):
            if key == query.get("_id"):
                del self.docs[key]
                count += 1
        return type("DeleteResult", (), {"deleted_count": count})()

    def insert_many(self, documents, ordered=True):
        for document in documents:
            self.docs[document["_id"]] = dict(document)

    def bulk_write(self, operations, ordered=True, session=None):
        for operation in operations:
            name = type(operation).__name__
            if name == "ReplaceOne":
                self.docs[operation._filter["_id"]] = dict(operation._doc)
            elif name == "DeleteOne":
                self.docs.pop(operation._filter["_id"], None)


class FakeTransaction:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class FakeSession(FakeTransaction):
    def start_transaction(self):
        return FakeTransaction()


class FakeClient:
    def start_session(self):
        return FakeSession()


class FakeDatabase:
    def __init__(self):
        self.client = FakeClient()
        self.collections = {}

    def __getitem__(self, name):
        return self.collections.setdefault(name, FakeCollection())


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    chat_id INTEGER PRIMARY KEY,
    role TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS wallets (
    chat_id INTEGER PRIMARY KEY,
    balance_usdt REAL NOT NULL DEFAULT 0,
    earned_usdt REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS wallet_ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    amount_usdt REAL NOT NULL
);
"""


def initialized_store(database):
    store = NativeMongoStore(database=database, collection_prefix="test_")
    conn = store.connection()
    conn.executescript(SCHEMA)
    conn.close()
    return store


def main():
    database = FakeDatabase()
    store = initialized_store(database)
    store.initialize_from_memory()
    store.create_change_tracking()
    store.sync_suspended = False

    conn = store.connection()
    with conn:
        conn.execute("INSERT INTO users(chat_id, role, active) VALUES (101, 'sender', 1)")
        conn.execute("INSERT INTO wallets(chat_id, balance_usdt, earned_usdt) VALUES (101, 25.5, 0)")
        conn.execute("INSERT INTO wallet_ledger(chat_id, kind, amount_usdt) VALUES (101, 'deposit', 25.5)")
    conn.close()

    assert len(database["test_users"].docs) == 1
    assert len(database["test_wallets"].docs) == 1
    assert len(database["test_wallet_ledger"].docs) == 1

    restarted = initialized_store(database)
    restarted.load_native_documents_into_memory()
    restarted.create_change_tracking()
    restarted.sync_suspended = False
    conn = restarted.connection()
    wallet = conn.execute("SELECT * FROM wallets WHERE chat_id = 101").fetchone()
    assert wallet is not None and float(wallet["balance_usdt"]) == 25.5
    with conn:
        conn.execute("UPDATE wallets SET balance_usdt = 20 WHERE chat_id = 101")
        conn.execute("DELETE FROM wallet_ledger WHERE chat_id = 101")
    conn.close()
    assert list(database["test_wallets"].docs.values())[0]["balance_usdt"] == 20
    assert len(database["test_wallet_ledger"].docs) == 0

    fd, legacy_path = tempfile.mkstemp(prefix="native_import_test_", suffix=".sqlite")
    os.close(fd)
    try:
        legacy = sqlite3.connect(legacy_path)
        legacy.executescript(SCHEMA)
        legacy.execute("INSERT INTO users(chat_id, role, active) VALUES (202, 'receiver', 1)")
        legacy.execute("INSERT INTO wallets(chat_id, balance_usdt, earned_usdt) VALUES (202, 0, 7.5)")
        legacy.commit()
        legacy.close()
        import_database = FakeDatabase()
        imported = initialized_store(import_database)
        counts = imported.import_sqlite_file(legacy_path)
        assert counts["users"] == 1
        imported.load_native_documents_into_memory()
        row = imported.connection().execute("SELECT * FROM wallets WHERE chat_id = 202").fetchone()
        assert row is not None and float(row["earned_usdt"]) == 7.5
    finally:
        try:
            os.remove(legacy_path)
        except OSError:
            pass

    # Full bot schema/handler smoke test.
    bot_database = FakeDatabase()
    bot_store = NativeMongoStore(database=bot_database, collection_prefix="bot_")
    original_native = bot.MONGO_NATIVE_ENABLED
    original_snapshot = bot.MONGO_SNAPSHOT_ENABLED
    original_store = bot._native_mongo_store
    try:
        bot.MONGO_NATIVE_ENABLED = True
        bot.MONGO_SNAPSHOT_ENABLED = False
        bot._native_mongo_store = bot_store
        bot.init_db()
        bot_store.initialize_from_memory()
        bot_store.create_change_tracking()
        bot_store.sync_suspended = False
        bot.init_db()
        bot.upsert_user(555, "sender", "native-test")
        wallet = bot.ensure_wallet(555)
        assert float(wallet["balance_usdt"]) == 0
        bot.manual_adjust_wallet(555, bot.Decimal("10"), "sender_balance", "native test")
        assert float(bot.get_wallet(555)["balance_usdt"]) == 10
        bot.upsert_user(777, "receiver", "receiver-test")
        bot.set_receiver_online(777, 3)
        conn = bot.get_conn()
        with conn:
            conn.execute(
                """
                INSERT INTO photos(
                    public_id, date, daily_no, sender_chat_id, receiver_chat_id,
                    sender_message_id, generated_file_id, qr_sha256, status,
                    created_at, offer_state, offer_expires_at,
                    sender_rate_usdt, receiver_rate_usdt, reserved_usdt, payload_type
                ) VALUES (
                    'native-claim-1', '2026-06-25', 1, 555, 0,
                    1, 'telegram-file', 'hash', 'pending',
                    '2026-06-25T12:00:00+05:30', 'open', '2099-06-25T12:05:00+05:30',
                    0.5, 0.2, 0.5, 'qr'
                )
                """
            )
        conn.close()
        claimed, reason, claimed_row, _auto_off = bot.claim_offer_in_db("native-claim-1", 777)
        assert claimed, reason
        assert int(claimed_row["receiver_chat_id"]) == 777
        bot.upsert_user(778, "receiver", "late-receiver")
        bot.set_receiver_online(778, 3)
        claimed_late, _reason_late, _row_late, _auto_off_late = bot.claim_offer_in_db("native-claim-1", 778)
        assert not claimed_late

        reloaded = NativeMongoStore(database=bot_database, collection_prefix="bot_")
        bot._native_mongo_store = reloaded
        bot.init_db()
        reloaded.load_native_documents_into_memory()
        reloaded.validate_critical_integrity()
        reloaded.create_change_tracking()
        reloaded.sync_suspended = False
        assert bot.get_user(555) is not None
        assert float(bot.get_wallet(555)["balance_usdt"]) == 10
        restored_order = bot.get_photo_record("native-claim-1")
        assert restored_order is not None and int(restored_order["receiver_chat_id"]) == 777

        saved_wallets = dict(bot_database["bot_wallets"].docs)
        bot_database["bot_wallets"].docs.clear()
        corrupt_reload = NativeMongoStore(database=bot_database, collection_prefix="bot_")
        bot._native_mongo_store = corrupt_reload
        bot.init_db()
        corrupt_reload.load_native_documents_into_memory()
        try:
            corrupt_reload.validate_critical_integrity()
            raise AssertionError("critical integrity validation accepted missing wallets")
        except RuntimeError as exc:
            assert "wallets" in str(exc)
        bot_database["bot_wallets"].docs = saved_wallets
    finally:
        bot.MONGO_NATIVE_ENABLED = original_native
        bot.MONGO_SNAPSHOT_ENABLED = original_snapshot
        bot._native_mongo_store = original_store
    print("native Mongo row persistence and restart test ok")


if __name__ == "__main__":
    main()
