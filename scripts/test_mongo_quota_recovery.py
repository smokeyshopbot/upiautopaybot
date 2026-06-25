import os
import tempfile

from pymongo.errors import NetworkTimeout, OperationFailure

import bot


class FakeCursor(list):
    pass


class FakeCollection:
    def __init__(self, rows=None):
        self.rows = list(rows or [])
        self.deleted_chunks = []

    def find(self, query=None, projection=None):
        return FakeCursor(self.rows)

    def distinct(self, field):
        return [row.get(field) for row in self.rows if row.get(field) is not None]

    def delete_many(self, query):
        self.deleted_chunks.append(query)
        return type("DeleteResult", (), {"deleted_count": 0})()

    def delete_one(self, query):
        target = query.get("_id")
        self.rows = [row for row in self.rows if row.get("_id") != target]


class FakeDatabase:
    def __init__(self):
        self.collections = {
            "sqlite_snapshots.files": FakeCollection(
                [{"_id": "old", "filename": f"{bot.MONGO_SNAPSHOT_ID}.sqlite3"}]
            ),
            "sqlite_snapshots.chunks": FakeCollection(),
        }

    def __getitem__(self, name):
        return self.collections[name]


class FakeStateCollection:
    def __init__(self):
        self.state = {"_id": bot.MONGO_SNAPSHOT_ID, "file_id": "old"}

    def find_one(self, query):
        return dict(self.state)

    def update_one(self, query, update, upsert=False):
        self.state.update(update["$set"])


class FakeGridFS:
    def __init__(self, database):
        self.database = database
        self.put_calls = 0
        self.deleted = []

    def put(self, data, **kwargs):
        self.put_calls += 1
        if self.put_calls == 1:
            raise OperationFailure("over your space quota", code=8000)
        file_id = kwargs["_id"]
        self.database["sqlite_snapshots.files"].rows.append(
            {
                "_id": file_id,
                "filename": kwargs["filename"],
                "metadata": kwargs["metadata"],
            }
        )
        return file_id

    def delete(self, file_id):
        self.deleted.append(file_id)
        self.database["sqlite_snapshots.files"].delete_one({"_id": file_id})


class TimeoutThenSuccessGridFS(FakeGridFS):
    def put(self, data, **kwargs):
        self.put_calls += 1
        if self.put_calls == 1:
            raise NetworkTimeout("temporary GridFS read timeout")
        return super().put(data, **kwargs)


class QuotaIndexCollection(FakeCollection):
    def create_index(self, name):
        raise OperationFailure("over your space quota", code=8000)


class ConnectionDatabase(FakeDatabase):
    name = "quota_test"

    def __init__(self):
        super().__init__()
        self.collections[bot.MONGO_STATE_COLLECTION] = QuotaIndexCollection()


class FakeAdmin:
    def command(self, name):
        return {"ok": 1}


class FakeClient:
    def __init__(self, *args, **kwargs):
        self.admin = FakeAdmin()
        self.database = ConnectionDatabase()

    def get_default_database(self):
        return self.database

    def __getitem__(self, name):
        return self.database


def main() -> None:
    path = os.path.join(tempfile.gettempdir(), "upi_quota_recovery_test.db")
    with open(path, "wb") as handle:
        handle.write(b"compact-snapshot")

    database = FakeDatabase()
    state = FakeStateCollection()
    filesystem = FakeGridFS(database)
    original_objects = bot._mongo_objects
    original_database = bot._mongo_db
    original_enabled = bot.MONGO_ENABLED
    original_uri = bot.MONGO_URI
    original_db_path = bot.DB_PATH
    original_fingerprint = bot._mongo_last_synced_fingerprint
    original_client_factory = bot.MongoClient
    original_gridfs_factory = bot.gridfs.GridFS
    original_client = bot._mongo_client
    original_fs = bot._mongo_fs
    original_state = bot._mongo_state_col
    try:
        # Exact crash regression: optional create_index must not abort startup
        # when Atlas permits reads/deletes but rejects writes for quota.
        bot._mongo_client = None
        bot._mongo_db = None
        bot._mongo_fs = None
        bot._mongo_state_col = None
        bot.MONGO_ENABLED = True
        bot.MONGO_URI = "mongodb://quota-test"
        bot.MongoClient = FakeClient
        bot.gridfs.GridFS = lambda database, collection: FakeGridFS(database)
        _client, connected_db, _fs, connected_state = bot._mongo_objects()
        assert connected_db.name == "quota_test"
        assert isinstance(connected_state, QuotaIndexCollection)

        timeout_database = FakeDatabase()
        timeout_filesystem = TimeoutThenSuccessGridFS(timeout_database)
        uploaded_id = bot._upload_sqlite_snapshot(timeout_filesystem, b"retry-me")
        assert uploaded_id is not None
        assert timeout_filesystem.put_calls == 3, timeout_filesystem.put_calls

        bot.MONGO_ENABLED = True
        bot.DB_PATH = path
        bot._mongo_db = database
        bot._mongo_last_synced_fingerprint = None
        bot._mongo_objects = lambda: (object(), database, filesystem, state)
        bot.sync_db_to_mongo(force=True)
        assert filesystem.put_calls == 2, filesystem.put_calls
        assert "old" in filesystem.deleted, filesystem.deleted
        assert state.state["file_id"] != "old", state.state
        assert int(state.state["size_bytes"]) == len(b"compact-snapshot")
        print("mongo quota recovery test ok")
    finally:
        bot._mongo_objects = original_objects
        bot._mongo_db = original_database
        bot.MongoClient = original_client_factory
        bot.gridfs.GridFS = original_gridfs_factory
        bot._mongo_client = original_client
        bot._mongo_fs = original_fs
        bot._mongo_state_col = original_state
        bot.MONGO_ENABLED = original_enabled
        bot.MONGO_URI = original_uri
        bot.DB_PATH = original_db_path
        bot._mongo_last_synced_fingerprint = original_fingerprint
        try:
            os.remove(path)
        except OSError:
            pass


if __name__ == "__main__":
    main()
