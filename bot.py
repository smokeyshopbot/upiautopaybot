"""
UPI Autopay Bot Telegram Bot — Open Marketplace Version

Features:
- User-only Telegram bot with web-admin control panel
- Sender photos are sanitized: QR is detected, decoded, validated, and rebuilt as a clean QR image
- Pairing is removed: sender QR submissions become open offers for all online receivers
- First receiver to accept gets the QR; simultaneous/late clicks see an expired/claimed message
- Receiver /on LIMIT and /off commands, web-admin online/offline toggles, and auto-off at zero limit
- QR expiry with automatic reserve release, even after receiver acceptance
- Sender wallet balance, low-balance warnings, USDT wallet loads, tx-hash duplicate prevention, and auto/manual verification
- Receiver earnings, payout requests, admin notification badges, manual wallet adjustments, and dispute review
- Default validation allows only UPI AutoPay mandate QR payloads, not regular UPI payment QRs
- Deletes original sender photos after successful clean QR offer creation, and also after QR validation rejection
- Done/Failed updates edit the existing QR photo captions instead of sending extra chat messages
- Optional forwarding/downloading for bot-generated clean QR messages via ALLOW_FORWARD_DOWNLOAD
- MongoDB-ready persistence for live deployment, with SQLite still available for local testing
- Single-process bot + admin website, Local Windows PowerShell ready and Railway ready
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import html
import io
import json
import logging
import os
import random
import re
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urlencode, urlparse
from urllib.request import Request as UrlRequest, urlopen
from zoneinfo import ZoneInfo

import cv2
import numpy as np
import qrcode
from dotenv import load_dotenv
from telegram import BotCommandScopeChat, InlineKeyboardButton, InlineKeyboardMarkup, InputMediaPhoto, Update
from telegram.constants import ChatType
from telegram.error import TelegramError
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
import uvicorn
try:
    import aiohttp
except ImportError:  # optional; requirements.txt includes it, but keep local upgrades safe
    aiohttp = None

try:
    from pymongo import MongoClient
    from pymongo.errors import PyMongoError
    import gridfs
except ImportError:  # MongoDB is optional unless STORAGE_BACKEND=mongodb or MONGO_URI is set
    MongoClient = None
    PyMongoError = Exception
    gridfs = None

from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

load_dotenv()

APP_NAME = "UPI Autopay Bot"

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
ADMIN_IDS_RAW = os.getenv("ADMIN_IDS", "").strip()
# Public/admin-contact text shown to unregistered users on /start.
# Supports multiple values separated by commas, e.g. @admin1,@admin2,123456789
BOT_ADMIN_CONTACTS_RAW = (os.getenv("BOT_ADMIN_CONTACTS", "").strip() or os.getenv("ADMIN_CONTACTS", "").strip())
# Public support username/contact used by /support and the Support button.
# Prefer a Telegram username, e.g. @your_support, so the direct chat button can open reliably.
SUPPORT_USERNAME_RAW = (
    os.getenv("SUPPORT_USERNAME", "").strip()
    or os.getenv("SUPPORT_CONTACT", "").strip()
    or os.getenv("SUPPORT_TELEGRAM", "").strip()
)
ADMIN_PANEL_USERNAME = os.getenv("ADMIN_PANEL_USERNAME", "admin").strip() or "admin"
ADMIN_PANEL_PASSWORD = os.getenv("ADMIN_PANEL_PASSWORD", "").strip()
ADMIN_SESSION_SECRET = os.getenv("ADMIN_SESSION_SECRET", "").strip()
ADMIN_COOKIE_SECURE = os.getenv("ADMIN_COOKIE_SECURE", "false").strip().lower() in {"1", "true", "yes", "on"}
ADMIN_COOKIE_NAME = "upi_autopay_admin_session"
BOT_TZ = os.getenv("BOT_TZ", "Asia/Kolkata").strip() or "Asia/Kolkata"

# Storage
# Default remains SQLite for local testing. For live deployment, set MONGO_URI and the bot
# automatically uses MongoDB-backed persistence without needing a Railway/Render volume.
MONGO_URI = (os.getenv("MONGO_URI", "").strip() or os.getenv("MONGODB_URI", "").strip())
STORAGE_BACKEND = os.getenv("STORAGE_BACKEND", "mongodb" if MONGO_URI else "sqlite").strip().lower()
MONGO_ENABLED = STORAGE_BACKEND in {"mongo", "mongodb"}
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "").strip() or "upi_autopay_bot"
MONGO_STATE_COLLECTION = os.getenv("MONGO_STATE_COLLECTION", "bot_state").strip() or "bot_state"
MONGO_SNAPSHOT_ID = os.getenv("MONGO_SNAPSHOT_ID", "upi_autopay_main").strip() or "upi_autopay_main"
MONGO_SYNC_ON_COMMIT = os.getenv("MONGO_SYNC_ON_COMMIT", "true").strip().lower() in {"1", "true", "yes", "on"}
MONGO_TLS_ALLOW_INVALID_CERTIFICATES = os.getenv("MONGO_TLS_ALLOW_INVALID_CERTIFICATES", "false").strip().lower() in {"1", "true", "yes", "on"}
# When MongoDB is enabled, this is only a local runtime cache restored from/synced to MongoDB.
DB_PATH = os.getenv("DB_PATH", "/tmp/upi_autopay_bot.db" if MONGO_ENABLED else "upi_autopay_bot.db").strip() or ("/tmp/upi_autopay_bot.db" if MONGO_ENABLED else "upi_autopay_bot.db")

# Local default: polling. Railway can also run polling. If you want a webhook, set MODE=webhook + WEBHOOK_URL.
MODE = os.getenv("MODE", "polling").strip().lower()
WEBHOOK_URL = os.getenv("WEBHOOK_URL", "").strip().rstrip("/")
WEBHOOK_SECRET_TOKEN = os.getenv("WEBHOOK_SECRET_TOKEN", "").strip()
PORT = int(os.getenv("PORT", "8080"))

MAX_PROCESS_DIMENSION = int(os.getenv("MAX_PROCESS_DIMENSION", "1600"))

# Telegram privacy switch for the bot-generated clean QR messages.
# - ALLOW_FORWARD_DOWNLOAD=true means users can forward/save/download the generated QR.
# - ALLOW_FORWARD_DOWNLOAD=false means Telegram protect_content is enabled.
# Legacy PROTECT_CONTENT is still supported if ALLOW_FORWARD_DOWNLOAD is not set.
_ALLOW_FORWARD_DOWNLOAD_RAW = os.getenv("ALLOW_FORWARD_DOWNLOAD")
if _ALLOW_FORWARD_DOWNLOAD_RAW is not None:
    ALLOW_FORWARD_DOWNLOAD = _ALLOW_FORWARD_DOWNLOAD_RAW.strip().lower() in {"1", "true", "yes", "on"}
    PROTECT_CONTENT = not ALLOW_FORWARD_DOWNLOAD
else:
    PROTECT_CONTENT = os.getenv("PROTECT_CONTENT", "false").strip().lower() in {"1", "true", "yes", "on"}
    ALLOW_FORWARD_DOWNLOAD = not PROTECT_CONTENT

BLOCK_CONTACT_PATTERNS = os.getenv("BLOCK_CONTACT_PATTERNS", "true").strip().lower() in {"1", "true", "yes", "on"}
STRICT_QR_REGEX = os.getenv("STRICT_QR_REGEX", "").strip()
ALLOWED_QR_PREFIXES = [p.strip() for p in os.getenv("ALLOWED_QR_PREFIXES", "").split(",") if p.strip()]
STORE_QR_DATA = os.getenv("STORE_QR_DATA", "false").strip().lower() in {"1", "true", "yes", "on"}

# After a QR is successfully rebuilt and delivered, delete the sender's original photo message.
# Telegram allows bots to delete incoming messages in private chats, subject to Telegram's normal limits.
DELETE_ORIGINAL_AFTER_SUCCESS = os.getenv("DELETE_ORIGINAL_AFTER_SUCCESS", "true").strip().lower() in {"1", "true", "yes", "on"}

# If a sender uploads an invalid/rejected QR, delete that original upload too.
DELETE_ORIGINAL_AFTER_REJECTION = os.getenv("DELETE_ORIGINAL_AFTER_REJECTION", "true").strip().lower() in {"1", "true", "yes", "on"}

# When receiver uses /done or /failed as a reply, delete that command message after a successful caption update.
DELETE_STATUS_COMMAND_AFTER_USE = os.getenv("DELETE_STATUS_COMMAND_AFTER_USE", "true").strip().lower() in {"1", "true", "yes", "on"}

# QR validation mode:
# - upi_mandate: only allow UPI AutoPay / mandate creation QR payloads such as upi://mandate?...
# - generic: allow any QR after optional STRICT_QR_REGEX / ALLOWED_QR_PREFIXES / BLOCK_CONTACT_PATTERNS checks
QR_VALIDATION_MODE = os.getenv("QR_VALIDATION_MODE", "upi_mandate").strip().lower()

# For UPI mandates, purpose=01 is usually used for one-time mandates.
# Keep this true if you only want recurring AutoPay-style mandates.
REJECT_UPI_ONETIME_MANDATES = os.getenv("REJECT_UPI_ONETIME_MANDATES", "true").strip().lower() in {"1", "true", "yes", "on"}

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()


# Open marketplace settings. The web panel can override most of these in Secret Settings / Payments.
QR_EXPIRE_MINUTES = int(os.getenv("QR_EXPIRE_MINUTES", "5"))
MARKETPLACE_WATCH_INTERVAL_SECONDS = int(os.getenv("MARKETPLACE_WATCH_INTERVAL_SECONDS", "10"))
PAYMENT_WATCH_INTERVAL_SECONDS = int(os.getenv("PAYMENT_WATCH_INTERVAL_SECONDS", "30"))
PAYMENT_TIMEOUT_MINUTES = int(os.getenv("PAYMENT_TIMEOUT_MINUTES", "30"))
PAYMENT_REMINDER_MINUTES = int(os.getenv("PAYMENT_REMINDER_MINUTES", "20"))
ACTIVE_PAYMENT_CHECK_STATUSES = ("waiting", "manual_pending")
PAYMENT_WATCH_BATCH_SIZE = int(os.getenv("PAYMENT_WATCH_BATCH_SIZE", "25"))
PAYMENT_WATCH_CONCURRENCY = int(os.getenv("PAYMENT_WATCH_CONCURRENCY", "5"))
PAYMENT_AUTO_VERIFY_TIMEOUT_SECONDS = int(os.getenv("PAYMENT_AUTO_VERIFY_TIMEOUT_SECONDS", "60"))
EVM_LOG_LOOKBACK_BLOCKS = int(os.getenv("EVM_LOG_LOOKBACK_BLOCKS", "50000"))
BEP20_RPC_URL = os.getenv("BEP20_RPC_URL", "https://bsc-rpc.publicnode.com").strip()
POLYGON_RPC_URL = os.getenv("POLYGON_RPC_URL", "https://polygon-rpc.com").strip()
BEP20_RPC_URLS = os.getenv(
    "BEP20_RPC_URLS",
    f"{BEP20_RPC_URL},https://bsc-rpc.publicnode.com,https://bsc.drpc.org,https://rpc.ankr.com/bsc,https://bsc-dataseed.binance.org",
).strip()
POLYGON_RPC_URLS = os.getenv(
    "POLYGON_RPC_URLS",
    f"{POLYGON_RPC_URL},https://polygon-bor-rpc.publicnode.com,https://polygon.drpc.org,https://rpc.ankr.com/polygon",
).strip()
BEP20_RPC_BLOCK_CHUNK_SIZE = int(os.getenv("BEP20_RPC_BLOCK_CHUNK_SIZE", "450"))
POLYGON_RPC_BLOCK_CHUNK_SIZE = int(os.getenv("POLYGON_RPC_BLOCK_CHUNK_SIZE", "500"))
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "").strip()
MANUAL_VERIFICATION_DELAY_MINUTES = int(os.getenv("MANUAL_VERIFICATION_DELAY_MINUTES", "5"))
PAYMENT_VERIFY_TASK_TIMEOUT_SECONDS = int(os.getenv("PAYMENT_VERIFY_TASK_TIMEOUT_SECONDS", "60"))
DEFAULT_SENDER_RATE_USDT = os.getenv("DEFAULT_SENDER_RATE_USDT", "0").strip() or "0"
DEFAULT_RECEIVER_RATE_USDT = os.getenv("DEFAULT_RECEIVER_RATE_USDT", "0").strip() or "0"
DEFAULT_MIN_PAYOUT_USDT = os.getenv("DEFAULT_MIN_PAYOUT_USDT", "1").strip() or "1"
DEFAULT_MIN_WALLET_TOPUP_USDT = os.getenv("DEFAULT_MIN_WALLET_TOPUP_USDT", "1").strip() or "1"
DEFAULT_BEP20_MANUAL_TOLERANCE_USDT = os.getenv("BEP20_MANUAL_TOLERANCE_USDT", "0.01").strip() or "0.01"
DEFAULT_POLYGON_MANUAL_TOLERANCE_USDT = os.getenv("POLYGON_MANUAL_TOLERANCE_USDT", "0.07").strip() or "0.07"
DEFAULT_BINANCE_MANUAL_TOLERANCE_USDT = os.getenv("BINANCE_MANUAL_TOLERANCE_USDT", "0.00").strip() or "0.00"

# USDT / Binance Pay verification defaults. The admin panel can save live overrides.
BEP20_WALLET_ADDRESS = os.getenv("BEP20_WALLET_ADDRESS", "").strip()
POLYGON_WALLET_ADDRESS = os.getenv("POLYGON_WALLET_ADDRESS", "").strip()
BSCSCAN_API_KEY = os.getenv("BSCSCAN_API_KEY", "").strip()
POLYGONSCAN_API_KEY = os.getenv("POLYGONSCAN_API_KEY", "").strip()
BEP20_REQUIRED_CONFIRMATIONS = int(os.getenv("BEP20_REQUIRED_CONFIRMATIONS", "3"))
POLYGON_REQUIRED_CONFIRMATIONS = int(os.getenv("POLYGON_REQUIRED_CONFIRMATIONS", "20"))
BINANCE_PAY_ID = os.getenv("BINANCE_PAY_ID", "").strip()
BINANCE_PAY_NAME = os.getenv("BINANCE_PAY_NAME", "").strip()
BINANCE_API_KEY = os.getenv("BINANCE_API_KEY", "").strip()
BINANCE_API_SECRET = os.getenv("BINANCE_API_SECRET", "").strip()
BINANCE_API_BASE_URL = os.getenv("BINANCE_API_BASE_URL", "https://api.binance.com").strip().rstrip("/") or "https://api.binance.com"
BINANCE_PAY_HISTORY_LOOKBACK_SECONDS = int(os.getenv("BINANCE_PAY_HISTORY_LOOKBACK_SECONDS", "3600"))
BINANCE_RECV_WINDOW_MS = int(os.getenv("BINANCE_RECV_WINDOW_MS", "5000"))

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    level=getattr(logging, LOG_LEVEL, logging.INFO),
)
logger = logging.getLogger("upi_autopay_bot")


# -----------------------------
# MongoDB-backed persistence
# -----------------------------

_mongo_client = None
_mongo_db = None
_mongo_fs = None
_mongo_state_col = None
_mongo_sync_lock = threading.RLock()
_mongo_restored_once = False
_mongo_last_synced_fingerprint: tuple[int, int] | None = None
_mongo_sync_in_progress = False


def _mongo_configured() -> bool:
    return bool(MONGO_ENABLED)


def _mongo_available_or_raise() -> None:
    if not _mongo_configured():
        return
    if not MONGO_URI:
        raise BotConfigError("STORAGE_BACKEND=mongodb requires MONGO_URI or MONGODB_URI.")
    if MongoClient is None or gridfs is None:
        raise BotConfigError("MongoDB storage requires pymongo. Run: pip install -r requirements.txt")


def _mongo_objects():
    """Return Mongo client/db/GridFS/state collection, creating them lazily."""
    global _mongo_client, _mongo_db, _mongo_fs, _mongo_state_col
    _mongo_available_or_raise()
    if not _mongo_configured():
        return None, None, None, None
    if _mongo_client is None:
        logger.info("Connecting MongoDB storage backend")
        kwargs = {
            "serverSelectionTimeoutMS": 10000,
            "connectTimeoutMS": 10000,
            "socketTimeoutMS": 20000,
            "retryWrites": True,
        }
        if MONGO_TLS_ALLOW_INVALID_CERTIFICATES:
            kwargs["tlsAllowInvalidCertificates"] = True
        _mongo_client = MongoClient(MONGO_URI, **kwargs)
        # Fail fast at startup instead of discovering a bad URI after users are active.
        _mongo_client.admin.command("ping")
        default_db = None
        try:
            default_db = _mongo_client.get_default_database()
        except Exception:
            default_db = None
        _mongo_db = default_db if default_db is not None else _mongo_client[MONGO_DB_NAME]
        _mongo_fs = gridfs.GridFS(_mongo_db, collection="sqlite_snapshots")
        _mongo_state_col = _mongo_db[MONGO_STATE_COLLECTION]
        _mongo_state_col.create_index("updated_at")
        logger.info("MongoDB storage connected: database=%s state_collection=%s", _mongo_db.name, MONGO_STATE_COLLECTION)
    return _mongo_client, _mongo_db, _mongo_fs, _mongo_state_col


def restore_mongo_snapshot_if_configured() -> None:
    """Restore the latest SQLite snapshot from MongoDB into the local runtime cache.

    The existing bot code is intentionally kept on SQLite semantics because it relies on
    transactions and many SQL joins. In MongoDB mode, MongoDB is the persistent store and
    the SQLite file is a disposable single-process cache. This removes the need for a
    persistent disk volume on Railway/Render while preserving the tested bot behavior.
    """
    global _mongo_restored_once, _mongo_last_synced_fingerprint
    if not _mongo_configured() or _mongo_restored_once:
        return
    _mongo_restored_once = True
    _, _, fs, state_col = _mongo_objects()
    if fs is None or state_col is None:
        return

    db_path = os.path.abspath(DB_PATH)
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    try:
        state = state_col.find_one({"_id": MONGO_SNAPSHOT_ID})
        file_id = state.get("file_id") if state else None
        if not file_id:
            logger.info("No MongoDB database snapshot found yet; a new one will be created after init.")
            return
        data = fs.get(file_id).read()
        tmp_path = f"{db_path}.mongo_restore_tmp"
        with open(tmp_path, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, db_path)
        try:
            os.remove(f"{db_path}-wal")
            os.remove(f"{db_path}-shm")
        except FileNotFoundError:
            pass
        except Exception:
            logger.debug("Could not remove old SQLite WAL/SHM files", exc_info=True)
        stat = os.stat(db_path)
        _mongo_last_synced_fingerprint = (stat.st_mtime_ns, stat.st_size)
        logger.info("Restored database snapshot from MongoDB: %s bytes", len(data))
    except Exception as exc:
        raise BotConfigError(f"Could not restore MongoDB database snapshot: {exc}") from exc


def sync_db_to_mongo(force: bool = False) -> None:
    """Upload the local runtime DB snapshot to MongoDB.

    Called after commits in MongoDB mode. The function is synchronous on purpose so a
    successful bot/admin action is durable in MongoDB before the handler returns.
    """
    global _mongo_last_synced_fingerprint, _mongo_sync_in_progress
    if not _mongo_configured() or (not MONGO_SYNC_ON_COMMIT and not force):
        return
    if _mongo_sync_in_progress:
        return
    db_path = os.path.abspath(DB_PATH)
    if not os.path.exists(db_path):
        return
    with _mongo_sync_lock:
        if _mongo_sync_in_progress:
            return
        _mongo_sync_in_progress = True
        try:
            stat = os.stat(db_path)
            fingerprint = (stat.st_mtime_ns, stat.st_size)
            if not force and _mongo_last_synced_fingerprint == fingerprint:
                return
            _, _, fs, state_col = _mongo_objects()
            if fs is None or state_col is None:
                return
            with open(db_path, "rb") as f:
                data = f.read()
            if not data:
                return
            old_state = state_col.find_one({"_id": MONGO_SNAPSHOT_ID}) or {}
            old_file_id = old_state.get("file_id")
            file_id = fs.put(
                data,
                filename=f"{MONGO_SNAPSHOT_ID}.sqlite3",
                contentType="application/vnd.sqlite3",
                metadata={"snapshot_id": MONGO_SNAPSHOT_ID, "app": APP_NAME},
            )
            state_col.update_one(
                {"_id": MONGO_SNAPSHOT_ID},
                {
                    "$set": {
                        "file_id": file_id,
                        "filename": f"{MONGO_SNAPSHOT_ID}.sqlite3",
                        "size_bytes": len(data),
                        "storage_backend": "mongodb-backed-sqlite",
                        "updated_at": now_iso() if "now_iso" in globals() else datetime.utcnow().isoformat(timespec="seconds"),
                    }
                },
                upsert=True,
            )
            if old_file_id and old_file_id != file_id:
                try:
                    fs.delete(old_file_id)
                except Exception:
                    logger.debug("Could not delete previous MongoDB SQLite snapshot", exc_info=True)
            _mongo_last_synced_fingerprint = fingerprint
            logger.debug("Synced database snapshot to MongoDB: %s bytes", len(data))
        except PyMongoError as exc:
            raise RuntimeError(f"MongoDB database sync failed: {exc}") from exc
        finally:
            _mongo_sync_in_progress = False


class MongoSyncedSQLiteConnection(sqlite3.Connection):
    """SQLite connection that syncs the committed runtime DB file to MongoDB."""

    def commit(self) -> None:  # type: ignore[override]
        super().commit()
        sync_db_to_mongo()

    def __exit__(self, exc_type, exc, tb):  # type: ignore[override]
        result = super().__exit__(exc_type, exc, tb)
        if exc_type is None:
            sync_db_to_mongo()
        return result


def close_mongo_storage() -> None:
    global _mongo_client, _mongo_db, _mongo_fs, _mongo_state_col
    if _mongo_configured():
        try:
            sync_db_to_mongo(force=True)
        except Exception:
            logger.exception("Final MongoDB database sync failed")
    if _mongo_client is not None:
        _mongo_client.close()
    _mongo_client = None
    _mongo_db = None
    _mongo_fs = None
    _mongo_state_col = None


def parse_admin_ids(raw: str) -> set[int]:
    out: set[int] = set()
    for item in raw.replace(";", ",").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            out.add(int(item))
        except ValueError:
            logger.warning("Ignoring invalid ADMIN_IDS entry: %r", item)
    return out


ADMIN_IDS = parse_admin_ids(ADMIN_IDS_RAW)


def parse_contact_list(raw: str) -> list[str]:
    contacts: list[str] = []
    for item in raw.replace(";", ",").split(","):
        item = item.strip()
        if item:
            contacts.append(item)
    return contacts


def admin_contact_list() -> list[str]:
    # Prefer public contact handles from BOT_ADMIN_CONTACTS. If it is not set,
    # fall back to ADMIN_IDS so unregistered users still know whom to contact.
    contacts = parse_contact_list(BOT_ADMIN_CONTACTS_RAW)
    if contacts:
        return contacts
    return [str(admin_id) for admin_id in sorted(ADMIN_IDS)]


def admin_contact_text() -> str:
    contacts = admin_contact_list()
    if not contacts:
        return "Not set. Please ask the owner to set BOT_ADMIN_CONTACTS or ADMIN_IDS."
    return "\n".join(f"• {contact}" for contact in contacts)


def support_contact_value() -> str:
    contacts = parse_contact_list(SUPPORT_USERNAME_RAW)
    if contacts:
        return contacts[0]
    contacts = admin_contact_list()
    return contacts[0] if contacts else ""


def support_chat_url(contact: str | None = None) -> str | None:
    contact = (contact or support_contact_value()).strip()
    if not contact:
        return None
    if contact.startswith("https://t.me/") or contact.startswith("tg://"):
        return contact
    if contact.startswith("http://t.me/"):
        return "https://" + contact.removeprefix("http://")
    if contact.startswith("@"):
        username = contact[1:].strip()
        if username:
            return f"https://t.me/{username}"
    if re.fullmatch(r"[A-Za-z0-9_]{5,32}", contact):
        return f"https://t.me/{contact}"
    if re.fullmatch(r"\d{5,20}", contact):
        return f"tg://user?id={contact}"
    return None


def support_display_text() -> str:
    contact = support_contact_value()
    if not contact:
        return "Support is not configured yet. Ask the owner to set SUPPORT_USERNAME in .env."
    return contact


def support_keyboard(include_back: bool = True) -> InlineKeyboardMarkup | None:
    rows: list[list[InlineKeyboardButton]] = []
    url = support_chat_url()
    if url:
        rows.append([InlineKeyboardButton("💬 Open Support Chat", url=url)])
    if include_back:
        rows.append([InlineKeyboardButton("⬅️ Back", callback_data="nav:home")])
    return InlineKeyboardMarkup(rows) if rows else None


@dataclass(frozen=True)
class UserRow:
    chat_id: int
    role: str
    alias: str | None
    active: bool


@dataclass(frozen=True)
class PhotoRow:
    public_id: str
    date: str
    daily_no: int
    sender_chat_id: int
    receiver_chat_id: int
    sender_message_id: int | None
    receiver_message_id: int | None
    generated_file_id: str | None
    status: str


class BotConfigError(RuntimeError):
    pass


# -----------------------------
# Database helpers
# -----------------------------


def get_conn() -> sqlite3.Connection:
    restore_mongo_snapshot_if_configured()
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)) or ".", exist_ok=True)
    conn = sqlite3.connect(
        DB_PATH,
        timeout=20,
        factory=MongoSyncedSQLiteConnection if _mongo_configured() else sqlite3.Connection,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    # WAL stores recent writes outside the main .db file. In MongoDB mode the db file
    # itself is snapshotted after commits, so keep journal_mode=DELETE for portability.
    if _mongo_configured():
        conn.execute("PRAGMA journal_mode = DELETE")
    else:
        conn.execute("PRAGMA journal_mode = WAL")
    return conn


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    try:
        return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    except Exception:
        return set()


def _add_column_if_missing(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    if column not in _table_columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _migrate_db(conn: sqlite3.Connection) -> None:
    # Keep older SQLite databases compatible with the open marketplace version.
    for column, definition in {
        "offer_state": "TEXT NOT NULL DEFAULT 'claimed'",
        "claimed_at": "TEXT",
        "offer_expires_at": "TEXT",
        "sender_rate_usdt": "REAL NOT NULL DEFAULT 0",
        "receiver_rate_usdt": "REAL NOT NULL DEFAULT 0",
        "charged_usdt": "REAL NOT NULL DEFAULT 0",
        "earned_usdt": "REAL NOT NULL DEFAULT 0",
        "reserved_usdt": "REAL NOT NULL DEFAULT 0",
        "settled_at": "TEXT",
        "failure_reason": "TEXT",
    }.items():
        _add_column_if_missing(conn, "photos", column, definition)

    for column, definition in {
        "pay_to": "TEXT",
        "pay_to_name": "TEXT",
        "payment_details_json": "TEXT",
        "reminder_sent_at": "TEXT",
        "payment_chat_id": "INTEGER",
        "payment_msg_id": "INTEGER",
        "payment_message_template": "TEXT",
        "manual_proof_file_id": "TEXT",
        "manual_submitted_at": "TEXT",
        "topup_completed_notified_at": "TEXT",
    }.items():
        _add_column_if_missing(conn, "payment_deposits", column, definition)

    _add_column_if_missing(conn, "payout_requests", "payout_details", "TEXT")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS receiver_payout_details (
            chat_id INTEGER PRIMARY KEY,
            details_text TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(chat_id) REFERENCES users(chat_id) ON DELETE CASCADE
        )
        """
    )

    # Marketplace preset broadcasts now close after the first reply. These fields
    # let all delivered copies of the same broadcast be linked and safely cleared.
    _add_column_if_missing(conn, "message_events", "broadcast_id", "TEXT")
    _add_column_if_missing(conn, "message_events", "cleared_at", "TEXT")
    _add_column_if_missing(conn, "message_events", "canceled_by_event_id", "INTEGER")
    try:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_message_events_broadcast ON message_events(broadcast_id, replied_at)")
    except Exception:
        logger.exception("Could not create marketplace message broadcast index")

    _add_column_if_missing(conn, "disputes", "ref_id", "TEXT")
    _add_column_if_missing(conn, "disputes", "admin_note", "TEXT")
    try:
        rows = conn.execute("SELECT id FROM disputes WHERE ref_id IS NULL OR ref_id = ''").fetchall()
        for row in rows:
            conn.execute("UPDATE disputes SET ref_id = ? WHERE id = ?", (generate_dispute_ref(conn), row["id"]))
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_disputes_ref_id ON disputes(ref_id)")
    except Exception:
        logger.exception("Could not backfill dispute references")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS payment_tx_hashes (
            tx_hash_key TEXT PRIMARY KEY,
            network TEXT NOT NULL,
            tx_hash TEXT NOT NULL UNIQUE,
            first_ref_id TEXT,
            first_chat_id INTEGER,
            first_source TEXT,
            last_status TEXT,
            raw_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_tx_hashes_hash_unique ON payment_tx_hashes(tx_hash)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_payment_tx_hashes_ref ON payment_tx_hashes(first_ref_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_payment_tx_hashes_chat ON payment_tx_hashes(first_chat_id)")
    # Backfill the permanent TxHash registry from existing deposits and verification logs.
    # This makes hashes that were auto-credited or manually submitted before this patch
    # single-use going forward, even if a deposit later expires/rejects or its row is edited.
    try:
        conn.execute(
            """
            INSERT OR IGNORE INTO payment_tx_hashes(
                tx_hash_key, network, tx_hash, first_ref_id, first_chat_id, first_source,
                last_status, raw_json, created_at, updated_at
            )
            SELECT
                tx_hash_key,
                LOWER(COALESCE(NULLIF(network, ''), NULLIF(method, ''), 'unknown')),
                LOWER(tx_hash),
                ref_id,
                chat_id,
                COALESCE(NULLIF(source, ''), 'migration_deposit'),
                status,
                raw_json,
                COALESCE(confirmed_at, manual_submitted_at, created_at, ?),
                ?
            FROM payment_deposits
            WHERE tx_hash_key IS NOT NULL AND tx_hash IS NOT NULL AND tx_hash != ''
            """,
            (now_iso(), now_iso()),
        )
        rows = conn.execute(
            """
            SELECT l.ref_id, l.chat_id, l.method, l.result, l.reason, l.tx_hash, l.raw_json, l.created_at,
                   d.network AS dep_network, d.method AS dep_method
            FROM payment_verification_logs l
            LEFT JOIN payment_deposits d ON d.ref_id = l.ref_id
            WHERE l.tx_hash IS NOT NULL AND l.tx_hash != ''
            """
        ).fetchall()
        for row in rows:
            h = str(row["tx_hash"] or "").strip().lower()
            if not re.fullmatch(r"0x[a-fA-F0-9]{64}", h):
                continue
            network = str(row["dep_network"] or row["dep_method"] or row["method"] or "unknown").strip().lower()
            if network in {"usdt", "usdt_bep20"}:
                network = "bep20"
            elif network in {"usdt_polygon", "polygon_usdt"}:
                network = "polygon"
            key = tx_hash_key(network, h)
            conn.execute(
                """
                INSERT OR IGNORE INTO payment_tx_hashes(
                    tx_hash_key, network, tx_hash, first_ref_id, first_chat_id, first_source,
                    last_status, raw_json, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, 'migration_log', ?, ?, ?, ?)
                """,
                (key, network, h, row["ref_id"], row["chat_id"], row["result"], row["raw_json"], row["created_at"] or now_iso(), now_iso()),
            )
    except Exception:
        logger.exception("Could not backfill payment TxHash registry")

    conn.execute("CREATE INDEX IF NOT EXISTS idx_photos_offer_state ON photos(offer_state, offer_expires_at)")

    # Chat ID 0 is never messaged. It is a database placeholder for open/unclaimed
    # offers in older schemas where photos.receiver_chat_id is NOT NULL.
    now = datetime.now(ZoneInfo(BOT_TZ)).isoformat(timespec="seconds")
    conn.execute(
        """
        INSERT OR IGNORE INTO users(chat_id, role, alias, active, created_at, updated_at)
        VALUES (0, 'receiver', 'Unclaimed marketplace offer', 0, ?, ?)
        """,
        (now, now),
    )

def _legacy_pre_migrate_before_schema(conn: sqlite3.Connection) -> None:
    """Upgrade columns needed by indexes before the main schema script runs.

    Older local SQLite test databases may already contain message_events without
    marketplace broadcast columns. If an index references one of those columns
    before the normal migration step, SQLite aborts startup. This tiny
    pre-migration keeps old databases bootable.
    """
    tables = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    if "message_events" in tables:
        _add_column_if_missing(conn, "message_events", "broadcast_id", "TEXT")
        _add_column_if_missing(conn, "message_events", "cleared_at", "TEXT")
        _add_column_if_missing(conn, "message_events", "canceled_by_event_id", "INTEGER")
    if "photos" in tables:
        _add_column_if_missing(conn, "photos", "failure_reason", "TEXT")
    if "payout_requests" in tables:
        _add_column_if_missing(conn, "payout_requests", "payout_details", "TEXT")


def init_db() -> None:
    with get_conn() as conn:
        _legacy_pre_migrate_before_schema(conn)
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                chat_id INTEGER PRIMARY KEY,
                role TEXT NOT NULL CHECK(role IN ('sender', 'receiver')),
                alias TEXT,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS telegram_profiles (
                chat_id INTEGER PRIMARY KEY,
                username TEXT,
                first_name TEXT,
                last_name TEXT,
                last_seen_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS admin_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pairs (
                sender_chat_id INTEGER PRIMARY KEY,
                receiver_chat_id INTEGER NOT NULL,
                label TEXT,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(sender_chat_id) REFERENCES users(chat_id) ON DELETE CASCADE,
                FOREIGN KEY(receiver_chat_id) REFERENCES users(chat_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS daily_counts (
                date TEXT PRIMARY KEY,
                count INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS photos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                public_id TEXT NOT NULL UNIQUE,
                date TEXT NOT NULL,
                daily_no INTEGER NOT NULL,
                sender_chat_id INTEGER NOT NULL,
                receiver_chat_id INTEGER,
                sender_message_id INTEGER,
                receiver_message_id INTEGER,
                generated_file_id TEXT,
                qr_sha256 TEXT,
                qr_data TEXT,
                status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'done', 'failed')),
                status_by INTEGER,
                created_at TEXT NOT NULL,
                status_at TEXT,
                failure_reason TEXT,
                processing_ms INTEGER,
                offer_state TEXT NOT NULL DEFAULT 'claimed',
                claimed_at TEXT,
                offer_expires_at TEXT,
                sender_rate_usdt REAL NOT NULL DEFAULT 0,
                receiver_rate_usdt REAL NOT NULL DEFAULT 0,
                charged_usdt REAL NOT NULL DEFAULT 0,
                earned_usdt REAL NOT NULL DEFAULT 0,
                reserved_usdt REAL NOT NULL DEFAULT 0,
                settled_at TEXT,
                FOREIGN KEY(sender_chat_id) REFERENCES users(chat_id),
                FOREIGN KEY(receiver_chat_id) REFERENCES users(chat_id)
            );

            CREATE TABLE IF NOT EXISTS message_templates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                audience TEXT NOT NULL CHECK(audience IN ('sender', 'receiver', 'both')),
                button_text TEXT NOT NULL,
                message_text TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS message_replies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                template_id INTEGER NOT NULL,
                audience TEXT NOT NULL CHECK(audience IN ('sender', 'receiver', 'both')),
                button_text TEXT NOT NULL,
                reply_text TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(template_id) REFERENCES message_templates(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS message_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                template_id INTEGER NOT NULL,
                initiator_chat_id INTEGER NOT NULL,
                recipient_chat_id INTEGER NOT NULL,
                sender_chat_id INTEGER NOT NULL,
                receiver_chat_id INTEGER NOT NULL,
                direction TEXT NOT NULL CHECK(direction IN ('sender_to_receiver', 'receiver_to_sender')),
                broadcast_id TEXT,
                delivered_message_id INTEGER,
                created_at TEXT NOT NULL,
                replied_at TEXT,
                reply_id INTEGER,
                cleared_at TEXT,
                canceled_by_event_id INTEGER,
                FOREIGN KEY(template_id) REFERENCES message_templates(id),
                FOREIGN KEY(reply_id) REFERENCES message_replies(id)
            );

            CREATE TABLE IF NOT EXISTS receiver_presence (
                chat_id INTEGER PRIMARY KEY,
                online INTEGER NOT NULL DEFAULT 0,
                limit_total INTEGER NOT NULL DEFAULT 0,
                limit_remaining INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(chat_id) REFERENCES users(chat_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS offer_notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                public_id TEXT NOT NULL,
                receiver_chat_id INTEGER NOT NULL,
                message_id INTEGER NOT NULL,
                state TEXT NOT NULL DEFAULT 'sent',
                created_at TEXT NOT NULL,
                updated_at TEXT,
                UNIQUE(public_id, receiver_chat_id),
                FOREIGN KEY(public_id) REFERENCES photos(public_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS wallets (
                chat_id INTEGER PRIMARY KEY,
                balance_usdt REAL NOT NULL DEFAULT 0,
                reserved_usdt REAL NOT NULL DEFAULT 0,
                earned_usdt REAL NOT NULL DEFAULT 0,
                paid_usdt REAL NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS wallet_ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER NOT NULL,
                kind TEXT NOT NULL,
                amount_usdt REAL NOT NULL,
                balance_after REAL,
                note TEXT,
                related_id TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS payment_deposits (
                ref_id TEXT PRIMARY KEY,
                chat_id INTEGER NOT NULL,
                method TEXT NOT NULL,
                network TEXT,
                amount_usdt REAL NOT NULL,
                expected_usdt REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'waiting',
                pay_to TEXT,
                pay_to_name TEXT,
                payment_details_json TEXT,
                tx_hash TEXT,
                tx_hash_key TEXT UNIQUE,
                binance_tx_id TEXT UNIQUE,
                source TEXT,
                raw_json TEXT,
                manual_note TEXT,
                manual_check_result TEXT,
                created_at TEXT NOT NULL,
                confirmed_at TEXT,
                credited_at TEXT,
                topup_completed_notified_at TEXT,
                expires_at TEXT,
                reminder_sent_at TEXT,
                payment_chat_id INTEGER,
                payment_msg_id INTEGER,
                payment_message_template TEXT,
                manual_proof_file_id TEXT,
                manual_submitted_at TEXT,
                FOREIGN KEY(chat_id) REFERENCES users(chat_id)
            );

            CREATE TABLE IF NOT EXISTS payment_tx_hashes (
                tx_hash_key TEXT PRIMARY KEY,
                network TEXT NOT NULL,
                tx_hash TEXT NOT NULL UNIQUE,
                first_ref_id TEXT,
                first_chat_id INTEGER,
                first_source TEXT,
                last_status TEXT,
                raw_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS payment_verification_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ref_id TEXT,
                chat_id INTEGER,
                method TEXT,
                result TEXT NOT NULL,
                reason TEXT,
                tx_hash TEXT,
                raw_json TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS payout_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                receiver_chat_id INTEGER NOT NULL,
                amount_usdt REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                note TEXT,
                payout_details TEXT,
                created_at TEXT NOT NULL,
                resolved_at TEXT,
                FOREIGN KEY(receiver_chat_id) REFERENCES users(chat_id)
            );

            CREATE TABLE IF NOT EXISTS receiver_payout_details (
                chat_id INTEGER PRIMARY KEY,
                details_text TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(chat_id) REFERENCES users(chat_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS disputes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ref_id TEXT UNIQUE,
                public_id TEXT,
                chat_id INTEGER NOT NULL,
                role TEXT,
                message TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                created_at TEXT NOT NULL,
                resolved_at TEXT,
                admin_note TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_photos_date ON photos(date);
            CREATE INDEX IF NOT EXISTS idx_photos_receiver_status ON photos(receiver_chat_id, status);
            CREATE INDEX IF NOT EXISTS idx_photos_sender_status ON photos(sender_chat_id, status);
            CREATE INDEX IF NOT EXISTS idx_pairs_receiver ON pairs(receiver_chat_id);
            CREATE INDEX IF NOT EXISTS idx_telegram_profiles_username ON telegram_profiles(username);
            CREATE INDEX IF NOT EXISTS idx_message_templates_active ON message_templates(active, audience);
            CREATE INDEX IF NOT EXISTS idx_message_replies_template ON message_replies(template_id, active, audience);
            CREATE INDEX IF NOT EXISTS idx_message_events_recipient ON message_events(recipient_chat_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_receiver_presence_online ON receiver_presence(online, limit_remaining);
            CREATE INDEX IF NOT EXISTS idx_payment_deposits_status ON payment_deposits(status, created_at);
            CREATE INDEX IF NOT EXISTS idx_payment_deposits_chat ON payment_deposits(chat_id, created_at);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_tx_hashes_hash_unique ON payment_tx_hashes(tx_hash);
            CREATE INDEX IF NOT EXISTS idx_payment_tx_hashes_ref ON payment_tx_hashes(first_ref_id);
            CREATE INDEX IF NOT EXISTS idx_payment_tx_hashes_chat ON payment_tx_hashes(first_chat_id);
            CREATE INDEX IF NOT EXISTS idx_payout_requests_status ON payout_requests(status, created_at);
            CREATE INDEX IF NOT EXISTS idx_disputes_status ON disputes(status, created_at);
            """
        )
        _migrate_db(conn)


def now_dt() -> datetime:
    return datetime.now(ZoneInfo(BOT_TZ))


def now_iso() -> str:
    # Keep ISO only for database storage. User-facing messages use display_datetime().
    return now_dt().isoformat(timespec="seconds")


def today_str() -> str:
    return now_dt().date().isoformat()


def observe_telegram_profile(tg_user) -> None:
    if tg_user is None:
        return
    try:
        chat_id = int(tg_user.id)
    except Exception:
        return
    username = getattr(tg_user, "username", None)
    first_name = getattr(tg_user, "first_name", None)
    last_name = getattr(tg_user, "last_name", None)
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO telegram_profiles(chat_id, username, first_name, last_name, last_seen_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(chat_id) DO UPDATE SET
                username = excluded.username,
                first_name = excluded.first_name,
                last_name = excluded.last_name,
                last_seen_at = excluded.last_seen_at
            """,
            (chat_id, username, first_name, last_name, now_iso()),
        )


def display_date(date_str: str | None = None) -> str:
    try:
        dt = datetime.strptime(date_str or today_str(), "%Y-%m-%d")
        # Example: 16 Jun 2026
        return dt.strftime("%d %b %Y").lstrip("0")
    except Exception:
        return date_str or today_str()


def display_datetime(value: str | datetime | None = None) -> str:
    try:
        if value is None:
            dt = now_dt()
        elif isinstance(value, datetime):
            dt = value
        else:
            dt = datetime.fromisoformat(value)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=ZoneInfo(BOT_TZ))
            else:
                dt = dt.astimezone(ZoneInfo(BOT_TZ))

        day = dt.strftime("%d %b %Y").lstrip("0")
        time_part = dt.strftime("%I:%M %p").lstrip("0")
        tz_name = dt.tzname() or BOT_TZ
        return f"{day}, {time_part} {tz_name}"
    except Exception:
        return str(value) if value is not None else now_iso()


def is_admin(chat_id: int | None) -> bool:
    return chat_id is not None and chat_id in ADMIN_IDS


def require_admin(update: Update) -> bool:
    return is_admin(update.effective_chat.id if update.effective_chat else None)


def upsert_user(chat_id: int, role: str, alias: str | None = None) -> None:
    if role not in {"sender", "receiver"}:
        raise ValueError("role must be sender or receiver")

    with get_conn() as conn:
        existing = conn.execute("SELECT chat_id FROM users WHERE chat_id = ?", (chat_id,)).fetchone()
        if existing:
            conn.execute(
                """
                UPDATE users
                SET role = ?, alias = COALESCE(?, alias), active = 1, updated_at = ?
                WHERE chat_id = ?
                """,
                (role, alias, now_iso(), chat_id),
            )
        else:
            conn.execute(
                """
                INSERT INTO users(chat_id, role, alias, active, created_at, updated_at)
                VALUES (?, ?, ?, 1, ?, ?)
                """,
                (chat_id, role, alias, now_iso(), now_iso()),
            )


def set_user_active(chat_id: int, active: bool) -> bool:
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE users SET active = ?, updated_at = ? WHERE chat_id = ?",
            (1 if active else 0, now_iso(), chat_id),
        )
        return cur.rowcount > 0


def get_user(chat_id: int) -> UserRow | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE chat_id = ?", (chat_id,)).fetchone()
    if not row:
        return None
    return UserRow(chat_id=row["chat_id"], role=row["role"], alias=row["alias"], active=bool(row["active"]))


def ensure_default_sender_user(chat_id: int) -> UserRow:
    """Create first-time bot users as active senders without changing existing roles."""
    user = get_user(chat_id)
    if user:
        return user

    with get_conn() as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO users(chat_id, role, alias, active, created_at, updated_at)
            VALUES (?, 'sender', NULL, 1, ?, ?)
            """,
            (chat_id, now_iso(), now_iso()),
        )
    return get_user(chat_id) or UserRow(chat_id=chat_id, role="sender", alias=None, active=True)


def list_users(
    role: str | None = None,
    limit: int = 100,
    search: str | None = None,
    active: bool | None = None,
) -> list[sqlite3.Row]:
    with get_conn() as conn:
        base = """
            SELECT u.*, p.username, p.first_name, p.last_name, p.last_seen_at
            FROM users u
            LEFT JOIN telegram_profiles p ON p.chat_id = u.chat_id
        """
        where: list[str] = []
        params: list[object] = []

        if role in {"sender", "receiver"}:
            where.append("u.role = ?")
            params.append(role)

        if active is not None:
            where.append("u.active = ?")
            params.append(1 if active else 0)

        q = (search or "").strip()
        if q:
            like = f"%{q.lower()}%"
            where.append(
                "("
                "LOWER(CAST(u.chat_id AS TEXT)) LIKE ? OR "
                "LOWER(COALESCE(u.alias, '')) LIKE ? OR "
                "LOWER(COALESCE(u.role, '')) LIKE ? OR "
                "LOWER(COALESCE(p.username, '')) LIKE ? OR "
                "LOWER(COALESCE(p.first_name, '')) LIKE ? OR "
                "LOWER(COALESCE(p.last_name, '')) LIKE ? OR "
                "LOWER(COALESCE(p.first_name, '') || ' ' || COALESCE(p.last_name, '')) LIKE ?"
                ")"
            )
            params.extend([like, like, like, like, like, like, like])

        sql = base
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY u.created_at DESC LIMIT ?"
        params.append(limit)
        return conn.execute(sql, tuple(params)).fetchall()


def get_admin_user_row(chat_id: int) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT u.*, p.username, p.first_name, p.last_name, p.last_seen_at
            FROM users u
            LEFT JOIN telegram_profiles p ON p.chat_id = u.chat_id
            WHERE u.chat_id = ?
            """,
            (chat_id,),
        ).fetchone()


def lookup_chat_id_from_identifier(identifier: str) -> int:
    value = identifier.strip()
    if not value:
        raise ValueError("ID/Username is required")
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    username = value.lstrip("@").strip().lower()
    if not re.fullmatch(r"[A-Za-z0-9_]{5,32}", username):
        raise ValueError("Enter a numeric Telegram ID or a valid @username")
    with get_conn() as conn:
        row = conn.execute(
            "SELECT chat_id FROM telegram_profiles WHERE lower(username) = ? ORDER BY last_seen_at DESC LIMIT 1",
            (username,),
        ).fetchone()
    if not row:
        raise ValueError("That username is not known yet. Ask the user to send /start or /myid to the bot first.")
    return int(row["chat_id"])


def pair_sender_receiver(sender_chat_id: int, receiver_chat_id: int, label: str | None = None) -> None:
    sender = get_user(sender_chat_id)
    receiver = get_user(receiver_chat_id)

    if not sender or sender.role != "sender":
        raise ValueError("sender_chat_id is not registered as a sender")
    if not receiver or receiver.role != "receiver":
        raise ValueError("receiver_chat_id is not registered as a receiver")
    if not sender.active or not receiver.active:
        raise ValueError("sender and receiver must both be active")

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO pairs(sender_chat_id, receiver_chat_id, label, active, created_at, updated_at)
            VALUES (?, ?, ?, 1, ?, ?)
            ON CONFLICT(sender_chat_id) DO UPDATE SET
                receiver_chat_id = excluded.receiver_chat_id,
                label = excluded.label,
                active = 1,
                updated_at = excluded.updated_at
            """,
            (sender_chat_id, receiver_chat_id, label, now_iso(), now_iso()),
        )


def unpair_sender(sender_chat_id: int) -> bool:
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM pairs WHERE sender_chat_id = ?", (sender_chat_id,))
        return cur.rowcount > 0


def get_active_pair_for_sender(sender_chat_id: int) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT p.*, s.active AS sender_active, r.active AS receiver_active
            FROM pairs p
            JOIN users s ON s.chat_id = p.sender_chat_id
            JOIN users r ON r.chat_id = p.receiver_chat_id
            WHERE p.sender_chat_id = ? AND p.active = 1
            """,
            (sender_chat_id,),
        ).fetchone()


def list_pairs(limit: int = 100) -> list[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT p.*, s.alias AS sender_alias, r.alias AS receiver_alias,
                   s.active AS sender_active, r.active AS receiver_active,
                   sp.username AS sender_username, rp.username AS receiver_username,
                   sp.first_name AS sender_first_name, rp.first_name AS receiver_first_name,
                   sp.last_name AS sender_last_name, rp.last_name AS receiver_last_name
            FROM pairs p
            JOIN users s ON s.chat_id = p.sender_chat_id
            JOIN users r ON r.chat_id = p.receiver_chat_id
            LEFT JOIN telegram_profiles sp ON sp.chat_id = p.sender_chat_id
            LEFT JOIN telegram_profiles rp ON rp.chat_id = p.receiver_chat_id
            ORDER BY p.updated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()


def reserve_daily_number(date_str: str) -> int:
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("INSERT OR IGNORE INTO daily_counts(date, count) VALUES (?, 0)", (date_str,))
        conn.execute("UPDATE daily_counts SET count = count + 1 WHERE date = ?", (date_str,))
        row = conn.execute("SELECT count FROM daily_counts WHERE date = ?", (date_str,)).fetchone()
        conn.commit()
    return int(row["count"])


def save_photo_record(
    *,
    public_id: str,
    date_str: str,
    daily_no: int,
    sender_chat_id: int,
    receiver_chat_id: int,
    sender_message_id: int,
    receiver_message_id: int,
    generated_file_id: str,
    qr_sha256: str,
    qr_data: str | None,
    processing_ms: int,
) -> None:
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO photos(
                public_id, date, daily_no, sender_chat_id, receiver_chat_id,
                sender_message_id, receiver_message_id, generated_file_id,
                qr_sha256, qr_data, status, created_at, processing_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
            """,
            (
                public_id,
                date_str,
                daily_no,
                sender_chat_id,
                receiver_chat_id,
                sender_message_id,
                receiver_message_id,
                generated_file_id,
                qr_sha256,
                qr_data,
                now_iso(),
                processing_ms,
            ),
        )


def row_to_photo(row: sqlite3.Row | None) -> PhotoRow | None:
    if not row:
        return None
    return PhotoRow(
        public_id=row["public_id"],
        date=row["date"],
        daily_no=int(row["daily_no"]),
        sender_chat_id=int(row["sender_chat_id"]),
        receiver_chat_id=int(row["receiver_chat_id"] or 0),
        sender_message_id=row["sender_message_id"],
        receiver_message_id=row["receiver_message_id"],
        generated_file_id=row["generated_file_id"],
        status=row["status"],
    )


def find_photo_by_public_id(public_id: str) -> PhotoRow | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM photos WHERE public_id = ?", (public_id,)).fetchone()
    return row_to_photo(row)


def get_photo_record(public_id: str) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM photos WHERE public_id = ?", (public_id,)).fetchone()


def qr_detail_url(public_id: str) -> str:
    return f"/admin/qrs/{quote(str(public_id))}"


def qr_image_url(public_id: str) -> str:
    return f"/admin/photos/{quote(str(public_id))}/image"


def qr_id_link(public_id: str) -> str:
    public_id = str(public_id)
    url = qr_detail_url(public_id)
    return f'<a class="qr-detail-id" href="{esc(url)}">{esc(public_id)}</a>'


def find_photo_by_receiver_message_id(receiver_chat_id: int, message_id: int) -> PhotoRow | None:
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT * FROM photos
            WHERE receiver_chat_id = ? AND receiver_message_id = ?
            """,
            (receiver_chat_id, message_id),
        ).fetchone()
    return row_to_photo(row)


def find_photo_by_sender_message_id(sender_chat_id: int, message_id: int) -> PhotoRow | None:
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT * FROM photos
            WHERE sender_chat_id = ? AND sender_message_id = ?
            """,
            (sender_chat_id, message_id),
        ).fetchone()
    return row_to_photo(row)


def clean_failure_reason_text(reason: str | None, max_len: int = 600) -> str:
    text = " ".join(str(reason or "").strip().split())
    if len(text) > max_len:
        text = text[: max_len - 1].rstrip() + "…"
    return text


def update_photo_status(public_id: str, status: str, status_by: int, failure_reason: str | None = None) -> bool:
    failure_reason = clean_failure_reason_text(failure_reason) if status == "failed" else None
    with get_conn() as conn:
        cur = conn.execute(
            """
            UPDATE photos
            SET status = ?, status_by = ?, status_at = ?, failure_reason = ?
            WHERE public_id = ? AND status = 'pending'
            """,
            (status, status_by, now_iso(), failure_reason, public_id),
        )
        return cur.rowcount > 0


def stats_for(scope: str) -> dict[str, int | str]:
    return stats_for_filters(scope=scope)


def _scope_to_sql(scope: str) -> tuple[str, tuple, str]:
    params: tuple = ()
    where = ""
    label = scope

    if scope in {"", "today"}:
        where = "WHERE date = ?"
        params = (today_str(),)
        label = today_str()
    elif scope in {"all", "lifetime"}:
        where = ""
        params = ()
        label = "lifetime"
    elif re.fullmatch(r"\d{4}-\d{2}-\d{2}", scope):
        where = "WHERE date = ?"
        params = (scope,)
        label = scope
    else:
        where = "WHERE date = ?"
        params = (today_str(),)
        label = today_str()

    return where, params, label


def stats_for_filters(
    *,
    scope: str,
    sender_chat_id: int | None = None,
    receiver_chat_id: int | None = None,
) -> dict[str, int | str]:
    base_where, base_params, label = _scope_to_sql(scope)
    clauses: list[str] = []
    params: list = []

    if base_where:
        clauses.append(base_where.removeprefix("WHERE "))
        params.extend(base_params)
    if sender_chat_id is not None:
        clauses.append("sender_chat_id = ?")
        params.append(sender_chat_id)
    if receiver_chat_id is not None:
        clauses.append("receiver_chat_id = ?")
        params.append(receiver_chat_id)

    where = "WHERE " + " AND ".join(clauses) if clauses else ""

    with get_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT status, COUNT(*) AS n
            FROM photos
            {where}
            GROUP BY status
            """,
            tuple(params),
        ).fetchall()
        total = conn.execute(f"SELECT COUNT(*) AS n FROM photos {where}", tuple(params)).fetchone()["n"]

    counts = {"pending": 0, "done": 0, "failed": 0}
    for row in rows:
        counts[row["status"]] = int(row["n"])
    counts["total"] = int(total)
    counts["scope"] = label
    return counts


def _stats_block(label: str, counts: dict[str, int | str]) -> str:
    return (
        f"{label}\n"
        f"📦 Total: {counts['total']}\n"
        f"⏳ Pending: {counts['pending']}\n"
        f"✅ Done: {counts['done']}\n"
        f"❌ Failed: {counts['failed']}"
    )


def stats_summary_text(
    title: str,
    *,
    sender_chat_id: int | None = None,
    receiver_chat_id: int | None = None,
) -> str:
    today = stats_for_filters(scope="today", sender_chat_id=sender_chat_id, receiver_chat_id=receiver_chat_id)
    lifetime = stats_for_filters(scope="lifetime", sender_chat_id=sender_chat_id, receiver_chat_id=receiver_chat_id)

    clean_title = title.strip().rstrip(":")
    today_label = f"📅 Today — {display_date(str(today['scope']))}"
    return (
        f"📊 {clean_title}\n\n"
        f"{_stats_block(today_label, today)}\n\n"
        f"{_stats_block('🏁 Lifetime', lifetime)}"
    )


def stats_for_pair_text(pair_row: sqlite3.Row) -> str:
    # Keep Telegram pair stats private-safe: do not show raw sender/receiver IDs.
    label = pair_row["label"] or "Unnamed pair"
    title = f"Pair stats — {label}"
    return stats_summary_text(title, sender_chat_id=int(pair_row["sender_chat_id"]), receiver_chat_id=int(pair_row["receiver_chat_id"]))


def find_pair(sender_chat_id: int) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT p.*, s.alias AS sender_alias, r.alias AS receiver_alias,
                   s.active AS sender_active, r.active AS receiver_active,
                   sp.username AS sender_username, rp.username AS receiver_username,
                   sp.first_name AS sender_first_name, rp.first_name AS receiver_first_name,
                   sp.last_name AS sender_last_name, rp.last_name AS receiver_last_name
            FROM pairs p
            JOIN users s ON s.chat_id = p.sender_chat_id
            JOIN users r ON r.chat_id = p.receiver_chat_id
            LEFT JOIN telegram_profiles sp ON sp.chat_id = p.sender_chat_id
            LEFT JOIN telegram_profiles rp ON rp.chat_id = p.receiver_chat_id
            WHERE p.sender_chat_id = ?
            """,
            (sender_chat_id,),
        ).fetchone()


def admin_pair_stats_keyboard(rows: list[sqlite3.Row]) -> InlineKeyboardMarkup:
    buttons: list[list[InlineKeyboardButton]] = []
    for row in rows[:50]:
        label = row["label"] or row["sender_alias"] or str(row["sender_chat_id"])
        text = f"{label} → {row['receiver_alias'] or row['receiver_chat_id']}"
        if len(text) > 55:
            text = text[:52] + "..."
        buttons.append([InlineKeyboardButton(text, callback_data=f"pairstats:{row['sender_chat_id']}")])
    return InlineKeyboardMarkup(buttons)


def pending_rows(receiver_chat_id: int | None = None, limit: int = 30) -> list[sqlite3.Row]:
    with get_conn() as conn:
        if receiver_chat_id is not None:
            return conn.execute(
                """
                SELECT * FROM photos
                WHERE receiver_chat_id = ? AND status = 'pending'
                ORDER BY created_at ASC LIMIT ?
                """,
                (receiver_chat_id, limit),
            ).fetchall()
        return conn.execute(
            """
            SELECT * FROM photos
            WHERE status = 'pending'
            ORDER BY created_at ASC LIMIT ?
            """,
            (limit,),
        ).fetchall()



# -----------------------------
# Open marketplace, wallets, payments, disputes
# -----------------------------


def _dec(value, default: str = "0") -> Decimal:
    try:
        return Decimal(str(value if value is not None else default).strip())
    except (InvalidOperation, ValueError, TypeError):
        return Decimal(default)


def _money(value) -> str:
    return f"{_dec(value):.2f}"


def _money3(value) -> str:
    return f"{_dec(value):.3f}"


def _money4(value) -> str:
    return f"{_dec(value):.4f}"


def _setting_raw(key: str, default: str = "") -> str:
    value = get_admin_setting(key)
    if value is None or value == "":
        return str(default)
    return str(value)


def setting_bool(key: str, default: bool = False) -> bool:
    raw = _setting_raw(key, "true" if default else "false").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def setting_int(key: str, default: int) -> int:
    try:
        return int(_setting_raw(key, str(default)).strip())
    except (TypeError, ValueError):
        return int(default)


def setting_decimal(key: str, default: str | Decimal) -> Decimal:
    return _dec(_setting_raw(key, str(default)), str(default))


def get_marketplace_settings() -> dict[str, Decimal | int | bool | str]:
    return {
        "maintenance_mode": setting_bool("maintenance_mode", False),
        "sender_rate_usdt": setting_decimal("sender_rate_usdt", DEFAULT_SENDER_RATE_USDT),
        "receiver_rate_usdt": setting_decimal("receiver_rate_usdt", DEFAULT_RECEIVER_RATE_USDT),
        "qr_expire_minutes": setting_int("qr_expire_minutes", QR_EXPIRE_MINUTES),
        "payment_timeout_minutes": setting_int("payment_timeout_minutes", PAYMENT_TIMEOUT_MINUTES),
        "payment_reminder_minutes": setting_int("payment_reminder_minutes", PAYMENT_REMINDER_MINUTES),
        "payment_watch_interval_seconds": setting_int("payment_watch_interval_seconds", PAYMENT_WATCH_INTERVAL_SECONDS),
        "manual_verification_delay_minutes": setting_int("manual_verification_delay_minutes", MANUAL_VERIFICATION_DELAY_MINUTES),
        "min_payout_usdt": setting_decimal("min_payout_usdt", DEFAULT_MIN_PAYOUT_USDT),
        "wallet_min_usdt": setting_decimal("wallet_min_usdt", DEFAULT_MIN_WALLET_TOPUP_USDT),
        "bep20_enabled": setting_bool("bep20_enabled", False),
        "polygon_enabled": setting_bool("polygon_enabled", False),
        "binance_enabled": setting_bool("binance_enabled", False),
        "bep20_wallet_address": _setting_raw("bep20_wallet_address", BEP20_WALLET_ADDRESS).strip(),
        "polygon_wallet_address": _setting_raw("polygon_wallet_address", POLYGON_WALLET_ADDRESS).strip(),
        "binance_pay_id": _setting_raw("binance_pay_id", BINANCE_PAY_ID).strip(),
        "binance_pay_name": _setting_raw("binance_pay_name", BINANCE_PAY_NAME).strip(),
        "bep20_manual_tolerance_usdt": setting_decimal("bep20_manual_tolerance_usdt", DEFAULT_BEP20_MANUAL_TOLERANCE_USDT),
        "polygon_manual_tolerance_usdt": setting_decimal("polygon_manual_tolerance_usdt", DEFAULT_POLYGON_MANUAL_TOLERANCE_USDT),
        "binance_manual_tolerance_usdt": setting_decimal("binance_manual_tolerance_usdt", DEFAULT_BINANCE_MANUAL_TOLERANCE_USDT),
        "bscscan_api_key": _setting_raw("bscscan_api_key", BSCSCAN_API_KEY).strip(),
        "polygonscan_api_key": _setting_raw("polygonscan_api_key", POLYGONSCAN_API_KEY).strip(),
        "bep20_rpc_url": _setting_raw("bep20_rpc_url", BEP20_RPC_URL).strip(),
        "polygon_rpc_url": _setting_raw("polygon_rpc_url", POLYGON_RPC_URL).strip(),
        "bep20_rpc_urls": _setting_raw("bep20_rpc_urls", BEP20_RPC_URLS).strip(),
        "polygon_rpc_urls": _setting_raw("polygon_rpc_urls", POLYGON_RPC_URLS).strip(),
        "etherscan_api_key": _setting_raw("etherscan_api_key", ETHERSCAN_API_KEY).strip(),
        "bep20_required_confirmations": setting_int("bep20_required_confirmations", BEP20_REQUIRED_CONFIRMATIONS),
        "polygon_required_confirmations": setting_int("polygon_required_confirmations", POLYGON_REQUIRED_CONFIRMATIONS),
        "binance_api_key": _setting_raw("binance_api_key", BINANCE_API_KEY).strip(),
        "binance_api_secret": _setting_raw("binance_api_secret", BINANCE_API_SECRET).strip(),
        "binance_api_base_url": _setting_raw("binance_api_base_url", BINANCE_API_BASE_URL).strip().rstrip("/") or BINANCE_API_BASE_URL,
        "binance_recv_window_ms": setting_int("binance_recv_window_ms", BINANCE_RECV_WINDOW_MS),
        "binance_pay_history_lookback_seconds": setting_int("binance_pay_history_lookback_seconds", BINANCE_PAY_HISTORY_LOOKBACK_SECONDS),
    }


def maintenance_mode_enabled() -> bool:
    return bool(get_marketplace_settings()["maintenance_mode"])


def payment_method_enabled(method: str, settings: dict | None = None) -> bool:
    method = (method or "").strip().lower()
    settings = settings or get_marketplace_settings()
    if method in {"bep20", "usdt", "usdt_bep20"}:
        return bool(settings.get("bep20_enabled") and str(settings.get("bep20_wallet_address") or "").strip())
    if method in {"polygon", "usdt_polygon", "polygon_usdt"}:
        return bool(settings.get("polygon_enabled") and str(settings.get("polygon_wallet_address") or "").strip())
    if method in {"binance", "binance_pay", "binance_usdt"}:
        return bool(settings.get("binance_enabled") and str(settings.get("binance_pay_id") or "").strip())
    return False


def available_payment_methods(settings: dict | None = None) -> list[tuple[str, str]]:
    settings = settings or get_marketplace_settings()
    methods: list[tuple[str, str]] = []
    if payment_method_enabled("bep20", settings):
        methods.append(("bep20", "USDT BEP20"))
    if payment_method_enabled("polygon", settings):
        methods.append(("polygon", "USDT Polygon"))
    if payment_method_enabled("binance", settings):
        methods.append(("binance", "Binance Pay USDT"))
    return methods


def ensure_wallet(chat_id: int) -> sqlite3.Row:
    with get_conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO wallets(chat_id, balance_usdt, reserved_usdt, earned_usdt, paid_usdt, updated_at) VALUES (?, 0, 0, 0, 0, ?)",
            (chat_id, now_iso()),
        )
        return conn.execute("SELECT * FROM wallets WHERE chat_id = ?", (chat_id,)).fetchone()


def get_wallet(chat_id: int) -> sqlite3.Row:
    return ensure_wallet(chat_id)


def available_sender_balance(chat_id: int) -> Decimal:
    wallet = get_wallet(chat_id)
    return max(Decimal("0"), _dec(wallet["balance_usdt"]) - _dec(wallet["reserved_usdt"]))


def _wallet_snapshot(conn: sqlite3.Connection, chat_id: int) -> sqlite3.Row:
    conn.execute(
        "INSERT OR IGNORE INTO wallets(chat_id, balance_usdt, reserved_usdt, earned_usdt, paid_usdt, updated_at) VALUES (?, 0, 0, 0, 0, ?)",
        (chat_id, now_iso()),
    )
    return conn.execute("SELECT * FROM wallets WHERE chat_id = ?", (chat_id,)).fetchone()


def reserve_sender_funds(sender_chat_id: int, amount: Decimal, related_id: str) -> tuple[bool, str]:
    if amount <= 0:
        return True, "No sender charge configured."
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        wallet = _wallet_snapshot(conn, sender_chat_id)
        available = _dec(wallet["balance_usdt"]) - _dec(wallet["reserved_usdt"])
        if available < amount:
            conn.rollback()
            return False, f"Insufficient wallet balance. Available: ${_money(available)} USDT, required: ${_money(amount)} USDT. Use /wallet and /loadwallet to add balance."
        conn.execute(
            "UPDATE wallets SET reserved_usdt = reserved_usdt + ?, updated_at = ? WHERE chat_id = ?",
            (float(amount), now_iso(), sender_chat_id),
        )
        conn.execute(
            "INSERT INTO wallet_ledger(chat_id, kind, amount_usdt, balance_after, note, related_id, created_at) VALUES (?, 'reserve', ?, ?, ?, ?, ?)",
            (sender_chat_id, float(amount), float(available - amount), "Reserved for QR offer", related_id, now_iso()),
        )
        conn.commit()
    return True, "Reserved."


def release_sender_reserve(sender_chat_id: int, amount: Decimal, related_id: str, note: str) -> None:
    if amount <= 0:
        return
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        wallet = _wallet_snapshot(conn, sender_chat_id)
        release = min(_dec(wallet["reserved_usdt"]), amount)
        conn.execute(
            "UPDATE wallets SET reserved_usdt = MAX(0, reserved_usdt - ?), updated_at = ? WHERE chat_id = ?",
            (float(release), now_iso(), sender_chat_id),
        )
        after = _dec(wallet["balance_usdt"]) - (_dec(wallet["reserved_usdt"]) - release)
        conn.execute(
            "INSERT INTO wallet_ledger(chat_id, kind, amount_usdt, balance_after, note, related_id, created_at) VALUES (?, 'release', ?, ?, ?, ?, ?)",
            (sender_chat_id, float(release), float(after), note, related_id, now_iso()),
        )
        conn.commit()


def settle_photo_wallets(public_id: str, status: str) -> None:
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM photos WHERE public_id = ?", (public_id,)).fetchone()
        if not row or row["settled_at"]:
            conn.rollback()
            return
        sender_rate = _dec(row["sender_rate_usdt"])
        receiver_rate = _dec(row["receiver_rate_usdt"])
        sender_chat_id = int(row["sender_chat_id"])
        receiver_chat_id = int(row["receiver_chat_id"] or 0)
        now = now_iso()
        _wallet_snapshot(conn, sender_chat_id)
        if receiver_chat_id:
            _wallet_snapshot(conn, receiver_chat_id)
        if status == "done":
            conn.execute(
                "UPDATE wallets SET reserved_usdt = MAX(0, reserved_usdt - ?), balance_usdt = MAX(0, balance_usdt - ?), updated_at = ? WHERE chat_id = ?",
                (float(sender_rate), float(sender_rate), now, sender_chat_id),
            )
            sender_wallet = conn.execute("SELECT * FROM wallets WHERE chat_id = ?", (sender_chat_id,)).fetchone()
            conn.execute(
                "INSERT INTO wallet_ledger(chat_id, kind, amount_usdt, balance_after, note, related_id, created_at) VALUES (?, 'scan_charge', ?, ?, ?, ?, ?)",
                (sender_chat_id, -float(sender_rate), float(sender_wallet["balance_usdt"]), "QR marked done", public_id, now),
            )
            if receiver_chat_id and receiver_rate > 0:
                conn.execute(
                    "UPDATE wallets SET earned_usdt = earned_usdt + ?, updated_at = ? WHERE chat_id = ?",
                    (float(receiver_rate), now, receiver_chat_id),
                )
                receiver_wallet = conn.execute("SELECT * FROM wallets WHERE chat_id = ?", (receiver_chat_id,)).fetchone()
                due = _dec(receiver_wallet["earned_usdt"]) - _dec(receiver_wallet["paid_usdt"])
                conn.execute(
                    "INSERT INTO wallet_ledger(chat_id, kind, amount_usdt, balance_after, note, related_id, created_at) VALUES (?, 'scan_earning', ?, ?, ?, ?, ?)",
                    (receiver_chat_id, float(receiver_rate), float(due), "QR marked done", public_id, now),
                )
            conn.execute("UPDATE photos SET charged_usdt = ?, earned_usdt = ?, settled_at = ? WHERE public_id = ?", (float(sender_rate), float(receiver_rate), now, public_id))
        else:
            sender_wallet_before = conn.execute("SELECT * FROM wallets WHERE chat_id = ?", (sender_chat_id,)).fetchone()
            release_amount = min(_dec(sender_wallet_before["reserved_usdt"]), sender_rate)
            conn.execute(
                "UPDATE wallets SET reserved_usdt = MAX(0, reserved_usdt - ?), updated_at = ? WHERE chat_id = ?",
                (float(release_amount), now, sender_chat_id),
            )
            sender_wallet = conn.execute("SELECT * FROM wallets WHERE chat_id = ?", (sender_chat_id,)).fetchone()
            available = _dec(sender_wallet["balance_usdt"]) - _dec(sender_wallet["reserved_usdt"])
            conn.execute(
                "INSERT INTO wallet_ledger(chat_id, kind, amount_usdt, balance_after, note, related_id, created_at) VALUES (?, 'scan_release', ?, ?, ?, ?, ?)",
                (sender_chat_id, float(release_amount), float(available), "QR failed/expired, reserve released", public_id, now),
            )
            conn.execute("UPDATE photos SET settled_at = ? WHERE public_id = ?", (now, public_id))
        conn.commit()


def manual_adjust_wallet(chat_id: int, amount: Decimal, target: str, note: str) -> dict:
    """Apply an admin wallet/earnings adjustment and return the updated totals.

    target is intentionally role-specific in the web UI:
    - sender_balance updates sender wallet balance;
    - receiver_earned updates receiver earnings balance;
    - receiver_paid is reserved for payout settlement.
    """
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        wallet = _wallet_snapshot(conn, chat_id)
        now = now_iso()
        if target == "sender_balance":
            new_balance = _dec(wallet["balance_usdt"]) + amount
            reserved = _dec(wallet["reserved_usdt"])
            if new_balance < reserved:
                conn.rollback()
                raise ValueError(f"Sender balance cannot go below reserved balance (${_money(reserved)} USDT).")
            conn.execute("UPDATE wallets SET balance_usdt = ?, updated_at = ? WHERE chat_id = ?", (float(new_balance), now, chat_id))
            updated = conn.execute("SELECT * FROM wallets WHERE chat_id = ?", (chat_id,)).fetchone()
            balance_after = float(updated["balance_usdt"])
            kind = "manual_sender_adjust"
            label = "wallet balance"
        elif target == "receiver_earned":
            new_earned = _dec(wallet["earned_usdt"]) + amount
            paid = _dec(wallet["paid_usdt"])
            if new_earned < paid:
                conn.rollback()
                raise ValueError(f"Receiver earnings cannot go below already-paid amount (${_money(paid)} USDT).")
            conn.execute("UPDATE wallets SET earned_usdt = ?, updated_at = ? WHERE chat_id = ?", (float(new_earned), now, chat_id))
            updated = conn.execute("SELECT * FROM wallets WHERE chat_id = ?", (chat_id,)).fetchone()
            balance_after = float(_dec(updated["earned_usdt"]) - _dec(updated["paid_usdt"]))
            kind = "manual_receiver_adjust"
            label = "earnings balance"
        elif target == "receiver_paid":
            new_paid = _dec(wallet["paid_usdt"]) + amount
            earned = _dec(wallet["earned_usdt"])
            if new_paid < 0:
                conn.rollback()
                raise ValueError("Receiver paid amount cannot be negative.")
            if new_paid > earned:
                conn.rollback()
                raise ValueError(f"Receiver paid amount cannot exceed earned amount (${_money(earned)} USDT).")
            conn.execute("UPDATE wallets SET paid_usdt = ?, updated_at = ? WHERE chat_id = ?", (float(new_paid), now, chat_id))
            updated = conn.execute("SELECT * FROM wallets WHERE chat_id = ?", (chat_id,)).fetchone()
            balance_after = float(_dec(updated["earned_usdt"]) - _dec(updated["paid_usdt"]))
            kind = "manual_receiver_paid"
            label = "paid earnings"
        else:
            conn.rollback()
            raise ValueError("Invalid adjustment target")
        conn.execute(
            "INSERT INTO wallet_ledger(chat_id, kind, amount_usdt, balance_after, note, related_id, created_at) VALUES (?, ?, ?, ?, ?, NULL, ?)",
            (chat_id, kind, float(amount), balance_after, note, now),
        )
        conn.commit()
    return {
        "chat_id": chat_id,
        "target": target,
        "label": label,
        "kind": kind,
        "amount": amount,
        "balance_after": Decimal(str(balance_after)),
        "note": note,
    }


def online_receivers(limit: int = 500) -> list[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT r.*, u.alias, u.active, p.username, p.first_name, p.last_name
            FROM receiver_presence r
            JOIN users u ON u.chat_id = r.chat_id
            LEFT JOIN telegram_profiles p ON p.chat_id = r.chat_id
            WHERE r.online = 1 AND r.limit_remaining > 0 AND u.role = 'receiver' AND u.active = 1
            ORDER BY r.updated_at ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()


def active_receivers(limit: int = 1000) -> list[sqlite3.Row]:
    """All active receivers for marketplace preset-message broadcasts.

    QR offers still use online_receivers(); preset messages use every active receiver
    because they are marketplace announcements/questions, not claimable scan tasks.
    """
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT u.*, p.username, p.first_name, p.last_name
            FROM users u
            LEFT JOIN telegram_profiles p ON p.chat_id = u.chat_id
            WHERE u.role = 'receiver' AND u.active = 1 AND u.chat_id != 0
            ORDER BY u.updated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()


def active_senders(limit: int = 1000) -> list[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT u.*, p.username, p.first_name, p.last_name
            FROM users u
            LEFT JOIN telegram_profiles p ON p.chat_id = u.chat_id
            WHERE u.role = 'sender' AND u.active = 1 AND u.chat_id != 0
            ORDER BY u.updated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()


def set_receiver_online(chat_id: int, limit_total: int) -> None:
    limit_total = max(0, int(limit_total))
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO receiver_presence(chat_id, online, limit_total, limit_remaining, updated_at)
            VALUES (?, 1, ?, ?, ?)
            ON CONFLICT(chat_id) DO UPDATE SET
                online = 1,
                limit_total = excluded.limit_total,
                limit_remaining = excluded.limit_remaining,
                updated_at = excluded.updated_at
            """,
            (chat_id, limit_total, limit_total, now_iso()),
        )


def set_receiver_offline(chat_id: int) -> None:
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO receiver_presence(chat_id, online, limit_total, limit_remaining, updated_at)
            VALUES (?, 0, 0, 0, ?)
            ON CONFLICT(chat_id) DO UPDATE SET online = 0, limit_remaining = 0, updated_at = excluded.updated_at
            """,
            (chat_id, now_iso()),
        )


def receiver_presence_row(chat_id: int) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM receiver_presence WHERE chat_id = ?", (chat_id,)).fetchone()


def marketplace_status_text(for_chat_id: int | None = None) -> str:
    receivers = online_receivers()
    capacity = sum(int(r["limit_remaining"] or 0) for r in receivers)
    settings = get_marketplace_settings()
    text = (
        "📡 Marketplace status\n\n"
        f"🟢 Online receivers: {len(receivers)}\n"
        f"📊 Current scan capacity: {capacity}\n"
        f"⏱ QR expiry: {settings['qr_expire_minutes']} minutes\n"
    )
    if settings["maintenance_mode"]:
        text += "\n🚧 Maintenance mode is ON. New QR submissions are paused.\n"
    if for_chat_id:
        user = get_user(for_chat_id)
        if user and user.role == "sender":
            wallet = get_wallet(for_chat_id)
            rate = _dec(settings["sender_rate_usdt"])
            available = _dec(wallet["balance_usdt"]) - _dec(wallet["reserved_usdt"])
            text += f"\n💼 Your available balance: ${_money(available)} USDT\n"
            if rate > 0:
                scans = str(max(0, int(available // rate)))
                text += f"🧾 Estimated scans available: {scans}\n"
        elif user and user.role == "receiver":
            presence = receiver_presence_row(for_chat_id)
            if presence and presence["online"]:
                text += f"\nYour receiver status: 🟢 online, {presence['limit_remaining']} / {presence['limit_total']} scans left.\n"
            else:
                text += "\nYour receiver status: 🔴 offline. Use /on LIMIT to go online.\n"
    return text


def build_offer_keyboard(public_id: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[InlineKeyboardButton("✅ Accept Scan", callback_data=f"claim:{public_id}")]])


def build_offer_text(public_id: str, daily_no: int, sender_rate: Decimal, receiver_rate: Decimal, expires_at: str) -> str:
    return (
        "📥 New QR scan available\n"
        f"🆔 Offer ID: {public_id}\n"
        f"📷 Photo #{daily_no} today\n"
        f"⏱ Expires: {display_datetime(expires_at)}\n\n"
        "Tap Accept Scan to claim it. The QR will be sent only if you win the claim."
    )


def save_open_offer(
    *,
    public_id: str,
    date_str: str,
    daily_no: int,
    sender_chat_id: int,
    sender_message_id: int,
    generated_file_id: str,
    qr_sha256: str,
    qr_data: str | None,
    processing_ms: int,
    sender_rate: Decimal,
    receiver_rate: Decimal,
    expires_at: str,
) -> None:
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO photos(
                public_id, date, daily_no, sender_chat_id, receiver_chat_id,
                sender_message_id, receiver_message_id, generated_file_id,
                qr_sha256, qr_data, status, created_at, processing_ms,
                offer_state, offer_expires_at, sender_rate_usdt, receiver_rate_usdt, reserved_usdt
            ) VALUES (?, ?, ?, ?, 0, ?, NULL, ?, ?, ?, 'pending', ?, ?, 'open', ?, ?, ?, ?)
            """,
            (
                public_id,
                date_str,
                daily_no,
                sender_chat_id,
                sender_message_id,
                generated_file_id,
                qr_sha256,
                qr_data,
                now_iso(),
                processing_ms,
                expires_at,
                float(sender_rate),
                float(receiver_rate),
                float(sender_rate),
            ),
        )


def list_open_offers_to_expire(now_value: str | None = None, limit: int = 100) -> list[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT * FROM photos
            WHERE offer_state = 'open' AND offer_expires_at IS NOT NULL AND offer_expires_at <= ?
            ORDER BY offer_expires_at ASC LIMIT ?
            """,
            (now_value or now_iso(), limit),
        ).fetchall()


def list_pending_qrs_to_expire(now_value: str | None = None, limit: int = 100) -> list[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT * FROM photos
            WHERE status = 'pending'
              AND offer_state IN ('open', 'claimed')
              AND offer_expires_at IS NOT NULL
              AND offer_expires_at <= ?
            ORDER BY offer_expires_at ASC LIMIT ?
            """,
            (now_value or now_iso(), limit),
        ).fetchall()


def expire_offer_in_db(public_id: str, reason: str = "expired") -> sqlite3.Row | None:
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM photos WHERE public_id = ?", (public_id,)).fetchone()
        if not row or row["offer_state"] != "open":
            conn.rollback()
            return None
        conn.execute(
            "UPDATE photos SET offer_state = ?, status_at = ? WHERE public_id = ? AND offer_state = 'open'",
            (reason, now_iso(), public_id),
        )
        conn.commit()
        return row


def record_offer_notification(public_id: str, receiver_chat_id: int, message_id: int) -> None:
    with get_conn() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO offer_notifications(public_id, receiver_chat_id, message_id, state, created_at, updated_at)
            VALUES (?, ?, ?, 'sent', COALESCE((SELECT created_at FROM offer_notifications WHERE public_id = ? AND receiver_chat_id = ?), ?), ?)
            """,
            (public_id, receiver_chat_id, message_id, public_id, receiver_chat_id, now_iso(), now_iso()),
        )


def offer_notifications(public_id: str) -> list[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM offer_notifications WHERE public_id = ?", (public_id,)).fetchall()


def set_offer_notification_state(public_id: str, receiver_chat_id: int | None, state: str) -> None:
    with get_conn() as conn:
        if receiver_chat_id is None:
            conn.execute("UPDATE offer_notifications SET state = ?, updated_at = ? WHERE public_id = ?", (state, now_iso(), public_id))
        else:
            conn.execute("UPDATE offer_notifications SET state = ?, updated_at = ? WHERE public_id = ? AND receiver_chat_id = ?", (state, now_iso(), public_id, receiver_chat_id))


def claim_offer_in_db(public_id: str, receiver_chat_id: int) -> tuple[bool, str, sqlite3.Row | None, bool]:
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        actor = conn.execute("SELECT * FROM users WHERE chat_id = ?", (receiver_chat_id,)).fetchone()
        if not actor or actor["role"] != "receiver" or not actor["active"]:
            conn.rollback()
            return False, "Only active receivers can accept offers.", None, False
        presence = conn.execute("SELECT * FROM receiver_presence WHERE chat_id = ?", (receiver_chat_id,)).fetchone()
        if not presence or not presence["online"] or int(presence["limit_remaining"] or 0) <= 0:
            conn.rollback()
            return False, "You are offline or your limit is 0. Use /on LIMIT first.", None, False
        row = conn.execute("SELECT * FROM photos WHERE public_id = ?", (public_id,)).fetchone()
        if not row:
            conn.rollback()
            return False, "Offer not found.", None, False
        if row["offer_state"] != "open" or int(row["receiver_chat_id"] or 0) != 0:
            conn.rollback()
            return False, "Offer expired. Another receiver already accepted this QR.", row, False
        if row["offer_expires_at"] and row["offer_expires_at"] <= now_iso():
            conn.execute("UPDATE photos SET offer_state = 'expired', status_at = ? WHERE public_id = ?", (now_iso(), public_id))
            conn.commit()
            return False, "Offer expired.", row, False
        remaining_before = int(presence["limit_remaining"] or 0)
        remaining_after = max(0, remaining_before - 1)
        auto_off = remaining_after <= 0
        cur = conn.execute(
            """
            UPDATE photos
            SET receiver_chat_id = ?, offer_state = 'claimed', claimed_at = ?
            WHERE public_id = ? AND offer_state = 'open' AND receiver_chat_id = 0
            """,
            (receiver_chat_id, now_iso(), public_id),
        )
        if cur.rowcount <= 0:
            conn.rollback()
            return False, "Offer expired. Another receiver already accepted this QR.", row, False
        conn.execute(
            "UPDATE receiver_presence SET limit_remaining = ?, online = ?, updated_at = ? WHERE chat_id = ?",
            (remaining_after, 0 if auto_off else 1, now_iso(), receiver_chat_id),
        )
        updated = conn.execute("SELECT * FROM photos WHERE public_id = ?", (public_id,)).fetchone()
        conn.commit()
        return True, "Claimed.", updated, auto_off


def set_receiver_message_for_offer(public_id: str, receiver_message_id: int) -> None:
    with get_conn() as conn:
        conn.execute("UPDATE photos SET receiver_message_id = ? WHERE public_id = ?", (receiver_message_id, public_id))


def generate_dispute_ref(conn: sqlite3.Connection | None = None) -> str:
    def _new_ref() -> str:
        return "DSP" + now_dt().strftime("%y%m%d") + secrets.token_hex(3).upper()

    if conn is not None:
        for _ in range(20):
            ref = _new_ref()
            exists = conn.execute("SELECT 1 FROM disputes WHERE ref_id = ?", (ref,)).fetchone()
            if not exists:
                return ref
        return "DSP" + secrets.token_hex(6).upper()

    with get_conn() as local_conn:
        return generate_dispute_ref(local_conn)


def create_dispute(chat_id: int, public_id: str | None, message: str) -> str:
    user = get_user(chat_id)
    role = user.role if user else None
    with get_conn() as conn:
        ref_id = generate_dispute_ref(conn)
        conn.execute(
            "INSERT INTO disputes(ref_id, public_id, chat_id, role, message, status, created_at) VALUES (?, ?, ?, ?, ?, 'open', ?)",
            (ref_id, public_id, chat_id, role, message.strip(), now_iso()),
        )
        return ref_id


def pending_dispute_count() -> int:
    with get_conn() as conn:
        return int(conn.execute("SELECT COUNT(*) AS n FROM disputes WHERE status IN ('open','under_review')").fetchone()["n"])


def pending_payout_count() -> int:
    with get_conn() as conn:
        return int(conn.execute("SELECT COUNT(*) AS n FROM payout_requests WHERE status = 'pending'").fetchone()["n"])


def pending_payout_amount(receiver_chat_id: int) -> Decimal:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT COALESCE(SUM(amount_usdt), 0) AS amount FROM payout_requests WHERE receiver_chat_id = ? AND status = 'pending'",
            (receiver_chat_id,),
        ).fetchone()
    return _dec(row["amount"] if row else "0")


def receiver_earnings_numbers(chat_id: int) -> tuple[sqlite3.Row, Decimal, Decimal, Decimal, Decimal]:
    wallet = get_wallet(chat_id)
    earned = _dec(wallet["earned_usdt"])
    paid = _dec(wallet["paid_usdt"])
    requested = pending_payout_amount(chat_id)
    due = max(Decimal("0"), earned - paid)
    available = max(Decimal("0"), due - requested)
    return wallet, due, requested, available, paid


def create_payout_request(receiver_chat_id: int, amount: Decimal, note: str | None = None, payout_details: str | None = None) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO payout_requests(receiver_chat_id, amount_usdt, status, note, payout_details, created_at)
            VALUES (?, ?, 'pending', ?, ?, ?)
            """,
            (receiver_chat_id, float(amount), note, (payout_details or '').strip() or None, now_iso()),
        )
        return int(cur.lastrowid)


def clean_payout_details_text(text: str) -> str:
    # Keep payout instructions readable and compact for the admin panel.
    cleaned = re.sub(r"\n{3,}", "\n\n", (text or "").strip())
    return cleaned[:1000]


def get_receiver_payout_details(chat_id: int) -> str | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT details_text FROM receiver_payout_details WHERE chat_id = ?",
            (chat_id,),
        ).fetchone()
    if not row:
        return None
    details = str(row["details_text"] or "").strip()
    return details or None


def save_receiver_payout_details(chat_id: int, details_text: str) -> None:
    details = clean_payout_details_text(details_text)
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO receiver_payout_details(chat_id, details_text, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(chat_id) DO UPDATE SET details_text = excluded.details_text, updated_at = excluded.updated_at
            """,
            (chat_id, details, now_iso()),
        )


def payout_details_preview(details_text: str | None, limit: int = 350) -> str:
    details = (details_text or "").strip()
    if not details:
        return "Not saved yet"
    if len(details) > limit:
        return details[:limit].rstrip() + "..."
    return details


def payment_method_button_label(details_text: str | None, limit: int = 42) -> str:
    details = (details_text or "").strip()
    if not details:
        return "💾 Use saved payment details"
    first_line = next((line.strip() for line in details.splitlines() if line.strip()), "saved payment details")
    first_line = re.sub(r"\s+", " ", first_line)
    if len(first_line) > limit:
        first_line = first_line[: max(1, limit - 1)].rstrip() + "…"
    return f"💾 Use saved: {first_line}"


def user_recent_claimed_pending(receiver_chat_id: int, limit: int = 30) -> list[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT * FROM photos
            WHERE receiver_chat_id = ? AND status = 'pending' AND offer_state = 'claimed'
            ORDER BY claimed_at ASC LIMIT ?
            """,
            (receiver_chat_id, limit),
        ).fetchall()


def generate_payment_ref() -> str:
    return "DEP" + now_dt().strftime("%y%m%d") + secrets.token_hex(3).upper()


def generate_unique_usdt_amount(base_amount: Decimal) -> Decimal:
    base = _dec(base_amount).quantize(Decimal("0.001"))

    # Keep the unique payment marker small and predictable:
    #   1 USDT -> 1.001 ... 1.099
    # This gives 99 simultaneously open deposits for the same requested amount
    # without turning a $1 top-up into something like $1.979. Amounts may be
    # reused only after the older deposit is completed/credited, expired, or rejected.
    active_status_sql = """
        credited_at IS NULL
        AND status NOT IN ('expired', 'credited', 'rejected')
        AND ROUND(expected_usdt, 3) = ?
    """

    suffixes = list(range(1, 100))
    random.shuffle(suffixes)
    with get_conn() as conn:
        for suffix in suffixes:
            unique = (base + Decimal(suffix) / Decimal("1000")).quantize(Decimal("0.001"))
            exists = conn.execute(
                f"SELECT 1 FROM payment_deposits WHERE {active_status_sql} LIMIT 1",
                (float(unique),),
            ).fetchone()
            if not exists:
                return unique

    raise ValueError(
        "Too many active wallet top-ups with this same amount. Please wait for an older top-up to complete/expire or enter a slightly different amount."
    )


def create_deposit(chat_id: int, amount: Decimal, method: str) -> sqlite3.Row:
    method = method.strip().lower()
    network = "polygon" if method in {"polygon", "usdt_polygon", "polygon_usdt"} else "bep20" if method in {"bep20", "usdt", "usdt_bep20"} else "binance"
    if network not in {"bep20", "polygon", "binance"}:
        raise ValueError("Method must be bep20, polygon, or binance")
    settings = get_marketplace_settings()
    if not payment_method_enabled(network, settings):
        raise ValueError(f"{network.upper()} top-up is disabled or missing payment details in payment settings")
    min_topup = _dec(settings.get("wallet_min_usdt"), DEFAULT_MIN_WALLET_TOPUP_USDT)
    if amount < min_topup:
        raise ValueError(f"Minimum wallet top-up is ${_money(min_topup)} USDT")
    expected = generate_unique_usdt_amount(amount)
    ref_id = generate_payment_ref()
    timeout_minutes = max(1, int(settings.get("payment_timeout_minutes") or PAYMENT_TIMEOUT_MINUTES))
    expires_at = datetime.fromtimestamp(now_dt().timestamp() + timeout_minutes * 60, ZoneInfo(BOT_TZ)).isoformat(timespec="seconds")
    if network == "polygon":
        pay_to = str(settings["polygon_wallet_address"]).strip()
        pay_to_name = "USDT Polygon wallet"
    elif network == "binance":
        pay_to = str(settings["binance_pay_id"]).strip()
        pay_to_name = str(settings["binance_pay_name"]).strip() or "Binance Pay"
    else:
        pay_to = str(settings["bep20_wallet_address"]).strip()
        pay_to_name = "USDT BEP20 wallet"
    details = {
        "network": network,
        "pay_to": pay_to,
        "pay_to_name": pay_to_name,
        "created_from_settings": {
            "wallet_min_usdt": str(min_topup),
        },
    }
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO payment_deposits(ref_id, chat_id, method, network, amount_usdt, expected_usdt, status, pay_to, pay_to_name, payment_details_json, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, 'waiting', ?, ?, ?, ?, ?)
            """,
            (ref_id, chat_id, method, network, float(amount), float(expected), pay_to, pay_to_name, json.dumps(details), now_iso(), expires_at),
        )
        return conn.execute("SELECT * FROM payment_deposits WHERE ref_id = ?", (ref_id,)).fetchone()


def get_deposit(ref_id: str) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM payment_deposits WHERE ref_id = ?", (ref_id.strip().upper(),)).fetchone()


def normalize_payment_network(network: str | None) -> str:
    value = str(network or "").strip().lower()
    if value in {"usdt", "usdt_bep20", "bsc", "bep-20"}:
        return "bep20"
    if value in {"usdt_polygon", "polygon_usdt", "matic"}:
        return "polygon"
    return value or "unknown"


def normalize_tx_hash(tx_hash: str | None) -> str:
    return str(tx_hash or "").strip().lower()


def tx_hash_key(network: str, tx_hash: str) -> str:
    return f"{normalize_payment_network(network)}:{normalize_tx_hash(tx_hash)}"


def _reserve_tx_hash_on_conn(
    conn: sqlite3.Connection,
    *,
    network: str,
    tx_hash: str,
    ref_id: str | None,
    chat_id: int | None,
    source: str,
    status: str,
    raw: dict | None = None,
    allow_existing_for_ref: bool = False,
) -> tuple[bool, str, str]:
    """Permanently reserve a blockchain TxHash so it can never be reused.

    payment_deposits only has one tx_hash_key column, so a user could otherwise
    overwrite/clear a failed manual hash. This registry is append-only in spirit:
    once a valid TxHash is seen by manual submit or auto-credit, it stays used.
    """
    normalized_network = normalize_payment_network(network)
    normalized_hash = normalize_tx_hash(tx_hash)
    if not re.fullmatch(r"0x[a-fA-F0-9]{64}", normalized_hash):
        return False, "", "Invalid transaction hash format"
    key = tx_hash_key(normalized_network, normalized_hash)
    now = now_iso()
    existing = conn.execute(
        "SELECT * FROM payment_tx_hashes WHERE tx_hash_key = ? OR tx_hash = ?",
        (key, normalized_hash),
    ).fetchone()
    if existing:
        existing_ref = str(existing["first_ref_id"] or "").upper()
        if allow_existing_for_ref and ref_id and existing_ref == str(ref_id).upper():
            conn.execute(
                """
                UPDATE payment_tx_hashes
                SET last_status = ?, raw_json = COALESCE(?, raw_json), updated_at = ?
                WHERE tx_hash_key = ?
                """,
                (status, json.dumps(raw or {}, default=str)[:5000] if raw else None, now, key),
            )
            return True, key, ""
        return False, key, "This transaction hash has already been used."
    try:
        conn.execute(
            """
            INSERT INTO payment_tx_hashes(
                tx_hash_key, network, tx_hash, first_ref_id, first_chat_id, first_source,
                last_status, raw_json, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                key,
                normalized_network,
                normalized_hash,
                str(ref_id).upper() if ref_id else None,
                int(chat_id) if chat_id is not None else None,
                source,
                status,
                json.dumps(raw or {}, default=str)[:5000] if raw else None,
                now,
                now,
            ),
        )
        return True, key, ""
    except sqlite3.IntegrityError:
        return False, key, "This transaction hash has already been used."


def reserve_tx_hash(
    *,
    network: str,
    tx_hash: str,
    ref_id: str | None,
    chat_id: int | None,
    source: str,
    status: str = "submitted",
    raw: dict | None = None,
    allow_existing_for_ref: bool = False,
) -> tuple[bool, str, str]:
    with get_conn() as conn:
        return _reserve_tx_hash_on_conn(
            conn,
            network=network,
            tx_hash=tx_hash,
            ref_id=ref_id,
            chat_id=chat_id,
            source=source,
            status=status,
            raw=raw,
            allow_existing_for_ref=allow_existing_for_ref,
        )


def log_payment_check(ref_id: str | None, chat_id: int | None, method: str | None, result: str, reason: str = "", tx_hash: str | None = None, raw: dict | None = None) -> None:
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO payment_verification_logs(ref_id, chat_id, method, result, reason, tx_hash, raw_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (ref_id, chat_id, method, result, reason[:500], tx_hash, json.dumps(raw or {}, default=str)[:5000], now_iso()),
        )


def _http_get_json(url: str, headers: dict[str, str] | None = None, timeout: int = 8) -> dict:
    req = UrlRequest(url, headers=headers or {"User-Agent": APP_NAME})
    with urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", "replace")
    return json.loads(raw)


def _http_post_json(url: str, payload: dict, headers: dict[str, str] | None = None, timeout: int = 8) -> dict:
    body = json.dumps(payload).encode("utf-8")
    req_headers = {"User-Agent": APP_NAME, "Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    req = UrlRequest(url, data=body, headers=req_headers, method="POST")
    with urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", "replace")
    return json.loads(raw)


def _split_rpc_urls(value: str, defaults: list[str]) -> list[str]:
    """Return de-duplicated RPC URLs from comma/newline separated settings."""
    urls: list[str] = []
    raw = str(value or "")
    for item in re.split(r"[,\n\r\s]+", raw):
        clean = item.strip().rstrip("/")
        if clean and clean not in urls:
            urls.append(clean)
    for item in defaults:
        clean = str(item or "").strip().rstrip("/")
        if clean and clean not in urls:
            urls.append(clean)
    return urls


def _rpc_urls(network: str) -> list[str]:
    """Use several RPC providers, not one.

    Some public BSC/Polygon endpoints reject large eth_getLogs requests or fail
    intermittently. The working payment bot scans across multiple providers in
    small chunks, so this bot follows the same pattern.
    """
    network = normalize_payment_network(network)
    if network == "polygon":
        primary = _setting_raw("polygon_rpc_url", POLYGON_RPC_URL).strip()
        multi = _setting_raw("polygon_rpc_urls", POLYGON_RPC_URLS).strip()
        defaults = [
            POLYGON_RPC_URL,
            "https://polygon-rpc.com",
            "https://polygon-bor-rpc.publicnode.com",
            "https://polygon.drpc.org",
            "https://rpc.ankr.com/polygon",
        ]
    else:
        primary = _setting_raw("bep20_rpc_url", BEP20_RPC_URL).strip()
        multi = _setting_raw("bep20_rpc_urls", BEP20_RPC_URLS).strip()
        defaults = [
            BEP20_RPC_URL,
            "https://bsc-rpc.publicnode.com",
            "https://bsc.drpc.org",
            "https://rpc.ankr.com/bsc",
            "https://bsc-dataseed.binance.org",
        ]
    return _split_rpc_urls(",".join(x for x in (multi, primary) if x), defaults)


def _rpc_url(network: str) -> str:
    urls = _rpc_urls(network)
    return urls[0] if urls else ""


def _safe_rpc_name(rpc_url: str) -> str:
    return str(rpc_url or "").replace("https://", "").replace("http://", "").split("/")[0]


def _rpc_call_url(rpc_url: str, method: str, params: list, timeout: int = 12) -> object:
    url = str(rpc_url or "").strip().rstrip("/")
    if not url:
        raise ValueError("RPC URL is not configured")
    payload = {"jsonrpc": "2.0", "id": int(time.time() * 1000), "method": method, "params": params}
    data = _http_post_json(url, payload, timeout=timeout)
    if data.get("error"):
        err = data.get("error")
        if isinstance(err, dict):
            raise ValueError(str(err.get("message") or err))
        raise ValueError(str(err))
    return data.get("result")


def _rpc_call(network: str, method: str, params: list, timeout: int = 12, rpc_url: str | None = None) -> object:
    if rpc_url:
        return _rpc_call_url(rpc_url, method, params, timeout=timeout)
    errors: list[str] = []
    for url in _rpc_urls(network):
        try:
            return _rpc_call_url(url, method, params, timeout=timeout)
        except Exception as exc:
            errors.append(f"{_safe_rpc_name(url)}: {exc}")
    raise ValueError(" | ".join(errors) or f"{normalize_payment_network(network).upper()} RPC URL is not configured")


def _topic_address(address: str) -> str:
    address = str(address or "").strip().lower()
    if address.startswith("0x"):
        address = address[2:]
    return "0x" + ("0" * 24) + address[-40:]


def _int_from_hex_or_dec(value, default: int = 0) -> int:
    try:
        text = str(value or "").strip()
        if not text:
            return default
        return int(text, 16) if text.startswith("0x") else int(text)
    except Exception:
        return default


def _token_cfg(network: str) -> dict[str, str | int]:
    network = (network or "bep20").lower()
    settings = get_marketplace_settings()
    if network == "polygon":
        return {
            "network": "polygon",
            "label": "USDT Polygon",
            "api_url": "https://api.polygonscan.com/api",
            "api_key": str(settings["polygonscan_api_key"]),
            "wallet": str(settings["polygon_wallet_address"]),
            "contract": "0xc2132D05D31c914a87C6611C10748AEb04B58e8F".lower(),
            "decimals": 6,
            "confirmations": int(settings["polygon_required_confirmations"]),
        }
    return {
        "network": "bep20",
        "label": "USDT BEP20",
        "api_url": "https://api.bscscan.com/api",
        "api_key": str(settings["bscscan_api_key"]),
        "wallet": str(settings["bep20_wallet_address"]),
        "contract": "0x55d398326f99059fF775485246999027B3197955".lower(),
        "decimals": 18,
        "confirmations": int(settings["bep20_required_confirmations"]),
    }


def _latest_block_number_rpc(network: str, rpc_url: str | None = None) -> int | None:
    try:
        result = _rpc_call(network, "eth_blockNumber", [], rpc_url=rpc_url)
        return _int_from_hex_or_dec(result) if result else None
    except Exception:
        return None


def _block_timestamp_from_number_rpc(network: str, block_number: str | int | None, rpc_url: str | None = None) -> int:
    try:
        if block_number is None or block_number == "":
            return 0
        tag = hex(block_number) if isinstance(block_number, int) else (str(block_number) if str(block_number).startswith("0x") else hex(int(str(block_number))))
        result = _rpc_call(network, "eth_getBlockByNumber", [tag, False], rpc_url=rpc_url)
        if isinstance(result, dict):
            return _int_from_hex_or_dec(result.get("timestamp"), 0)
    except Exception:
        return 0
    return 0


def _decode_usdt_transfer_log(network: str, log: dict) -> dict | None:
    cfg = _token_cfg(network)
    transfer_sig = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    if not isinstance(log, dict):
        return None
    topics = log.get("topics") or []
    if len(topics) < 3 or str(topics[0]).lower() != transfer_sig:
        return None
    if str(log.get("address") or "").lower() != str(cfg["contract"]).lower():
        return None
    to_topic = str(topics[2] or "").lower()
    to_addr = "0x" + to_topic[-40:] if len(to_topic) >= 40 else ""
    data = str(log.get("data") or "0x0").strip()
    try:
        raw_value = int(data, 16)
    except Exception:
        raw_value = 0
    block_number = str(log.get("blockNumber") or "")
    return {
        "hash": str(log.get("transactionHash") or log.get("hash") or "").lower(),
        "contractAddress": str(cfg["contract"]).lower(),
        "to": to_addr,
        "value": str(raw_value),
        "network": normalize_payment_network(network),
        "blockNumber": block_number,
    }


def _rpc_scan_token_txs(network: str, wallet: str, tx_hash: str | None = None, min_ts: int | None = None) -> tuple[list[dict], str]:
    """Fallback scanner using eth_getLogs across multiple RPCs in chunks.

    The previous implementation used one provider and one big getLogs call. Many
    public BSC/Polygon RPCs reject that, causing the automatic watcher to log
    "could not verify through chain API" even when payment was sent. This mirrors
    the working project's approach: newest chunks first, multiple providers.
    """
    cfg = _token_cfg(network)
    network_key = normalize_payment_network(network)
    wallet = (wallet or str(cfg["wallet"])).strip()
    if not wallet or not re.fullmatch(r"0x[a-fA-F0-9]{40}", wallet):
        return [], f"{cfg['label']} wallet address is not configured"

    block_seconds = 2 if network_key == "polygon" else 3
    chunk_size = max(10, int(POLYGON_RPC_BLOCK_CHUNK_SIZE if network_key == "polygon" else BEP20_RPC_BLOCK_CHUNK_SIZE))
    errors: list[str] = []

    for rpc_url in _rpc_urls(network_key):
        provider = _safe_rpc_name(rpc_url)
        try:
            latest_hex = _rpc_call_url(rpc_url, "eth_blockNumber", [], timeout=12)
            latest = _int_from_hex_or_dec(latest_hex, 0)
            if not latest:
                errors.append(f"{provider} blockNumber failed")
                continue

            if min_ts:
                seconds_back = max(900, int(time.time()) - int(min_ts) + 900)
            else:
                timeout_minutes = int(get_marketplace_settings().get("payment_timeout_minutes") or PAYMENT_TIMEOUT_MINUTES)
                seconds_back = max(1800, timeout_minutes * 60 + 900)
            dynamic_blocks = int(seconds_back / max(0.5, block_seconds)) + 500
            lookback = min(max(dynamic_blocks, chunk_size * 2), max(chunk_size * 2, int(EVM_LOG_LOOKBACK_BLOCKS)))
            from_block = max(0, latest - lookback)
            wallet_topic = _topic_address(wallet)
            transfer_topic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
            rows: list[dict] = []

            end_block = latest
            while end_block >= from_block:
                start_block = max(from_block, end_block - chunk_size + 1)
                params = [{
                    "fromBlock": hex(start_block),
                    "toBlock": hex(end_block),
                    "address": str(cfg["contract"]),
                    "topics": [transfer_topic, None, wallet_topic],
                }]
                try:
                    logs = _rpc_call_url(rpc_url, "eth_getLogs", params, timeout=20)
                except Exception as exc:
                    errors.append(f"{provider} getLogs {start_block}-{end_block} failed: {exc}")
                    end_block = start_block - 1
                    continue
                if not isinstance(logs, list):
                    errors.append(f"{provider} getLogs returned unexpected payload")
                    end_block = start_block - 1
                    continue

                for log in reversed(logs):
                    tx = _decode_usdt_transfer_log(network_key, log)
                    if not tx:
                        continue
                    if tx_hash and str(tx.get("hash") or "").lower() != tx_hash.lower():
                        continue
                    block_no = _int_from_hex_or_dec(tx.get("blockNumber"), 0)
                    if block_no:
                        tx["confirmations"] = str(max(0, latest - block_no + 1))
                    tx["source"] = f"{network_key}_rpc_logs:{provider}"
                    rows.append(tx)

                # If a specific hash was requested and found in this newest chunk,
                # no need to scan older chunks.
                if tx_hash and rows:
                    return rows, ""
                end_block = start_block - 1

            if rows:
                logger.info("Payment scanner used RPC fallback for %s via %s wallet %s", network_key, provider, wallet[-6:])
                return rows, ""
        except Exception as exc:
            errors.append(f"{provider} RPC scan error: {exc}")
            continue

    return [], _public_payment_error_text(errors or ["No matching incoming USDT transfer found yet."])


def _scan_token_txs_etherscan_v2(network: str, wallet: str, tx_hash: str | None = None) -> tuple[list[dict], str]:
    """Optional Etherscan V2 multichain scan, matching the working payment project."""
    cfg = _token_cfg(network)
    key = _setting_raw("etherscan_api_key", ETHERSCAN_API_KEY).strip()
    if not key:
        return [], ""
    chainid = "137" if normalize_payment_network(network) == "polygon" else "56"
    params = {
        "chainid": chainid,
        "module": "account",
        "action": "tokentx",
        "contractaddress": cfg["contract"],
        "address": wallet,
        "page": "1",
        "offset": "1000",
        "sort": "desc",
        "apikey": key,
    }
    try:
        payload = _http_get_json(f"https://api.etherscan.io/v2/api?{urlencode(params)}")
        result = payload.get("result")
        if str(payload.get("status") or "").strip() == "1" and isinstance(result, list):
            if tx_hash:
                result = [tx for tx in result if str(tx.get("hash") or tx.get("txhash") or "").lower() == tx_hash.lower()]
            for tx in result:
                tx["source"] = f"etherscan_v2:{normalize_payment_network(network)}"
                tx["network"] = normalize_payment_network(network)
            return result, "" if result else "No matching incoming USDT transfer found yet."
        msg = str(payload.get("message") or "").strip()
        res = str(payload.get("result") or "").strip()
        return [], f"Etherscan V2 {cfg['label']} returned {' '.join(x for x in (msg, res[:160]) if x)}".strip()
    except Exception as exc:
        return [], f"Etherscan V2 {cfg['label']} failed: {exc}"


def _scan_token_txs(network: str, wallet: str, tx_hash: str | None = None, min_ts: int | None = None) -> tuple[list[dict], str]:
    cfg = _token_cfg(network)
    wallet = (wallet or str(cfg["wallet"])).strip()
    if not wallet or not re.fullmatch(r"0x[a-fA-F0-9]{40}", wallet):
        return [], f"{cfg['label']} wallet address is not configured"

    # Priority 1: Etherscan API V2 for both BEP20 and Polygon.
    explorer_error = ""
    v2_rows, v2_err = _scan_token_txs_etherscan_v2(network, wallet, tx_hash=tx_hash)
    if v2_rows:
        logger.info("Payment scanner used Etherscan V2 for %s wallet %s", normalize_payment_network(network), wallet[-6:])
        return v2_rows, ""
    if v2_err:
        explorer_error = v2_err

    # Priority 2: legacy BscScan/PolygonScan explorer API.
    params = {
        "module": "account",
        "action": "tokentx",
        "contractaddress": cfg["contract"],
        "address": wallet,
        "page": "1",
        "offset": "1000",
        "sort": "desc",
    }
    if cfg["api_key"]:
        params["apikey"] = str(cfg["api_key"])
    url = f"{cfg['api_url']}?{urlencode(params)}"
    try:
        payload = _http_get_json(url)
        result = payload.get("result")
        status = str(payload.get("status") or "").strip()
        if status and status != "1":
            message = str(payload.get("message") or "").strip()
            result_text = str(payload.get("result") or "").strip()
            combined = " ".join(x for x in (message, result_text) if x).strip()
            low = combined.lower()
            if "no transactions found" in low:
                explorer_error = "No recent USDT transactions found for this payment wallet yet"
            elif "invalid api key" in low or "missing or invalid action" in low or "api key" in low:
                explorer_error = f"{cfg['label']} explorer API key is missing or invalid"
            elif "rate limit" in low or "max rate" in low:
                explorer_error = f"{cfg['label']} explorer rate limit reached. Try again shortly."
            elif result_text:
                explorer_error = f"{cfg['label']} explorer returned: {result_text}"
            elif message and message.upper() != "NOTOK":
                explorer_error = f"{cfg['label']} explorer returned: {message}"
            else:
                explorer_error = f"{cfg['label']} explorer could not return transactions"
        elif isinstance(result, list):
            if tx_hash:
                result = [tx for tx in result if str(tx.get("hash") or "").lower() == tx_hash.lower()]
            if result:
                return result, ""
            explorer_error = "No matching incoming USDT transfer found yet."
        else:
            text = str(payload.get("result") or payload.get("message") or "").strip()
            explorer_error = _public_payment_error_text(text or "Explorer did not return transactions")
    except Exception as exc:
        explorer_error = f"Explorer API error: {exc}"

    # Fallback: use public EVM RPC logs. This keeps automatic checking alive when
    # BscScan/PolygonScan is delayed, missing an API key, or rate-limited.
    rpc_rows, rpc_err = _rpc_scan_token_txs(network, wallet, tx_hash=tx_hash, min_ts=min_ts)
    if rpc_rows:
        logger.info("Payment scanner used RPC fallback for %s wallet %s", normalize_payment_network(network), wallet[-6:])
        return rpc_rows, ""
    return [], _public_payment_error_text(rpc_err or explorer_error or "No matching incoming USDT transfer found yet.")

def _latest_block_number(network: str) -> int | None:
    cfg = _token_cfg(network)
    params = {"module": "proxy", "action": "eth_blockNumber"}
    if cfg["api_key"]:
        params["apikey"] = str(cfg["api_key"])
    try:
        payload = _http_get_json(f"{cfg['api_url']}?{urlencode(params)}")
        result = str(payload.get("result") or "").strip()
        if result.startswith("0x"):
            return int(result, 16)
    except Exception:
        pass
    return _latest_block_number_rpc(network)


def _block_timestamp_from_number(network: str, block_number: str | int | None) -> int:
    """Best-effort block timestamp lookup for direct TxHash receipt checks."""
    if block_number is None or block_number == "":
        return 0
    try:
        if isinstance(block_number, int):
            tag = hex(block_number)
        else:
            block_text = str(block_number).strip()
            tag = block_text if block_text.startswith("0x") else hex(int(block_text))
    except Exception:
        return 0
    cfg = _token_cfg(network)
    params = {"module": "proxy", "action": "eth_getBlockByNumber", "tag": tag, "boolean": "false"}
    if cfg["api_key"]:
        params["apikey"] = str(cfg["api_key"])
    try:
        payload = _http_get_json(f"{cfg['api_url']}?{urlencode(params)}")
        result = payload.get("result") or {}
        if isinstance(result, dict):
            ts = str(result.get("timestamp") or "").strip()
            if ts.startswith("0x"):
                return int(ts, 16)
            if ts:
                return int(ts)
    except Exception:
        pass
    return _block_timestamp_from_number_rpc(network, block_number)


def _receipt_usdt_transfer_by_hash_rpc(network: str, tx_hash: str, expected_wallet: str) -> tuple[dict | None, str]:
    cfg = _token_cfg(network)
    network_key = normalize_payment_network(network)
    wallet_lower = (expected_wallet or "").lower()
    errors: list[str] = []

    for rpc_url in _rpc_urls(network_key):
        provider = _safe_rpc_name(rpc_url)
        try:
            latest_hex = _rpc_call_url(rpc_url, "eth_blockNumber", [], timeout=12)
            latest = _int_from_hex_or_dec(latest_hex, 0)
            result = _rpc_call_url(rpc_url, "eth_getTransactionReceipt", [tx_hash], timeout=20)
        except Exception as exc:
            errors.append(f"{provider} receipt lookup failed: {exc}")
            continue

        if not isinstance(result, dict):
            errors.append(f"{provider} did not find this tx on {cfg['label']}")
            continue

        status = str(result.get("status") or "").lower()
        if status and status not in {"0x1", "1"}:
            return None, "Transaction exists but failed on-chain."

        token_logs: list[dict] = []
        for log in result.get("logs") or []:
            tx = _decode_usdt_transfer_log(network_key, log)
            if tx:
                token_logs.append(tx)
        if not token_logs:
            errors.append(f"{provider}: Transaction is not a USDT transfer on the selected network")
            continue

        for tx in token_logs:
            if str(tx.get("to") or "").lower() == wallet_lower:
                block_no = _int_from_hex_or_dec(tx.get("blockNumber"), 0)
                if latest and block_no:
                    tx["confirmations"] = str(max(0, latest - block_no + 1))
                ts = _block_timestamp_from_number_rpc(network_key, block_no, rpc_url=rpc_url)
                if ts:
                    tx["timeStamp"] = str(ts)
                tx["source"] = f"{network_key}_rpc_receipt:{provider}"
                return tx, ""

        # The tx is real and contains USDT transfers, but none to the configured wallet.
        return token_logs[0], "Transaction is not a USDT transfer to your payment wallet."

    return None, " | ".join(errors) or "Transaction was not found on the selected network."


def _receipt_usdt_transfer_by_hash(network: str, tx_hash: str, expected_wallet: str) -> tuple[dict | None, str]:
    """Read a transaction receipt by hash and parse USDT Transfer logs.

    The normal tokentx scan searches the bot payment wallet address, so a user who
    submits a TxHash sent to the wrong wallet can otherwise look like "not found".
    This receipt check lets us tell the user the real reason and ask for the
    correct TxHash instead of creating an admin-review item.
    """
    cfg = _token_cfg(network)
    params = {"module": "proxy", "action": "eth_getTransactionReceipt", "txhash": tx_hash}
    if cfg["api_key"]:
        params["apikey"] = str(cfg["api_key"])
    explorer_reason = ""
    try:
        payload = _http_get_json(f"{cfg['api_url']}?{urlencode(params)}")
        result = payload.get("result")
    except Exception as exc:
        payload = {}
        result = None
        explorer_reason = f"{cfg['label']} explorer API error: {exc}"
    if not result:
        msg = str(payload.get("message") or payload.get("result") or "").strip()
        low = msg.lower()
        if not explorer_reason:
            if "invalid api key" in low or "api key" in low:
                explorer_reason = f"{cfg['label']} explorer API key is missing or invalid"
            elif "rate limit" in low or "max rate" in low:
                explorer_reason = f"{cfg['label']} explorer rate limit reached. Try again shortly."
            else:
                explorer_reason = "Transaction was not found on the selected network."
        rpc_tx, rpc_reason = _receipt_usdt_transfer_by_hash_rpc(network, tx_hash, expected_wallet)
        if rpc_tx is not None:
            return rpc_tx, rpc_reason
        return None, _public_payment_error_text(rpc_reason or explorer_reason)
    if not isinstance(result, dict):
        rpc_tx, rpc_reason = _receipt_usdt_transfer_by_hash_rpc(network, tx_hash, expected_wallet)
        if rpc_tx is not None:
            return rpc_tx, rpc_reason
        return None, _public_payment_error_text(rpc_reason or "Transaction was not found on the selected network.")

    transfer_sig = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    wallet_lower = (expected_wallet or "").lower()
    token_logs: list[dict] = []
    for log in result.get("logs") or []:
        if not isinstance(log, dict):
            continue
        topics = log.get("topics") or []
        if not topics or str(topics[0]).lower() != transfer_sig:
            continue
        if str(log.get("address") or "").lower() != str(cfg["contract"]).lower():
            continue
        if len(topics) < 3:
            continue
        to_topic = str(topics[2] or "").lower()
        to_addr = "0x" + to_topic[-40:] if len(to_topic) >= 40 else ""
        data = str(log.get("data") or "0x0").strip()
        try:
            raw_value = int(data, 16)
        except Exception:
            raw_value = 0
        tx = {
            "hash": tx_hash.lower(),
            "contractAddress": str(cfg["contract"]).lower(),
            "to": to_addr,
            "value": str(raw_value),
            "network": network,
            "blockNumber": str(result.get("blockNumber") or ""),
        }
        token_logs.append(tx)

    if not token_logs:
        return None, "Transaction is not a USDT transfer on the selected network."

    for tx in token_logs:
        if str(tx.get("to") or "").lower() == wallet_lower:
            block_hex = str(tx.get("blockNumber") or "")
            latest = _latest_block_number(network)
            confirmations = 0
            try:
                block_no = int(block_hex, 16) if block_hex.startswith("0x") else int(block_hex or 0)
                if latest and block_no:
                    confirmations = max(0, latest - block_no + 1)
            except Exception:
                confirmations = 0
            tx["confirmations"] = str(confirmations)
            ts = _block_timestamp_from_number(network, block_hex)
            if ts:
                tx["timeStamp"] = str(ts)
            return tx, ""

    # There is a USDT transfer in this TxHash, but it was not sent to our payment wallet.
    return token_logs[0], "Transaction is not a USDT transfer to your payment wallet."


def _tx_confirmations_for_network(tx: dict, network: str, required_default: int = 0) -> int:
    """Return confirmations for explorer/RPC rows, matching the reference bot.

    Some Polygon explorer responses omit the `confirmations` field. Treating the
    missing value as 0 made valid Polygon payments look unconfirmed forever. If
    confirmations are absent, compute them from blockNumber and the latest chain
    block; if that also fails, allow the row through instead of blocking it.
    """
    try:
        raw = tx.get("confirmations")
        if raw not in (None, ""):
            return int(raw)
    except Exception:
        pass
    try:
        block_raw = tx.get("blockNumber")
        if block_raw not in (None, ""):
            block_no = _int_from_hex_or_dec(block_raw, 0)
            latest = _latest_block_number(network)
            if latest and block_no:
                return max(0, int(latest) - int(block_no) + 1)
    except Exception:
        pass
    try:
        return max(1, int(required_default or 1))
    except Exception:
        return 1


def verify_usdt_transfer(deposit: sqlite3.Row, tx_hash: str | None = None, manual: bool = False) -> tuple[bool, str, dict | None]:
    network = str(deposit["network"] or "bep20")
    cfg = _token_cfg(network)
    settings = get_marketplace_settings()
    expected = _dec(deposit["expected_usdt"])
    if manual:
        tolerance = _dec(settings.get("polygon_manual_tolerance_usdt") if network == "polygon" else settings.get("bep20_manual_tolerance_usdt"))
    else:
        tolerance = Decimal("0")
    pay_to = ""
    try:
        pay_to = str(deposit["pay_to"] or "").strip()
    except Exception:
        pay_to = ""
    verify_wallet = pay_to or str(cfg["wallet"])
    wallet = str(verify_wallet).lower()
    normalized_hash = normalize_tx_hash(tx_hash) if tx_hash else None

    min_ts = 0
    try:
        min_ts = int(datetime.fromisoformat(str(deposit["created_at"])).timestamp()) - 60
    except Exception:
        pass

    def _candidate_timestamp(tx: dict) -> int:
        """Fetch a block timestamp only after a transfer is otherwise promising.

        RPC log scans can return many wallet transfers. Calling eth_getBlockByNumber
        for every log makes Polygon checks feel slow and can push Telegram callback
        answers past their timeout. Explorer rows already include timeStamp; RPC rows
        get a timestamp lazily only when an amount/tx hash is a real candidate.
        """
        try:
            ts = int(tx.get("timeStamp") or 0)
        except Exception:
            ts = 0
        if ts or not min_ts:
            return ts
        block_no = tx.get("blockNumber")
        if block_no is None or block_no == "":
            return 0
        try:
            ts = _block_timestamp_from_number(network, block_no)
        except Exception:
            ts = 0
        if ts:
            tx["timeStamp"] = str(ts)
        return ts

    def _check_candidate_tx(tx: dict) -> tuple[bool, str, dict | None]:
        if str(tx.get("contractAddress") or "").lower() != str(cfg["contract"]):
            return False, "Transaction is not a USDT transfer on the selected network.", tx
        if str(tx.get("to") or "").lower() != wallet:
            return False, "Transaction is not a USDT transfer to your payment wallet.", tx
        confirmations = _tx_confirmations_for_network(tx, network, int(cfg["confirmations"]))
        tx["confirmations"] = str(confirmations)
        if confirmations < int(cfg["confirmations"]):
            return False, f"Transaction needs more confirmations ({confirmations}/{cfg['confirmations']}).", tx
        actual = _dec(tx.get("value")) / (Decimal(10) ** int(cfg["decimals"]))
        if abs(actual - expected) <= tolerance:
            ts = _candidate_timestamp(tx)
            if ts and min_ts and ts < min_ts:
                return False, "Transaction is older than this payment request.", tx
            tx["match_actual_usdt"] = str(actual)
            tx["match_expected_usdt"] = str(expected)
            tx["network"] = network
            return True, "verified", tx
        return False, f"Amount does not match. Received: {actual.normalize()} USDT.", tx

    # When the user supplies a TxHash, check the transaction receipt directly first.
    # The normal wallet scan can miss a just-paid hash when explorer account pages lag,
    # are rate-limited, or when the wallet has no recent token rows yet.
    receipt_reason = ""
    if normalized_hash:
        receipt_tx, receipt_reason = _receipt_usdt_transfer_by_hash(network, normalized_hash, wallet)
        if receipt_tx is not None:
            ok, reason, checked_tx = _check_candidate_tx(receipt_tx)
            if ok:
                return True, reason, checked_tx
            # Receipt errors are authoritative for a specific hash: wrong wallet,
            # wrong network/token, old request, pending confirmations, or amount mismatch.
            return False, reason, checked_tx

    txs, err = _scan_token_txs(network, verify_wallet, tx_hash=normalized_hash, min_ts=min_ts)
    if err:
        if normalized_hash and receipt_reason:
            return False, _public_payment_error_text(receipt_reason), None
        return False, _public_payment_error_text(err), None

    found_hash = False
    wrong_wallet = False
    wrong_token = False
    older_than_request = False
    amount_mismatches: list[str] = []
    confirmation_reason = ""

    for tx in txs:
        h = str(tx.get("hash") or "").lower()
        if normalized_hash and h != normalized_hash:
            continue
        if normalized_hash and h == normalized_hash:
            found_hash = True
        if str(tx.get("contractAddress") or "").lower() != str(cfg["contract"]):
            wrong_token = True
            continue
        if str(tx.get("to") or "").lower() != wallet:
            wrong_wallet = True
            continue
        confirmations = _tx_confirmations_for_network(tx, network, int(cfg["confirmations"]))
        tx["confirmations"] = str(confirmations)
        if confirmations < int(cfg["confirmations"]):
            confirmation_reason = f"Transaction needs more confirmations ({confirmations}/{cfg['confirmations']})."
            return False, confirmation_reason, tx
        actual = _dec(tx.get("value")) / (Decimal(10) ** int(cfg["decimals"]))
        if abs(actual - expected) <= tolerance:
            ts = _candidate_timestamp(tx)
            if ts and min_ts and ts < min_ts:
                older_than_request = True
                continue
            tx["match_actual_usdt"] = str(actual)
            tx["match_expected_usdt"] = str(expected)
            tx["network"] = network
            return True, "verified", tx
        amount_mismatches.append(str(actual.normalize()))

    if normalized_hash:
        if not found_hash:
            return False, receipt_reason or "Transaction was not found on the selected network.", None
        if wrong_token:
            return False, "Transaction is not a USDT transfer on the selected network.", None
        if wrong_wallet:
            return False, "Transaction is not a USDT transfer to your payment wallet.", None
        if older_than_request:
            return False, "Transaction is older than this payment request.", None
        if amount_mismatches:
            shown = ", ".join(dict.fromkeys(amount_mismatches[:3]))
            more = "…" if len(amount_mismatches) > 3 else ""
            return False, f"Amount does not match. Received: {shown}{more} USDT.", None
        if confirmation_reason:
            return False, confirmation_reason, None
        return False, receipt_reason or "Transaction was not found on the selected network.", None

    return False, "No matching incoming USDT transfer found yet.", None

def _binance_signed_json(path: str, params: dict[str, str | int], api_key: str, api_secret: str, base_url: str) -> dict:
    query = urlencode(params)
    sig = hmac.new(api_secret.encode(), query.encode(), hashlib.sha256).hexdigest()
    url = f"{base_url}{path}?{query}&signature={sig}"
    return _http_get_json(url, headers={"X-MBX-APIKEY": api_key, "User-Agent": APP_NAME})


def verify_binance_deposit(deposit: sqlite3.Row, manual: bool = False) -> tuple[bool, str, dict | None]:
    settings = get_marketplace_settings()
    api_key = str(settings["binance_api_key"])
    api_secret = str(settings["binance_api_secret"])
    base_url = str(settings["binance_api_base_url"])
    if not api_key or not api_secret:
        return False, "Binance API key/secret is not configured", None
    expected = _dec(deposit["expected_usdt"])
    tolerance = _dec(settings.get("binance_manual_tolerance_usdt"), DEFAULT_BINANCE_MANUAL_TOLERANCE_USDT) if manual else Decimal("0")
    created_ms = max(0, int(datetime.fromisoformat(str(deposit["created_at"])).timestamp() * 1000) - 30_000)
    now_ms = int(time.time() * 1000)
    params = {
        "timestamp": now_ms,
        "recvWindow": int(settings["binance_recv_window_ms"]),
        "startTime": created_ms,
        "endTime": now_ms,
        "limit": 100,
    }
    try:
        payload = _binance_signed_json("/sapi/v1/pay/transactions", params, api_key, api_secret, base_url)
    except Exception as exc:
        return False, f"Binance Pay API error: {exc}", None
    rows = payload.get("data") or payload.get("rows") or []
    if isinstance(rows, dict):
        rows = rows.get("data") or rows.get("rows") or []
    if not isinstance(rows, list):
        return False, "Binance Pay history returned an unexpected response", payload
    used = used_binance_tx_ids()
    for tx in sorted(rows, key=lambda x: int(x.get("transactionTime") or 0)):
        tx_id = str(tx.get("transactionId") or tx.get("tranId") or "").strip()
        if not tx_id or tx_id in used:
            continue
        order_type = str(tx.get("orderType") or "").upper().strip()
        if order_type and order_type not in {"C2C", "PAY", "C2C_HOLDING"}:
            continue
        amounts: list[Decimal] = []
        for key in ("amount", "transactionAmount", "orderAmount"):
            if tx.get(key) is not None:
                amounts.append(_dec(tx.get(key)))
        for detail in tx.get("fundsDetail") or []:
            if isinstance(detail, dict) and str(detail.get("currency") or detail.get("asset") or "").upper() == "USDT":
                amounts.append(_dec(detail.get("amount") or detail.get("quantity")))
        for amount in amounts:
            if abs(amount - expected) <= tolerance:
                tx["match_actual_usdt"] = str(amount)
                tx["match_expected_usdt"] = str(expected)
                return True, "verified", tx
    return False, "No matching incoming USDT Binance Pay transaction found", None


def used_binance_tx_ids() -> set[str]:
    with get_conn() as conn:
        rows = conn.execute("SELECT binance_tx_id FROM payment_deposits WHERE binance_tx_id IS NOT NULL AND status IN ('confirmed','credited')").fetchall()
    return {str(r["binance_tx_id"]) for r in rows if r["binance_tx_id"]}


def used_tx_hash_keys() -> set[str]:
    # Permanent single-use registry. The payment_deposits fallback keeps older
    # databases protected even before migration backfill completes.
    with get_conn() as conn:
        registry_rows = conn.execute("SELECT tx_hash_key FROM payment_tx_hashes WHERE tx_hash_key IS NOT NULL").fetchall()
        deposit_rows = conn.execute("SELECT tx_hash_key FROM payment_deposits WHERE tx_hash_key IS NOT NULL").fetchall()
    return {str(r["tx_hash_key"]) for r in [*registry_rows, *deposit_rows] if r["tx_hash_key"]}



# ───────────────────── Bot1-style wallet top-up verification ─────────────────────
# This async verifier mirrors the working Bot1.zip USDT logic: legacy explorer →
# Etherscan V2 → direct RPC logs for auto checks, and direct RPC receipt parsing
# for submitted TxHash/manual checks.  It is intentionally separate from the old
# synchronous scanner so wallet top-ups do not get stuck behind slow thread calls.

BOT1_TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
BOT1_ETHERSCAN_V2_BASE = "https://api.etherscan.io/v2/api"
BOT1_USDT_QUANT = Decimal("0.001")
BOT1_USDT_LEGACY_QUANT = Decimal("0.000001")


@dataclass(frozen=True)
class Bot1UsdtNetworkConfig:
    key: str
    display_name: str
    chainid: str
    contract: str
    decimals: int
    legacy_base_url: str
    legacy_api_key: str
    rpc_urls: list[str]
    rpc_block_chunk_size: int
    required_confirmations: int
    estimated_block_time_seconds: float


@dataclass
class Bot1UsdtCheckResult:
    found: bool = False
    source: str | None = None
    tx: dict | None = None
    errors: list[str] = field(default_factory=list)

    def short_error_text(self) -> str:
        if not self.errors:
            return "No matching USDT transfer found yet."
        cleaned: list[str] = []
        for err in self.errors:
            value = str(err or "").strip()
            if value and value not in cleaned:
                cleaned.append(value)
        return " | ".join(cleaned[-3:])[:700]

    def public_error_text(self) -> str:
        return _public_payment_error_text(self.errors)


def _bot1_network_config(network: str | None = None) -> Bot1UsdtNetworkConfig:
    key = normalize_payment_network(network)
    settings = get_marketplace_settings()
    if key == "polygon":
        return Bot1UsdtNetworkConfig(
            key="polygon",
            display_name="USDT (POLYGON)",
            chainid="137",
            contract="0xc2132D05D31c914a87C6611C10748AEb04B58e8F",
            decimals=6,
            legacy_base_url="https://api.polygonscan.com/api",
            legacy_api_key=str(settings.get("polygonscan_api_key") or POLYGONSCAN_API_KEY or "").strip(),
            rpc_urls=_rpc_urls("polygon"),
            rpc_block_chunk_size=max(10, int(POLYGON_RPC_BLOCK_CHUNK_SIZE or 500)),
            required_confirmations=max(1, int(settings.get("polygon_required_confirmations") or POLYGON_REQUIRED_CONFIRMATIONS or 20)),
            estimated_block_time_seconds=2.0,
        )
    return Bot1UsdtNetworkConfig(
        key="bep20",
        display_name="USDT (BEP20)",
        chainid="56",
        contract="0x55d398326f99059fF775485246999027B3197955",
        decimals=18,
        legacy_base_url="https://api.bscscan.com/api",
        legacy_api_key=str(settings.get("bscscan_api_key") or BSCSCAN_API_KEY or "").strip(),
        rpc_urls=_rpc_urls("bep20"),
        rpc_block_chunk_size=max(10, int(BEP20_RPC_BLOCK_CHUNK_SIZE or 450)),
        required_confirmations=max(1, int(settings.get("bep20_required_confirmations") or BEP20_REQUIRED_CONFIRMATIONS or 3)),
        estimated_block_time_seconds=3.0,
    )


def _bot1_to_decimal(value: float | str | Decimal) -> Decimal | None:
    try:
        return Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        return None


def _bot1_normalize_tx_hash(txn_hash: str | None) -> str:
    raw = str(txn_hash or "").strip()
    match = re.search(r"0x[a-fA-F0-9]{64}", raw)
    return match.group(0).lower() if match else ""


def _bot1_expected_decimal(expected: Decimal) -> Decimal:
    if expected == expected.quantize(BOT1_USDT_QUANT):
        return expected.quantize(BOT1_USDT_QUANT)
    return expected.quantize(BOT1_USDT_LEGACY_QUANT)


def _bot1_raw_token_value_to_decimal(raw_value: str, decimals: int) -> Decimal | None:
    try:
        text = str(raw_value or "0x0")
        raw_int = int(text, 16) if text.startswith("0x") else int(text)
        return Decimal(raw_int) / (Decimal(10) ** int(decimals))
    except Exception:
        return None


def _bot1_parse_int(value) -> int | None:
    try:
        if isinstance(value, str) and value.startswith("0x"):
            return int(value, 16)
        return int(value)
    except Exception:
        return None


def _bot1_address_to_topic(address: str) -> str | None:
    addr = (address or "").lower().replace("0x", "")
    if len(addr) != 40 or any(c not in "0123456789abcdef" for c in addr):
        return None
    return "0x" + ("0" * 24) + addr


def _bot1_safe_rpc_name(rpc_url: str) -> str:
    return str(rpc_url or "").replace("https://", "").replace("http://", "").split("/")[0]


def _bot1_amount_match_details(actual: Decimal, expected: Decimal) -> dict | None:
    try:
        expected_q = _bot1_expected_decimal(expected)
        if actual != expected_q:
            return None
        diff = abs(actual - expected_q).quantize(BOT1_USDT_LEGACY_QUANT)
    except Exception:
        return None
    return {"actual": actual, "expected": expected_q, "difference": diff, "type": "exact"}


def _bot1_amount_match_details_with_tolerance(actual: Decimal, expected: Decimal, tolerance: Decimal) -> dict | None:
    try:
        expected_q = _bot1_expected_decimal(expected)
        diff = abs(actual - expected_q).quantize(BOT1_USDT_LEGACY_QUANT)
        if diff > tolerance:
            return None
    except Exception:
        return None
    return {"actual": actual, "expected": expected_q, "difference": diff, "type": "exact" if diff == 0 else "manual_tolerance"}


def _bot1_api_tx_has_required_confirmations(cfg: Bot1UsdtNetworkConfig, tx: dict) -> bool:
    confirmations = _bot1_parse_int(tx.get("confirmations"))
    if confirmations is None:
        # Bot1 behavior: explorer token-transfer APIs normally include this; if
        # missing, let RPC fallback/receipt checks enforce confirmations.
        return True
    return confirmations >= cfg.required_confirmations


def _bot1_etherscan_v2_api_key() -> str:
    """Use the admin setting first, then the environment variable."""
    return _setting_raw("etherscan_api_key", ETHERSCAN_API_KEY).strip()


async def _bot1_http_get_json(url: str, params: dict[str, Any]) -> dict:
    if aiohttp is None:
        return await asyncio.to_thread(_http_get_json, f"{url}?{urlencode(params)}")
    timeout = aiohttp.ClientTimeout(total=15)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(url, params=params) as resp:
            if resp.status >= 400:
                text = await resp.text()
                raise RuntimeError(f"HTTP {resp.status}: {text[:200]}")
            return await resp.json(content_type=None)


async def _bot1_etherscan_v2_get(cfg: Bot1UsdtNetworkConfig, params: dict[str, Any]) -> dict:
    key = _bot1_etherscan_v2_api_key()
    if not key:
        raise RuntimeError("ETHERSCAN_API_KEY missing")
    request_params = dict(params)
    request_params["chainid"] = cfg.chainid
    request_params["apikey"] = key
    return await _bot1_http_get_json(BOT1_ETHERSCAN_V2_BASE, params=request_params)


async def _bot1_rpc_call(rpc_url: str, method: str, params: list[Any]) -> Any:
    if aiohttp is None:
        return await asyncio.to_thread(_rpc_call_url, rpc_url, method, params, 20)
    payload = {"jsonrpc": "2.0", "id": int(time.time() * 1000), "method": method, "params": params}
    timeout = aiohttp.ClientTimeout(total=20)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.post(rpc_url, json=payload) as resp:
            if resp.status >= 400:
                text = await resp.text()
                raise RuntimeError(f"HTTP {resp.status}: {text[:200]}")
            data = await resp.json(content_type=None)
    if "error" in data:
        raise RuntimeError(data["error"])
    return data.get("result")


def _bot1_match_api_transfer(cfg: Bot1UsdtNetworkConfig, transfers: list[dict], expected: Decimal, lookback: int, wallet_address: str) -> dict | None:
    cutoff = int(time.time()) - int(lookback)
    wallet = str(wallet_address or "").lower()
    contract = cfg.contract.lower()
    for tx in transfers:
        try:
            if int(tx.get("timeStamp", "0") or 0) < cutoff:
                continue
        except ValueError:
            continue
        if str(tx.get("to", "")).lower() != wallet:
            continue
        if str(tx.get("contractAddress", cfg.contract)).lower() != contract:
            continue
        try:
            decimals = int(tx.get("tokenDecimal", str(cfg.decimals)) or cfg.decimals)
            value = Decimal(str(tx.get("value", "0"))) / (Decimal(10) ** decimals)
        except (InvalidOperation, ValueError):
            continue
        match = _bot1_amount_match_details(value, expected)
        if match is not None:
            if not _bot1_api_tx_has_required_confirmations(cfg, tx):
                logger.info(
                    "Matching %s transfer found but waiting for confirmations. hash=%s confirmations=%s required=%s",
                    cfg.display_name, tx.get("hash") or tx.get("txhash"), tx.get("confirmations"), cfg.required_confirmations,
                )
                continue
            matched_tx = dict(tx)
            matched_tx.update({
                "network": cfg.key,
                "match_actual_usdt": str(match["actual"]),
                "match_expected_usdt": str(match["expected"]),
                "match_difference_usdt": str(match["difference"]),
                "match_type": match["type"],
            })
            return matched_tx
    return None


async def _bot1_details_via_legacy_explorer(cfg: Bot1UsdtNetworkConfig, expected: Decimal, lookback: int, wallet_address: str) -> tuple[dict | None, str | None]:
    params = {
        "module": "account",
        "action": "tokentx",
        "contractaddress": cfg.contract,
        "address": wallet_address,
        "sort": "desc",
        "offset": "100",
        "page": "1",
    }
    if cfg.legacy_api_key:
        params["apikey"] = cfg.legacy_api_key
    try:
        data = await _bot1_http_get_json(cfg.legacy_base_url, params=params)
    except Exception as exc:
        error = f"Legacy {cfg.display_name} explorer failed: {exc}"
        logger.warning(error)
        return None, error
    if data.get("status") != "1":
        msg = str(data.get("message") or "NOTOK")
        res = str(data.get("result") or "")[:160]
        error = f"Legacy {cfg.display_name} explorer returned {msg}: {res}"
        logger.warning(error)
        return None, error
    tx = _bot1_match_api_transfer(cfg, data.get("result", []), expected, lookback, wallet_address)
    if tx:
        tx["source"] = f"legacy_{cfg.key}_explorer"
        tx["network"] = cfg.key
    return tx, None


async def _bot1_details_via_etherscan_v2(cfg: Bot1UsdtNetworkConfig, expected: Decimal, lookback: int, wallet_address: str) -> tuple[dict | None, str | None]:
    params = {
        "module": "account",
        "action": "tokentx",
        "contractaddress": cfg.contract,
        "address": wallet_address,
        "sort": "desc",
        "offset": "100",
        "page": "1",
    }
    try:
        data = await _bot1_etherscan_v2_get(cfg, params)
    except Exception as exc:
        error = f"Etherscan V2 {cfg.display_name} failed: {exc}"
        logger.warning(error)
        return None, error
    if data.get("status") != "1":
        msg = str(data.get("message") or "NOTOK")
        res = str(data.get("result") or "")[:160]
        error = f"Etherscan V2 {cfg.display_name} returned {msg}: {res}"
        logger.warning(error)
        return None, error
    tx = _bot1_match_api_transfer(cfg, data.get("result", []), expected, lookback, wallet_address)
    if tx:
        tx["source"] = f"etherscan_v2:{cfg.key}"
        tx["network"] = cfg.key
    return tx, None


async def _bot1_scan_rpc_logs_in_chunks(
    cfg: Bot1UsdtNetworkConfig,
    rpc_url: str,
    from_block: int,
    to_block: int,
    wallet_topic: str,
    wallet_address: str,
    expected: Decimal,
    latest_block: int,
) -> dict | None:
    end = to_block
    while end >= from_block:
        start = max(from_block, end - cfg.rpc_block_chunk_size + 1)
        logs = await _bot1_rpc_call(rpc_url, "eth_getLogs", [{
            "address": cfg.contract,
            "fromBlock": hex(start),
            "toBlock": hex(end),
            "topics": [BOT1_TRANSFER_TOPIC, None, wallet_topic],
        }])
        if not isinstance(logs, list):
            raise RuntimeError(f"unexpected log payload: {logs!r}")
        for log in reversed(logs):
            raw_value = log.get("data", "0x0")
            value = _bot1_raw_token_value_to_decimal(raw_value, cfg.decimals)
            match = _bot1_amount_match_details(value, expected) if value is not None else None
            if match is not None:
                log_block = _bot1_parse_int(log.get("blockNumber"))
                confirmations = (latest_block - log_block + 1) if log_block is not None else 0
                if confirmations < cfg.required_confirmations:
                    logger.info(
                        "Matching %s transfer found but waiting for confirmations. tx=%s confirmations=%s required=%s",
                        cfg.display_name, log.get("transactionHash"), confirmations, cfg.required_confirmations,
                    )
                    continue
                token_decimals = Decimal(10) ** cfg.decimals
                return {
                    "hash": log.get("transactionHash"),
                    "txhash": log.get("transactionHash"),
                    "to": wallet_address,
                    "value": str(int(Decimal(value) * token_decimals)),
                    "value_usdt": str(value),
                    "tokenDecimal": str(cfg.decimals),
                    "contractAddress": cfg.contract,
                    "network": cfg.key,
                    "match_actual_usdt": str(match["actual"]),
                    "match_expected_usdt": str(match["expected"]),
                    "match_difference_usdt": str(match["difference"]),
                    "match_type": match["type"],
                    "source": f"{cfg.key}_rpc_logs:{_bot1_safe_rpc_name(rpc_url)}",
                    "blockNumber": log.get("blockNumber"),
                    "confirmations": confirmations,
                }
        end = start - 1
    return None


async def _bot1_details_via_rpc_logs(cfg: Bot1UsdtNetworkConfig, expected: Decimal, lookback: int, wallet_address: str) -> tuple[dict | None, list[str]]:
    wallet_topic = _bot1_address_to_topic(wallet_address)
    if not wallet_topic:
        return None, [f"Invalid or missing {cfg.display_name} wallet address in Payment Settings"]
    errors: list[str] = []
    for rpc_url in cfg.rpc_urls:
        try:
            latest_hex = await _bot1_rpc_call(rpc_url, "eth_blockNumber", [])
            latest_block = int(latest_hex, 16)
        except Exception as exc:
            errors.append(f"{_bot1_safe_rpc_name(rpc_url)} blockNumber failed: {exc}")
            continue
        block_lookback = max(
            int(lookback / max(0.5, cfg.estimated_block_time_seconds)) + 300,
            cfg.rpc_block_chunk_size * 2,
        )
        from_block = max(0, latest_block - block_lookback)
        try:
            tx = await _bot1_scan_rpc_logs_in_chunks(
                cfg=cfg,
                rpc_url=rpc_url,
                from_block=from_block,
                to_block=latest_block,
                wallet_topic=wallet_topic,
                wallet_address=wallet_address,
                expected=expected,
                latest_block=latest_block,
            )
            if tx:
                return tx, errors
        except Exception as exc:
            errors.append(f"{_bot1_safe_rpc_name(rpc_url)} getLogs failed: {exc}")
            continue
    return None, errors


async def bot1_check_usdt_received_detailed(
    expected_amount: float | str | Decimal,
    lookback: int,
    *,
    wallet_address: str | None = None,
    network: str | None = None,
) -> Bot1UsdtCheckResult:
    cfg = _bot1_network_config(network)
    result = Bot1UsdtCheckResult()
    expected = _bot1_to_decimal(expected_amount)
    if expected is None:
        result.errors.append(f"Invalid expected amount: {expected_amount!r}")
        return result
    wallet_address = (wallet_address or "").strip()
    if not _bot1_address_to_topic(wallet_address):
        result.errors.append(f"Invalid or missing {cfg.display_name} wallet address in Payment Settings")
        return result

    # Priority 1: Etherscan API V2 multichain endpoint. It uses one API key with
    # chainid=56 for BNB Smart Chain and chainid=137 for Polygon.
    if _bot1_etherscan_v2_api_key():
        tx, error = await _bot1_details_via_etherscan_v2(cfg, expected, lookback, wallet_address)
        if tx:
            result.found = True
            result.source = tx.get("source", "etherscan_v2")
            result.tx = tx
            return result
        if error:
            result.errors.append(error)
    else:
        result.errors.append("ETHERSCAN_API_KEY missing; skipping Etherscan V2")

    # Priority 2: legacy chain-specific explorer API.
    tx, error = await _bot1_details_via_legacy_explorer(cfg, expected, lookback, wallet_address)
    if tx:
        result.found = True
        result.source = tx.get("source", f"legacy_{cfg.key}_explorer")
        result.tx = tx
        return result
    if error:
        result.errors.append(error)

    # Priority 3: RPC log fallback.
    tx, rpc_errors = await _bot1_details_via_rpc_logs(cfg, expected, lookback, wallet_address)
    if tx:
        result.found = True
        result.source = tx.get("source", f"{cfg.key}_rpc_logs")
        result.tx = tx
        return result
    result.errors.extend(rpc_errors)
    logger.info(
        "Bot1-style USDT auto-check not found. network=%s expected=%s wallet=%s errors=%s",
        cfg.key, expected, wallet_address, result.short_error_text(),
    )
    return result


async def _bot1_receipt_block_timestamp(rpc_url: str, block_number) -> int | None:
    if not block_number:
        return None
    try:
        tag = str(block_number) if str(block_number).startswith("0x") else hex(int(str(block_number)))
        source = str(rpc_url or "")
        if source.startswith("etherscan_v2:"):
            network = source.split(":", 1)[1] or "bep20"
            cfg = _bot1_network_config(network)
            payload = await _bot1_etherscan_v2_get(
                cfg,
                {"module": "proxy", "action": "eth_getBlockByNumber", "tag": tag, "boolean": "false"},
            )
            block = payload.get("result")
        else:
            block = await _bot1_rpc_call(rpc_url, "eth_getBlockByNumber", [tag, False])
        if not isinstance(block, dict):
            return None
        return _bot1_parse_int(block.get("timestamp"))
    except Exception:
        return None


async def _bot1_match_receipt_transfer(
    cfg: Bot1UsdtNetworkConfig,
    receipt: dict,
    expected: Decimal,
    tolerance: Decimal,
    wallet_address: str,
    wallet_topic: str,
    latest_block: int,
    rpc_url: str,
    min_timestamp: float | int | None = None,
) -> tuple[dict | None, str | None]:
    status = str(receipt.get("status") or "").lower()
    if status and status not in {"0x1", "1"}:
        return None, "Transaction exists but failed on-chain"
    block_number = _bot1_parse_int(receipt.get("blockNumber"))
    if block_number is None:
        return None, "Transaction exists but is not mined yet"
    confirmations = latest_block - block_number + 1
    if confirmations < cfg.required_confirmations:
        return None, f"Transaction found but has {confirmations} confirmation(s); requires {cfg.required_confirmations}"
    tx_timestamp = await _bot1_receipt_block_timestamp(rpc_url, receipt.get("blockNumber"))
    if min_timestamp is not None:
        try:
            min_ts = float(min_timestamp)
        except (TypeError, ValueError):
            min_ts = None
        if min_ts is not None:
            if tx_timestamp is None:
                return None, "Could not verify transaction time"
            if tx_timestamp < min_ts:
                return None, "Transaction is older than this payment request"

    contract = cfg.contract.lower()
    actual_values: list[str] = []
    for log in receipt.get("logs") or []:
        if bool(log.get("removed")):
            continue
        if str(log.get("address") or "").lower() != contract:
            continue
        topics = [str(topic or "").lower() for topic in (log.get("topics") or [])]
        if len(topics) < 3 or topics[0] != BOT1_TRANSFER_TOPIC.lower() or topics[2] != wallet_topic.lower():
            continue
        value = _bot1_raw_token_value_to_decimal(str(log.get("data") or "0x0"), cfg.decimals)
        if value is None:
            continue
        actual_values.append(str(value))
        match = _bot1_amount_match_details_with_tolerance(value, expected, tolerance)
        if match is None:
            continue
        token_decimals = Decimal(10) ** cfg.decimals
        return {
            "hash": receipt.get("transactionHash"),
            "txhash": receipt.get("transactionHash"),
            "transactionHash": receipt.get("transactionHash"),
            "to": wallet_address,
            "value": str(int(Decimal(value) * token_decimals)),
            "value_usdt": str(value),
            "tokenDecimal": str(cfg.decimals),
            "contractAddress": cfg.contract,
            "network": cfg.key,
            "match_actual_usdt": str(match["actual"]),
            "match_expected_usdt": str(match["expected"]),
            "match_difference_usdt": str(match["difference"]),
            "match_type": match["type"],
            "source": f"{cfg.key}_rpc_receipt:{_bot1_safe_rpc_name(rpc_url)}",
            "blockNumber": receipt.get("blockNumber"),
            "confirmations": confirmations,
            "timeStamp": str(int(tx_timestamp)) if tx_timestamp is not None else "",
        }, None
    if actual_values:
        return None, f"Transaction found, but amount does not match. Received: {', '.join(actual_values[:3])} USDT"
    return None, f"Transaction found, but it is not a {cfg.display_name} transfer to your payment wallet"


async def _bot1_receipt_via_etherscan_v2(
    cfg: Bot1UsdtNetworkConfig,
    normalized_hash: str,
    expected: Decimal,
    tolerance: Decimal,
    wallet_address: str,
    wallet_topic: str,
    min_timestamp: float | int | None = None,
) -> tuple[dict | None, str | None]:
    """Verify a submitted TxHash through Etherscan V2 before RPC fallback."""
    try:
        latest_payload = await _bot1_etherscan_v2_get(cfg, {"module": "proxy", "action": "eth_blockNumber"})
        latest_result = str(latest_payload.get("result") or "").strip()
        latest_block = int(latest_result, 16) if latest_result.startswith("0x") else int(latest_result)
    except Exception as exc:
        return None, f"Etherscan V2 {cfg.display_name} blockNumber failed: {exc}"

    try:
        receipt_payload = await _bot1_etherscan_v2_get(
            cfg,
            {"module": "proxy", "action": "eth_getTransactionReceipt", "txhash": normalized_hash},
        )
    except Exception as exc:
        return None, f"Etherscan V2 {cfg.display_name} receipt lookup failed: {exc}"

    if receipt_payload.get("error"):
        return None, f"Etherscan V2 {cfg.display_name} receipt lookup failed: {receipt_payload.get('error')}"
    receipt = receipt_payload.get("result")
    if not receipt:
        msg = str(receipt_payload.get("message") or "").strip()
        return None, f"Etherscan V2 did not find this tx on {cfg.display_name}" + (f": {msg}" if msg else "")
    if not isinstance(receipt, dict):
        return None, f"Etherscan V2 {cfg.display_name} returned unexpected receipt payload"

    return await _bot1_match_receipt_transfer(
        cfg=cfg,
        receipt=receipt,
        expected=expected,
        tolerance=tolerance,
        wallet_address=wallet_address,
        wallet_topic=wallet_topic,
        latest_block=latest_block,
        rpc_url=f"etherscan_v2:{cfg.key}",
        min_timestamp=min_timestamp,
    )


async def bot1_verify_usdt_tx_hash_detailed(
    txn_hash: str,
    expected_amount: float | str | Decimal,
    *,
    wallet_address: str | None = None,
    network: str | None = None,
    min_timestamp: float | int | None = None,
    amount_tolerance: float | str | Decimal = Decimal("0.01"),
) -> Bot1UsdtCheckResult:
    cfg = _bot1_network_config(network)
    result = Bot1UsdtCheckResult()
    normalized_hash = _bot1_normalize_tx_hash(txn_hash)
    if not normalized_hash:
        result.errors.append("Invalid transaction hash format")
        return result
    expected = _bot1_to_decimal(expected_amount)
    if expected is None:
        result.errors.append(f"Invalid expected amount: {expected_amount!r}")
        return result
    tolerance = _bot1_to_decimal(amount_tolerance) or Decimal("0")
    if tolerance < 0:
        tolerance = Decimal("0")
    wallet_address = (wallet_address or "").strip()
    wallet_topic = _bot1_address_to_topic(wallet_address)
    if not wallet_topic:
        result.errors.append(f"Invalid or missing {cfg.display_name} wallet address in Payment Settings")
        return result

    # Priority 1 for manual TxHash verification: Etherscan API V2 receipt lookup.
    if _bot1_etherscan_v2_api_key():
        tx, error = await _bot1_receipt_via_etherscan_v2(
            cfg=cfg,
            normalized_hash=normalized_hash,
            expected=expected,
            tolerance=tolerance,
            wallet_address=wallet_address,
            wallet_topic=wallet_topic,
            min_timestamp=min_timestamp,
        )
        if tx:
            tx["source"] = f"etherscan_v2_receipt:{cfg.key}"
            result.found = True
            result.source = tx.get("source", "etherscan_v2_receipt")
            result.tx = tx
            return result
        if error:
            result.errors.append(error)
    else:
        result.errors.append("ETHERSCAN_API_KEY missing; skipping Etherscan V2 receipt lookup")

    # Priority 2: direct RPC receipt fallback.
    for rpc_url in cfg.rpc_urls:
        try:
            latest_hex = await _bot1_rpc_call(rpc_url, "eth_blockNumber", [])
            latest_block = int(latest_hex, 16)
            receipt = await _bot1_rpc_call(rpc_url, "eth_getTransactionReceipt", [normalized_hash])
        except Exception as exc:
            result.errors.append(f"{_bot1_safe_rpc_name(rpc_url)} receipt lookup failed: {exc}")
            continue
        if not receipt:
            result.errors.append(f"{_bot1_safe_rpc_name(rpc_url)} did not find this tx on {cfg.display_name}")
            continue
        tx, error = await _bot1_match_receipt_transfer(
            cfg=cfg,
            receipt=receipt,
            expected=expected,
            tolerance=tolerance,
            wallet_address=wallet_address,
            wallet_topic=wallet_topic,
            latest_block=latest_block,
            rpc_url=rpc_url,
            min_timestamp=min_timestamp,
        )
        if tx:
            result.found = True
            result.source = tx.get("source", f"{cfg.key}_rpc_receipt")
            result.tx = tx
            return result
        if error:
            result.errors.append(error)
    logger.info(
        "Bot1-style USDT tx-hash check not verified. network=%s hash=%s expected=%s wallet=%s errors=%s",
        cfg.key, normalized_hash, expected, wallet_address, result.short_error_text(),
    )
    return result


async def verify_usdt_transfer_bot1_async(deposit: sqlite3.Row, tx_hash: str | None = None, manual: bool = False) -> tuple[bool, str, dict | None]:
    network = normalize_payment_network(str(deposit["network"] or "bep20"))
    settings = get_marketplace_settings()
    expected = _dec(deposit["expected_usdt"])
    pay_to = str(deposit["pay_to"] or "").strip()
    cfg = _bot1_network_config(network)
    verify_wallet = pay_to or (str(settings.get("polygon_wallet_address") or "").strip() if network == "polygon" else str(settings.get("bep20_wallet_address") or "").strip())
    if not verify_wallet:
        return False, f"Invalid or missing {cfg.display_name} wallet address in Payment Settings", None

    min_ts = None
    try:
        min_ts = int(datetime.fromisoformat(str(deposit["created_at"])).timestamp()) - 60
    except Exception:
        pass

    if tx_hash:
        tolerance = Decimal("0")
        if manual:
            tolerance = _dec(settings.get("polygon_manual_tolerance_usdt") if network == "polygon" else settings.get("bep20_manual_tolerance_usdt"))
        result = await bot1_verify_usdt_tx_hash_detailed(
            tx_hash,
            expected,
            wallet_address=verify_wallet,
            network=network,
            min_timestamp=min_ts,
            amount_tolerance=tolerance,
        )
    else:
        timeout_minutes = int(settings.get("payment_timeout_minutes") or PAYMENT_TIMEOUT_MINUTES or 30)
        lookback = max(3600, timeout_minutes * 60 + 600)
        result = await bot1_check_usdt_received_detailed(expected, lookback, wallet_address=verify_wallet, network=network)

    if result.found:
        tx = result.tx or {}
        tx["network"] = network
        return True, "verified", tx
    return False, result.public_error_text(), None


async def verify_and_credit_deposit_bot1_async(ref_id: str, tx_hash: str | None = None, manual: bool = False, source: str = "auto") -> tuple[bool, str]:
    dep = get_deposit(ref_id)
    if not dep:
        return False, "Deposit not found"
    if dep["credited_at"]:
        return False, "Deposit already credited"
    method = str(dep["method"] or "").lower()
    network = normalize_payment_network(str(dep["network"] or method))
    if method == "binance" or network == "binance":
        return await asyncio.to_thread(verify_and_credit_deposit, ref_id, tx_hash, manual, source)

    pending_tx_key = None
    normalized_hash = None
    if tx_hash:
        normalized_hash = normalize_tx_hash(tx_hash)
        if not re.fullmatch(r"0x[a-fA-F0-9]{64}", normalized_hash):
            log_payment_check(ref_id, int(dep["chat_id"]), method, "failed", "Invalid transaction hash format", tx_hash)
            return False, "Invalid transaction hash format"
        allow_existing_for_this_ref = normalize_tx_hash(dep["tx_hash"]) == normalized_hash
        reserved, key, reserve_reason = reserve_tx_hash(
            network=network,
            tx_hash=normalized_hash,
            ref_id=ref_id,
            chat_id=int(dep["chat_id"]),
            source=source,
            status="manual_submitted" if manual else "submitted",
            allow_existing_for_ref=allow_existing_for_this_ref,
        )
        pending_tx_key = key
        if not reserved:
            log_payment_check(ref_id, int(dep["chat_id"]), method, "failed", reserve_reason or "Duplicate transaction hash", tx_hash)
            return False, reserve_reason or "This transaction hash has already been used."

    ok, reason, tx = await verify_usdt_transfer_bot1_async(dep, tx_hash=normalized_hash, manual=manual)
    if normalized_hash and tx:
        tx["hash"] = normalized_hash
    log_payment_check(ref_id, int(dep["chat_id"]), method, "verified" if ok else "failed", reason, tx_hash, tx)

    if not ok:
        with get_conn() as conn:
            if manual:
                if source == "manual_tx_hash":
                    conn.execute(
                        """
                        UPDATE payment_deposits
                        SET tx_hash = COALESCE(?, tx_hash), tx_hash_key = COALESCE(?, tx_hash_key),
                            manual_check_result = 'failed', manual_note = ?
                        WHERE ref_id = ? AND credited_at IS NULL AND status = 'waiting'
                        """,
                        (normalized_hash or tx_hash, pending_tx_key, reason[:500], ref_id),
                    )
                else:
                    conn.execute(
                        """
                        UPDATE payment_deposits
                        SET status = 'manual_pending', tx_hash = COALESCE(?, tx_hash), tx_hash_key = COALESCE(?, tx_hash_key), manual_check_result = 'failed', manual_note = ?
                        WHERE ref_id = ? AND credited_at IS NULL AND status IN ('waiting','manual_pending')
                        """,
                        (normalized_hash or tx_hash, pending_tx_key, reason[:500], ref_id),
                    )
            else:
                conn.execute(
                    "UPDATE payment_deposits SET tx_hash = COALESCE(?, tx_hash), manual_note = ? WHERE ref_id = ? AND credited_at IS NULL",
                    (normalized_hash or tx_hash, reason[:500], ref_id),
                )
        return False, reason
    return credit_deposit_if_confirmed(ref_id, tx, source)


def credit_deposit_if_confirmed(ref_id: str, verified_tx: dict | None, source: str) -> tuple[bool, str]:
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        dep = conn.execute("SELECT * FROM payment_deposits WHERE ref_id = ?", (ref_id,)).fetchone()
        if not dep:
            conn.rollback()
            return False, "Deposit not found"
        if dep["credited_at"]:
            conn.rollback()
            return False, "Deposit already credited"
        network = normalize_payment_network(str(dep["network"] or dep["method"]))
        tx_hash = normalize_tx_hash(str((verified_tx or {}).get("hash") or dep["tx_hash"] or "").strip()) or None
        tx_key = tx_hash_key(network, tx_hash) if tx_hash else None
        binance_tx_id = str((verified_tx or {}).get("transactionId") or (verified_tx or {}).get("tranId") or dep["binance_tx_id"] or "").strip() or None
        if tx_key and tx_hash:
            reserved, tx_key, reserve_reason = _reserve_tx_hash_on_conn(
                conn,
                network=network,
                tx_hash=tx_hash,
                ref_id=ref_id,
                chat_id=int(dep["chat_id"]),
                source=source,
                status="credited",
                raw=verified_tx,
                allow_existing_for_ref=True,
            )
            if not reserved:
                conn.rollback()
                return False, reserve_reason or "Duplicate transaction hash"
            dup = conn.execute("SELECT ref_id FROM payment_deposits WHERE tx_hash_key = ? AND ref_id != ?", (tx_key, ref_id)).fetchone()
            if dup:
                conn.rollback()
                return False, f"Duplicate tx hash already used by {dup['ref_id']}"
        if binance_tx_id:
            dup = conn.execute("SELECT ref_id FROM payment_deposits WHERE binance_tx_id = ? AND ref_id != ?", (binance_tx_id, ref_id)).fetchone()
            if dup:
                conn.rollback()
                return False, f"Duplicate Binance transaction already used by {dup['ref_id']}"
        now = now_iso()
        conn.execute(
            """
            UPDATE payment_deposits
            SET status = 'credited', confirmed_at = COALESCE(confirmed_at, ?), credited_at = ?, tx_hash = COALESCE(?, tx_hash),
                tx_hash_key = COALESCE(?, tx_hash_key), binance_tx_id = COALESCE(?, binance_tx_id), source = ?, raw_json = ?
            WHERE ref_id = ? AND credited_at IS NULL
            """,
            (now, now, tx_hash, tx_key, binance_tx_id, source, json.dumps(verified_tx or {}, default=str)[:5000], ref_id),
        )
        _wallet_snapshot(conn, int(dep["chat_id"]))
        conn.execute("UPDATE wallets SET balance_usdt = balance_usdt + ?, updated_at = ? WHERE chat_id = ?", (float(_dec(dep["amount_usdt"])), now, int(dep["chat_id"])))
        wallet = conn.execute("SELECT * FROM wallets WHERE chat_id = ?", (int(dep["chat_id"]),)).fetchone()
        conn.execute(
            "INSERT INTO wallet_ledger(chat_id, kind, amount_usdt, balance_after, note, related_id, created_at) VALUES (?, 'deposit_credit', ?, ?, ?, ?, ?)",
            (int(dep["chat_id"]), float(_dec(dep["amount_usdt"])), float(wallet["balance_usdt"]), f"Wallet load credited via {source}", ref_id, now),
        )
        conn.commit()
    return True, "Deposit credited"


def verify_and_credit_deposit(ref_id: str, tx_hash: str | None = None, manual: bool = False, source: str = "auto") -> tuple[bool, str]:
    dep = get_deposit(ref_id)
    if not dep:
        return False, "Deposit not found"
    if dep["credited_at"]:
        return False, "Deposit already credited"
    method = str(dep["method"] or "").lower()
    pending_tx_key = None
    normalized_hash = None
    if method == "binance" or str(dep["network"] or "") == "binance":
        ok, reason, tx = verify_binance_deposit(dep, manual=manual)
    else:
        normalized_hash = None
        if tx_hash:
            normalized_hash = normalize_tx_hash(tx_hash)
            if not re.fullmatch(r"0x[a-fA-F0-9]{64}", normalized_hash):
                log_payment_check(ref_id, int(dep["chat_id"]), method, "failed", "Invalid transaction hash format", tx_hash)
                return False, "Invalid transaction hash format"
            # If this deposit already has this TxHash saved from a previous manual
            # submission, the automatic watcher/manual retry must be allowed to
            # re-check it for the same reference instead of treating it as reused.
            allow_existing_for_this_ref = normalize_tx_hash(dep["tx_hash"]) == normalized_hash
            reserved, key, reserve_reason = reserve_tx_hash(
                network=str(dep["network"] or method),
                tx_hash=normalized_hash,
                ref_id=ref_id,
                chat_id=int(dep["chat_id"]),
                source=source,
                status="manual_submitted" if manual else "submitted",
                allow_existing_for_ref=allow_existing_for_this_ref,
            )
            pending_tx_key = key
            if not reserved:
                log_payment_check(ref_id, int(dep["chat_id"]), method, "failed", reserve_reason or "Duplicate transaction hash", tx_hash)
                return False, reserve_reason or "This transaction hash has already been used."
        ok, reason, tx = verify_usdt_transfer(dep, tx_hash=normalized_hash, manual=manual)
        if tx_hash and tx:
            tx["hash"] = normalized_hash
    log_payment_check(ref_id, int(dep["chat_id"]), method, "verified" if ok else "failed", reason, tx_hash, tx)
    if not ok:
        with get_conn() as conn:
            if manual:
                # For USDT manual TxHash flow, keep the payment session in 'waiting' until
                # the user sends the screenshot proof. This mirrors the reference bot and
                # prevents a half-submitted TxHash from immediately becoming an admin-review row.
                if source == "manual_tx_hash":
                    if _manual_failure_is_user_fixable(reason):
                        conn.execute(
                            """
                            UPDATE payment_deposits
                            SET tx_hash = COALESCE(?, tx_hash), tx_hash_key = COALESCE(?, tx_hash_key),
                                manual_check_result = 'failed', manual_note = ?
                            WHERE ref_id = ? AND credited_at IS NULL AND status = 'waiting'
                            """,
                            (normalized_hash or tx_hash, pending_tx_key, reason[:500], ref_id),
                        )
                    else:
                        conn.execute(
                            """
                            UPDATE payment_deposits
                            SET tx_hash = COALESCE(?, tx_hash), tx_hash_key = COALESCE(?, tx_hash_key),
                                manual_check_result = 'failed', manual_note = ?
                            WHERE ref_id = ? AND credited_at IS NULL AND status = 'waiting'
                            """,
                            (normalized_hash or tx_hash, pending_tx_key, reason[:500], ref_id),
                        )
                else:
                    conn.execute(
                        """
                        UPDATE payment_deposits
                        SET status = 'manual_pending', tx_hash = COALESCE(?, tx_hash), tx_hash_key = COALESCE(?, tx_hash_key), manual_check_result = 'failed', manual_note = ?
                        WHERE ref_id = ? AND credited_at IS NULL AND status IN ('waiting','manual_pending')
                        """,
                        (normalized_hash or tx_hash, pending_tx_key, reason[:500], ref_id),
                    )
            else:
                conn.execute(
                    "UPDATE payment_deposits SET tx_hash = COALESCE(?, tx_hash), manual_note = ? WHERE ref_id = ? AND credited_at IS NULL",
                    (normalized_hash or tx_hash, reason[:500], ref_id),
                )
        return False, reason
    return credit_deposit_if_confirmed(ref_id, tx, source)


def _verification_timeout_reason(source: str = "auto") -> str:
    if source == "manual_tx_hash":
        return "Automatic TxHash check could not finish. Support review required."
    return "Payment check could not finish. Try again shortly."


async def verify_and_credit_deposit_async(
    ref_id: str,
    tx_hash: str | None = None,
    manual: bool = False,
    source: str = "auto",
    timeout_seconds: int | None = None,
) -> tuple[bool, str]:
    """Run payment verification without letting a Telegram handler hang forever.

    Explorer/Binance APIs can occasionally stall or raise unexpected errors. The
    user should always get the next step instead of being left after the
    "Checking transaction hash" message. Manual TxHash timeouts are kept in the
    same flow so the user can submit screenshot proof for admin review.
    """
    timeout = int(timeout_seconds or PAYMENT_VERIFY_TASK_TIMEOUT_SECONDS)
    try:
        dep = get_deposit(ref_id)
        method = str((dep["method"] if dep and dep["method"] is not None else "")).lower()
        network = normalize_payment_network(str((dep["network"] if dep and dep["network"] is not None else method))) if dep else ""
        if dep and method != "binance" and network != "binance":
            return await asyncio.wait_for(
                verify_and_credit_deposit_bot1_async(ref_id, tx_hash, manual, source),
                timeout=max(5, timeout),
            )
        return await asyncio.wait_for(
            asyncio.to_thread(verify_and_credit_deposit, ref_id, tx_hash, manual, source),
            timeout=max(5, timeout),
        )
    except asyncio.TimeoutError:
        reason = _verification_timeout_reason(source)
        logger.warning("Payment verification timed out ref=%s source=%s manual=%s", ref_id, source, manual)
    except Exception as exc:
        reason = "Automatic TxHash check could not finish. Support review required." if source == "manual_tx_hash" else f"Payment check error: {exc}"
        logger.exception("Payment verification crashed ref=%s source=%s manual=%s", ref_id, source, manual)

    # Best-effort log/update so the admin panel has a reason and manual TxHash
    # can continue to screenshot proof instead of getting stuck.
    try:
        dep = get_deposit(ref_id)
        if dep:
            method = str(dep["method"] or dep["network"] or "wallet")
            log_payment_check(ref_id, int(dep["chat_id"]), method, "error", reason, tx_hash, None)
            if manual and source == "manual_tx_hash" and tx_hash:
                normalized = normalize_tx_hash(tx_hash)
                key = None
                if re.fullmatch(r"0x[a-fA-F0-9]{64}", normalized):
                    reserved, key, reserve_reason = reserve_tx_hash(
                        network=str(dep["network"] or method),
                        tx_hash=normalized,
                        ref_id=ref_id,
                        chat_id=int(dep["chat_id"]),
                        source=source,
                        status="manual_error",
                        allow_existing_for_ref=True,
                    )
                    if not reserved:
                        reason = reserve_reason or "This transaction hash has already been used."
                with get_conn() as conn:
                    conn.execute(
                        """
                        UPDATE payment_deposits
                        SET tx_hash = COALESCE(?, tx_hash), tx_hash_key = COALESCE(?, tx_hash_key),
                            manual_check_result = 'error', manual_note = ?
                        WHERE ref_id = ? AND credited_at IS NULL AND status = 'waiting'
                        """,
                        (normalized, key, reason[:500], ref_id),
                    )
    except Exception:
        logger.exception("Could not record payment verification timeout/error ref=%s", ref_id)
    return False, reason



# -----------------------------
# Privacy-safe preset messaging
# -----------------------------


def _normalize_audience(value: str) -> str:
    value = value.strip().lower()
    if value not in {"sender", "receiver", "both"}:
        raise ValueError("audience must be sender, receiver, or both")
    return value


def _validate_button_text(text: str) -> str:
    text = text.strip()
    if not text:
        raise ValueError("button text cannot be empty")
    if len(text) > 60:
        raise ValueError("button text must be 60 characters or less")
    return text


def _validate_preset_text(text: str, field: str = "message") -> str:
    text = text.strip()
    if not text:
        raise ValueError(f"{field} text cannot be empty")
    if len(text) > 900:
        raise ValueError(f"{field} text must be 900 characters or less")
    return text


def parse_pipe_command(raw_text: str, command_name: str) -> list[str]:
    # Telegram sends the command itself in update.message.text. Everything after the first space is the payload.
    parts = raw_text.split(maxsplit=1)
    if len(parts) < 2:
        raise ValueError(f"Usage: {command_name} ...")
    payload = parts[1]
    fields = [part.strip() for part in payload.split("|")]
    return fields


def add_message_template(audience: str, button_text: str, message_text: str) -> int:
    audience = _normalize_audience(audience)
    button_text = _validate_button_text(button_text)
    message_text = _validate_preset_text(message_text, "message")
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO message_templates(audience, button_text, message_text, active, created_at, updated_at)
            VALUES (?, ?, ?, 1, ?, ?)
            """,
            (audience, button_text, message_text, now_iso(), now_iso()),
        )
        return int(cur.lastrowid)


def add_message_reply(template_id: int, audience: str, button_text: str, reply_text: str) -> int:
    audience = _normalize_audience(audience)
    button_text = _validate_button_text(button_text)
    reply_text = _validate_preset_text(reply_text, "reply")
    with get_conn() as conn:
        template = conn.execute(
            "SELECT id FROM message_templates WHERE id = ?",
            (template_id,),
        ).fetchone()
        if not template:
            raise ValueError("message template not found")
        cur = conn.execute(
            """
            INSERT INTO message_replies(template_id, audience, button_text, reply_text, active, created_at, updated_at)
            VALUES (?, ?, ?, ?, 1, ?, ?)
            """,
            (template_id, audience, button_text, reply_text, now_iso(), now_iso()),
        )
        return int(cur.lastrowid)


def set_message_template_active(template_id: int, active: bool) -> bool:
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE message_templates SET active = ?, updated_at = ? WHERE id = ?",
            (1 if active else 0, now_iso(), template_id),
        )
        return cur.rowcount > 0


def set_message_reply_active(reply_id: int, active: bool) -> bool:
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE message_replies SET active = ?, updated_at = ? WHERE id = ?",
            (1 if active else 0, now_iso(), reply_id),
        )
        return cur.rowcount > 0


def delete_message_template_permanent(template_id: int) -> bool:
    with get_conn() as conn:
        # Remove message logs first because older DB schemas keep FK references to templates/replies.
        conn.execute("DELETE FROM message_events WHERE template_id = ?", (template_id,))
        conn.execute("DELETE FROM message_events WHERE reply_id IN (SELECT id FROM message_replies WHERE template_id = ?)", (template_id,))
        conn.execute("DELETE FROM message_replies WHERE template_id = ?", (template_id,))
        cur = conn.execute("DELETE FROM message_templates WHERE id = ?", (template_id,))
        return cur.rowcount > 0


def delete_message_reply_permanent(reply_id: int) -> bool:
    with get_conn() as conn:
        conn.execute("UPDATE message_events SET reply_id = NULL WHERE reply_id = ?", (reply_id,))
        cur = conn.execute("DELETE FROM message_replies WHERE id = ?", (reply_id,))
        return cur.rowcount > 0


def get_message_template(template_id: int) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM message_templates WHERE id = ?", (template_id,)).fetchone()


def get_message_reply(reply_id: int) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM message_replies WHERE id = ?", (reply_id,)).fetchone()


def list_message_templates(active_only: bool = False, limit: int = 100) -> list[sqlite3.Row]:
    with get_conn() as conn:
        if active_only:
            return conn.execute(
                "SELECT * FROM message_templates WHERE active = 1 ORDER BY id ASC LIMIT ?",
                (limit,),
            ).fetchall()
        return conn.execute("SELECT * FROM message_templates ORDER BY id ASC LIMIT ?", (limit,)).fetchall()


def list_message_replies(template_id: int | None = None, active_only: bool = False) -> list[sqlite3.Row]:
    clauses: list[str] = []
    params: list = []
    if template_id is not None:
        clauses.append("template_id = ?")
        params.append(template_id)
    if active_only:
        clauses.append("active = 1")
    where = "WHERE " + " AND ".join(clauses) if clauses else ""
    with get_conn() as conn:
        return conn.execute(
            f"SELECT * FROM message_replies {where} ORDER BY template_id ASC, id ASC",
            tuple(params),
        ).fetchall()


def export_preset_messages_payload() -> dict[str, Any]:
    """Build a portable JSON backup for preset marketplace messages and replies."""
    with get_conn() as conn:
        templates = conn.execute("SELECT * FROM message_templates ORDER BY id ASC").fetchall()
        replies = conn.execute("SELECT * FROM message_replies ORDER BY template_id ASC, id ASC").fetchall()

    replies_by_template: dict[int, list[sqlite3.Row]] = {}
    for reply in replies:
        replies_by_template.setdefault(int(reply["template_id"]), []).append(reply)

    messages: list[dict[str, Any]] = []
    for template in templates:
        tid = int(template["id"])
        messages.append({
            "old_id": tid,
            "audience": str(template["audience"]),
            "button_text": str(template["button_text"]),
            "message_text": str(template["message_text"]),
            "active": bool(int(template["active"] or 0)),
            "replies": [
                {
                    "old_id": int(reply["id"]),
                    "audience": str(reply["audience"]),
                    "button_text": str(reply["button_text"]),
                    "reply_text": str(reply["reply_text"]),
                    "active": bool(int(reply["active"] or 0)),
                }
                for reply in replies_by_template.get(tid, [])
            ],
        })

    return {
        "app": APP_NAME,
        "type": "preset_messages",
        "version": 1,
        "exported_at": now_iso(),
        "messages": messages,
    }


def _coerce_import_messages(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        messages = payload
    elif isinstance(payload, dict):
        messages = payload.get("messages")
    else:
        raise ValueError("Import JSON must be an object with a messages list.")
    if not isinstance(messages, list):
        raise ValueError("Import JSON must contain a messages list.")
    if len(messages) > 500:
        raise ValueError("Import is limited to 500 preset messages at once.")
    return messages


def import_preset_messages_payload(payload: Any, mode: str = "replace") -> tuple[int, int]:
    """Import preset messages. Returns (message_count, reply_count)."""
    mode = str(mode or "replace").strip().lower()
    if mode not in {"replace", "append"}:
        raise ValueError("Import mode must be replace or append.")
    messages = _coerce_import_messages(payload)

    parsed: list[dict[str, Any]] = []
    reply_total = 0
    for idx, item in enumerate(messages, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"Message #{idx} must be an object.")
        audience = _normalize_audience(str(item.get("audience", "")))
        button_text = _validate_button_text(str(item.get("button_text", "")))
        message_text = _validate_preset_text(str(item.get("message_text", "")), "message")
        active = 1 if bool(item.get("active", True)) else 0
        raw_replies = item.get("replies", [])
        if raw_replies is None:
            raw_replies = []
        if not isinstance(raw_replies, list):
            raise ValueError(f"Replies for message #{idx} must be a list.")
        if reply_total + len(raw_replies) > 2000:
            raise ValueError("Import is limited to 2000 reply buttons at once.")

        parsed_replies: list[dict[str, Any]] = []
        for ridx, reply in enumerate(raw_replies, start=1):
            if not isinstance(reply, dict):
                raise ValueError(f"Reply #{ridx} for message #{idx} must be an object.")
            parsed_replies.append({
                "audience": _normalize_audience(str(reply.get("audience", ""))),
                "button_text": _validate_button_text(str(reply.get("button_text", ""))),
                "reply_text": _validate_preset_text(str(reply.get("reply_text", "")), "reply"),
                "active": 1 if bool(reply.get("active", True)) else 0,
            })
        reply_total += len(parsed_replies)
        parsed.append({
            "audience": audience,
            "button_text": button_text,
            "message_text": message_text,
            "active": active,
            "replies": parsed_replies,
        })

    created_messages = 0
    created_replies = 0
    stamp = now_iso()
    with get_conn() as conn:
        if mode == "replace":
            conn.execute("DELETE FROM message_events")
            conn.execute("DELETE FROM message_replies")
            conn.execute("DELETE FROM message_templates")
        for item in parsed:
            cur = conn.execute(
                """
                INSERT INTO message_templates(audience, button_text, message_text, active, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (item["audience"], item["button_text"], item["message_text"], item["active"], stamp, stamp),
            )
            template_id = int(cur.lastrowid)
            created_messages += 1
            for reply in item["replies"]:
                conn.execute(
                    """
                    INSERT INTO message_replies(template_id, audience, button_text, reply_text, active, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (template_id, reply["audience"], reply["button_text"], reply["reply_text"], reply["active"], stamp, stamp),
                )
                created_replies += 1
    return created_messages, created_replies


def active_templates_for_role(role: str) -> list[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT * FROM message_templates
            WHERE active = 1 AND audience IN (?, 'both')
            ORDER BY id ASC
            """,
            (role,),
        ).fetchall()


def active_replies_for_template(template_id: int, role: str) -> list[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT * FROM message_replies
            WHERE template_id = ? AND active = 1 AND audience IN (?, 'both')
            ORDER BY id ASC
            """,
            (template_id, role),
        ).fetchall()


def active_pairs_for_receiver(receiver_chat_id: int) -> list[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT p.*, s.alias AS sender_alias, r.alias AS receiver_alias,
                   s.active AS sender_active, r.active AS receiver_active,
                   sp.username AS sender_username, rp.username AS receiver_username,
                   sp.first_name AS sender_first_name, rp.first_name AS receiver_first_name,
                   sp.last_name AS sender_last_name, rp.last_name AS receiver_last_name
            FROM pairs p
            JOIN users s ON s.chat_id = p.sender_chat_id
            JOIN users r ON r.chat_id = p.receiver_chat_id
            LEFT JOIN telegram_profiles sp ON sp.chat_id = p.sender_chat_id
            LEFT JOIN telegram_profiles rp ON rp.chat_id = p.receiver_chat_id
            WHERE p.receiver_chat_id = ? AND p.active = 1 AND s.active = 1 AND r.active = 1
            ORDER BY p.updated_at DESC
            """,
            (receiver_chat_id,),
        ).fetchall()


def create_message_event(
    *,
    template_id: int,
    initiator_chat_id: int,
    recipient_chat_id: int,
    sender_chat_id: int,
    receiver_chat_id: int,
    direction: str,
    delivered_message_id: int | None,
    broadcast_id: str | None = None,
) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO message_events(
                template_id, initiator_chat_id, recipient_chat_id,
                sender_chat_id, receiver_chat_id, direction,
                broadcast_id, delivered_message_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                template_id,
                initiator_chat_id,
                recipient_chat_id,
                sender_chat_id,
                receiver_chat_id,
                direction,
                broadcast_id,
                delivered_message_id,
                now_iso(),
            ),
        )
        return int(cur.lastrowid)


def update_message_event_delivery(event_id: int, delivered_message_id: int) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE message_events SET delivered_message_id = ? WHERE id = ?",
            (delivered_message_id, event_id),
        )


def get_message_event(event_id: int) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM message_events WHERE id = ?", (event_id,)).fetchone()


def claim_message_broadcast_reply(event_id: int, reply_id: int) -> tuple[bool, str, sqlite3.Row | None, list[sqlite3.Row]]:
    """Claim a marketplace preset broadcast for the first reply.

    Returns (claimed, reason, event_or_winner, other_delivered_events). The reply
    button that wins marks this event as replied and marks all sibling delivered
    copies as cleared, so they can be deleted/disabled and cannot send conflicting
    replies later.
    """
    stamp = now_iso()
    with get_conn() as conn:
        try:
            conn.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError:
            pass

        event = conn.execute("SELECT * FROM message_events WHERE id = ?", (event_id,)).fetchone()
        if not event:
            return False, "missing", None, []

        if event["cleared_at"] or event["replied_at"]:
            return False, "closed", event, []

        broadcast_id = str(event["broadcast_id"] or "").strip()
        if not broadcast_id:
            # Older delivered messages did not have a broadcast id; keep them safe
            # by treating that one event as its own one-message broadcast.
            broadcast_id = f"legacy:{event_id}"
            conn.execute("UPDATE message_events SET broadcast_id = ? WHERE id = ?", (broadcast_id, event_id))

        winner = conn.execute(
            """
            SELECT * FROM message_events
            WHERE broadcast_id = ? AND replied_at IS NOT NULL
            ORDER BY replied_at ASC, id ASC
            LIMIT 1
            """,
            (broadcast_id,),
        ).fetchone()
        if winner:
            conn.execute(
                "UPDATE message_events SET cleared_at = ?, canceled_by_event_id = ? WHERE id = ? AND cleared_at IS NULL",
                (stamp, int(winner["id"]), event_id),
            )
            return False, "already_answered", winner, []

        conn.execute(
            "UPDATE message_events SET replied_at = ?, reply_id = ? WHERE id = ?",
            (stamp, reply_id, event_id),
        )
        others = conn.execute(
            """
            SELECT * FROM message_events
            WHERE broadcast_id = ?
              AND id != ?
              AND delivered_message_id IS NOT NULL
              AND cleared_at IS NULL
            ORDER BY id ASC
            """,
            (broadcast_id, event_id),
        ).fetchall()
        conn.execute(
            """
            UPDATE message_events
            SET cleared_at = ?, canceled_by_event_id = ?
            WHERE broadcast_id = ? AND id != ? AND cleared_at IS NULL
            """,
            (stamp, event_id, broadcast_id, event_id),
        )
        claimed_event = conn.execute("SELECT * FROM message_events WHERE id = ?", (event_id,)).fetchone()
        return True, "claimed", claimed_event, others


def mark_message_event_replied(event_id: int, reply_id: int) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE message_events SET replied_at = ?, reply_id = ? WHERE id = ?",
            (now_iso(), reply_id, event_id),
        )


def build_template_keyboard(role: str, sender_chat_id: int) -> InlineKeyboardMarkup | None:
    templates = active_templates_for_role(role)
    if not templates:
        return None
    rows: list[list[InlineKeyboardButton]] = []
    for template in templates[:40]:
        rows.append([
            InlineKeyboardButton(
                template["button_text"],
                callback_data=f"msgsend:{sender_chat_id}:{template['id']}",
            )
        ])
    return InlineKeyboardMarkup(rows)


def build_receiver_pair_keyboard(pairs: list[sqlite3.Row]) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    for idx, pair in enumerate(pairs[:40], start=1):
        # Deliberately do not show chat IDs, usernames, or admin aliases to preserve privacy.
        rows.append([
            InlineKeyboardButton(
                f"Route {idx}",
                callback_data=f"msgpair:{pair['sender_chat_id']}",
            )
        ])
    return InlineKeyboardMarkup(rows)


def build_reply_keyboard(event_id: int, template_id: int, recipient_role: str) -> InlineKeyboardMarkup | None:
    replies = active_replies_for_template(template_id, recipient_role)
    if not replies:
        return None
    rows: list[list[InlineKeyboardButton]] = []
    for reply in replies[:40]:
        rows.append([
            InlineKeyboardButton(
                reply["button_text"],
                callback_data=f"msgreply:{event_id}:{reply['id']}",
            )
        ])
    return InlineKeyboardMarkup(rows)


def build_delivered_preset_text(template: sqlite3.Row, direction: str, event_id: int | None = None) -> str:
    from_label = "Sender" if direction == "sender_to_receiver" else "Receiver"
    return (
        "📣 New marketplace message\n"
        f"From: {from_label}\n\n"
        f"{template['message_text']}\n\n"
        "Reply below 👇"
    )


def build_delivered_reply_text(
    reply: sqlite3.Row,
    event_id: int,
    direction: str | None = None,
    template: sqlite3.Row | None = None,
) -> str:
    if direction == "sender_to_receiver":
        from_label = "Receiver"
    elif direction == "receiver_to_sender":
        from_label = "Sender"
    else:
        from_label = "User"

    original_line = ""
    if template is not None:
        original = str(template["message_text"] or "").strip()
        if original:
            if len(original) > 120:
                original = original[:117].rstrip() + "..."
            original_line = f"\nFor: {original}\n"

    return (
        "🔔 New marketplace reply\n"
        f"From: {from_label}"
        f"{original_line}\n"
        f"{reply['reply_text']}"
    )

# -----------------------------
# QR sanitizing
# -----------------------------


def resize_for_fast_qr_detection(image: np.ndarray) -> np.ndarray:
    height, width = image.shape[:2]
    largest = max(width, height)
    if largest <= MAX_PROCESS_DIMENSION:
        return image
    scale = MAX_PROCESS_DIMENSION / largest
    new_width = max(1, int(width * scale))
    new_height = max(1, int(height * scale))
    return cv2.resize(image, (new_width, new_height), interpolation=cv2.INTER_AREA)


def _first_param(params: dict[str, list[str]], key: str) -> str:
    values = params.get(key.lower(), [])
    if not values:
        return ""
    return values[0].strip()


def _validate_upi_autopay_mandate(data: str) -> None:
    parsed = urlparse(data)

    # Normal payment QRs look like upi://pay?...; AutoPay / mandate QRs should use upi://mandate?...
    if parsed.scheme.lower() != "upi" or parsed.netloc.lower() != "mandate":
        raise ValueError("Only UPI AutoPay mandate QR codes are allowed. Regular UPI payment QR codes are rejected.")

    params_raw = parse_qs(parsed.query, keep_blank_values=True)
    params = {k.lower(): v for k, v in params_raw.items()}

    # Keep this allowlist strict enough to reject regular UPI payment QRs,
    # but not so strict that valid AutoPay mandate QRs from different PSPs fail.
    # Some mandate QRs include mn/tid, but many real PSP-generated mandate QRs
    # only include tr as the reference/order identifier.
    required = [
        "pa",             # payee VPA
        "pn",             # payee name
        "am",             # amount
        "cu",             # currency
        "tr",             # order/reference id
        "validitystart",  # mandate start date
        "validityend",    # mandate end date
        "recur",          # recurrence pattern
        "txnType",        # should be CREATE
    ]

    missing = [key for key in required if not _first_param(params, key)]
    if missing:
        raise ValueError("UPI mandate QR is missing required fields: " + ", ".join(missing))

    if _first_param(params, "cu").upper() != "INR":
        raise ValueError("Only INR UPI mandate QR codes are allowed.")

    if _first_param(params, "txntype").upper() != "CREATE":
        raise ValueError("Only UPI mandate creation QR codes are allowed.")

    purpose = _first_param(params, "purpose").upper()
    if REJECT_UPI_ONETIME_MANDATES and purpose == "01":
        raise ValueError("One-time UPI mandates are rejected. Only recurring AutoPay mandates are allowed.")

    recurrence = _first_param(params, "recur").upper()
    if recurrence in {"", "ONETIME", "ONE_TIME", "ONE-TIME"}:
        raise ValueError("Only recurring UPI AutoPay mandates are allowed.")

    amount_raw = _first_param(params, "am")
    try:
        amount = float(amount_raw)
    except ValueError as exc:
        raise ValueError("UPI mandate amount is invalid.") from exc
    if amount <= 0:
        raise ValueError("UPI mandate amount must be greater than zero.")

    payee_vpa = _first_param(params, "pa")
    if not re.fullmatch(r"[A-Za-z0-9._-]{2,256}@[A-Za-z0-9._-]{2,64}", payee_vpa):
        raise ValueError("UPI mandate payee VPA is invalid.")


def _validate_generic_qr_data(data: str) -> None:
    if STRICT_QR_REGEX:
        if not re.fullmatch(STRICT_QR_REGEX, data):
            raise ValueError("QR code does not match the required format.")

    if ALLOWED_QR_PREFIXES:
        if not any(data.startswith(prefix) for prefix in ALLOWED_QR_PREFIXES):
            raise ValueError("QR code is not from an approved prefix/domain.")

    if BLOCK_CONTACT_PATTERNS:
        forbidden_patterns = [
            r"t\.me/",
            r"telegram\.me/",
            r"telegram\.dog/",
            r"wa\.me/",
            r"api\.whatsapp\.com/",
            r"whatsapp",
            r"instagram\.com/",
            r"facebook\.com/",
            r"fb\.me/",
            r"mailto:",
            r"tel:",
            r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
            r"(?<![A-Za-z0-9_])@[A-Za-z0-9_]{4,32}\b",
            r"(?<!\d)\+?\d[\d\s().-]{7,}\d(?!\d)",
        ]
        for pattern in forbidden_patterns:
            if re.search(pattern, data, flags=re.IGNORECASE):
                raise ValueError("QR contains blocked contact information.")


def validate_qr_data(data: str) -> str:
    data = data.strip()
    if not data:
        raise ValueError("QR code is empty.")
    if len(data) > 2000:
        raise ValueError("QR code data is too long.")

    if QR_VALIDATION_MODE == "upi_mandate":
        _validate_upi_autopay_mandate(data)
    elif QR_VALIDATION_MODE == "generic":
        _validate_generic_qr_data(data)
    else:
        raise ValueError(f"Invalid QR_VALIDATION_MODE configured: {QR_VALIDATION_MODE}")

    return data


def _decode_with_detector(detector: cv2.QRCodeDetector, image: np.ndarray) -> str | None:
    # First reject multiple readable QR codes. One job = one QR.
    try:
        ok, decoded_info, _points, _straight = detector.detectAndDecodeMulti(image)
        if ok:
            infos = [x.strip() for x in decoded_info if x and x.strip()]
            unique_infos = list(dict.fromkeys(infos))
            if len(unique_infos) > 1:
                raise ValueError("Multiple QR codes found. Send one QR at a time.")
            if len(unique_infos) == 1:
                return unique_infos[0]
    except ValueError:
        raise
    except Exception:
        # Some OpenCV builds can fail on detectAndDecodeMulti; fallback below.
        pass

    data, points, _straight = detector.detectAndDecode(image)
    if data and points is not None:
        return data.strip()
    return None


def decode_qr_data_from_bytes(image_bytes: bytes) -> str:
    np_bytes = np.frombuffer(image_bytes, np.uint8)
    image = cv2.imdecode(np_bytes, cv2.IMREAD_COLOR)
    if image is None:
        raise ValueError("Could not read the image.")

    detector = cv2.QRCodeDetector()
    resized = resize_for_fast_qr_detection(image)
    attempts: list[np.ndarray] = [resized]

    try:
        gray = cv2.cvtColor(resized, cv2.COLOR_BGR2GRAY)
        attempts.append(gray)
    except Exception:
        pass

    if resized.shape[:2] != image.shape[:2]:
        attempts.append(image)

    last_error: ValueError | None = None
    for attempt in attempts:
        try:
            data = _decode_with_detector(detector, attempt)
        except ValueError as exc:
            last_error = exc
            break
        if data:
            return validate_qr_data(data)

    if last_error:
        raise last_error
    raise ValueError("No readable QR code found. Send a clearer photo containing one QR code.")


def rebuild_clean_qr_png(qr_data: str) -> io.BytesIO:
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=12,
        border=4,
    )
    qr.add_data(qr_data)
    qr.make(fit=True)

    clean_img = qr.make_image(fill_color="black", back_color="white").convert("RGB")

    output = io.BytesIO()
    output.name = "clean_qr.png"
    clean_img.save(output, format="PNG", optimize=True)
    output.seek(0)
    return output


def decode_and_rebuild_sync(image_bytes: bytes) -> tuple[io.BytesIO, str, str]:
    qr_data = decode_qr_data_from_bytes(image_bytes)
    qr_hash = hashlib.sha256(qr_data.encode("utf-8")).hexdigest()
    clean_qr_file = rebuild_clean_qr_png(qr_data)
    return clean_qr_file, qr_data, qr_hash


async def extract_and_rebuild_clean_qr(message) -> tuple[io.BytesIO, str, str]:
    telegram_file = await message.photo[-1].get_file()
    raw = io.BytesIO()
    await telegram_file.download_to_memory(raw)
    return await asyncio.to_thread(decode_and_rebuild_sync, raw.getvalue())


async def delete_message_safely(context: ContextTypes.DEFAULT_TYPE, chat_id: int, message_id: int, reason: str = "message") -> None:
    try:
        await context.bot.delete_message(chat_id=chat_id, message_id=message_id)
    except TelegramError as exc:
        # Do not fail the flow just because Telegram refused deletion.
        logger.warning("Could not delete %s %s/%s: %s", reason, chat_id, message_id, exc)


async def delete_original_sender_message_safely(
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    message_id: int,
    *,
    rejected: bool = False,
) -> None:
    if rejected:
        if not DELETE_ORIGINAL_AFTER_REJECTION:
            return
        await delete_message_safely(context, chat_id, message_id, "rejected original sender photo")
        return

    if not DELETE_ORIGINAL_AFTER_SUCCESS:
        return
    await delete_message_safely(context, chat_id, message_id, "original sender photo")


# -----------------------------
# Message/caption helpers
# -----------------------------


def build_caption(date_str: str, daily_no: int, public_id: str) -> str:
    return (
        f"📅 Date: {display_date(date_str)}\n"
        f"📷 Photo #{daily_no} today\n"
        f"🆔 ID: {public_id}"
    )


def build_status_caption(photo: PhotoRow, status: str, failure_reason: str | None = None) -> str:
    emoji = "✅" if status == "done" else "❌"
    status_text = status.upper()
    lines = [
        build_caption(photo.date, photo.daily_no, photo.public_id),
        "",
        f"{emoji} Status: {status_text}",
        f"🕒 Updated: {display_datetime()}",
    ]
    if status == "failed":
        reason = clean_failure_reason_text(failure_reason)
        if reason:
            lines.append(f"📝 Reason: {reason}")
    return "\n".join(lines)


def build_sender_offer_caption(
    date_str: str,
    daily_no: int,
    public_id: str,
    status_line: str,
    *,
    expires_at: str | None = None,
    sender_rate: Decimal | str | float | int | None = None,
) -> str:
    lines = [build_caption(date_str, daily_no, public_id), "", status_line]
    if expires_at:
        lines.append(f"⏱ Expires: {display_datetime(expires_at)}")
    if sender_rate is not None:
        lines.append(f"💳 Reserved: ${_money(sender_rate)} USDT")
    return "\n".join(lines)


async def edit_sender_offer_caption(bot, chat_id: int, message_id: int | None, caption: str) -> bool:
    if not message_id:
        return False
    try:
        await bot.edit_message_caption(chat_id=chat_id, message_id=message_id, caption=caption)
        return True
    except TelegramError as exc:
        logger.warning("Could not edit sender offer caption %s/%s: %s", chat_id, message_id, exc)
        return False


def receiver_status_keyboard(public_id: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("✅ Done", callback_data=f"done:{public_id}"),
                InlineKeyboardButton("❌ Failed", callback_data=f"failed:{public_id}"),
            ],
            [InlineKeyboardButton("⚠️ Dispute", callback_data=f"disputeqr:{public_id}")],
        ]
    )


def failure_reason_keyboard(public_id: str) -> InlineKeyboardMarkup:
    rows = [[InlineKeyboardButton(label, callback_data=f"failreason:{public_id}:{key}")] for key, label in FAIL_REASON_BUTTONS]
    rows.append([InlineKeyboardButton("⬅️ Cancel", callback_data="nav:home")])
    return InlineKeyboardMarkup(rows)


def sender_notify_keyboard(public_id: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("🔔 Notify Receiver", callback_data=f"notify:{public_id}")],
            [InlineKeyboardButton("⚠️ Dispute", callback_data=f"disputeqr:{public_id}")],
        ]
    )


def split_chunks(lines: list[str], max_len: int = 3500) -> Iterable[str]:
    chunk = ""
    for line in lines:
        candidate = f"{chunk}\n{line}" if chunk else line
        if len(candidate) > max_len:
            if chunk:
                yield chunk
            chunk = line
        else:
            chunk = candidate
    if chunk:
        yield chunk


# -----------------------------
# Command handlers
# -----------------------------


def main_menu_keyboard(user: UserRow | None = None) -> InlineKeyboardMarkup:
    if user and user.active and user.role == "receiver":
        return InlineKeyboardMarkup(
            [
                [
                    InlineKeyboardButton("💰 Earnings", callback_data="nav:wallet"),
                    InlineKeyboardButton("📥 Pending QR", callback_data="nav:pending"),
                ],
                [
                    InlineKeyboardButton("💬 Messages", callback_data="nav:messages"),
                    InlineKeyboardButton("📜 QR History", callback_data="nav:history"),
                ],
                [
                    InlineKeyboardButton("📊 Stats", callback_data="nav:stats"),
                    InlineKeyboardButton("⚠️ Dispute", callback_data="nav:dispute"),
                ],
                [
                    InlineKeyboardButton("📋 Commands", callback_data="nav:commands"),
                    InlineKeyboardButton("🛟 Support", callback_data="nav:support"),
                ],
            ]
        )
    if user and user.active and user.role == "sender":
        return InlineKeyboardMarkup(
            [
                [
                    InlineKeyboardButton("👛 Wallet", callback_data="nav:wallet"),
                    InlineKeyboardButton("📡 Status", callback_data="nav:status"),
                ],
                [
                    InlineKeyboardButton("💬 Messages", callback_data="nav:messages"),
                    InlineKeyboardButton("📜 QR History", callback_data="nav:history"),
                ],
                [
                    InlineKeyboardButton("📊 Stats", callback_data="nav:stats"),
                    InlineKeyboardButton("⚠️ Dispute", callback_data="nav:dispute"),
                ],
                [
                    InlineKeyboardButton("📋 Commands", callback_data="nav:commands"),
                    InlineKeyboardButton("🛟 Support", callback_data="nav:support"),
                ],
            ]
        )
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("📋 Commands", callback_data="nav:commands")],
            [InlineKeyboardButton("🛟 Support", callback_data="nav:support")],
        ]
    )


def main_menu_text(user: UserRow | None, chat_id: int) -> str:
    if user and user.active and user.role == "sender":
        return (
            "✅ You are registered as a <b>sender</b>.\n\n"
            "📤 Send a photo containing exactly one UPI AutoPay QR code.\n"
            "🧼 I will rebuild it as a clean QR and post it as an open offer to online receivers.\n\n"
            "Use the menu below for wallet, marketplace messages, QR history, disputes, stats, commands, and support."
        )
    if user and user.active and user.role == "receiver":
        return (
            "✅ You are registered as a <b>receiver/buyer</b>.\n\n"
            "🟢 Go online when you are ready to receive QR offers.\n"
            "📥 Accepted QRs will appear here with Done/Failed buttons.\n\n"
            "Use the menu below for earnings, pending QRs, marketplace messages, QR history, disputes, stats, commands, and support."
        )
    return (
        "👋 You are not registered yet.\n\n"
        f"🆔 Your chat ID: <code>{chat_id}</code>\n\n"
        "📩 Send this ID to support/admin to get access.\n\n"
        f"👤 Support: {html.escape(support_display_text())}"
    )


def commands_help_text(user: UserRow | None = None) -> str:
    lines = ["📋 Available commands and usage"]
    if user and user.active:
        lines.append(f"Role: {user.role}")
    lines.extend([
        "",
        "General:",
        "• /start — open the main menu",
        "• /commands — show this command list",
        "• /myid — show your Telegram chat ID and username",
        "• /support — show support contact and open-chat button",
        "• /messages — send a preset marketplace broadcast",
        "• /history — show your QR history",
        "• /dispute — open a support dispute",
        "• /stats — show your totals",
    ])
    if user and user.active and user.role == "sender":
        lines.extend([
            "",
            "Sender:",
            "• Send a QR photo — create a new open QR scan offer",
            "• /status — show marketplace receiver capacity",
            "• /wallet — show your wallet balance",
            "• /loadwallet — Top-up your wallet",
        ])
    elif user and user.active and user.role == "receiver":
        lines.extend([
            "",
            "Receiver:",
            "• /on LIMIT — go online, example: /on 25",
            "• /off — go offline",
            "• /pending — show your claimed pending QRs",
            "• /done — mark the QR you replied to as done",
            "• /failed — mark the QR you replied to as failed by selecting a reason",
            "• /earnings — show receiver earnings",
            "• /withdraw — request payout",
        ])
    else:
        lines.extend(["", "After admin activates your account, this list will show only the commands for your role."])
    return "\n".join(lines)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    observe_telegram_profile(update.effective_user)
    if not update.effective_chat or not update.message:
        return
    if update.effective_chat.type != ChatType.PRIVATE:
        await update.message.reply_text("Please use this bot only in private chat.")
        return

    chat_id = update.effective_chat.id
    user = ensure_default_sender_user(chat_id)
    await refresh_bot_commands_for_chat(context.bot, chat_id, user)

    await update.message.reply_text(
        main_menu_text(user, chat_id),
        parse_mode="HTML",
        reply_markup=main_menu_keyboard(user),
    )


async def myid(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    observe_telegram_profile(update.effective_user)
    if update.message and update.effective_chat:
        username = getattr(update.effective_user, "username", None) if update.effective_user else None
        suffix = f"\nUsername: @{username}" if username else "\nUsername: not set / hidden"
        await update.message.reply_text(f"Your ID is:\n`{update.effective_chat.id}`{suffix}", parse_mode="Markdown")


async def commands_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    observe_telegram_profile(update.effective_user)
    if not update.message or not update.effective_chat:
        return
    user = get_user(update.effective_chat.id)
    await update.message.reply_text(
        commands_help_text(user),
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Back to Menu", callback_data="nav:home")]]),
    )


async def support_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    observe_telegram_profile(update.effective_user)
    if not update.message:
        return
    await update.message.reply_text(
        "🛟 Support\n\n"
        f"Contact: {support_display_text()}\n\n"
        "Use the button below to open the support chat directly.",
        reply_markup=support_keyboard(include_back=False),
    )


async def stats_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    observe_telegram_profile(update.effective_user)
    if not update.message or not update.effective_chat:
        return

    chat_id = update.effective_chat.id

    user = get_user(chat_id)
    if not user or not user.active:
        await update.message.reply_text("You are not registered yet.")
        return

    if user.role == "sender":
        await update.message.reply_text(stats_summary_text("Your sender stats", sender_chat_id=chat_id))
    else:
        await update.message.reply_text(stats_summary_text("Your receiver stats", receiver_chat_id=chat_id))






def _receiver_pending_text_keyboard(chat_id: int) -> tuple[str, InlineKeyboardMarkup | None]:
    rows = user_recent_claimed_pending(chat_id)
    if not rows:
        return "No claimed pending QRs.", None

    lines = ["Your claimed pending QRs:", "Tap an ID below to reopen that specific QR.", ""]
    keyboard: list[list[InlineKeyboardButton]] = []
    for row in rows:
        public_id = str(row["public_id"])
        lines.append(f"{public_id} | 📷 Photo #{row['daily_no']} | 📅 {display_date(row['date'])}")
        keyboard.append([InlineKeyboardButton(public_id, callback_data=f"pendingqr:{public_id}")])
    return "\n".join(lines), InlineKeyboardMarkup(keyboard)


def qr_status_line(row: sqlite3.Row) -> str:
    status = str(row["status"] or "pending").lower()
    offer_state = str(row["offer_state"] or "").replace("_", " ").strip().title()
    if status == "done":
        label = "✅ Done"
    elif status == "failed":
        label = "❌ Failed"
    else:
        label = "⏳ Pending"
    if offer_state:
        label = f"{label} · {offer_state}"
    return label


def user_qr_history_rows(chat_id: int, role: str, limit: int = 10, offset: int = 0) -> list[sqlite3.Row]:
    field = "sender_chat_id" if role == "sender" else "receiver_chat_id"
    with get_conn() as conn:
        return conn.execute(
            f"""
            SELECT * FROM photos
            WHERE {field} = ?
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            """,
            (chat_id, limit, offset),
        ).fetchall()


def user_qr_history_count(chat_id: int, role: str) -> int:
    field = "sender_chat_id" if role == "sender" else "receiver_chat_id"
    with get_conn() as conn:
        return int(conn.execute(f"SELECT COUNT(*) AS n FROM photos WHERE {field} = ?", (chat_id,)).fetchone()["n"] or 0)


def _history_datetime(value: str | datetime | None) -> str:
    try:
        if value is None:
            dt = now_dt()
        elif isinstance(value, datetime):
            dt = value
        else:
            dt = datetime.fromisoformat(str(value))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=ZoneInfo(BOT_TZ))
        dt = dt.astimezone(ZoneInfo("UTC"))
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return esc(value or "")


def _qr_history_entry_lines(row: sqlite3.Row, role: str) -> list[str]:
    status = str(row["status"] or "pending").lower()
    offer_state = str(row["offer_state"] or "").replace("_", " ").strip().title()
    if status == "done":
        status_text = "✅ Done"
    elif status == "failed":
        status_text = "❌ Failed"
    elif offer_state.lower() == "expired":
        status_text = "⌛ Expired"
    elif offer_state:
        status_text = f"⏳ Pending — {offer_state}"
    else:
        status_text = "⏳ Pending"
    amount_label = "Charged" if role == "sender" else "Earned"
    amount_value = row["charged_usdt"] if role == "sender" else row["earned_usdt"]
    # Privacy rule: never show the opposite party identity in user-facing QR history.
    # Senders and receivers/buyers must not see each other's chat IDs, aliases, usernames, or links.
    return [
        f"<b>QR ID:</b> <code>{esc(row['public_id'])}</code>",
        f"<b>Date/Time:</b> {esc(_history_datetime(row['created_at']))}",
        f"<b>Photo No:</b> #{esc(row['daily_no'])}",
        f"<b>Status:</b> {esc(status_text)}",
        f"<b>{amount_label}:</b> ${_money(amount_value)} USDT",
    ]


def _qr_history_text_keyboard(chat_id: int, user: UserRow, page: int = 0, page_size: int = 10) -> tuple[str, InlineKeyboardMarkup]:
    total = user_qr_history_count(chat_id, user.role)
    total_pages = max(1, (total + page_size - 1) // page_size) if total else 1
    page = max(0, min(int(page or 0), total_pages - 1))
    rows = user_qr_history_rows(chat_id, user.role, page_size, page * page_size)
    title = "📜 QR History"
    lines = [f"<b>{esc(title)} — Page {page + 1}/{total_pages}</b>", "Showing 10 QR logs per page, newest first.", ""]
    if not rows:
        lines.append("No QR history yet.")
    else:
        for idx, row in enumerate(rows, start=1):
            if idx > 1:
                lines.append("")
            lines.extend(_qr_history_entry_lines(row, user.role))
    buttons: list[list[InlineKeyboardButton]] = []
    nav: list[InlineKeyboardButton] = []
    if page > 0:
        nav.append(InlineKeyboardButton("⬅️ Previous", callback_data=f"qr_history:{page-1}"))
    if page + 1 < total_pages:
        nav.append(InlineKeyboardButton("Next ➡️", callback_data=f"qr_history:{page+1}"))
    if nav:
        buttons.append(nav)
    buttons.append([InlineKeyboardButton("⬅️ Back", callback_data="nav:home")])
    return "\n".join(lines), InlineKeyboardMarkup(buttons)


def _qr_history_text(chat_id: int, user: UserRow) -> str:
    text, _markup = _qr_history_text_keyboard(chat_id, user, 0)
    return text


async def history_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    observe_telegram_profile(update.effective_user)
    if not update.message or not update.effective_chat:
        return
    chat_id = update.effective_chat.id
    user = get_user(chat_id)
    if not user or not user.active:
        await update.message.reply_text("You are not registered yet.")
        return
    text, markup = _qr_history_text_keyboard(chat_id, user, 0)
    await update.message.reply_text(text, parse_mode="HTML", reply_markup=markup)


async def pending_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message or not update.effective_chat:
        return

    chat_id = update.effective_chat.id

    user = get_user(chat_id)
    if not user or user.role != "receiver" or not user.active:
        await update.message.reply_text("Only active receivers can use this.")
        return
    text, markup = _receiver_pending_text_keyboard(chat_id)
    await update.message.reply_text(text, reply_markup=markup)



# -----------------------------
# Preset message command handlers
# -----------------------------


def _audience_allows(audience: str, role: str) -> bool:
    return str(audience or "").strip().lower() in {role, "both"}


def _opposite_role(role: str) -> str:
    return "receiver" if role == "sender" else "sender"


def _preset_recipients_for_role(role: str) -> list[sqlite3.Row]:
    # Marketplace messaging is broadcast to the opposite active role.
    # QR offers remain limited to online receivers elsewhere in the bot.
    if role == "sender":
        return active_receivers()
    if role == "receiver":
        return active_senders()
    return []


def _message_event_route(initiator_chat_id: int, initiator_role: str, recipient_chat_id: int) -> tuple[int, int, str]:
    if initiator_role == "sender":
        return initiator_chat_id, recipient_chat_id, "sender_to_receiver"
    return recipient_chat_id, initiator_chat_id, "receiver_to_sender"


def _messages_menu_text(user: UserRow) -> str:
    target = "receivers" if user.role == "sender" else "senders"
    return (
        "💬 Marketplace preset messages\n\n"
        f"Choose a preset below. It will be sent to all active {target}.\n"
        "Any reply button they tap will come back only to you."
    )


async def _show_messages_menu(message_or_query, chat_id: int) -> None:
    user = get_user(chat_id)
    if not user or not user.active:
        text = "You are not registered yet."
        if hasattr(message_or_query, "edit_message_text"):
            await message_or_query.edit_message_text(text)
        else:
            await message_or_query.reply_text(text)
        return

    markup = build_template_keyboard(user.role, chat_id)
    if not markup:
        text = "No preset messages are available for your role right now."
        back = InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Back", callback_data="nav:home")]])
        if hasattr(message_or_query, "edit_message_text"):
            await message_or_query.edit_message_text(text, reply_markup=back)
        else:
            await message_or_query.reply_text(text, reply_markup=back)
        return

    rows = list(markup.inline_keyboard)
    rows.append([InlineKeyboardButton("⬅️ Back", callback_data="nav:home")])
    markup = InlineKeyboardMarkup(rows)
    if hasattr(message_or_query, "edit_message_text"):
        await message_or_query.edit_message_text(_messages_menu_text(user), reply_markup=markup)
    else:
        await message_or_query.reply_text(_messages_menu_text(user), reply_markup=markup)


async def messages_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    observe_telegram_profile(update.effective_user)
    if not update.message or not update.effective_chat:
        return
    if update.effective_chat.type != ChatType.PRIVATE:
        await update.message.reply_text("Please use preset messages only in private chat.")
        return
    await _show_messages_menu(update.message, update.effective_chat.id)


async def preset_send_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.message:
        return
    chat_id = query.message.chat.id
    data = query.data or ""
    parts = data.split(":")
    if len(parts) == 3:
        _prefix, owner_raw, template_raw = parts
        try:
            if int(owner_raw) != chat_id:
                await query.answer("This preset menu belongs to another account.", show_alert=True)
                return
        except ValueError:
            await query.answer("Invalid preset button.", show_alert=True)
            return
    elif len(parts) == 2:
        _prefix, template_raw = parts
    else:
        await query.answer("Invalid preset button.", show_alert=True)
        return

    user = get_user(chat_id)
    if not user or not user.active:
        await query.answer("You are not registered yet.", show_alert=True)
        return

    try:
        template_id = int(template_raw)
    except ValueError:
        await query.answer("Invalid preset button.", show_alert=True)
        return

    template = get_message_template(template_id)
    if not template or not int(template["active"]):
        await query.answer("This preset message is no longer active.", show_alert=True)
        return
    if not _audience_allows(str(template["audience"]), user.role):
        await query.answer("This preset is not available for your role.", show_alert=True)
        return

    recipient_role = _opposite_role(user.role)
    recipients = [r for r in _preset_recipients_for_role(user.role) if int(r["chat_id"]) != chat_id]
    if not recipients:
        await query.answer(f"No active {recipient_role}s found right now.", show_alert=True)
        return

    broadcast_id = f"msg_{int(time.time())}_{chat_id}_{template_id}_{secrets.token_hex(6)}"
    sent = 0
    failed = 0
    for recipient in recipients:
        recipient_chat_id = int(recipient["chat_id"])
        sender_chat_id, receiver_chat_id, direction = _message_event_route(chat_id, user.role, recipient_chat_id)
        event_id = create_message_event(
            template_id=template_id,
            initiator_chat_id=chat_id,
            recipient_chat_id=recipient_chat_id,
            sender_chat_id=sender_chat_id,
            receiver_chat_id=receiver_chat_id,
            direction=direction,
            delivered_message_id=None,
            broadcast_id=broadcast_id,
        )
        try:
            msg = await context.bot.send_message(
                chat_id=recipient_chat_id,
                text=build_delivered_preset_text(template, direction, event_id),
                reply_markup=build_reply_keyboard(event_id, template_id, recipient_role),
                protect_content=PROTECT_CONTENT,
            )
            update_message_event_delivery(event_id, msg.message_id)
            sent += 1
            await asyncio.sleep(0.03)
        except TelegramError as exc:
            logger.warning("Could not deliver preset message %s event %s to %s: %s", template_id, event_id, recipient_chat_id, exc)
            failed += 1

    if sent == 0:
        await query.answer(f"Could not send to any active {recipient_role} right now.", show_alert=True)
        return
    if failed:
        await query.answer(f"Sent to {sent}. {failed} failed.", show_alert=False)
    else:
        await query.answer("Sent ✅", show_alert=False)


async def _delete_or_close_marketplace_message(context: ContextTypes.DEFAULT_TYPE, event: sqlite3.Row) -> None:
    chat_id = int(event["recipient_chat_id"] or 0)
    message_id = event["delivered_message_id"]
    if not chat_id or not message_id:
        return
    try:
        await context.bot.delete_message(chat_id=chat_id, message_id=int(message_id))
        return
    except TelegramError:
        pass
    try:
        await context.bot.edit_message_text(
            chat_id=chat_id,
            message_id=int(message_id),
            text="✅ Already answered.\nThis marketplace message is closed.",
            reply_markup=None,
        )
    except TelegramError:
        try:
            await context.bot.edit_message_reply_markup(chat_id=chat_id, message_id=int(message_id), reply_markup=None)
        except TelegramError:
            pass


async def _clear_other_marketplace_messages(context: ContextTypes.DEFAULT_TYPE, events: list[sqlite3.Row]) -> None:
    for event in events:
        await _delete_or_close_marketplace_message(context, event)
        await asyncio.sleep(0.03)


async def preset_reply_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.message:
        return
    chat_id = query.message.chat.id
    data = query.data or ""
    try:
        _prefix, event_raw, reply_raw = data.split(":", 2)
        event_id = int(event_raw)
        reply_id = int(reply_raw)
    except Exception:
        await query.answer("Invalid reply button.", show_alert=True)
        return

    user = get_user(chat_id)
    if not user or not user.active:
        await query.answer("You are not registered yet.", show_alert=True)
        return

    event = get_message_event(event_id)
    reply = get_message_reply(reply_id)
    if not event or not reply or not int(reply["active"]):
        await query.answer("This preset reply is no longer available.", show_alert=True)
        return
    if int(event["recipient_chat_id"]) != chat_id:
        await query.answer("This reply button is not for your account.", show_alert=True)
        return
    if int(reply["template_id"]) != int(event["template_id"]):
        await query.answer("This reply does not match the original message.", show_alert=True)
        return
    if not _audience_allows(str(reply["audience"]), user.role):
        await query.answer("This reply is not available for your role.", show_alert=True)
        return

    claimed, reason, claimed_event, other_events = claim_message_broadcast_reply(event_id, reply_id)
    if not claimed:
        try:
            await query.edit_message_reply_markup(reply_markup=None)
        except TelegramError:
            pass
        if reason in {"already_answered", "closed"}:
            await query.answer("Already answered by someone else.", show_alert=True)
        else:
            await query.answer("This marketplace message is no longer available.", show_alert=True)
        return

    event = claimed_event or event
    template_for_notice = get_message_template(int(event["template_id"]))
    try:
        await context.bot.send_message(
            chat_id=int(event["initiator_chat_id"]),
            text=build_delivered_reply_text(reply, event_id, str(event["direction"]), template_for_notice),
            protect_content=PROTECT_CONTENT,
        )
    except TelegramError as exc:
        logger.warning("Could not deliver preset reply %s for event %s to %s: %s", reply_id, event_id, event["initiator_chat_id"], exc)
        await query.answer("Reply saved, but the sender could not be notified right now.", show_alert=True)
        return

    try:
        await query.edit_message_reply_markup(reply_markup=None)
    except TelegramError:
        pass
    await _clear_other_marketplace_messages(context, other_events)
    await query.answer("Reply sent ✅", show_alert=False)


# -----------------------------
# Sender / receiver flow
# -----------------------------


async def notify_active_senders(context: ContextTypes.DEFAULT_TYPE, text: str) -> tuple[int, int]:
    sent = 0
    failed = 0
    for sender in active_senders():
        try:
            await context.bot.send_message(chat_id=int(sender["chat_id"]), text=text, protect_content=PROTECT_CONTENT)
            sent += 1
            await asyncio.sleep(0.03)
        except TelegramError as exc:
            logger.warning("Could not notify sender %s: %s", sender["chat_id"], exc)
            failed += 1
    return sent, failed


async def on_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    observe_telegram_profile(update.effective_user)
    if not update.message or not update.effective_chat:
        return
    chat_id = update.effective_chat.id
    user = get_user(chat_id)
    if not user or user.role != "receiver" or not user.active:
        await update.message.reply_text("Only active receivers can use /on.")
        return
    try:
        limit = int(context.args[0]) if context.args else 0
    except ValueError:
        limit = 0
    if limit <= 0:
        await update.message.reply_text("Usage: /on LIMIT\nExample: /on 25")
        return
    set_receiver_online(chat_id, limit)
    await update.message.reply_text(f"🟢 You are online. Current limit: {limit} scans.")
    sent, failed = await notify_active_senders(
        context,
        f"🟢 A receiver is online now.\n📊 Current limit: {limit} scans.\n\nUse /status to see total live capacity.",
    )
    logger.info("Receiver %s online; notified senders sent=%s failed=%s", chat_id, sent, failed)


async def off_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    observe_telegram_profile(update.effective_user)
    if not update.message or not update.effective_chat:
        return
    chat_id = update.effective_chat.id
    user = get_user(chat_id)
    if not user or user.role != "receiver" or not user.active:
        await update.message.reply_text("Only active receivers can use /off.")
        return
    set_receiver_offline(chat_id)
    await update.message.reply_text("🔴 You are offline. New offers will stop until you use /on LIMIT again.")
    sent, failed = await notify_active_senders(
        context,
        "🔴 A receiver went offline.\nPlease check /status before sending more QRs.",
    )
    logger.info("Receiver %s offline; notified senders sent=%s failed=%s", chat_id, sent, failed)


async def marketplace_status_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    observe_telegram_profile(update.effective_user)
    if not update.message or not update.effective_chat:
        return
    user = get_user(update.effective_chat.id)
    if not user or not user.active:
        await update.message.reply_text("You are not registered yet.")
        return
    if user.role == "receiver":
        await update.message.reply_text("/status is only for senders. Use /pending for your QR tasks and /earnings for your balance.")
        return
    await update.message.reply_text(marketplace_status_text(update.effective_chat.id))


# In-memory wallet top-up states. These are short flows only; deposits themselves are persisted.
WALLET_TOPUP_FLOW: dict[int, dict] = {}
MANUAL_TXHASH_FLOW: dict[int, dict] = {}
WITHDRAW_FLOW: dict[int, dict] = {}
DISPUTE_FLOW: dict[int, dict] = {}
FAIL_REASON_FLOW: dict[int, dict] = {}
FAIL_REASON_CHOICES: dict[str, str] = {
    "qr_not_working": "QR not working",
    "qr_expired": "QR expired",
    "limit_over": "My limit is over",
}
FAIL_REASON_BUTTONS: list[tuple[str, str]] = [
    ("qr_not_working", "❌ QR not working"),
    ("qr_expired", "⏱ QR expired"),
    ("limit_over", "🚫 My limit is over"),
]


def _wallet_main_keyboard(user_role: str) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    if user_role == "sender":
        rows.append([InlineKeyboardButton("➕ Top-up Wallet", callback_data="nav:loadwallet")])
        rows.append([InlineKeyboardButton("👛 Wallet History", callback_data="wallet_history:0")])
    elif user_role == "receiver":
        rows.append([InlineKeyboardButton("💸 Withdraw", callback_data="withdraw:start")])
    rows.append([InlineKeyboardButton("⬅️ Back", callback_data="nav:home")])
    return InlineKeyboardMarkup(rows)


def _receiver_earnings_text(chat_id: int) -> str:
    wallet, _due, requested, available, _paid = receiver_earnings_numbers(chat_id)
    return (
        "💰 *Receiver earnings*\n\n"
        f"Total earned: *${_money(wallet['earned_usdt'])} USDT*\n"
        f"Paid: *${_money(wallet['paid_usdt'])} USDT*\n"
        f"Requested: *${_money(requested)} USDT*\n"
        f"Available to withdraw: *${_money(available)} USDT*"
    )


def _sender_wallet_text(chat_id: int) -> str:
    wallet = get_wallet(chat_id)
    available = _dec(wallet["balance_usdt"]) - _dec(wallet["reserved_usdt"])
    return (
        "👛 *Your Wallet*\n\n"
        f"💵 USDT Balance: *${_money(wallet['balance_usdt'])}*\n"
        f"🔒 Reserved: *${_money(wallet['reserved_usdt'])}*\n"
        f"✅ Available: *${_money(available)}*"
    )


def _topup_methods_keyboard(settings: dict | None = None) -> InlineKeyboardMarkup:
    settings = settings or get_marketplace_settings()
    rows: list[list[InlineKeyboardButton]] = []
    if payment_method_enabled("bep20", settings):
        rows.append([InlineKeyboardButton("🟡 USDT (BEP20)", callback_data="wallet_currency:bep20")])
    if payment_method_enabled("polygon", settings):
        rows.append([InlineKeyboardButton("🟣 USDT (POLYGON)", callback_data="wallet_currency:polygon")])
    if payment_method_enabled("binance", settings):
        rows.append([InlineKeyboardButton("🟡 Binance Pay", callback_data="wallet_currency:binance")])
    rows.append([InlineKeyboardButton("⬅️ Back", callback_data="nav:wallet")])
    return InlineKeyboardMarkup(rows)


def _payment_label(network: str) -> str:
    network = (network or "bep20").lower()
    if network == "polygon":
        return "USDT (POLYGON)"
    if network == "binance":
        return "Binance Pay"
    return "USDT (BEP20)"


def _payment_title(network: str) -> str:
    network = (network or "bep20").lower()
    if network == "polygon":
        return "🟣 *USDT (POLYGON) Payment*"
    if network == "binance":
        return "🟡 *Binance Pay*"
    return "🟡 *USDT (BEP20) Payment*"


def _network_line(network: str, confirmations: int | None = None) -> str:
    network = (network or "bep20").lower()
    if network == "polygon":
        base = "🌐 Network: *Polygon PoS*"
    elif network == "binance":
        base = "🌐 Network: *Binance Pay*"
    else:
        base = "🌐 Network: *BNB Smart Chain (BEP20)*"
    if confirmations and network in {"bep20", "polygon"}:
        return base + f"\n✅ Payment will be confirmed after *{confirmations} network confirmations*."
    return base


def _deposit_payment_keyboard(dep: sqlite3.Row) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[
        InlineKeyboardButton("🔄 Check Payment", callback_data=f"checkpay:{dep['ref_id']}"),
        InlineKeyboardButton("✍️ Manual Verify", callback_data=f"manualpay:{dep['ref_id']}"),
    ]])


def _format_payment_time_left(seconds_left: int | float) -> str:
    seconds = max(0, int(seconds_left))
    minutes, seconds = divmod(seconds, 60)
    return f"{minutes}m {seconds:02d}s"


def _deposit_seconds_left(dep: sqlite3.Row | dict) -> int:
    try:
        expires_raw = dep["expires_at"]
        expires_dt = datetime.fromisoformat(str(expires_raw))
        if expires_dt.tzinfo is None:
            expires_dt = expires_dt.replace(tzinfo=ZoneInfo(BOT_TZ))
        else:
            expires_dt = expires_dt.astimezone(ZoneInfo(BOT_TZ))
        return max(0, int(expires_dt.timestamp() - now_dt().timestamp()))
    except Exception:
        timeout_minutes = int(get_marketplace_settings().get("payment_timeout_minutes") or PAYMENT_TIMEOUT_MINUTES)
        return max(60, timeout_minutes * 60)


def _render_payment_template(template: str, dep: sqlite3.Row | dict) -> str:
    return (str(template or "")
        .replace("{{TIME_LEFT}}", _format_payment_time_left(_deposit_seconds_left(dep)))
        .replace("{TIME_LEFT}", _format_payment_time_left(_deposit_seconds_left(dep))))


def _manual_unlock_text(dep: sqlite3.Row | dict) -> tuple[bool, str]:
    settings = get_marketplace_settings()
    delay_minutes = max(0, int(settings.get("manual_verification_delay_minutes") or MANUAL_VERIFICATION_DELAY_MINUTES))
    try:
        created_dt = datetime.fromisoformat(str(dep["created_at"]))
        if created_dt.tzinfo is None:
            created_dt = created_dt.replace(tzinfo=ZoneInfo(BOT_TZ))
        else:
            created_dt = created_dt.astimezone(ZoneInfo(BOT_TZ))
        age_seconds = now_dt().timestamp() - created_dt.timestamp()
    except Exception:
        age_seconds = delay_minutes * 60
    remaining = max(0, delay_minutes * 60 - int(age_seconds))
    if remaining <= 0:
        return True, "Manual Verify is unlocked now."
    minutes = max(1, (remaining + 59) // 60)
    return False, f"Manual Verify unlocks in about {minutes} minute(s)."


def _deposit_expired_text(dep: sqlite3.Row) -> str:
    settings = get_marketplace_settings()
    timeout_minutes = max(1, int(settings.get("payment_timeout_minutes") or PAYMENT_TIMEOUT_MINUTES))
    return (
        "⏰ *Wallet Top-up Expired*\n\n"
        f"Wallet Top-up ID: `{dep['ref_id']}`\n"
        f"The payment was not completed within *{timeout_minutes} minutes*.\n\n"
        "Please start a new wallet top-up."
    )


def _deposit_pending_reminder_text(dep: sqlite3.Row) -> str:
    remaining_minutes = max(1, (_deposit_seconds_left(dep) + 59) // 60)
    return (
        "⌛ Wallet Top-up Still Pending\n\n"
        f"Wallet Top-up ID: `{dep['ref_id']}`\n\n"
        f"Your payment is still pending. It will expire in about *{remaining_minutes} minutes* if payment is not completed.\n\n"
        "If you already paid, use the payment buttons in the original message or contact support."
    )


def save_deposit_payment_message(ref_id: str, chat_id: int, message_id: int, template: str) -> None:
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE payment_deposits
            SET payment_chat_id = ?, payment_msg_id = ?, payment_message_template = ?
            WHERE ref_id = ?
            """,
            (chat_id, message_id, template, ref_id),
        )


async def refresh_deposit_payment_message(bot, dep: sqlite3.Row) -> None:
    if not dep["payment_chat_id"] or not dep["payment_msg_id"] or not dep["payment_message_template"]:
        return
    if dep["status"] != "waiting" or dep["credited_at"]:
        return
    try:
        await bot.edit_message_text(
            chat_id=int(dep["payment_chat_id"]),
            message_id=int(dep["payment_msg_id"]),
            text=_render_payment_template(str(dep["payment_message_template"]), dep),
            parse_mode="Markdown",
            reply_markup=_deposit_payment_keyboard(dep),
        )
    except TelegramError as exc:
        logger.debug("Could not update payment timer %s: %s", dep["ref_id"], exc)


async def delete_deposit_payment_message(bot, dep: sqlite3.Row) -> None:
    if not dep["payment_chat_id"] or not dep["payment_msg_id"]:
        return
    try:
        await bot.delete_message(
            chat_id=int(dep["payment_chat_id"]),
            message_id=int(dep["payment_msg_id"]),
        )
    except TelegramError as exc:
        logger.debug("Could not delete payment details message %s: %s", dep["ref_id"], exc)


async def clear_deposit_payment_buttons(bot, dep: sqlite3.Row) -> None:
    # Backward-compatible helper name: final payment states should remove the
    # payment details message entirely, not just hide the buttons.
    await delete_deposit_payment_message(bot, dep)


async def send_wallet_topup_completed_message(bot, chat_id: int, amount_usdt, balance_usdt) -> None:
    await bot.send_message(
        chat_id=int(chat_id),
        text=(
            "✅ Wallet Top-up Completed!\n\n"
            f"💰 ${_money(amount_usdt)} USDT added to your wallet.\n"
            f"👛 Current USDT Balance: ${_money(balance_usdt)}\n\n"
            "Use /wallet to check your balance."
        ),
        protect_content=PROTECT_CONTENT,
    )


def reserve_deposit_completed_notification(ref_id: str) -> bool:
    """Reserve the post-credit Telegram message so it is sent only once.

    Polygon and BEP20 can be checked by both the per-deposit poller and the
    global watcher. This DB flag prevents duplicate completion messages while
    still allowing a retry if Telegram rejects the send.
    """
    with get_conn() as conn:
        cur = conn.execute(
            """
            UPDATE payment_deposits
            SET topup_completed_notified_at = ?
            WHERE ref_id = ?
              AND credited_at IS NOT NULL
              AND COALESCE(topup_completed_notified_at, '') = ''
            """,
            (now_iso(), str(ref_id or '').strip().upper()),
        )
        return bool(cur.rowcount)


def reset_deposit_completed_notification(ref_id: str) -> None:
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE payment_deposits
            SET topup_completed_notified_at = NULL
            WHERE ref_id = ?
            """,
            (str(ref_id or '').strip().upper(),),
        )


async def send_deposit_completed_message(bot, dep: sqlite3.Row) -> None:
    dep_latest = get_deposit(str(dep["ref_id"])) or dep
    await delete_deposit_payment_message(bot, dep_latest)
    if not dep_latest["credited_at"]:
        return
    if not reserve_deposit_completed_notification(str(dep_latest["ref_id"])):
        return
    wallet = get_wallet(int(dep_latest["chat_id"]))
    try:
        await send_wallet_topup_completed_message(bot, int(dep_latest["chat_id"]), dep_latest["amount_usdt"], wallet["balance_usdt"])
    except TelegramError:
        reset_deposit_completed_notification(str(dep_latest["ref_id"]))
        raise


async def send_wallet_topup_rejected_message(bot, chat_id: int) -> None:
    await bot.send_message(
        chat_id=int(chat_id),
        text="❌ Your payment could not be verified. Please contact support if you believe this is a mistake.",
        protect_content=PROTECT_CONTENT,
    )


async def send_admin_wallet_adjustment_message(bot, adjustment: dict) -> None:
    amount = _dec(adjustment.get("amount"))
    balance_after = adjustment.get("balance_after")
    if amount >= 0:
        message_text = (
            "✅ Wallet balance added by admin.\n"
            f"Added: ${_money(abs(amount))} USDT\n"
            f"New USDT balance: ${_money(balance_after)} USDT\n"
            "Use /wallet to check your balance."
        )
    else:
        message_text = (
            "⚠️ Wallet balance adjusted by admin.\n"
            f"Removed: ${_money(abs(amount))} USDT\n"
            f"New USDT balance: ${_money(balance_after)} USDT\n"
            "Use /wallet to check your balance."
        )
    await bot.send_message(
        chat_id=int(adjustment["chat_id"]),
        text=message_text,
        protect_content=PROTECT_CONTENT,
    )


def _manual_failure_is_amount_mismatch(reason: str | None) -> bool:
    low = (reason or "").lower()
    return bool(
        re.search(r"amount\s+(?:does\s+not\s+match|mismatch|outside\s+tolerance)", low, flags=re.I)
        or re.search(r"received:\s*\$?\s*[0-9][0-9.,]*\s*usdt", low, flags=re.I)
        or "wrong amount" in low
    )


def _manual_failure_is_user_fixable(reason: str) -> bool:
    low = (reason or "").lower()
    # A real USDT tx to the payment wallet with an amount outside tolerance is
    # not an incorrect TxHash. Send it to admin review instead of asking the user
    # to keep submitting another hash.
    if _manual_failure_is_amount_mismatch(low):
        return False
    # These are clear TxHash/user-input problems. Do not move them to admin review;
    # ask the user to submit the correct transaction hash instead.
    return any(
        phrase in low
        for phrase in (
            "invalid transaction hash",
            "already been used",
            "duplicate",
            "not found on the selected network",
            "not a usdt transfer to your payment wallet",
            "not a usdt transfer on the selected network",
            "older than this payment request",
        )
    )



def _payment_status_label(status: str, credited_at: str | None = None) -> str:
    status = str(status or "").lower()
    if credited_at or status == "credited":
        return "✅ Completed"
    if status == "expired":
        return "❌ Expired"
    if status == "rejected":
        return "❌ Rejected"
    if status == "manual_pending":
        return "📝 Submitted for review"
    if status == "waiting":
        return "⏳ Pending"
    return status.replace("_", " ").title() or "Pending"


def _payment_method_label(method: str | None, network: str | None = None) -> str:
    key = normalize_payment_network(network or method)
    if key == "polygon":
        return "USDT (POLYGON)"
    if key == "binance":
        return "Binance Pay"
    return "USDT (BEP20)"


def _wallet_ledger_label(row: sqlite3.Row) -> str:
    kind = str(row["kind"] or "").lower()
    amount = _dec(row["amount_usdt"])
    if kind in {"manual_sender_adjust", "manual_receiver_adjust"}:
        return "Admin Wallet Add" if amount >= 0 else "Admin Wallet Remove"
    if kind == "receiver_payout_mark_paid":
        return "Earnings Payout Paid"
    if kind == "qr_done_debit":
        return "QR Scan Charge"
    if kind == "qr_done_earn":
        return "QR Scan Earning"
    if kind == "qr_failed_release":
        return "QR Reserve Released"
    if kind == "deposit_credit":
        return "Wallet Top-up Credit"
    return kind.replace("_", " ").title() or "Wallet Update"


def _wallet_ledger_payment_method_label(row: sqlite3.Row) -> str:
    amount = _dec(row["amount_usdt"])
    return "Admin wallet add" if amount >= 0 else "Admin wallet remove"


def _wallet_history_entries(chat_id: int) -> list[dict]:
    entries: list[dict] = []
    with get_conn() as conn:
        deposits = conn.execute(
            "SELECT * FROM payment_deposits WHERE chat_id = ? ORDER BY created_at DESC",
            (chat_id,),
        ).fetchall()
        ledgers = conn.execute(
            "SELECT * FROM wallet_ledger WHERE chat_id = ? ORDER BY created_at DESC",
            (chat_id,),
        ).fetchall()
    for dep in deposits:
        entries.append({
            "type": "deposit",
            "created_at": str(dep["created_at"] or ""),
            "ref_id": str(dep["ref_id"] or ""),
            "method": _payment_method_label(dep["method"], dep["network"]),
            "amount": _dec(dep["amount_usdt"]),
            "expected": _dec(dep["expected_usdt"]),
            "status": _payment_status_label(dep["status"], dep["credited_at"]),
            "note": str(dep["manual_note"] or "").strip(),
        })
    allowed_admin_adjustments = {"manual_sender_adjust", "manual_receiver_adjust"}
    for row in ledgers:
        # User-facing Wallet History should only show wallet top-up requests and
        # admin balance/earnings add-remove entries. Internal wallet movements
        # such as QR reserves, QR charges, QR earnings, reserve releases, payout
        # markers, and deposit_credit duplicates are intentionally hidden here.
        if str(row["kind"] or "").lower() not in allowed_admin_adjustments:
            continue
        entries.append({
            "type": "ledger",
            "created_at": str(row["created_at"] or ""),
            "label": _wallet_ledger_label(row),
            "method": _wallet_ledger_payment_method_label(row),
            "amount": _dec(row["amount_usdt"]),
            "balance_after": row["balance_after"],
            "note": str(row["note"] or "").strip(),
            "related_id": str(row["related_id"] or "").strip(),
        })
    entries.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
    return entries


def _wallet_history_text(chat_id: int, page: int = 0, page_size: int = 10) -> tuple[str, InlineKeyboardMarkup]:
    entries = _wallet_history_entries(chat_id)
    total = len(entries)
    total_pages = max(1, (total + page_size - 1) // page_size) if total else 1
    page = max(0, min(int(page or 0), total_pages - 1))
    shown = entries[page * page_size:(page + 1) * page_size]
    lines = [f"<b>👛 Wallet History — Page {page + 1}/{total_pages}</b>", "Showing wallet top-ups and admin balance updates, newest first.", ""]
    if not shown:
        lines.append("No wallet history yet.")
    else:
        for idx, item in enumerate(shown, start=1):
            if idx > 1:
                lines.append("")
            if item["type"] == "deposit":
                lines.extend([
                    f"<b>Wallet Top-up ID</b> <code>{esc(item['ref_id'])}</code>",
                    f"<b>Date/Time:</b> {esc(_history_datetime(item['created_at']))}",
                    f"<b>Payment Method:</b> {esc(item['method'])}",
                    f"<b>Amount:</b> ${_money(item['amount'])} USDT",
                    f"<b>Status:</b> {esc(item['status'])}",
                ])
            else:
                amount = _dec(item["amount"])
                sign = "+" if amount >= 0 else "-"
                lines.extend([
                    f"<b>{esc(item['label'])}</b>",
                    f"<b>Date/Time:</b> {esc(_history_datetime(item['created_at']))}",
                    f"<b>Payment Method:</b> {esc(item['method'])}",
                    f"<b>Amount:</b> {sign}${_money(abs(amount))} USDT",
                    "<b>Status:</b> ✅ Completed",
                ])
                if item.get("related_id"):
                    lines.append(f"<b>Related ID:</b> <code>{esc(item['related_id'])}</code>")
    buttons: list[list[InlineKeyboardButton]] = []
    nav: list[InlineKeyboardButton] = []
    if page > 0:
        nav.append(InlineKeyboardButton("⬅️ Previous", callback_data=f"wallet_history:{page-1}"))
    if page + 1 < total_pages:
        nav.append(InlineKeyboardButton("Next ➡️", callback_data=f"wallet_history:{page+1}"))
    if nav:
        buttons.append(nav)
    buttons.append([InlineKeyboardButton("➕ Top-up Again", callback_data="nav:loadwallet")])
    buttons.append([InlineKeyboardButton("⬅️ Back", callback_data="nav:wallet")])
    return "\n".join(lines), InlineKeyboardMarkup(buttons)


async def _send_wallet_home(message, chat_id: int) -> None:
    user = get_user(chat_id)
    if not user or not user.active:
        await message.reply_text("You are not registered yet.")
        return
    if user.role == "sender":
        await message.reply_text(
            _sender_wallet_text(chat_id),
            parse_mode="Markdown",
            reply_markup=_wallet_main_keyboard("sender"),
        )
    else:
        await message.reply_text(
            _receiver_earnings_text(chat_id),
            parse_mode="Markdown",
            reply_markup=_wallet_main_keyboard("receiver"),
        )


async def _send_load_wallet_options(message, chat_id: int) -> None:
    settings = get_marketplace_settings()
    if not available_payment_methods(settings):
        await message.reply_text(
            "👛 *Top-up Wallet*\n\n⚠️ No wallet top-up payment methods are configured right now. Please contact support.",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Back", callback_data="nav:wallet")]]),
        )
        return
    await message.reply_text(
        "👛 *Top-up Wallet*\n\nChoose how you'd like to add funds:",
        parse_mode="Markdown",
        reply_markup=_topup_methods_keyboard(settings),
    )


async def _send_topup_amount_prompt(message_or_query, chat_id: int, network: str) -> None:
    settings = get_marketplace_settings()
    min_topup = _dec(settings.get("wallet_min_usdt"), DEFAULT_MIN_WALLET_TOPUP_USDT)
    WALLET_TOPUP_FLOW[chat_id] = {"step": "amount", "network": network}
    text = (
        "💰 Enter the amount you want to top up in *$ (USDT)*.\n\n"
        f"Payment method: *{_payment_label(network)}*\n"
        f"_(Minimum: ${_money(min_topup)})_\n\n"
        "Press Back to abort."
    )
    markup = InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Back", callback_data="nav:loadwallet")]])
    if hasattr(message_or_query, "edit_message_text"):
        await message_or_query.edit_message_text(text, parse_mode="Markdown", reply_markup=markup)
    else:
        await message_or_query.reply_text(text, parse_mode="Markdown", reply_markup=markup)



PAYMENT_POLL_TASKS: dict[str, asyncio.Task] = {}


def schedule_deposit_payment_poll(application: Application | None, ref_id: str) -> None:
    """Start a Bot1-style per-deposit poller for faster auto-crediting.

    The global watcher remains as a safety net/resume worker, but each newly
    created top-up also gets its own lightweight poll task so Polygon/BEP20
    payments do not wait behind other deposits.
    """
    ref = str(ref_id or "").strip().upper()
    if not application or not ref:
        return
    existing = PAYMENT_POLL_TASKS.get(ref)
    if existing and not existing.done():
        return

    async def _runner() -> None:
        try:
            await poll_single_deposit_payment(application, ref)
        finally:
            PAYMENT_POLL_TASKS.pop(ref, None)

    try:
        task = application.create_task(_runner(), name=f"payment_poll_{ref}")
    except TypeError:
        task = application.create_task(_runner())
    PAYMENT_POLL_TASKS[ref] = task


async def poll_single_deposit_payment(application: Application, ref_id: str) -> None:
    first_check = True
    while True:
        dep = get_deposit(ref_id)
        if not dep:
            return
        if dep["credited_at"]:
            try:
                await send_deposit_completed_message(application.bot, dep)
            except TelegramError:
                pass
            return
        status = str(dep["status"] or "")
        if status not in ACTIVE_PAYMENT_CHECK_STATUSES:
            return
        if status == "manual_pending" and not str(dep["tx_hash"] or "").strip():
            return
        settings = get_marketplace_settings()
        interval_seconds = max(5, int(settings.get("payment_watch_interval_seconds") or PAYMENT_WATCH_INTERVAL_SECONDS))
        reminder_minutes = max(0, int(settings.get("payment_reminder_minutes") or PAYMENT_REMINDER_MINUTES))

        # Do the first check shortly after creating the payment page, then use the
        # configured interval. This mirrors the reference bot but avoids waiting a
        # full global watcher cycle.
        await asyncio.sleep(3 if first_check else interval_seconds)
        first_check = False

        dep = get_deposit(ref_id)
        if not dep:
            return
        if dep["credited_at"]:
            try:
                await send_deposit_completed_message(application.bot, dep)
            except TelegramError:
                pass
            return
        status = str(dep["status"] or "")
        if status not in ACTIVE_PAYMENT_CHECK_STATUSES:
            return
        await _process_one_payment_auto_check(application, dep, reminder_minutes)

        dep_after = get_deposit(ref_id)
        if not dep_after or dep_after["credited_at"] or str(dep_after["status"] or "") not in ACTIVE_PAYMENT_CHECK_STATUSES:
            return

async def _send_deposit_payment_message(message, dep: sqlite3.Row, context: ContextTypes.DEFAULT_TYPE | None = None) -> None:
    network = str(dep["network"] or "bep20").lower()
    expected = _money3(dep["expected_usdt"])
    amount = _money(dep["amount_usdt"])
    pay_to = str(dep["pay_to"] or "").strip()
    pay_to_name = str(dep["pay_to_name"] or "").strip()
    settings = get_marketplace_settings()
    confirmations = int(settings.get("polygon_required_confirmations") if network == "polygon" else settings.get("bep20_required_confirmations") or 0)
    if network == "binance":
        details = (
            f"🆔 Binance Pay ID: `{pay_to}`\n"
            f"👤 Name: {esc(pay_to_name or 'Binance Pay')}\n\n"
            "*Steps:*\n"
            f"1️⃣ Open Binance app → Pay → Send\n"
            f"2️⃣ Search Pay ID: `{pay_to}`\n"
            "3️⃣ Send exactly the unique USDT amount above\n\n"
            "⚠️ Do not round the amount. The unique decimals identify your wallet top-up automatically.\n"
            f"🌐 Network: *Binance Pay*\n"
        )
    else:
        details = (
            "To this wallet:\n"
            f"`{pay_to}`\n\n"
            "⚠️ Send the exact amount shown above. The final USDT received must be exact; do not let exchange/network fees reduce this amount.\n"
            f"{_network_line(network, confirmations)}\n"
        )
    interval_seconds = int(get_marketplace_settings().get("payment_watch_interval_seconds") or PAYMENT_WATCH_INTERVAL_SECONDS)
    template = (
        f"{_payment_title(network)}\n\n"
        f"📋 Wallet Top-up ID `{dep['ref_id']}` | ${amount} USDT\n\n"
        "Send this amount:\n"
        f"```\n{expected} USDT\n```\n"
        f"{details}\n"
        "⏳ Time left: *{{TIME_LEFT}}*\n"
        f"🔄 Bot checks automatically every {interval_seconds} seconds until this top-up is credited or expired.\n"
        "🧾 If you already paid and it is not verified, tap *Manual Verify* below."
    )
    sent = await message.reply_text(
        _render_payment_template(template, dep),
        parse_mode="Markdown",
        reply_markup=_deposit_payment_keyboard(dep),
    )
    save_deposit_payment_message(dep["ref_id"], int(sent.chat_id), int(sent.message_id), template)
    schedule_deposit_payment_poll(getattr(context, "application", None) if context else None, str(dep["ref_id"]))


async def wallet_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    observe_telegram_profile(update.effective_user)
    if not update.message or not update.effective_chat:
        return
    chat_id = update.effective_chat.id
    user = get_user(chat_id)
    if not user or not user.active:
        await update.message.reply_text("You are not registered yet.")
        return
    if user.role != "sender":
        await update.message.reply_text("Only active senders can use /wallet.")
        return
    await update.message.reply_text(
        _sender_wallet_text(chat_id),
        parse_mode="Markdown",
        reply_markup=_wallet_main_keyboard("sender"),
    )


async def loadwallet_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    observe_telegram_profile(update.effective_user)
    if not update.message or not update.effective_chat:
        return
    user = get_user(update.effective_chat.id)
    if not user or user.role != "sender" or not user.active:
        await update.message.reply_text("Only active senders can load wallet.")
        return
    if not context.args:
        await _send_load_wallet_options(update.message, update.effective_chat.id)
        return
    # Compatibility: /loadwallet 25 bep20 still works, but the bot no longer presents that as the main flow.
    if len(context.args) < 2:
        await update.message.reply_text("Use /loadwallet to top up your wallet.")
        return
    amount = _dec(context.args[0])
    method = context.args[1].strip().lower()
    if amount <= 0:
        await update.message.reply_text("Amount must be greater than 0.")
        return
    try:
        dep = create_deposit(update.effective_chat.id, amount, method)
    except Exception as exc:
        await update.message.reply_text(f"Could not create deposit: {exc}")
        return
    await _send_deposit_payment_message(update.message, dep, context)


async def wallet_nav_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.message:
        return
    await query.answer()
    chat_id = query.message.chat.id
    data = query.data or ""
    user = get_user(chat_id)

    if data == "nav:commands":
        await query.edit_message_text(
            commands_help_text(user),
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Back", callback_data="nav:home")]]),
        )
        return
    if data == "nav:support":
        await query.edit_message_text(
            "🛟 Support\n\n"
            f"Contact: {support_display_text()}\n\n"
            "Use the button below to open the support chat directly.",
            reply_markup=support_keyboard(include_back=True),
        )
        return
    if data == "nav:home":
        WALLET_TOPUP_FLOW.pop(chat_id, None)
        MANUAL_TXHASH_FLOW.pop(chat_id, None)
        WITHDRAW_FLOW.pop(chat_id, None)
        DISPUTE_FLOW.pop(chat_id, None)
        FAIL_REASON_FLOW.pop(chat_id, None)
        await query.edit_message_text(
            main_menu_text(user, chat_id),
            parse_mode="HTML",
            reply_markup=main_menu_keyboard(user),
        )
        return

    if not user or not user.active:
        await query.edit_message_text(
            "You are not registered yet. Use Support below to request access.",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🛟 Support", callback_data="nav:support")],
                [InlineKeyboardButton("⬅️ Back", callback_data="nav:home")],
            ]),
        )
        return

    if data == "nav:messages":
        await _show_messages_menu(query, chat_id)
        return

    if data == "nav:wallet":
        if user.role == "receiver":
            await query.edit_message_text(
                _receiver_earnings_text(chat_id),
                parse_mode="Markdown",
                reply_markup=_wallet_main_keyboard("receiver"),
            )
        else:
            await query.edit_message_text(
                _sender_wallet_text(chat_id),
                parse_mode="Markdown",
                reply_markup=_wallet_main_keyboard("sender"),
            )
        return
    if data == "nav:loadwallet":
        if user.role != "sender":
            await query.edit_message_text("Only senders can load wallet.")
            return
        settings = get_marketplace_settings()
        if not available_payment_methods(settings):
            await query.edit_message_text(
                "👛 *Top-up Wallet*\n\n⚠️ No wallet top-up payment methods are configured right now. Please contact support.",
                parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Back", callback_data="nav:wallet")]]),
            )
            return
        await query.edit_message_text(
            "👛 *Top-up Wallet*\n\nChoose how you'd like to add funds:",
            parse_mode="Markdown",
            reply_markup=_topup_methods_keyboard(settings),
        )
        return
    if data == "nav:status":
        if user.role != "sender":
            await query.edit_message_text(
                "/status is only for senders. Use Pending QR and Earnings from the receiver menu.",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Back", callback_data="nav:home")]]),
            )
            return
        await query.edit_message_text(
            marketplace_status_text(chat_id),
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Back", callback_data="nav:home")]]),
        )
        return
    if data == "nav:pending":
        if user.role != "receiver":
            await query.edit_message_text("Only receivers have pending QR tasks.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Back", callback_data="nav:home")]]))
            return
        text, markup = _receiver_pending_text_keyboard(chat_id)
        if markup:
            rows = list(markup.inline_keyboard)
            rows.append([InlineKeyboardButton("⬅️ Back", callback_data="nav:home")])
            markup = InlineKeyboardMarkup(rows)
        else:
            markup = InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Back", callback_data="nav:home")]])
        await query.edit_message_text(text, reply_markup=markup)
        return
    if data == "nav:history":
        text, markup = _qr_history_text_keyboard(chat_id, user, 0)
        await query.edit_message_text(text, parse_mode="HTML", reply_markup=markup)
        return
    if data == "nav:dispute":
        DISPUTE_FLOW[chat_id] = {"public_id": None, "step": "reason"}
        await query.edit_message_text(
            "⚠️ *Open dispute*\n\nPlease send the reason for this dispute now.",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Cancel", callback_data="nav:home")]]),
        )
        return
    if data == "nav:stats":
        if user.role == "sender":
            text = stats_summary_text("Your sender stats", sender_chat_id=chat_id)
        else:
            text = stats_summary_text("Your receiver stats", receiver_chat_id=chat_id)
        await query.edit_message_text(
            text,
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Back", callback_data="nav:home")]]),
        )
        return


async def wallet_currency_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.message:
        return
    chat_id = query.message.chat.id
    user = get_user(chat_id)
    if not user or user.role != "sender" or not user.active:
        await query.answer("Only active senders can load wallet.", show_alert=True)
        return
    network = (query.data or "").split(":", 1)[1].strip().lower()
    if not payment_method_enabled(network):
        await query.answer("That payment method is disabled right now.", show_alert=True)
        return
    await query.answer()
    await _send_topup_amount_prompt(query, chat_id, network)


async def qr_history_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.message:
        return
    chat_id = query.message.chat.id
    user = get_user(chat_id)
    if not user or not user.active:
        await query.answer("You are not registered.", show_alert=True)
        return
    await query.answer()
    try:
        page = int((query.data or "qr_history:0").split(":", 1)[1])
    except Exception:
        page = 0
    text, markup = _qr_history_text_keyboard(chat_id, user, page)
    await query.edit_message_text(text, parse_mode="HTML", reply_markup=markup)


async def wallet_history_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.message:
        return
    chat_id = query.message.chat.id
    user = get_user(chat_id)
    if not user or not user.active:
        await query.answer("You are not registered.", show_alert=True)
        return
    await query.answer()
    try:
        page = int((query.data or "wallet_history:0").split(":", 1)[1])
    except Exception:
        page = 0
    text, markup = _wallet_history_text(chat_id, page)
    await query.edit_message_text(text, parse_mode="HTML", reply_markup=markup)


async def _safe_callback_answer(query, text: str | None = None, show_alert: bool = False) -> bool:
    try:
        await query.answer(text=text, show_alert=show_alert)
        return True
    except TelegramError as exc:
        # Telegram callback queries expire quickly. Polygon checks can take longer
        # than the answer window when public RPC/explorer endpoints are slow, so
        # never let an expired callback stop the wallet-credit notification path.
        logger.info("Could not answer callback query: %s", exc)
        return False


async def check_payment_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.message:
        return
    ref_id = (query.data or "").split(":", 1)[1].strip().upper()
    dep = get_deposit(ref_id)
    if not dep:
        await _safe_callback_answer(query, "Payment session not found.", show_alert=True)
        return
    if int(dep["chat_id"]) != int(query.from_user.id):
        await _safe_callback_answer(query, "This payment session is not yours.", show_alert=True)
        return
    if dep["credited_at"] or dep["status"] in {"credited", "confirmed"}:
        await _safe_callback_answer(query, "✅ Wallet top-up already completed.", show_alert=True)
        try:
            await send_deposit_completed_message(context.bot, dep)
        except TelegramError:
            pass
        return
    if dep["status"] not in ACTIVE_PAYMENT_CHECK_STATUSES:
        await _safe_callback_answer(query, "⚠️ This payment session is already processed or expired.", show_alert=True)
        await delete_deposit_payment_message(context.bot, dep)
        return

    # Answer immediately before the chain scan. If the Polygon RPC fallback takes
    # more than Telegram's callback-query window, the handler can still finish and
    # send the same completion message as BEP20.
    answered = await _safe_callback_answer(query, "🔄 Checking payment...", show_alert=False)
    tx_hash = str(dep["tx_hash"] or "").strip() or None
    use_hash = tx_hash
    ok, reason = await verify_and_credit_deposit_async(ref_id, use_hash, False, "check_button")
    if ok:
        await _safe_callback_answer(query, "✅ Payment detected! Processing...", show_alert=False)
        try:
            dep_after = get_deposit(ref_id) or dep
            await send_deposit_completed_message(context.bot, dep_after)
        except TelegramError:
            pass
    else:
        _unlocked, unlock_text = _manual_unlock_text(dep)
        not_found_text = f"❌ Payment not found yet. Payment check is still running. {unlock_text}"
        final_answered = await _safe_callback_answer(query, not_found_text, show_alert=True)
        if answered and not final_answered:
            try:
                await query.message.reply_text(not_found_text)
            except TelegramError:
                pass


async def manual_payment_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.message:
        return
    ref_id = (query.data or "").split(":", 1)[1].strip().upper()
    dep = get_deposit(ref_id)
    if not dep:
        await query.answer("Payment session not found.", show_alert=True)
        return
    if int(dep["chat_id"]) != int(query.from_user.id):
        await query.answer("This payment session is not yours.", show_alert=True)
        return
    active_manual = MANUAL_TXHASH_FLOW.get(int(query.from_user.id)) or {}
    if active_manual.get("ref_id") == ref_id and active_manual.get("step") == "screenshot":
        await query.answer("Please send the screenshot proof first.", show_alert=True)
        return
    if dep["credited_at"] or dep["status"] in {"credited", "confirmed"}:
        await query.answer("✅ Wallet top-up already completed.", show_alert=True)
        try:
            await send_deposit_completed_message(context.bot, dep)
        except TelegramError:
            pass
        return
    if dep["status"] != "waiting":
        await query.answer("⚠️ This payment session is already processed or expired.", show_alert=True)
        await delete_deposit_payment_message(context.bot, dep)
        return

    unlocked, unlock_text = _manual_unlock_text(dep)
    if not unlocked:
        await query.answer(f"Payment check is still running.\n{unlock_text}", show_alert=True)
        return

    network = str(dep["network"] or dep["method"] or "").lower()
    if network == "binance":
        await query.answer("Checking Binance Pay history...", show_alert=False)
        ok, reason = await verify_and_credit_deposit_async(ref_id, None, True, "manual_binance")
        if ok:
            dep_after = get_deposit(ref_id) or dep
            await delete_deposit_payment_message(context.bot, dep_after)
            await send_deposit_completed_message(context.bot, dep_after)
        else:
            with get_conn() as conn:
                conn.execute(
                    "UPDATE payment_deposits SET status='manual_pending', manual_check_result='pending', manual_note=?, manual_submitted_at=? WHERE ref_id=? AND credited_at IS NULL",
                    (reason[:500], now_iso(), ref_id),
                )
            await delete_deposit_payment_message(context.bot, dep)
            await query.message.reply_text(
                "⏳ Manual Binance Pay verification submitted for review.\n"
                f"Reference: {ref_id}"
            )
        return

    MANUAL_TXHASH_FLOW[int(query.from_user.id)] = {"step": "txn_hash", "ref_id": ref_id}
    await query.answer()
    await query.message.reply_text(
        "🔍 *Manual USDT Verification*\n\n"
        "Please send your *USDT transaction hash / TxID* first.\n"
        "After that, you will be asked for a screenshot proof.\n\n"
        "_(TxID usually starts with 0x... — find it in your wallet's transaction history)_",
        parse_mode="Markdown",
    )


async def wallet_text_flow(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message or not update.effective_chat or not update.message.text:
        return
    chat_id = update.effective_chat.id
    user = get_user(chat_id)
    if not user or not user.active:
        return
    text = update.message.text.strip()
    if chat_id in FAIL_REASON_FLOW:
        await update.message.reply_text("Please select one of the failure reason buttons.")
        return
    if chat_id in DISPUTE_FLOW:
        await submit_dispute_reason(update.message, chat_id, text)
        return
    if chat_id in WITHDRAW_FLOW:
        state = WITHDRAW_FLOW.get(chat_id) or {}
        step = state.get("step")
        if step in {"details", "payment_choice"}:
            await submit_withdraw_details(update.message, chat_id, text)
            return
        amount = _dec(text, "-1")
        await submit_withdraw_amount(update.message, chat_id, amount)
        return
    if chat_id in MANUAL_TXHASH_FLOW:
        state = MANUAL_TXHASH_FLOW.get(chat_id) or {}
        if state.get("step") == "screenshot":
            await update.message.reply_text("📸 Please send a screenshot/photo proof, not text.")
            return
        ref_id = str(state.get("ref_id") or "").upper()
        tx_hash = text.strip()
        dep = get_deposit(ref_id)
        if not dep or int(dep["chat_id"]) != chat_id:
            MANUAL_TXHASH_FLOW.pop(chat_id, None)
            await update.message.reply_text("Payment session not found anymore.")
            return
        if dep["credited_at"] or dep["status"] != "waiting":
            MANUAL_TXHASH_FLOW.pop(chat_id, None)
            await update.message.reply_text("⚠️ This payment session is already processed or expired.")
            return
        if not re.fullmatch(r"0x[a-fA-F0-9]{64}", tx_hash):
            await update.message.reply_text("❌ Please send a valid USDT transaction hash / TxID. It should look like `0x...`", parse_mode="Markdown")
            return
        checking_msg = await update.message.reply_text("🔎 Checking transaction hash...")
        try:
            ok, reason = await verify_and_credit_deposit_async(ref_id, tx_hash, True, "manual_tx_hash")
        finally:
            await delete_message_safely(
                context,
                chat_id,
                checking_msg.message_id,
                "manual transaction hash checking message",
            )
        if ok:
            MANUAL_TXHASH_FLOW.pop(chat_id, None)
            dep_after = get_deposit(ref_id) or dep
            await delete_deposit_payment_message(context.bot, dep_after)
            await send_deposit_completed_message(context.bot, dep_after)
        else:
            public_reason = _public_payment_error_text(reason)
            if _manual_failure_is_amount_mismatch(reason) or _manual_failure_is_amount_mismatch(public_reason):
                MANUAL_TXHASH_FLOW[chat_id] = {"step": "screenshot", "ref_id": ref_id, "tx_hash": tx_hash, "reason": public_reason}
                await update.message.reply_text(
                    "📸 Please send a screenshot proof of this USDT payment.\n\n"
                    "Your TxHash needs admin review before this wallet top-up can be approved.",
                    parse_mode="Markdown",
                )
                return
            if _manual_failure_is_user_fixable(reason):
                MANUAL_TXHASH_FLOW[chat_id] = {"step": "txn_hash", "ref_id": ref_id}
                if "already been used" in public_reason.lower() or "already linked" in public_reason.lower() or "duplicate" in public_reason.lower():
                    await update.message.reply_text(
                        "❌ This transaction hash has already been used for a wallet top-up.\n\n"
                        "Please submit a different, unused USDT transaction hash."
                    )
                else:
                    await update.message.reply_text(
                        "❌ The transaction hash you submitted is incorrect.\n\n"
                        "Please send the correct USDT transaction hash / TxID for this wallet top-up."
                    )
                return
            MANUAL_TXHASH_FLOW[chat_id] = {"step": "screenshot", "ref_id": ref_id, "tx_hash": tx_hash, "reason": public_reason}
            await update.message.reply_text(
                "📸 Now send a screenshot proof of this USDT payment.\n\n"
                "If the TxHash could not be auto-verified, support will review the proof.",
                parse_mode="Markdown",
            )
        return
    state = WALLET_TOPUP_FLOW.get(chat_id)
    if not state or state.get("step") != "amount":
        return
    try:
        amount = _dec(text)
    except Exception:
        await update.message.reply_text("❌ Enter a valid number.")
        return
    if amount <= 0:
        await update.message.reply_text("❌ Amount must be greater than zero.")
        return
    network = str(state.get("network") or "bep20")
    settings = get_marketplace_settings()
    min_topup = _dec(settings.get("wallet_min_usdt"), DEFAULT_MIN_WALLET_TOPUP_USDT)
    if amount < min_topup:
        await update.message.reply_text(f"❌ Minimum top-up amount is ${_money(min_topup)}.")
        return
    WALLET_TOPUP_FLOW.pop(chat_id, None)
    try:
        dep = create_deposit(chat_id, amount, network)
    except Exception as exc:
        await update.message.reply_text(f"Could not create deposit: {exc}")
        return
    await _send_deposit_payment_message(update.message, dep, context)


async def wallet_manual_screenshot_flow(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    if not update.message or not update.effective_chat:
        return False
    chat_id = update.effective_chat.id
    state = MANUAL_TXHASH_FLOW.get(chat_id)
    if not state or state.get("step") != "screenshot":
        return False
    if not update.message.photo:
        await update.message.reply_text("📸 Please send a screenshot/photo proof.")
        return True
    ref_id = str(state.get("ref_id") or "").upper()
    tx_hash = str(state.get("tx_hash") or "").strip()
    dep = get_deposit(ref_id)
    MANUAL_TXHASH_FLOW.pop(chat_id, None)
    if not dep or int(dep["chat_id"]) != chat_id:
        await update.message.reply_text("Payment session not found anymore.")
        return True
    proof_file_id = update.message.photo[-1].file_id
    normalized_hash = normalize_tx_hash(tx_hash)
    pending_tx_key = None
    if normalized_hash:
        reserved, pending_tx_key, reserve_reason = reserve_tx_hash(
            network=str(dep["network"] or dep["method"]),
            tx_hash=normalized_hash,
            ref_id=ref_id,
            chat_id=chat_id,
            source="manual_screenshot",
            status="manual_pending",
            allow_existing_for_ref=True,
        )
        if not reserved:
            await update.message.reply_text("❌ This transaction hash has already been used for another wallet top-up.")
            return True
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE payment_deposits
            SET status='manual_pending', tx_hash=COALESCE(?, tx_hash), tx_hash_key=COALESCE(?, tx_hash_key),
                manual_proof_file_id=?, manual_submitted_at=?,
                manual_check_result=CASE WHEN manual_check_result IS NULL OR manual_check_result='' OR manual_check_result='pending' THEN 'failed' ELSE manual_check_result END,
                manual_note=COALESCE(manual_note, ?)
            WHERE ref_id=? AND credited_at IS NULL AND status IN ('waiting','manual_pending')
            """,
            (normalized_hash, pending_tx_key, proof_file_id, now_iso(), str(state.get("reason") or "Manual proof submitted")[:500], ref_id),
        )
    await delete_deposit_payment_message(context.bot, dep)
    await update.message.reply_text(
        "⏳ Manual verification submitted for admin review.\n"
        f"Reference: {ref_id}",
    )
    return True


async def earnings_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    observe_telegram_profile(update.effective_user)
    if not update.message or not update.effective_chat:
        return
    chat_id = update.effective_chat.id
    user = get_user(chat_id)
    if not user or not user.active:
        await update.message.reply_text("You are not registered yet.")
        return
    if user.role != "receiver":
        await update.message.reply_text("Only active receivers can use /earnings.")
        return
    await update.message.reply_text(
        _receiver_earnings_text(chat_id),
        parse_mode="Markdown",
        reply_markup=_wallet_main_keyboard("receiver"),
    )


async def _send_withdraw_amount_prompt(message_or_query, chat_id: int) -> None:
    settings = get_marketplace_settings()
    min_payout = _dec(settings["min_payout_usdt"])
    _wallet, due, requested, available, _paid = receiver_earnings_numbers(chat_id)
    WITHDRAW_FLOW[chat_id] = {"step": "amount"}
    text = (
        "💸 Withdraw\n"
        f"Available: ${_money(available)} USDT\n"
        f"Minimum: ${_money(min_payout)} USDT\n\n"
        "Send quantity."
    )
    markup = InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Back", callback_data="nav:wallet")]])
    if hasattr(message_or_query, "edit_message_text"):
        await message_or_query.edit_message_text(text, reply_markup=markup)
    else:
        await message_or_query.reply_text(text, reply_markup=markup)


async def _send_withdraw_details_prompt(message_or_query, chat_id: int, amount: Decimal | None = None) -> None:
    state: dict[str, Any] = {"step": "details"}
    if amount is not None:
        state["amount"] = str(amount)
    WITHDRAW_FLOW[chat_id] = state
    text = "💳 Send payment details."
    markup = InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Cancel", callback_data="nav:wallet")]])
    if hasattr(message_or_query, "edit_message_text"):
        await message_or_query.edit_message_text(text, reply_markup=markup)
    else:
        await message_or_query.reply_text(text, reply_markup=markup)


async def _send_withdraw_payment_choice_prompt(message_or_query, chat_id: int, amount: Decimal, saved_details: str) -> None:
    WITHDRAW_FLOW[chat_id] = {"step": "payment_choice", "amount": str(amount)}
    text = (
        "💳 Payment details?\n"
        f"Quantity: ${_money(amount)} USDT"
    )
    markup = InlineKeyboardMarkup([
        [InlineKeyboardButton(payment_method_button_label(saved_details), callback_data="withdraw:use_saved")],
        [InlineKeyboardButton("✏️ Enter new payment details", callback_data="withdraw:new_details")],
        [InlineKeyboardButton("⬅️ Cancel", callback_data="nav:wallet")],
    ])
    if hasattr(message_or_query, "edit_message_text"):
        await message_or_query.edit_message_text(text, reply_markup=markup)
    else:
        await message_or_query.reply_text(text, reply_markup=markup)


async def _send_withdraw_prompt(message_or_query, chat_id: int) -> None:
    user = get_user(chat_id)
    if not user or user.role != "receiver" or not user.active:
        text = "Only active receivers can request payout."
        if hasattr(message_or_query, "edit_message_text"):
            await message_or_query.edit_message_text(text)
        else:
            await message_or_query.reply_text(text)
        return
    settings = get_marketplace_settings()
    min_payout = _dec(settings["min_payout_usdt"])
    _wallet, _due, _requested, available, _paid = receiver_earnings_numbers(chat_id)
    back_markup = InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Back", callback_data="nav:wallet")]])
    if available < min_payout:
        WITHDRAW_FLOW.pop(chat_id, None)
        text = (
            "💸 Withdraw\n"
            f"Available: ${_money(available)} USDT\n"
            f"Minimum: ${_money(min_payout)} USDT"
        )
        if hasattr(message_or_query, "edit_message_text"):
            await message_or_query.edit_message_text(text, reply_markup=back_markup)
        else:
            await message_or_query.reply_text(text, reply_markup=back_markup)
        return

    await _send_withdraw_amount_prompt(message_or_query, chat_id)


async def withdraw_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    observe_telegram_profile(update.effective_user)
    if not update.message or not update.effective_chat:
        return
    user = get_user(update.effective_chat.id)
    if not user or user.role != "receiver" or not user.active:
        await update.message.reply_text("Only active receivers can request payout.")
        return
    if context.args:
        amount = _dec(context.args[0])
        await submit_withdraw_amount(update.message, update.effective_chat.id, amount)
        return
    await _send_withdraw_prompt(update.message, update.effective_chat.id)


async def withdraw_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.message:
        return
    chat_id = query.message.chat.id
    data = query.data or "withdraw:start"
    user = get_user(chat_id)
    if not user or user.role != "receiver" or not user.active:
        await query.answer("Only active receivers can request payout.", show_alert=True)
        return
    await query.answer()
    if data == "withdraw:start":
        await _send_withdraw_prompt(query, chat_id)
        return
    if data == "withdraw:new_details":
        state = WITHDRAW_FLOW.get(chat_id) or {}
        amount = _dec(str(state.get("amount") or "0"), "0")
        await _send_withdraw_details_prompt(query, chat_id, amount if amount > 0 else None)
        return
    if data == "withdraw:use_saved":
        state = WITHDRAW_FLOW.get(chat_id) or {}
        amount = _dec(str(state.get("amount") or "0"), "0")
        saved_details = get_receiver_payout_details(chat_id)
        if amount <= 0:
            await _send_withdraw_amount_prompt(query, chat_id)
            return
        if not saved_details:
            await _send_withdraw_details_prompt(query, chat_id, amount)
            return
        await submit_withdraw_request(query, chat_id, amount, saved_details)
        return
    await _send_withdraw_prompt(query, chat_id)


async def submit_withdraw_details(message, chat_id: int, details_text: str) -> None:
    user = get_user(chat_id)
    if not user or user.role != "receiver" or not user.active:
        await message.reply_text("Only active receivers can request payout.")
        return
    details = clean_payout_details_text(details_text)
    if len(details) < 4:
        await message.reply_text("Send payment details.")
        return
    save_receiver_payout_details(chat_id, details)
    state = WITHDRAW_FLOW.get(chat_id) or {}
    pending_amount = state.get("amount")
    if pending_amount is not None:
        amount = _dec(str(pending_amount), "-1")
        await submit_withdraw_request(message, chat_id, amount, details)
        return
    await message.reply_text("✅ Payment details saved.")
    await _send_withdraw_amount_prompt(message, chat_id)


async def submit_withdraw_amount(message, chat_id: int, amount: Decimal) -> None:
    user = get_user(chat_id)
    if not user or user.role != "receiver" or not user.active:
        await message.reply_text("Only active receivers can request payout.")
        return
    settings = get_marketplace_settings()
    min_payout = _dec(settings["min_payout_usdt"])
    _wallet, due, requested, available, _paid = receiver_earnings_numbers(chat_id)
    if amount <= 0:
        await message.reply_text("Send a valid quantity.")
        return
    if amount < min_payout:
        await message.reply_text(f"Minimum payout is ${_money(min_payout)} USDT.")
        return
    if amount > available:
        await message.reply_text(
            f"Available: ${_money(available)} USDT\n"
            f"Due: ${_money(due)} USDT · Requested: ${_money(requested)} USDT"
        )
        return

    saved_details = get_receiver_payout_details(chat_id)
    if saved_details:
        await _send_withdraw_payment_choice_prompt(message, chat_id, amount, saved_details)
        return
    await _send_withdraw_details_prompt(message, chat_id, amount)


async def submit_withdraw_request(message_or_query, chat_id: int, amount: Decimal, payout_details: str) -> None:
    user = get_user(chat_id)
    if not user or user.role != "receiver" or not user.active:
        text = "Only active receivers can request payout."
        if hasattr(message_or_query, "edit_message_text"):
            await message_or_query.edit_message_text(text)
        else:
            await message_or_query.reply_text(text)
        return
    settings = get_marketplace_settings()
    min_payout = _dec(settings["min_payout_usdt"])
    _wallet, due, requested, available, _paid = receiver_earnings_numbers(chat_id)
    if amount <= 0:
        text = "Send a valid quantity."
    elif amount < min_payout:
        text = f"Minimum payout is ${_money(min_payout)} USDT."
    elif amount > available:
        text = f"Available: ${_money(available)} USDT\nDue: ${_money(due)} USDT · Requested: ${_money(requested)} USDT"
    else:
        text = ""
    if text:
        if hasattr(message_or_query, "edit_message_text"):
            await message_or_query.edit_message_text(text, reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Back", callback_data="nav:wallet")]]))
        else:
            await message_or_query.reply_text(text)
        return
    details = clean_payout_details_text(payout_details)
    if not details:
        await _send_withdraw_details_prompt(message_or_query, chat_id, amount)
        return
    save_receiver_payout_details(chat_id, details)
    payout_id = create_payout_request(chat_id, amount, payout_details=details)
    WITHDRAW_FLOW.pop(chat_id, None)
    text = f"✅ Withdrawal request #{payout_id} submitted for ${_money(amount)} USDT."
    if hasattr(message_or_query, "edit_message_text"):
        await message_or_query.edit_message_text(text)
    else:
        await message_or_query.reply_text(text)

def _dispute_public_id_from_reply(chat_id: int, user: UserRow, reply_message_id: int | None) -> str | None:
    if not reply_message_id:
        return None
    if user.role == "receiver":
        photo = find_photo_by_receiver_message_id(chat_id, reply_message_id)
    else:
        photo = find_photo_by_sender_message_id(chat_id, reply_message_id)
    return photo.public_id if photo else None


def _validate_dispute_public_id(chat_id: int, user: UserRow, public_id: str | None) -> tuple[bool, str | None]:
    if not public_id:
        return True, None
    row = get_photo_record(public_id)
    if not row:
        return False, "I could not find that QR ID."
    if user.role == "sender" and int(row["sender_chat_id"]) != chat_id:
        return False, "That QR ID is not linked to your sender account."
    if user.role == "receiver" and int(row["receiver_chat_id"] or 0) != chat_id:
        return False, "That QR ID is not linked to your receiver account."
    return True, None


async def dispute_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    observe_telegram_profile(update.effective_user)
    if not update.message or not update.effective_chat:
        return
    user = get_user(update.effective_chat.id)
    if not user or not user.active:
        await update.message.reply_text("You are not registered yet.")
        return

    public_id = None
    if context.args and re.fullmatch(r"\d{4}-\d{2}-\d{2}-\d{4}", context.args[0].strip()):
        public_id = context.args[0].strip()
    if not public_id and update.message.reply_to_message:
        public_id = _dispute_public_id_from_reply(update.effective_chat.id, user, update.message.reply_to_message.message_id)

    ok, error = _validate_dispute_public_id(update.effective_chat.id, user, public_id)
    if not ok:
        await update.message.reply_text(error or "Could not start that dispute.")
        return

    DISPUTE_FLOW[update.effective_chat.id] = {"public_id": public_id, "step": "reason"}
    qr_line = f"\nQR ID: `{public_id}`" if public_id else ""
    await update.message.reply_text(
        "⚠️ *Open dispute*\n"
        f"{qr_line}\n\n"
        "Please send the reason for this dispute now.",
        parse_mode="Markdown",
    )


async def dispute_qr_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.message:
        return
    await query.answer()
    chat_id = query.message.chat.id
    user = get_user(chat_id)
    if not user or not user.active:
        await query.message.reply_text("You are not registered yet.")
        return
    public_id = (query.data or "").split(":", 1)[1].strip()
    ok, error = _validate_dispute_public_id(chat_id, user, public_id)
    if not ok:
        await query.message.reply_text(error or "Could not start that dispute.")
        return
    DISPUTE_FLOW[chat_id] = {"public_id": public_id, "step": "reason"}
    await query.message.reply_text(
        "⚠️ *Open dispute*\n"
        f"QR ID: `{public_id}`\n\n"
        "Please send the reason for this dispute now.",
        parse_mode="Markdown",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅️ Cancel", callback_data="nav:home")]]),
    )


async def submit_dispute_reason(message, chat_id: int, reason: str) -> None:
    user = get_user(chat_id)
    if not user or not user.active:
        await message.reply_text("You are not registered yet.")
        DISPUTE_FLOW.pop(chat_id, None)
        return
    reason = reason.strip()
    if reason.lower() in {"cancel", "/cancel"}:
        DISPUTE_FLOW.pop(chat_id, None)
        await message.reply_text("Dispute cancelled.")
        return
    if len(reason) < 3:
        await message.reply_text("Please send a clear reason for the dispute.")
        return
    state = DISPUTE_FLOW.pop(chat_id, {})
    public_id = state.get("public_id")
    ref_id = create_dispute(chat_id, public_id, reason)
    await message.reply_text(f"✅ Dispute #{ref_id} submitted. Admin will review it soon.")


async def send_offer_to_receivers(context: ContextTypes.DEFAULT_TYPE, public_id: str) -> tuple[int, int]:
    row = get_photo_record(public_id)
    if not row:
        return 0, 0
    text = build_offer_text(public_id, int(row["daily_no"]), _dec(row["sender_rate_usdt"]), _dec(row["receiver_rate_usdt"]), str(row["offer_expires_at"]))
    sent = failed = 0
    receivers = online_receivers()
    for receiver in receivers:
        try:
            msg = await context.bot.send_message(
                chat_id=int(receiver["chat_id"]),
                text=text,
                reply_markup=build_offer_keyboard(public_id),
                protect_content=PROTECT_CONTENT,
            )
            record_offer_notification(public_id, int(receiver["chat_id"]), msg.message_id)
            sent += 1
            await asyncio.sleep(0.03)
        except TelegramError as exc:
            logger.warning("Could not send offer %s to receiver %s: %s", public_id, receiver["chat_id"], exc)
            failed += 1
    return sent, failed


async def handle_photo(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    observe_telegram_profile(update.effective_user)
    if not update.effective_chat or not update.message:
        return
    if await wallet_manual_screenshot_flow(update, context):
        return

    chat = update.effective_chat
    if chat.type != ChatType.PRIVATE:
        return

    user = get_user(chat.id)
    if not user or user.role != "sender" or not user.active:
        await update.message.reply_text("Only an active registered sender can send QR photos.")
        return

    settings = get_marketplace_settings()
    if settings["maintenance_mode"]:
        await update.message.reply_text("🚧 Maintenance mode is ON. New QR submissions are paused by admin.")
        return

    receivers = online_receivers()
    if not receivers:
        await update.message.reply_text("No receiver is online right now. Use /status to check capacity before sending.")
        return

    sender_rate = _dec(settings["sender_rate_usdt"])
    receiver_rate = _dec(settings["receiver_rate_usdt"])
    if sender_rate > 0 and available_sender_balance(chat.id) < sender_rate:
        await update.message.reply_text(
            f"Insufficient wallet balance. Required per scan: ${_money(sender_rate)} USDT.\n"
            f"Available: ${_money(available_sender_balance(chat.id))} USDT.\n\n"
            "Use /wallet and /loadwallet to add balance."
        )
        return

    started_at = time.perf_counter()
    try:
        clean_qr_file, qr_data, qr_hash = await extract_and_rebuild_clean_qr(update.message)
    except ValueError as exc:
        await update.message.reply_text(
            f"Photo rejected: {exc}\n\n"
            "Send a clear photo containing exactly one readable QR code. Captions/text are ignored."
        )
        await delete_original_sender_message_safely(context, chat.id, update.message.message_id, rejected=True)
        return
    except Exception:
        logger.exception("Unexpected QR processing error")
        await update.message.reply_text("Photo rejected: I could not process that QR image.")
        await delete_original_sender_message_safely(context, chat.id, update.message.message_id, rejected=True)
        return

    date_str = today_str()
    daily_no = reserve_daily_number(date_str)
    public_id = f"{date_str}-{daily_no:04d}"
    qr_expire_minutes = int(settings["qr_expire_minutes"])
    expires_at = datetime.fromtimestamp(now_dt().timestamp() + max(1, qr_expire_minutes) * 60, ZoneInfo(BOT_TZ)).isoformat(timespec="seconds")

    ok, reserve_msg = reserve_sender_funds(chat.id, sender_rate, public_id)
    if not ok:
        await update.message.reply_text(reserve_msg)
        return

    processing_ms = int((time.perf_counter() - started_at) * 1000)
    caption = build_sender_offer_caption(
        date_str,
        daily_no,
        public_id,
        "📡 Marketplace offer created.",
        expires_at=expires_at,
        sender_rate=sender_rate,
    )

    try:
        sender_msg = await context.bot.send_photo(
            chat_id=chat.id,
            photo=clean_qr_file,
            caption=caption,
            protect_content=PROTECT_CONTENT,
        )
        generated_file_id = sender_msg.photo[-1].file_id
    except TelegramError as exc:
        release_sender_reserve(chat.id, sender_rate, public_id, "Sender delivery failed")
        logger.warning("Telegram send failed: %s", exc)
        await update.message.reply_text("I generated the clean QR, but could not save/send it back to you. Please try again.")
        return

    save_open_offer(
        public_id=public_id,
        date_str=date_str,
        daily_no=daily_no,
        sender_chat_id=chat.id,
        sender_message_id=sender_msg.message_id,
        generated_file_id=generated_file_id,
        qr_sha256=qr_hash,
        qr_data=qr_data if STORE_QR_DATA else None,
        processing_ms=processing_ms,
        sender_rate=sender_rate,
        receiver_rate=receiver_rate,
        expires_at=expires_at,
    )

    sent, failed = await send_offer_to_receivers(context, public_id)
    if sent <= 0:
        expire_offer_in_db(public_id, "expired")
        release_sender_reserve(chat.id, sender_rate, public_id, "No receiver could be notified")
        await edit_sender_offer_caption(
            context.bot,
            chat.id,
            sender_msg.message_id,
            build_sender_offer_caption(
                date_str,
                daily_no,
                public_id,
                "❌ Offer failed. No online receiver could be notified. Reserved balance was released.",
            ),
        )
    else:
        await edit_sender_offer_caption(
            context.bot,
            chat.id,
            sender_msg.message_id,
            build_sender_offer_caption(
                date_str,
                daily_no,
                public_id,
                "📡 Offer sent to online receiver(s)",
                expires_at=expires_at,
                sender_rate=sender_rate,
            ),
        )

    await delete_original_sender_message_safely(context, chat.id, update.message.message_id)


async def reject_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message:
        await update.message.reply_text(
            "Please send the QR as a Telegram photo, not as a document. Photos are faster to process."
        )


async def resolve_pending_photo_for_status(
    *,
    bot,
    actor_chat_id: int,
    public_id: str | None = None,
    reply_to_message_id: int | None = None,
) -> tuple[PhotoRow | None, str | None]:
    actor = get_user(actor_chat_id)

    if not actor or actor.role != "receiver" or not actor.active:
        return None, "Only the assigned receiver can mark photos."

    if public_id:
        photo = find_photo_by_public_id(public_id)
    elif reply_to_message_id is not None:
        photo = find_photo_by_receiver_message_id(actor_chat_id, reply_to_message_id)
    else:
        return None, "Reply to a QR with /done or /failed, or tap the Done/Failed button under that QR."

    if not photo:
        return None, "I could not find that photo."

    record = get_photo_record(photo.public_id)
    if not record or record["offer_state"] != "claimed":
        return None, "This QR is not currently claimed."

    if photo.receiver_chat_id != actor_chat_id:
        return None, "This photo is not assigned to you."

    if photo.status != "pending":
        return None, f"That photo is already marked {photo.status.upper()}."

    if record["offer_expires_at"] and str(record["offer_expires_at"]) <= now_iso():
        expired_ok, _expired_msg, expired_row = expire_pending_qr_in_db(photo.public_id)
        if expired_ok and expired_row is not None:
            await notify_qr_expired_by_timeout(bot, photo.public_id, expired_row)
        return None, "This QR has expired."

    return photo, None


async def complete_photo(
    *,
    bot,
    actor_chat_id: int,
    status: str,
    public_id: str | None = None,
    reply_to_message_id: int | None = None,
    failure_reason: str | None = None,
) -> tuple[bool, str]:
    if status not in {"done", "failed"}:
        return False, "Invalid status."

    if status == "failed":
        failure_reason = clean_failure_reason_text(failure_reason)
        if not failure_reason:
            return False, "Please select the failure reason first."

    photo, error = await resolve_pending_photo_for_status(
        bot=bot,
        actor_chat_id=actor_chat_id,
        public_id=public_id,
        reply_to_message_id=reply_to_message_id,
    )
    if error or not photo:
        return False, error or "I could not find that photo."

    ok = update_photo_status(photo.public_id, status, actor_chat_id, failure_reason=failure_reason)
    if not ok:
        return False, "Could not update status. It may have already been marked."

    settle_photo_wallets(photo.public_id, status)

    status_text = status.upper()
    new_caption = build_status_caption(photo, status, failure_reason=failure_reason)
    if status == "failed":
        new_caption += "\n💳 Sender reserve released."

    # Update the existing QR photo captions on both sides. This avoids extra status messages.
    edit_errors: list[str] = []

    if photo.receiver_message_id:
        try:
            await bot.edit_message_caption(
                chat_id=photo.receiver_chat_id,
                message_id=photo.receiver_message_id,
                caption=new_caption,
                reply_markup=None,
            )
        except TelegramError as exc:
            logger.warning("Could not edit receiver QR caption %s/%s: %s", photo.receiver_chat_id, photo.receiver_message_id, exc)
            edit_errors.append("receiver")

    if photo.sender_message_id:
        try:
            await bot.edit_message_caption(
                chat_id=photo.sender_chat_id,
                message_id=photo.sender_message_id,
                caption=new_caption,
                reply_markup=None,
            )
        except TelegramError as exc:
            logger.warning("Could not edit sender QR caption %s/%s: %s", photo.sender_chat_id, photo.sender_message_id, exc)
            edit_errors.append("sender")

    if edit_errors:
        return False, f"Marked {status_text}, but I could not update the QR caption for: {', '.join(edit_errors)}."

    if status == "failed" and failure_reason:
        try:
            await bot.send_message(
                chat_id=photo.sender_chat_id,
                text=(
                    "❌ QR failed\n"
                    f"🆔 ID: {photo.public_id}\n"
                    f"📝 Reason: {failure_reason}"
                ),
            )
        except TelegramError as exc:
            logger.warning("Could not notify sender about failed QR %s: %s", photo.public_id, exc)

    emoji = "✅" if status == "done" else "❌"
    if status == "failed":
        return True, "❌ QR marked failed. Reason sent to sender."
    return True, f"{emoji} Status updated in the QR caption: {status_text}."


async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE, status: str) -> None:
    observe_telegram_profile(update.effective_user)
    if not update.message or not update.effective_chat:
        return

    public_id = context.args[0].strip() if context.args else None
    reply_to_message_id = None
    if update.message.reply_to_message:
        reply_to_message_id = update.message.reply_to_message.message_id

    ok, result = await complete_photo(
        bot=context.bot,
        actor_chat_id=update.effective_chat.id,
        status=status,
        public_id=public_id,
        reply_to_message_id=reply_to_message_id,
    )

    if ok:
        if DELETE_STATUS_COMMAND_AFTER_USE:
            await delete_message_safely(
                context,
                update.effective_chat.id,
                update.message.message_id,
                "status command message",
            )
        return

    await update.message.reply_text(result)


async def done_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await status_command(update, context, "done")


async def start_failure_reason_flow(
    message,
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    *,
    public_id: str | None = None,
    reply_to_message_id: int | None = None,
) -> None:
    photo, error = await resolve_pending_photo_for_status(
        bot=context.bot,
        actor_chat_id=chat_id,
        public_id=public_id,
        reply_to_message_id=reply_to_message_id,
    )
    if error or not photo:
        await message.reply_text(error or "I could not find that QR.")
        return
    FAIL_REASON_FLOW.pop(chat_id, None)
    await message.reply_text(
        f"❌ Select failure reason.\n🆔 ID: {photo.public_id}",
        reply_markup=failure_reason_keyboard(photo.public_id),
    )


async def submit_failure_reason(message, context: ContextTypes.DEFAULT_TYPE, chat_id: int, reason: str) -> None:
    # Custom typed failure reasons are intentionally not accepted.
    # Receivers must use the fixed failure reason buttons so sender/admin messages stay clean and predictable.
    await message.reply_text("Please select one of the failure reason buttons.")


async def failed_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    observe_telegram_profile(update.effective_user)
    if not update.message or not update.effective_chat:
        return

    public_id: str | None = None
    if context.args:
        first = context.args[0].strip()
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}-\d{4}", first):
            public_id = first

    reply_to_message_id = update.message.reply_to_message.message_id if update.message.reply_to_message else None
    await start_failure_reason_flow(
        update.message,
        context,
        update.effective_chat.id,
        public_id=public_id,
        reply_to_message_id=reply_to_message_id,
    )


async def fail_reason_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.message:
        return
    try:
        _prefix, public_id, reason_key = (query.data or "").split(":", 2)
    except Exception:
        await query.answer("Invalid failure reason.", show_alert=True)
        return

    reason = FAIL_REASON_CHOICES.get(reason_key)
    if not reason:
        await query.answer("Invalid failure reason.", show_alert=True)
        return

    chat_id = query.message.chat.id
    ok, result = await complete_photo(
        bot=context.bot,
        actor_chat_id=chat_id,
        status="failed",
        public_id=public_id,
        failure_reason=reason,
    )
    if ok:
        FAIL_REASON_FLOW.pop(chat_id, None)
        await query.answer("Marked failed.", show_alert=False)
        try:
            await query.edit_message_text(f"❌ QR marked failed\n🆔 ID: {public_id}\n📝 Reason: {reason}")
        except TelegramError:
            pass
        return

    await query.answer(result, show_alert=True)


async def claim_offer_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.message:
        return
    try:
        _action, public_id = query.data.split(":", 1)
    except Exception:
        await query.answer("Invalid offer button.", show_alert=True)
        return
    receiver_chat_id = query.message.chat.id
    ok, result, row, auto_off = claim_offer_in_db(public_id, receiver_chat_id)
    if not ok:
        await query.answer(result, show_alert=True)
        try:
            await query.edit_message_text(f"⛔ {result}\n🆔 Offer ID: {public_id}")
            set_offer_notification_state(public_id, receiver_chat_id, "expired")
        except TelegramError:
            pass
        return
    assert row is not None
    receiver_message_id: int | None = None
    accepted_caption = build_caption(row["date"], int(row["daily_no"]), public_id)

    await query.answer("✅ You got this QR", show_alert=False)
    # Edit the accepted offer message itself into the QR photo, so the receiver does not get a second QR message.
    for note in offer_notifications(public_id):
        note_chat_id = int(note["receiver_chat_id"])
        note_message_id = int(note["message_id"])
        try:
            if note_chat_id == receiver_chat_id:
                await context.bot.edit_message_media(
                    chat_id=note_chat_id,
                    message_id=note_message_id,
                    media=InputMediaPhoto(media=row["generated_file_id"], caption=accepted_caption),
                    reply_markup=receiver_status_keyboard(public_id),
                )
                receiver_message_id = note_message_id
                set_receiver_message_for_offer(public_id, note_message_id)
                set_offer_notification_state(public_id, receiver_chat_id, "claimed")
            else:
                await context.bot.edit_message_text(
                    chat_id=note_chat_id,
                    message_id=note_message_id,
                    text=f"⛔ Offer expired. Another receiver already accepted this QR.\n🆔 Offer ID: {public_id}",
                )
                set_offer_notification_state(public_id, note_chat_id, "expired")
            await asyncio.sleep(0.02)
        except TelegramError as exc:
            logger.debug("Could not edit offer notification %s/%s: %s", note["receiver_chat_id"], note["message_id"], exc)

    if receiver_message_id is None:
        # Fallback for rare Telegram edit failures: still deliver the QR, but keep this as an exception path.
        try:
            receiver_msg = await context.bot.send_photo(
                chat_id=receiver_chat_id,
                photo=row["generated_file_id"],
                caption=accepted_caption,
                reply_markup=receiver_status_keyboard(public_id),
                protect_content=PROTECT_CONTENT,
            )
            set_receiver_message_for_offer(public_id, receiver_msg.message_id)
            receiver_message_id = receiver_msg.message_id
        except TelegramError as exc:
            logger.warning("Could not deliver claimed QR %s to receiver %s: %s", public_id, receiver_chat_id, exc)
            await query.answer("Claim saved, but QR delivery failed. Ask admin to review.", show_alert=True)
            return

    await edit_sender_offer_caption(
        context.bot,
        int(row["sender_chat_id"]),
        int(row["sender_message_id"] or 0),
        build_sender_offer_caption(
            str(row["date"]),
            int(row["daily_no"]),
            public_id,
            "⏳ Your QR offer was accepted.",
            expires_at=str(row["offer_expires_at"] or ""),
            sender_rate=_dec(row["sender_rate_usdt"]),
        ),
    )
    if auto_off:
        await context.bot.send_message(
            chat_id=receiver_chat_id,
            text="🔴 Your scan limit reached zero, so you were set offline automatically. Use /on LIMIT to go online again.",
        )
        await notify_active_senders(context, "🔴 A receiver reached their limit and is now offline. Use /status for current capacity.")


async def pending_qr_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.message:
        return
    try:
        _action, public_id = (query.data or "").split(":", 1)
    except Exception:
        await query.answer("Invalid QR button.", show_alert=True)
        return
    chat_id = query.message.chat.id
    user = get_user(chat_id)
    if not user or user.role != "receiver" or not user.active:
        await query.answer("Only active receivers can open pending QRs.", show_alert=True)
        return
    row = get_photo_record(public_id)
    if not row or int(row["receiver_chat_id"] or 0) != chat_id:
        await query.answer("QR not found for your account.", show_alert=True)
        return
    if str(row["status"]) != "pending" or str(row["offer_state"]) != "claimed":
        await query.answer("This QR is no longer pending.", show_alert=True)
        return
    if row["offer_expires_at"] and str(row["offer_expires_at"]) <= now_iso():
        expired_ok, _expired_msg, expired_row = expire_pending_qr_in_db(public_id)
        if expired_ok and expired_row is not None:
            await notify_qr_expired_by_timeout(context.bot, public_id, expired_row)
        await query.answer("This QR has expired.", show_alert=True)
        return
    try:
        msg = await context.bot.send_photo(
            chat_id=chat_id,
            photo=row["generated_file_id"],
            caption=build_caption(row["date"], int(row["daily_no"]), public_id),
            reply_markup=receiver_status_keyboard(public_id),
            protect_content=PROTECT_CONTENT,
        )
        set_receiver_message_for_offer(public_id, msg.message_id)
        await query.answer("QR opened below.")
    except TelegramError as exc:
        logger.warning("Could not reopen pending QR %s for %s: %s", public_id, chat_id, exc)
        await query.answer("Could not open that QR right now.", show_alert=True)


async def button_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.message:
        return

    try:
        action, public_id = query.data.split(":", 1)
    except Exception:
        await query.answer("Invalid button.", show_alert=True)
        return

    if action not in {"done", "failed"}:
        await query.answer("Invalid action.", show_alert=True)
        return

    chat_id = query.message.chat.id
    if action == "failed":
        photo, error = await resolve_pending_photo_for_status(
            bot=context.bot,
            actor_chat_id=chat_id,
            public_id=public_id,
        )
        if error or not photo:
            await query.answer(error or "I could not find that QR.", show_alert=True)
            return
        FAIL_REASON_FLOW.pop(chat_id, None)
        await query.answer("Select failure reason.", show_alert=False)
        await query.message.reply_text(
            f"❌ Select failure reason.\n🆔 ID: {photo.public_id}",
            reply_markup=failure_reason_keyboard(photo.public_id),
        )
        return

    ok, result = await complete_photo(
        bot=context.bot,
        actor_chat_id=chat_id,
        status=action,
        public_id=public_id,
    )

    if ok:
        await query.answer(result)
        return

    await query.answer(result, show_alert=True)




async def notify_qr_expired_by_timeout(bot, public_id: str, row: sqlite3.Row) -> None:
    expired_offer_text = f"⏱ Offer expired.\n🆔 Offer ID: {public_id}\nThis QR can no longer be accepted or completed."
    expired_caption = (
        f"{build_caption(str(row['date']), int(row['daily_no']), public_id)}\n\n"
        "⏱ Status: EXPIRED\n"
        f"🕒 Updated: {display_datetime()}\n"
        "💳 Sender reserve released."
    )
    claimed_receiver_id = int(row["receiver_chat_id"] or 0)
    receiver_message_id = int(row["receiver_message_id"] or 0)

    for note in offer_notifications(public_id):
        note_chat_id = int(note["receiver_chat_id"])
        note_message_id = int(note["message_id"])
        try:
            if claimed_receiver_id and note_chat_id == claimed_receiver_id:
                await bot.edit_message_caption(
                    chat_id=note_chat_id,
                    message_id=note_message_id,
                    caption=expired_caption,
                    reply_markup=None,
                )
            else:
                await bot.edit_message_text(
                    chat_id=note_chat_id,
                    message_id=note_message_id,
                    text=expired_offer_text,
                )
            set_offer_notification_state(public_id, note_chat_id, "expired")
            await asyncio.sleep(0.02)
        except TelegramError:
            pass

    if claimed_receiver_id and receiver_message_id:
        try:
            await bot.edit_message_caption(
                chat_id=claimed_receiver_id,
                message_id=receiver_message_id,
                caption=expired_caption,
                reply_markup=None,
            )
        except TelegramError:
            pass

    try:
        if row["sender_message_id"]:
            await bot.edit_message_caption(
                chat_id=int(row["sender_chat_id"]),
                message_id=int(row["sender_message_id"]),
                caption=expired_caption,
                reply_markup=None,
            )
    except TelegramError:
        pass


async def expire_offer_runtime(bot, public_id: str, row: sqlite3.Row, reason_text: str = "Offer expired. No receiver accepted in time.") -> None:
    release_sender_reserve(int(row["sender_chat_id"]), _dec(row["sender_rate_usdt"]), public_id, reason_text)
    await notify_qr_expired_by_timeout(bot, public_id, row)



def expire_pending_qr_in_db(public_id: str) -> tuple[bool, str, sqlite3.Row | None]:
    """Admin action: expire any pending QR, whether still open or already claimed."""
    public_id = public_id.strip()
    if not public_id:
        return False, "QR ID is missing.", None
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM photos WHERE public_id = ?", (public_id,)).fetchone()
        if not row:
            conn.rollback()
            return False, "QR not found.", None
        if str(row["status"]).lower() != "pending":
            conn.rollback()
            return False, f"QR is already marked {str(row['status']).upper()}.", row
        cur = conn.execute(
            """
            UPDATE photos
            SET status = 'failed', offer_state = 'expired', status_by = NULL, status_at = ?
            WHERE public_id = ? AND status = 'pending'
            """,
            (now_iso(), public_id),
        )
        if cur.rowcount <= 0:
            conn.rollback()
            return False, "QR was already processed.", row
        conn.commit()

    # Release the sender reserve through the normal failed/expired settlement path.
    settle_photo_wallets(public_id, "failed")
    return True, "QR expired. Sender reserve released.", row


async def notify_admin_expired_qr(bot, public_id: str, row: sqlite3.Row) -> None:
    """Update Telegram messages after an admin manually expires a QR."""
    expired_offer_text = f"⏱ Offer expired by admin.\n🆔 Offer ID: {public_id}\nThis QR can no longer be accepted or completed."
    expired_caption = (
        f"{build_caption(str(row['date']), int(row['daily_no']), public_id)}\n\n"
        "⏱ Status: EXPIRED BY ADMIN\n"
        f"🕒 Updated: {display_datetime()}\n"
        "💳 Sender reserve released."
    )

    for note in offer_notifications(public_id):
        try:
            await bot.edit_message_text(
                chat_id=int(note["receiver_chat_id"]),
                message_id=int(note["message_id"]),
                text=expired_offer_text,
            )
            set_offer_notification_state(public_id, int(note["receiver_chat_id"]), "expired")
            await asyncio.sleep(0.02)
        except TelegramError:
            pass

    try:
        if row["sender_message_id"]:
            await bot.edit_message_caption(
                chat_id=int(row["sender_chat_id"]),
                message_id=int(row["sender_message_id"]),
                caption=expired_caption,
                reply_markup=None,
            )
    except TelegramError:
        pass

    receiver_id = int(row["receiver_chat_id"] or 0)
    try:
        if receiver_id and row["receiver_message_id"]:
            await bot.edit_message_caption(
                chat_id=receiver_id,
                message_id=int(row["receiver_message_id"]),
                caption=expired_caption,
                reply_markup=None,
            )
    except TelegramError:
        pass

    try:
        await bot.send_message(
            chat_id=int(row["sender_chat_id"]),
            text=f"⏱ Admin expired your pending QR. Reserved balance was released.\n🆔 ID: {public_id}",
            protect_content=PROTECT_CONTENT,
        )
    except TelegramError:
        pass

    if receiver_id:
        try:
            await bot.send_message(
                chat_id=receiver_id,
                text=f"⏱ Admin expired QR {public_id}. It can no longer be marked Done or Failed.",
                protect_content=PROTECT_CONTENT,
            )
        except TelegramError:
            pass


async def marketplace_watcher(application: Application) -> None:
    while True:
        try:
            for row in list_pending_qrs_to_expire(limit=100):
                public_id = str(row["public_id"])
                ok, _msg, expired_row = expire_pending_qr_in_db(public_id)
                if ok and expired_row is not None:
                    await notify_qr_expired_by_timeout(application.bot, public_id, expired_row)
            await asyncio.sleep(max(2, MARKETPLACE_WATCH_INTERVAL_SECONDS))
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Marketplace watcher error")
            await asyncio.sleep(10)


def list_deposits_for_auto_payment_check(limit: int = 25) -> list[sqlite3.Row]:
    """Return the deposits that should be checked by the background watcher.

    The old watcher used oldest-first ordering. In a live bot, old waiting/manual
    deposits can become stuck and starve newer payments forever. Newest-first,
    with saved TxHash rows first, makes every fresh payment get checked promptly.
    """
    limit = max(1, int(limit or PAYMENT_WATCH_BATCH_SIZE))
    now = now_iso()
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT * FROM payment_deposits
            WHERE credited_at IS NULL
              AND (
                    status = 'waiting'
                    OR (status = 'manual_pending' AND COALESCE(NULLIF(tx_hash, ''), '') != '')
                  )
            ORDER BY
              CASE WHEN COALESCE(NULLIF(tx_hash, ''), '') != '' THEN 0 ELSE 1 END,
              CASE WHEN status = 'waiting' AND expires_at IS NOT NULL AND expires_at <= ? THEN 0 ELSE 1 END,
              created_at DESC
            LIMIT ?
            """,
            (now, limit),
        ).fetchall()


async def _maybe_send_payment_reminder(application: Application, dep: sqlite3.Row, reminder_minutes: int) -> None:
    if str(dep["status"]) != "waiting" or reminder_minutes <= 0 or dep["reminder_sent_at"]:
        return
    try:
        created_dt = datetime.fromisoformat(str(dep["created_at"]))
        if created_dt.tzinfo is None:
            created_dt = created_dt.replace(tzinfo=ZoneInfo(BOT_TZ))
        age_minutes = (now_dt().timestamp() - created_dt.timestamp()) / 60
    except Exception:
        age_minutes = 0
    if age_minutes < reminder_minutes:
        return
    try:
        await application.bot.send_message(
            chat_id=int(dep["chat_id"]),
            text=_deposit_pending_reminder_text(dep),
            parse_mode="Markdown",
        )
        with get_conn() as conn:
            conn.execute(
                "UPDATE payment_deposits SET reminder_sent_at=? WHERE ref_id=? AND reminder_sent_at IS NULL",
                (now_iso(), dep["ref_id"]),
            )
    except TelegramError:
        pass


async def _expire_waiting_deposit_if_needed(application: Application, dep: sqlite3.Row) -> None:
    dep_after_check = get_deposit(dep["ref_id"]) or dep
    if (
        str(dep_after_check["status"]) == "waiting"
        and not dep_after_check["credited_at"]
        and dep_after_check["expires_at"]
        and str(dep_after_check["expires_at"]) <= now_iso()
    ):
        with get_conn() as conn:
            cur = conn.execute(
                """
                UPDATE payment_deposits
                SET status='expired', manual_note='Payment session expired'
                WHERE ref_id=? AND credited_at IS NULL AND status='waiting'
                """,
                (dep_after_check["ref_id"],),
            )
        if cur.rowcount:
            try:
                await clear_deposit_payment_buttons(application.bot, dep_after_check)
                await application.bot.send_message(
                    chat_id=int(dep_after_check["chat_id"]),
                    text=_deposit_expired_text(dep_after_check),
                    parse_mode="Markdown",
                )
            except TelegramError:
                pass


async def _process_one_payment_auto_check(application: Application, dep: sqlite3.Row, reminder_minutes: int) -> None:
    ref_id = str(dep["ref_id"])
    dep_current = get_deposit(ref_id) or dep
    if dep_current["credited_at"]:
        try:
            await send_deposit_completed_message(application.bot, dep_current)
        except TelegramError:
            pass
        return
    status = str(dep_current["status"])
    if status == "manual_pending" and not str(dep_current["tx_hash"] or "").strip():
        return
    if status not in ACTIVE_PAYMENT_CHECK_STATUSES:
        return

    if status == "waiting":
        await refresh_deposit_payment_message(application.bot, dep_current)
        await _maybe_send_payment_reminder(application, dep_current, reminder_minutes)

    tx_hash = str(dep_current["tx_hash"] or "").strip() or None
    ok, reason = await verify_and_credit_deposit_async(
        ref_id,
        tx_hash,
        False,
        "auto",
        timeout_seconds=max(5, int(PAYMENT_AUTO_VERIFY_TIMEOUT_SECONDS)),
    )
    if ok:
        try:
            dep_after = get_deposit(ref_id) or dep_current
            await send_deposit_completed_message(application.bot, dep_after)
        except TelegramError:
            pass
        logger.info("Auto payment checker credited %s", ref_id)
        return

    # If the sync verifier completed just as an async timeout/error was returned,
    # still send the once-only completion message instead of leaving the user
    # without the BEP20-style confirmation.
    dep_after = get_deposit(ref_id) or dep_current
    if dep_after["credited_at"]:
        try:
            await send_deposit_completed_message(application.bot, dep_after)
        except TelegramError:
            pass
        logger.info("Auto payment checker noticed already-credited %s", ref_id)
        return

    logger.info("Auto payment check %s not ready: %s", ref_id, reason)
    await _expire_waiting_deposit_if_needed(application, dep_current)


async def payment_watcher(application: Application) -> None:
    """Continuously verify wallet top-ups without needing Check Payment taps.

    Fixes made here:
    - newest active deposits are checked first so old stuck deposits do not block new payments;
    - checks run concurrently with a bounded semaphore instead of one slow explorer call blocking the loop;
    - manual-pending deposits with a saved TxHash are still rechecked automatically;
    - expiration happens only after a final auto-check attempt.
    """
    logger.info("Payment watcher started")
    while True:
        try:
            settings = get_marketplace_settings()
            interval_seconds = max(10, int(settings.get("payment_watch_interval_seconds") or PAYMENT_WATCH_INTERVAL_SECONDS))
            reminder_minutes = max(0, int(settings.get("payment_reminder_minutes") or PAYMENT_REMINDER_MINUTES))
            batch_size = max(1, int(os.getenv("PAYMENT_WATCH_BATCH_SIZE", str(PAYMENT_WATCH_BATCH_SIZE))))
            concurrency = max(1, int(os.getenv("PAYMENT_WATCH_CONCURRENCY", str(PAYMENT_WATCH_CONCURRENCY))))
            deposits = list_deposits_for_auto_payment_check(batch_size)
            if deposits:
                logger.info("Payment watcher checking %s active deposit(s)", len(deposits))
            semaphore = asyncio.Semaphore(concurrency)

            async def _guarded(dep: sqlite3.Row) -> None:
                async with semaphore:
                    try:
                        await _process_one_payment_auto_check(application, dep, reminder_minutes)
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        logger.exception("Auto payment check crashed for %s", dep["ref_id"])

            if deposits:
                await asyncio.gather(*[_guarded(dep) for dep in deposits])
            await asyncio.sleep(interval_seconds)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Payment watcher error")
            await asyncio.sleep(15)







MAINTENANCE_ALLOWED_COMMANDS = {"wallet", "loadwallet"}


async def maintenance_guard(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Block normal user bot actions while web-panel maintenance mode is ON.

    Owner/admin Telegram IDs remain exempt for testing. Existing sender payment
    checks remain available through /wallet and /loadwallet during maintenance.
    """
    user = update.effective_user
    if not user or not maintenance_mode_enabled():
        return
    if is_admin(int(user.id)):
        return

    if update.message and update.message.text:
        text = update.message.text.strip()
        if text.startswith("/"):
            command = text.split()[0].split("@", 1)[0].lstrip("/").lower()
            if command in MAINTENANCE_ALLOWED_COMMANDS:
                return

    message = "🛠 Bot is under maintenance. Please try again later or contact support."
    if update.callback_query:
        try:
            await update.callback_query.answer("Bot is under maintenance.", show_alert=True)
            if update.callback_query.message:
                await update.callback_query.edit_message_text(message)
        except TelegramError:
            pass
    elif update.message:
        await update.message.reply_text(message)
    raise ApplicationHandlerStop

async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.exception("Unhandled exception while handling update: %s", update, exc_info=context.error)



# -----------------------------
# Admin website
# -----------------------------

telegram_application: Application | None = None
polling_started = False
marketplace_background_task: asyncio.Task | None = None
payment_background_task: asyncio.Task | None = None
web_app = FastAPI(title=f"{APP_NAME} Admin")


def _background_task_done(name: str):
    def _done(task: asyncio.Task) -> None:
        if task.cancelled():
            logger.info("%s background task cancelled", name)
            return
        exc = task.exception()
        if exc is not None:
            logger.error("%s background task stopped unexpectedly", name, exc_info=(type(exc), exc, exc.__traceback__))
    return _done

ADMIN_USERNAME_KEY = "admin_username"
ADMIN_PASSWORD_HASH_KEY = "admin_password_hash"


def _hash_password(password: str) -> str:
    salt = os.urandom(16).hex()
    rounds = 260_000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), rounds).hex()
    return f"pbkdf2_sha256${rounds}${salt}${digest}"


def _verify_password(password: str, stored_hash: str) -> bool:
    try:
        algo, rounds_raw, salt, expected = stored_hash.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        rounds = int(rounds_raw)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), rounds).hex()
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def get_admin_setting(key: str) -> str | None:
    with get_conn() as conn:
        row = conn.execute("SELECT value FROM admin_settings WHERE key = ?", (key,)).fetchone()
    return str(row["value"]) if row else None


def set_admin_setting(key: str, value: str) -> None:
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO admin_settings(key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            (key, value, now_iso()),
        )


def delete_admin_setting(key: str) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM admin_settings WHERE key = ?", (key,))


def stored_admin_credentials_configured() -> bool:
    return bool(get_admin_setting(ADMIN_USERNAME_KEY) and get_admin_setting(ADMIN_PASSWORD_HASH_KEY))


def active_admin_username() -> str:
    return get_admin_setting(ADMIN_USERNAME_KEY) or ADMIN_PANEL_USERNAME


def active_admin_credential_source() -> str:
    return "admin panel settings" if stored_admin_credentials_configured() else "environment variables"


def verify_admin_login(username: str, password: str) -> bool:
    username = username.strip()
    stored_username = get_admin_setting(ADMIN_USERNAME_KEY)
    stored_hash = get_admin_setting(ADMIN_PASSWORD_HASH_KEY)
    if stored_username and stored_hash:
        return hmac.compare_digest(username, stored_username) and _verify_password(password, stored_hash)
    return bool(ADMIN_PANEL_PASSWORD) and hmac.compare_digest(username, ADMIN_PANEL_USERNAME) and hmac.compare_digest(password, ADMIN_PANEL_PASSWORD)


def _admin_secret() -> str:
    fallback = hashlib.sha256((BOT_TOKEN + ADMIN_PANEL_PASSWORD + ADMIN_PANEL_USERNAME).encode("utf-8")).hexdigest()
    return ADMIN_SESSION_SECRET or fallback


def _admin_session_token() -> str:
    stored_username = get_admin_setting(ADMIN_USERNAME_KEY) or ADMIN_PANEL_USERNAME
    stored_hash = get_admin_setting(ADMIN_PASSWORD_HASH_KEY) or hashlib.sha256(ADMIN_PANEL_PASSWORD.encode("utf-8")).hexdigest()
    payload = f"qr-admin-panel:{stored_username}:{stored_hash}".encode("utf-8")
    return hmac.new(_admin_secret().encode("utf-8"), payload, hashlib.sha256).hexdigest()


def admin_authed(request: Request) -> bool:
    cookie_value = request.cookies.get(ADMIN_COOKIE_NAME, "")
    return bool(cookie_value) and hmac.compare_digest(cookie_value, _admin_session_token())


def admin_guard(request: Request):
    if admin_authed(request):
        return None
    return RedirectResponse(url="/admin/login", status_code=303)


def redirect_with_msg(path: str, msg: str) -> RedirectResponse:
    sep = "&" if "?" in path else "?"
    return RedirectResponse(url=f"{path}{sep}msg={quote(msg)}", status_code=303)


def esc(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


PAGE_SIZE = 10


def page_number(request: Request, key: str = "page") -> int:
    try:
        return max(1, int(str(request.query_params.get(key, "1"))))
    except Exception:
        return 1


def pagination_url(request: Request, page: int, key: str = "page") -> str:
    params = dict(request.query_params)
    params[key] = str(max(1, page))
    return f"{request.url.path}?{urlencode(params)}"


def paginate_items(items: list, request: Request, *, key: str = "page", per_page: int = PAGE_SIZE):
    total = len(items)
    pages = max(1, (total + per_page - 1) // per_page)
    current = min(page_number(request, key), pages)
    start = (current - 1) * per_page
    chunk = items[start:start + per_page]
    prev_link = pagination_url(request, current - 1, key)
    next_link = pagination_url(request, current + 1, key)
    prev_html = f'<a class="btn page-btn" href="{esc(prev_link)}">← Previous</a>' if current > 1 else '<span class="btn page-btn disabled">← Previous</span>'
    next_html = f'<a class="btn page-btn" href="{esc(next_link)}">Next →</a>' if current < pages else '<span class="btn page-btn disabled">Next →</span>'
    if total <= per_page:
        pager = f'<div class="pagination compact"><span>Showing {esc(total)} of {esc(total)}</span></div>' if total else ''
    else:
        first = start + 1
        last = min(total, start + per_page)
        pager = (
            '<div class="pagination">'
            f'{prev_html}'
            f'<span class="page-info">Showing {esc(first)}–{esc(last)} of {esc(total)} · Page {esc(current)} / {esc(pages)}</span>'
            f'{next_html}'
            '</div>'
        )
    return chunk, pager


def strip_tags(value: str) -> str:
    return re.sub(r"<[^>]*>", "", str(value or ""))


def badge(active: bool) -> str:
    return '<span class="badge ok">Active</span>' if active else '<span class="badge bad">Inactive</span>'


def status_pill(status: str | None) -> str:
    value = (status or "pending").strip().lower()
    if value == "done":
        return '<span class="status-pill status-done">✅ Done</span>'
    if value == "failed":
        return '<span class="status-pill status-failed">❌ Failed</span>'
    return '<span class="status-pill status-pending">⏳ Pending</span>'


def deposit_status_pill(status: str | None) -> str:
    value = (status or "waiting").strip().lower()
    if value in {"credited", "confirmed", "paid"}:
        return '<span class="status-pill status-done">✅ Paid</span>'
    if value in {"expired"}:
        return '<span class="status-pill status-failed">❌ Expired</span>'
    if value in {"rejected", "failed"}:
        return '<span class="status-pill status-failed">❌ Failed</span>'
    return '<span class="status-pill status-pending">⏳ Pending</span>'


def dispute_status_pill(status: str | None) -> str:
    value = (status or "open").strip().lower()
    if value == "resolved":
        return '<span class="status-pill status-done">✅ Resolved</span>'
    if value == "rejected":
        return '<span class="status-pill status-failed">❌ Rejected</span>'
    if value == "under_review":
        return '<span class="status-pill status-pending">🔎 Under review</span>'
    return '<span class="status-pill status-pending">🟠 Open</span>'


def pending_payment_review_count() -> int:
    with get_conn() as conn:
        return int(conn.execute("SELECT COUNT(*) AS n FROM payment_deposits WHERE status = 'manual_pending' AND credited_at IS NULL").fetchone()["n"] or 0)


def payment_method_label(row: sqlite3.Row) -> str:
    method = str(row["method"] or row["network"] or "").lower()
    network = str(row["network"] or method).lower()
    if method == "binance" or network == "binance":
        return "Binance Pay"
    if network == "polygon":
        return "USDT (POLYGON)"
    return "USDT (BEP20)"


def payment_explorer_tx_url(row: sqlite3.Row) -> str | None:
    tx = str(row["tx_hash"] or "").strip()
    if not tx:
        return None
    network = str(row["network"] or row["method"] or "").lower()
    if network == "polygon":
        return f"https://polygonscan.com/tx/{quote(tx)}"
    if network == "bep20" or network in {"usdt", "usdt_bep20"}:
        return f"https://bscscan.com/tx/{quote(tx)}"
    return None



def _public_payment_error_text(errors: str | list[str] | tuple[str, ...] | None) -> str:
    if errors is None:
        return "Auto-check could not verify this transaction. Support review required."
    if isinstance(errors, str):
        raw_items = [part.strip() for part in re.split(r"\s*\|\s*", errors) if part.strip()]
    else:
        raw_items = [str(item or "").strip() for item in errors if str(item or "").strip()]
    if not raw_items:
        return "No matching USDT transfer found yet."
    combined = " | ".join(raw_items)
    low = combined.lower()

    received_values: list[str] = []
    for match in re.finditer(r"amount does not match\.?\s*received:\s*([^|]+?)\s*usdt", combined, flags=re.I):
        for value in [v.strip() for v in match.group(1).split(",") if v.strip()]:
            if value and value not in received_values:
                received_values.append(value)
    if received_values:
        shown = ", ".join(received_values[:3])
        more = "…" if len(received_values) > 3 else ""
        return f"Amount does not match. Received: {shown}{more} USDT."

    priority_checks = [
        (r"duplicate|already been used|already linked", "This TxHash is already linked to another payment."),
        (r"invalid transaction hash", "Invalid transaction hash format."),
        (r"not found on the selected network|did not find this tx", "Transaction was not found on the selected network."),
        (r"not a usdt transfer to your payment wallet|not a .*transfer to your payment wallet", "Transaction is not a USDT transfer to your payment wallet."),
        (r"not a usdt transfer", "Transaction is not a USDT transfer on the selected network."),
        (r"older than this payment request", "Transaction is older than this payment request."),
        (r"wallet address is not configured|wallet address is missing|invalid.*wallet", "Payment wallet is missing or invalid in Payment Settings."),
        (r"no matching incoming usdt|no recent usdt|no transactions found", "No matching incoming USDT transfer found yet."),
        (r"binance.*api key|api key/secret", "Binance API key/secret is missing or invalid in Secret Settings."),
        (r"explorer api key|invalid api key|missing api key", "Explorer API key is missing or invalid in Secret Settings."),
        (r"rate limit|max rate", "Explorer rate limit reached. Try again shortly."),
    ]
    for pattern, message in priority_checks:
        if re.search(pattern, low, flags=re.I):
            return message

    confirmation_match = re.search(r"(?:needs more confirmations|has)\s*\(?\s*(\d+)\s*/\s*(\d+)\)?|current:\s*(\d+).*requires?\s*(\d+)", combined, flags=re.I)
    if confirmation_match:
        nums = [x for x in confirmation_match.groups() if x]
        if len(nums) >= 2:
            return f"Transaction needs more confirmations ({nums[0]}/{nums[1]})."
        return "Transaction needs more confirmations."

    if re.search(r"notok|rpc|http \d+|getlogs|blocknumber|etherscan|bscscan|polygonscan|explorer", low, flags=re.I):
        return "Auto-check could not verify this transaction through the chain API. Support review required."

    first = re.sub(r"\s+", " ", raw_items[-1]).strip()
    first = re.sub(r"\{.*?\}", "", first).strip(" |:;,.{}[]'")
    if not first:
        return "Auto-check could not verify this transaction. Support review required."
    if len(first) > 180:
        first = first[:177].rstrip() + "…"
    return first


def payment_manual_check_label(row: sqlite3.Row) -> str:
    status = str(row["status"] or "").strip().lower()
    if status in {"credited", "confirmed", "paid"}:
        return "Payment approved"
    if status == "rejected":
        return "Payment rejected"
    if status == "expired":
        return "Payment expired"
    result = str(row["manual_check_result"] or "").strip().lower()
    if result in {"passed", "verified", "approved"}:
        return "Manual TxHash auto-approved"
    if result in {"duplicate"}:
        return "Duplicate TxHash blocked"
    if result in {"failed", "error"}:
        return "Manual TxHash needs review"
    if status == "manual_pending":
        return "Waiting for review"
    return "Payment check pending"

def completed_value(row: sqlite3.Row) -> str:
    status = str(row["status"] or "pending").lower()
    if status in {"done", "failed"} and row["status_at"]:
        return display_datetime(row["status_at"])
    return "—"


def _parse_iso_dt(value: str | datetime | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value))
        except Exception:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=ZoneInfo(BOT_TZ))
    else:
        dt = dt.astimezone(ZoneInfo(BOT_TZ))
    return dt


def duration_between(start_value: str | datetime | None, end_value: str | datetime | None) -> str:
    start_dt = _parse_iso_dt(start_value)
    end_dt = _parse_iso_dt(end_value)
    if not start_dt or not end_dt:
        return "—"
    seconds = max(0, int((end_dt - start_dt).total_seconds()))
    if seconds < 60:
        return f"{seconds}s"
    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {sec}s" if sec else f"{minutes}m"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h {minutes}m" if minutes else f"{hours}h"
    days, hours = divmod(hours, 24)
    return f"{days}d {hours}h" if hours else f"{days}d"


def qr_duration_value(row: sqlite3.Row) -> str:
    status = str(row["status"] or "pending").lower()
    if status in {"done", "failed"} and row["status_at"]:
        return duration_between(row["created_at"], row["status_at"])
    if row["claimed_at"]:
        return duration_between(row["created_at"], row["claimed_at"]) + " to claim"
    return "—"


def photo_no_html(row: sqlite3.Row) -> str:
    return f'📷 #{esc(row["daily_no"])}'


def user_stats_url(chat_id: int) -> str:
    return f"/admin/users/{int(chat_id)}/stats"


def user_link(row_or_id, *, username: str | None = None, alias: str | None = None) -> str:
    if isinstance(row_or_id, sqlite3.Row):
        chat_id = int(row_or_id["chat_id"])
        username = row_or_id["username"] if "username" in row_or_id.keys() else username
        alias = row_or_id["alias"] if "alias" in row_or_id.keys() else alias
    else:
        chat_id = int(row_or_id)
    name = f"@{username}" if username else "No username captured"
    alias_html = f'<span class="alias">{esc(alias)}</span>' if alias else ""
    return (
        f'<a class="user-id" href="{user_stats_url(chat_id)}">{esc(chat_id)}</a>'
        f'<a class="username" href="{user_stats_url(chat_id)}">{esc(name)}</a>'
        f'{alias_html}'
    )


def stat_cards_html(title: str, *, sender_chat_id: int | None = None, receiver_chat_id: int | None = None, show_identity: bool = True) -> str:
    today = stats_for_filters(scope="today", sender_chat_id=sender_chat_id, receiver_chat_id=receiver_chat_id)
    lifetime = stats_for_filters(scope="lifetime", sender_chat_id=sender_chat_id, receiver_chat_id=receiver_chat_id)

    identity = ""
    if show_identity and (sender_chat_id is not None or receiver_chat_id is not None):
        parts: list[str] = []
        if sender_chat_id is not None:
            sender = get_admin_user_row(int(sender_chat_id))
            parts.append(f'<div><span class="muted">Sender</span>{user_link(sender) if sender else esc(sender_chat_id)}</div>')
        if receiver_chat_id is not None:
            receiver = get_admin_user_row(int(receiver_chat_id))
            parts.append(f'<div><span class="muted">Receiver / Buyer</span>{user_link(receiver) if receiver else esc(receiver_chat_id)}</div>')
        identity = f'<div class="stats-identity">{"".join(parts)}</div>'

    def card(label: str, counts: dict[str, int | str]) -> str:
        return f'''
        <div class="card stat-card">
          <h3>{esc(label)}</h3>
          <div class="stats-grid">
            <div><b>📦 {counts['total']}</b><span>Total</span></div>
            <div><b>⏳ {counts['pending']}</b><span>Pending</span></div>
            <div><b>✅ {counts['done']}</b><span>Done</span></div>
            <div><b>❌ {counts['failed']}</b><span>Failed</span></div>
          </div>
        </div>'''

    return f'''
      <h2>📊 {esc(title)}</h2>
      {identity}
      <div class="cards two">
        {card('📅 Today — ' + display_date(today_str()), today)}
        {card('🏁 Lifetime', lifetime)}
      </div>
    '''


def admin_back_link_html(request: Request | None) -> str:
    if request is None:
        return ""
    path = request.url.path

    if path.startswith("/admin/users/") and path.endswith("/stats"):
        return '<a class="back-link" href="/admin/users">← Back to users</a>'

    if path.startswith("/admin/qrs/"):
        return '<a class="back-link" href="/admin/pending">← Back to QR list</a>'

    if path.startswith("/admin/stats/pair/"):
        back = str(request.query_params.get("back", "pairs")).strip().lower()
        if back == "stats":
            return '<a class="back-link" href="/admin/stats">← Back to stats</a>'
        return '<a class="back-link" href="/admin/pairs">← Back to pairs</a>'

    return ""


def render_page(title: str, body: str, request: Request | None = None) -> HTMLResponse:
    flash = ""
    if request is not None:
        msg = request.query_params.get("msg", "").strip()
        if msg:
            flash = f'<div class="flash">{esc(msg)}</div>'

    sidebar = "" if title == "Login" else f'''
      <button class="mobile-menu-btn" type="button" onclick="toggleSidebar()" aria-label="Toggle menu">☰ Menu</button>
      <div class="sidebar-overlay" onclick="closeSidebar()" aria-hidden="true"></div>
      <aside class="sidebar" id="adminSidebar">
        <div class="brand">
          <div class="logo">QR</div>
          <div><strong>{esc(APP_NAME)}</strong><span>Admin panel</span></div>
          <button class="sidebar-close" type="button" onclick="closeSidebar()" aria-label="Close menu">×</button>
        </div>
        <nav class="side-nav">
          <a href="/admin">🏠 Dashboard</a>
          <a href="/admin/users">👥 Users</a>
          <a href="/admin/marketplace">📡 Marketplace</a>
          <a href="/admin/payment-reviews">🧾 Pending Payments <span class="nav-count">{pending_payment_review_count()}</span></a>
          <a href="/admin/wallet-deposits">🏦 Wallet Deposits</a>
          <a href="/admin/payments">💳 Payment Settings</a>
          <a href="/admin/payouts">💸 Payout Requests <span class="nav-count">{pending_payout_count()}</span></a>
          <a href="/admin/disputes">⚠️ Disputes <span class="nav-count">{pending_dispute_count()}</span></a>
          <a href="/admin/messages">💬 Preset Messages</a>
          <a href="/admin/stats">📊 Stats</a>
          <a href="/admin/pending">⏳ Pending QR</a>
          <a href="/admin/settings">🔐 Secret Settings</a>
          <a href="/admin/logout">🚪 Logout</a>
        </nav>
      </aside>
    '''
    qr_modal = "" if title == "Login" else '''
      <div class="qr-modal" id="qrModal" onclick="closeQrModal(event)" aria-hidden="true">
        <div class="qr-dialog" role="dialog" aria-modal="true" aria-labelledby="qrModalTitle">
          <button class="modal-close" type="button" onclick="hideQrModal()" aria-label="Close QR preview">×</button>
          <h3 id="qrModalTitle">QR preview</h3>
          <img id="qrModalImage" src="" alt="Generated QR preview">
          <a id="qrModalOpen" class="btn" href="#" target="_blank" rel="noopener">Open image</a>
        </div>
      </div>
    '''
    generic_confirm_modal = "" if title == "Login" else """
      <div id="generic-confirm-modal" class="confirm-modal-shell" hidden>
        <div class="confirm-modal-backdrop" data-close-generic-confirm></div>
        <div class="confirm-modal-panel" role="dialog" aria-modal="true">
          <h2 id="generic-confirm-title">Confirm action?</h2>
          <p id="generic-confirm-desc" class="confirm-modal-desc">Please confirm this action.</p>
          <form id="generic-confirm-submit-form" method="post" action="">
            <div class="confirm-actions">
              <button type="button" class="secondary" data-close-generic-confirm>Cancel</button>
              <button type="submit" id="generic-confirm-submit" class="danger">Confirm</button>
            </div>
          </form>
        </div>
      </div>
    """
    login_shell = f'<div class="login-shell"><main>{flash}{body}</main></div>'
    back_link = admin_back_link_html(request)
    app_shell = f'<div class="layout">{sidebar}<main>{back_link}<div class="page-title"><h1>{esc(title)}</h1></div>{flash}{body}</main></div>{qr_modal}{generic_confirm_modal}'
    page_body = login_shell if title == "Login" else app_shell
    html_doc = f'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{esc(title)} · {esc(APP_NAME)}</title>
  <style>
    :root {{ --bg:#0f172a; --panel:#111827; --card:#1f2937; --text:#e5e7eb; --muted:#9ca3af; --line:#374151; --accent:#38bdf8; --good:#22c55e; --bad:#ef4444; --warn:#f59e0b; --shadow:rgba(0,0,0,.45); }}
    * {{ box-sizing: border-box; }}
    html, body {{ height:100%; overflow:hidden; }}
    body {{ margin:0; font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; background:var(--bg); color:var(--text); }}
    body.sidebar-open {{ overflow:hidden; }}
    a {{ color:inherit; }}
    .layout {{ display:block; height:100dvh; width:100%; overflow:hidden; }}
    .sidebar {{ width:270px; background:linear-gradient(180deg,#111827,#0b1220); border-right:1px solid var(--line); padding:18px; position:fixed; top:0; left:0; bottom:0; height:100dvh; overflow-y:auto; overscroll-behavior:contain; z-index:1000; }}
    .brand {{ display:flex; gap:12px; align-items:center; margin-bottom:22px; }}
    .brand span {{ display:block; color:var(--muted); font-size:13px; margin-top:2px; }}
    .logo {{ width:42px; height:42px; border-radius:14px; display:flex; align-items:center; justify-content:center; background:#2563eb; font-weight:900; flex:0 0 42px; }}
    .sidebar-close, .mobile-menu-btn {{ display:none; }}
    .side-nav {{ display:flex; flex-direction:column; gap:8px; }}
    .side-nav a, .btn {{ color:var(--text); text-decoration:none; background:#263244; border:1px solid var(--line); padding:10px 12px; border-radius:12px; display:inline-block; cursor:pointer; font-weight:700; }}
    .side-nav a:hover, .btn:hover {{ border-color:var(--accent); background:#1e3a5f; }}
    .nav-count {{ float:right; min-width:22px; height:22px; padding:2px 6px; border-radius:999px; background:#dc2626; color:white; font-size:12px; line-height:18px; text-align:center; font-weight:900; }}
    .layout > main {{ position:fixed; left:270px; right:0; top:0; bottom:0; overflow-y:auto; overflow-x:hidden; max-width:none; padding:24px; margin:0; width:auto; min-width:0; }}
    .layout > main > * {{ max-width:1280px; margin-left:auto; margin-right:auto; }}
    .login-shell main {{ position:static; max-width:1280px; width:100%; padding:0; margin:0 auto; }}
    .back-link {{ display:inline-flex; align-items:center; gap:6px; color:#93c5fd; text-decoration:none; font-weight:800; margin:0 0 14px; }}
    .back-link:hover {{ color:#bfdbfe; }}
    .page-title {{ display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:18px; }}
    .page-title h1 {{ margin:0; font-size:26px; }}
    .card {{ background:var(--card); border:1px solid var(--line); border-radius:18px; padding:18px; margin-bottom:18px; box-shadow: 0 10px 24px rgba(0,0,0,.18); }}
    .cards {{ display:grid; gap:18px; width:100%; min-width:0; }}
    .cards.two {{ grid-template-columns: repeat(auto-fit, minmax(min(260px, 100%), 1fr)); }}
    .flash {{ background:#063b4f; border:1px solid var(--accent); padding:12px 14px; border-radius:12px; margin-bottom:18px; }}
    input, select, textarea {{ width:100%; background:#0b1220; color:var(--text); border:1px solid var(--line); border-radius:12px; padding:11px; margin:6px 0 12px; }}
    textarea {{ min-height:90px; }}
    label {{ color:var(--muted); font-size:14px; }}
    form.inline {{ display:inline; }}
    button {{ background:#2563eb; color:white; border:0; padding:10px 12px; border-radius:12px; cursor:pointer; font-weight:800; }}
    button.danger {{ background:#dc2626; }}
    button.success {{ background:#16a34a; }}
    button.secondary {{ background:#374151; }}
    .dashboard-top-actions {{ display:flex; justify-content:flex-end; align-items:center; gap:12px; flex-wrap:wrap; margin-bottom:18px; }}
    .maintenance-state {{ display:flex; flex-direction:column; gap:3px; background:#111827; border:1px solid var(--line); border-radius:14px; padding:10px 14px; min-width:min(280px,100%); }}
    .maintenance-state span {{ color:var(--muted); font-size:13px; }}
    .maintenance-state.on {{ border-color:rgba(239,68,68,.55); background:rgba(127,29,29,.22); }}
    .maintenance-state.off {{ border-color:rgba(34,197,94,.4); background:rgba(20,83,45,.18); }}
    .settings-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:16px; }}
    .setting-card {{ background:#0b1220; border:1px solid var(--line); border-radius:18px; padding:18px; }}
    .payment-method-header {{ display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:14px; }}
    .payment-method-header strong {{ font-size:18px; }}
    .payment-toggle-button {{ min-width:118px; border-radius:999px; border:1px solid transparent; }}
    .payment-toggle-button.enabled {{ background:rgba(127,29,29,.45); color:#fecaca; border-color:rgba(239,68,68,.5); }}
    .payment-toggle-button.disabled {{ background:rgba(20,83,45,.45); color:#86efac; border-color:rgba(34,197,94,.5); }}
    .payment-method-card.is-disabled .method-details {{ opacity:.35; pointer-events:none; }}
    .method-off-note {{ display:none; }}
    .payment-method-card.is-disabled .method-off-note {{ display:block; }}
    .price-input-wrap {{ display:flex; align-items:center; gap:8px; background:#0b1220; border:1px solid var(--line); border-radius:12px; padding-right:12px; margin:6px 0 12px; }}
    .price-input-wrap input {{ border:0; margin:0; }}
    .price-input-wrap span {{ color:#cbd5e1; font-weight:900; }}
    .sr-only {{ position:absolute; width:1px; height:1px; padding:0; margin:-1px; overflow:hidden; clip:rect(0,0,0,0); white-space:nowrap; border:0; }}
    .table-wrap {{ width:100%; overflow-x:auto; -webkit-overflow-scrolling:touch; }}
    table {{ width:100%; border-collapse:collapse; min-width:720px; }}
    table.compact-table {{ min-width:840px; font-size:13px; }}
    table.compact-table th, table.compact-table td {{ padding:8px 7px; }}
    table.compact-table .status-pill {{ min-width:78px; padding:4px 8px; }}
    th, td {{ padding:12px 10px; border-bottom:1px solid var(--line); text-align:left; vertical-align:middle; }}
    th {{ color:#cbd5e1; background:#111827; }}
    th.cell-center, td.cell-center {{ text-align:center; }}
    td.cell-center .btn, td.cell-center form.inline, td.cell-center button {{ margin-inline:auto; }}
    .muted {{ color:var(--muted); }}
    .badge {{ padding:4px 8px; border-radius:999px; font-size:12px; font-weight:800; display:inline-block; }}
    .badge.ok {{ background:rgba(34,197,94,.18); color:#86efac; }}
    .badge.bad {{ background:rgba(239,68,68,.18); color:#fecaca; }}
    .badge.warn {{ background:rgba(245,158,11,.18); color:#fde68a; }}
    .status-pill {{ display:inline-flex; align-items:center; justify-content:center; gap:4px; border-radius:999px; padding:5px 10px; font-size:12px; font-weight:900; min-width:92px; }}
    .status-done {{ background:rgba(34,197,94,.18); color:#86efac; border:1px solid rgba(34,197,94,.35); }}
    .status-failed {{ background:rgba(239,68,68,.18); color:#fecaca; border:1px solid rgba(239,68,68,.35); }}
    .status-pending {{ background:rgba(245,158,11,.18); color:#fde68a; border:1px solid rgba(245,158,11,.35); }}
    .stats-identity {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:12px; margin:10px 0 18px; }}
    .stats-identity > div {{ background:#111827; border:1px solid var(--line); border-radius:14px; padding:13px; }}
    .stats-identity .muted {{ display:block; font-size:13px; margin-bottom:6px; }}
    .message-list {{ display:grid; gap:14px; }}
    .message-card {{ background:#111827; border:1px solid var(--line); border-radius:16px; padding:15px; }}
    .message-head {{ display:grid; grid-template-columns:80px 120px minmax(180px,1fr) minmax(240px,1.5fr) auto; gap:14px; align-items:center; }}
    .message-id {{ font-weight:900; color:#bfdbfe; }}
    .message-button {{ font-weight:900; }}
    .message-text {{ line-height:1.45; }}
    .reply-list {{ margin-top:14px; border-top:1px solid var(--line); padding-top:12px; display:grid; gap:10px; }}
    .reply-card {{ display:grid; grid-template-columns:80px 120px minmax(160px,1fr) minmax(220px,1.4fr) auto; gap:12px; align-items:center; background:#0b1220; border:1px solid var(--line); border-radius:14px; padding:11px; }}
    .date-cell, .photo-cell, .created-cell, .completed-cell {{ text-align:center; white-space:nowrap; }}
    .stats-grid {{ display:grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap:10px; width:100%; min-width:0; }}
    .stats-grid div {{ background:#111827; border:1px solid var(--line); border-radius:14px; padding:13px; text-align:center; min-width:0; }}
    .stats-grid b {{ font-size:22px; display:block; }}
    .stats-grid span {{ color:var(--muted); font-size:13px; }}
    .row {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap:14px; }}
    .pagination {{ display:flex; align-items:center; justify-content:center; gap:10px; flex-wrap:wrap; margin:14px 0 2px; }}
    .pagination.compact {{ justify-content:flex-start; color:var(--muted); font-size:13px; }}
    .page-info {{ color:var(--muted); font-weight:700; }}
    .page-btn.disabled {{ opacity:.45; pointer-events:none; }}
    .small {{ font-size:12px; }}
    code {{ background:#0b1220; padding:2px 5px; border-radius:6px; }}
    .user-id, .username {{ display:block; text-decoration:none; }}
    .user-id {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-weight:900; color:#bfdbfe; }}
    .username {{ color:#93c5fd; margin-top:3px; }}
    .alias {{ display:block; color:var(--muted); margin-top:3px; }}
    .qr-id, .qr-detail-id {{ color:#93c5fd; font-weight:900; text-decoration:none; border-bottom:1px dashed #93c5fd; white-space:nowrap; display:inline-block; min-width:max-content; }}
    .qr-id:hover, .qr-detail-id:hover {{ color:#bfdbfe; border-bottom-color:#bfdbfe; }}
    .qr-detail-image {{ width:min(100%, 420px); border-radius:18px; border:1px solid var(--line); background:white; padding:10px; }}
    .login-shell {{ min-height:100vh; display:flex; align-items:center; justify-content:center; padding:18px; }}
    .sidebar-overlay {{ display:none; }}
    .qr-modal {{ display:none; position:fixed; inset:0; background:rgba(0,0,0,.72); z-index:2000; align-items:center; justify-content:center; padding:20px; }}
    .qr-modal.open {{ display:flex; }}
    .qr-dialog {{ background:var(--card); border:1px solid var(--line); border-radius:20px; padding:18px; max-width:520px; width:min(520px, 96vw); text-align:center; box-shadow:0 24px 80px var(--shadow); position:relative; }}
    .qr-dialog h3 {{ margin-top:0; }}
    .qr-dialog img {{ max-width:100%; max-height:68vh; background:white; border-radius:14px; padding:10px; }}
    .modal-close {{ position:absolute; top:10px; right:10px; width:36px; height:36px; border-radius:999px; background:#374151; padding:0; font-size:22px; line-height:1; }}
    .proof-button {{ background:#075985; border:1px solid #0ea5e9; color:#7dd3fc; }}
    .payment-action-stack {{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; }}
    .break-anywhere {{ overflow-wrap:anywhere; word-break:break-word; }}
    .warning-text {{ color:#fde68a; }}
    .tx-hash-link {{ color:#7dd3fc; font-weight:900; text-decoration:none; overflow-wrap:anywhere; word-break:break-word; }}
    .tx-hash-link:hover {{ color:#bae6fd; text-decoration:underline; }}
    .proof-modal-template {{ display:none !important; }}
    .proof-modal-shell[hidden], .proof-image-fullscreen[hidden] {{ display:none !important; }}
    .proof-modal-shell {{ position:fixed; inset:0; z-index:2300; display:block; padding:0; }}
    .proof-modal-backdrop {{ position:absolute; inset:0; background:rgba(0,0,0,.72); backdrop-filter:blur(3px); }}
    .proof-modal-panel {{ position:relative; z-index:1; background:linear-gradient(180deg,#0b1328 0%,#091224 100%); border:1px solid var(--line); border-radius:20px; width:min(1180px, calc(100vw - 32px)); max-height:calc(100vh - 40px); overflow:auto; margin:20px auto; padding:24px; box-shadow:0 26px 90px var(--shadow); }}
    .proof-modal-close {{ position:sticky; top:0; margin-left:auto; display:flex; align-items:center; justify-content:center; width:42px; height:42px; border-radius:999px; background:#374151; padding:0; font-size:28px; line-height:1; z-index:2; }}
    .proof-modal-header {{ display:flex; align-items:flex-start; justify-content:space-between; gap:16px; margin-bottom:18px; }}
    .proof-modal-header h3 {{ margin:0; font-size:24px; }}
    .proof-modal-layout {{ display:grid; grid-template-columns:minmax(0, 1fr) minmax(320px, 42%); gap:22px; align-items:start; }}
    .proof-details-pane {{ min-width:0; }}
    .proof-overview-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:14px; margin-bottom:16px; }}
    .proof-card {{ background:#0b1220; border:1px solid var(--line); border-radius:16px; padding:16px; overflow-wrap:anywhere; }}
    .proof-label {{ display:block; color:var(--muted); font-size:13px; margin-bottom:8px; }}
    .proof-card strong {{ font-size:16px; line-height:1.4; }}
    .proof-detail-list {{ display:grid; gap:12px; margin-bottom:18px; }}
    .proof-detail-row {{ display:grid; grid-template-columns:minmax(145px,190px) minmax(0,1fr); gap:14px; align-items:start; padding:14px 0; border-top:1px solid var(--line); overflow-wrap:anywhere; }}
    .proof-detail-row:first-child {{ border-top:0; }}
    .proof-detail-row span {{ color:var(--muted); }}
    .proof-detail-row strong {{ line-height:1.5; }}
    .proof-image-block {{ display:grid; gap:10px; align-content:start; position:sticky; top:58px; min-width:0; }}
    .proof-image-button {{ display:block; width:100%; padding:0; margin:0; border:1px solid var(--line); border-radius:18px; background:#020617; cursor:zoom-in; overflow:hidden; }}
    .proof-image-button:hover {{ border-color:#a78bfa; box-shadow:0 0 0 3px rgba(124,58,237,.16); }}
    .proof-image {{ display:block; width:100%; max-height:calc(100vh - 190px); object-fit:contain; background:#020617; }}
    .proof-image-hint {{ color:var(--muted); font-size:12px; margin:0; }}
    .proof-image-fullscreen {{ position:fixed; inset:0; z-index:2600; display:flex; align-items:center; justify-content:center; padding:20px; background:rgba(2,6,23,.94); backdrop-filter:blur(3px); }}
    .proof-image-fullscreen img {{ max-width:min(100%,1200px); max-height:calc(100vh - 40px); object-fit:contain; border-radius:16px; background:#020617; box-shadow:0 26px 90px var(--shadow); }}
    .proof-image-fullscreen-close {{ position:fixed; top:18px; right:18px; display:flex; align-items:center; justify-content:center; width:44px; height:44px; border-radius:999px; font-size:28px; line-height:1; z-index:2601; background:#374151; padding:0; }}
    .confirm-modal-shell[hidden] {{ display:none !important; }}
    .confirm-modal-shell {{ position:fixed; inset:0; z-index:2500; display:flex; align-items:center; justify-content:center; padding:22px; }}
    .confirm-modal-backdrop {{ position:absolute; inset:0; background:rgba(0,0,0,.72); backdrop-filter:blur(3px); }}
    .confirm-modal-panel {{ position:relative; z-index:1; width:min(620px, calc(100vw - 44px)); background:var(--panel); border:1px solid var(--line); border-radius:20px; padding:28px; box-shadow:0 26px 90px var(--shadow); }}
    .confirm-modal-panel h2 {{ margin:0 0 12px; font-size:28px; }}
    .confirm-modal-desc {{ margin:0 0 26px; color:var(--muted); font-size:18px; line-height:1.45; }}
    .confirm-detail-row {{ display:grid; grid-template-columns:160px minmax(0, 1fr); gap:14px; align-items:start; padding:14px 0; border-top:1px solid var(--line); }}
    .confirm-detail-row span {{ color:var(--muted); }}
    .confirm-detail-row strong {{ text-align:right; overflow-wrap:anywhere; }}
    .confirm-actions {{ display:flex; justify-content:flex-end; gap:12px; margin-top:26px; flex-wrap:wrap; }}
    .confirm-actions button {{ min-width:160px; }}
    @media (max-width: 900px) {{ .proof-modal-layout {{ grid-template-columns:1fr; }} .proof-image-block {{ position:static; }} .proof-detail-row {{ grid-template-columns:1fr; gap:6px; }} .confirm-detail-row {{ grid-template-columns:1fr; gap:6px; }} .confirm-detail-row strong {{ text-align:left; }} }}
    @media (max-width: 760px) {{ .proof-modal-panel {{ width:min(calc(100vw - 18px),100%); max-height:calc(100vh - 18px); margin:9px auto; padding:18px; }} }}
    @media (max-width: 820px) {{
      html, body {{ width:100%; max-width:100%; height:100%; overflow:hidden; }}
      .layout {{ display:block; width:100%; max-width:100vw; height:100dvh; overflow:hidden; }}
      .mobile-menu-btn {{ display:block; position:fixed; top:12px; left:12px; z-index:1100; background:#2563eb; box-shadow:0 12px 30px var(--shadow); }}
      body.sidebar-open .mobile-menu-btn {{ display:block; }}
      .sidebar {{ width:min(86vw, 340px); height:100dvh; max-height:100dvh; position:fixed; top:0; left:0; right:auto; border-left:0; border-right:1px solid var(--line); padding:76px 16px 16px; transform:translateX(-105%); transition:transform .22s ease; box-shadow:18px 0 50px var(--shadow); overflow-y:auto; overscroll-behavior:contain; z-index:1000; }}
      body.sidebar-open .sidebar {{ transform:translateX(0); }}
      .sidebar-overlay {{ display:none; position:fixed; inset:0; background:rgba(0,0,0,.55); z-index:999; }}
      body.sidebar-open .sidebar-overlay {{ display:block; }}
      .sidebar-close {{ display:block; margin-left:auto; background:#374151; width:36px; height:36px; border-radius:999px; padding:0; font-size:24px; line-height:1; }}
      .brand {{ margin-bottom:14px; padding-right:4px; }}
      .brand > div:nth-child(2) {{ min-width:0; }}
      .brand strong {{ display:block; line-height:1.15; }}
      .side-nav {{ flex-direction:column; overflow:visible; padding-bottom:0; gap:10px; }}
      .side-nav a {{ white-space:normal; padding:13px 14px; }}
      .layout > main {{ position:fixed; left:0; right:0; top:0; bottom:0; padding:74px 12px 16px; width:auto; max-width:none; overflow-y:auto; overflow-x:hidden; -webkit-overflow-scrolling:touch; }}
      .layout > main > * {{ max-width:100%; }}
      .page-title {{ margin-bottom:12px; }}
      .page-title h1 {{ font-size:22px; }}
      h2 {{ font-size:22px; margin:10px 0 14px; }}
      .card {{ padding:14px; border-radius:16px; width:100%; max-width:100%; overflow:hidden; }}
      .cards.two {{ grid-template-columns:1fr; gap:14px; }}
      .stats-grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); gap:10px; }}
      .stats-grid div {{ padding:12px 8px; }}
      .stats-grid b {{ font-size:20px; }}
      table {{ min-width:760px; }}
      table.compact-table {{ min-width:780px; font-size:12px; }}
      table.compact-table th, table.compact-table td {{ padding:7px 6px; }}
      .pagination {{ gap:8px; }}
      .page-info {{ flex:0 0 100%; text-align:center; font-size:12px; order:-1; }}
      .message-head, .reply-card {{ grid-template-columns:1fr; gap:7px; align-items:start; }}
      .message-card {{ padding:13px; }}
      .reply-card form.inline, .message-head form.inline {{ justify-self:start; }}
    }}
    @media (max-width: 360px) {{
      .layout > main {{ padding-left:10px; padding-right:10px; }}
      .stats-grid {{ gap:8px; }}
      .stats-grid div {{ padding:10px 6px; }}
      .stats-grid b {{ font-size:18px; }}
      .stats-grid span {{ font-size:12px; }}
    }}
  </style>
</head>
<body>
  {page_body}
  <script>
    function openSidebar() {{ document.body.classList.add('sidebar-open'); }}
    function closeSidebar() {{ document.body.classList.remove('sidebar-open'); }}
    function toggleSidebar() {{ document.body.classList.toggle('sidebar-open'); }}
    function showPayoutDetails(button) {{
      const details = (button && button.getAttribute('data-details')) || 'No details saved';
      window.alert(details);
    }}
    document.addEventListener('click', function(event) {{
      if (event.target.closest && event.target.closest('.side-nav a')) {{ closeSidebar(); }}
    }});
    document.addEventListener('DOMContentLoaded', function() {{
      document.querySelectorAll('.side-nav a').forEach(function(a) {{
        a.addEventListener('click', function() {{ closeSidebar(); }});
      }});
    }});
    function hideQrModal() {{
      const modal = document.getElementById('qrModal');
      if (!modal) return;
      modal.classList.remove('open');
      modal.setAttribute('aria-hidden', 'true');
      const img = document.getElementById('qrModalImage');
      if (img) img.src = '';
    }}
    function closeQrModal(event) {{ if (event.target && event.target.id === 'qrModal') hideQrModal(); }}
    document.addEventListener('DOMContentLoaded', function() {{
      document.querySelectorAll('.side-nav a').forEach(function(a) {{ a.addEventListener('click', closeSidebar); }});
      document.querySelectorAll('a.qr-id').forEach(function(a) {{
        a.addEventListener('click', function(event) {{
          event.preventDefault();
          const src = a.getAttribute('data-qr-src') || a.href;
          const title = a.getAttribute('data-qr-title') || a.textContent || 'QR preview';
          const modal = document.getElementById('qrModal');
          const img = document.getElementById('qrModalImage');
          const heading = document.getElementById('qrModalTitle');
          const open = document.getElementById('qrModalOpen');
          if (!modal || !img || !heading || !open) {{ window.open(src, '_blank'); return; }}
          heading.textContent = 'QR preview · ' + title;
          img.src = src;
          open.href = src;
          modal.classList.add('open');
          modal.setAttribute('aria-hidden', 'false');
        }});
      }});
      const genericShell = document.getElementById('generic-confirm-modal');
      const genericForm = document.getElementById('generic-confirm-submit-form');
      const genericTitle = document.getElementById('generic-confirm-title');
      const genericDesc = document.getElementById('generic-confirm-desc');
      const genericButton = document.getElementById('generic-confirm-submit');
      function closeGenericConfirm() {{
        if (genericShell) genericShell.hidden = true;
        if (genericForm) genericForm.action = '';
      }}
      document.querySelectorAll('[data-close-generic-confirm]').forEach(function(el) {{
        el.addEventListener('click', closeGenericConfirm);
      }});
      document.querySelectorAll('form[data-confirm-message], form[data-confirm-title]').forEach(function(form) {{
        form.addEventListener('submit', function(event) {{
          if (!genericShell || !genericForm) return;
          event.preventDefault();
          genericForm.action = form.action;
          genericForm.method = form.method || 'post';
          if (genericTitle) genericTitle.textContent = form.getAttribute('data-confirm-title') || 'Confirm action?';
          if (genericDesc) genericDesc.textContent = form.getAttribute('data-confirm-message') || 'Please confirm this action.';
          if (genericButton) {{
            genericButton.textContent = form.getAttribute('data-confirm-button') || 'Confirm';
            genericButton.className = form.getAttribute('data-confirm-class') || 'danger';
          }}
          genericShell.hidden = false;
        }});
      }});
    }});
    document.addEventListener('keydown', function(event) {{
      if (event.key === 'Escape') {{ closeSidebar(); hideQrModal(); }}
    }});
  </script>
</body>
</html>'''
    return HTMLResponse(html_doc)


@web_app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return RedirectResponse(url="/admin", status_code=303)


@web_app.get("/admin/photos/{public_id}/image")
async def admin_photo_image(request: Request, public_id: str):
    if not admin_authed(request):
        raise HTTPException(status_code=403, detail="Admin login required")
    row = get_photo_record(public_id)
    if not row or not row["generated_file_id"]:
        raise HTTPException(status_code=404, detail="Generated QR not found")
    if telegram_application is None:
        raise HTTPException(status_code=503, detail="Bot is not ready")
    try:
        tg_file = await telegram_application.bot.get_file(row["generated_file_id"])
        output = io.BytesIO()
        await tg_file.download_to_memory(output)
        return Response(content=output.getvalue(), media_type="image/jpeg")
    except TelegramError as exc:
        logger.warning("Could not load QR preview for %s: %s", public_id, exc)
        raise HTTPException(status_code=502, detail="Could not load QR preview from Telegram") from exc


@web_app.get("/admin/qrs/{public_id}", response_class=HTMLResponse)
async def admin_qr_detail(request: Request, public_id: str):
    guard = admin_guard(request)
    if guard:
        return guard
    row = get_photo_record(public_id)
    if not row:
        return render_page("QR Detail", '<div class="card"><p>QR not found.</p></div>', request)
    sender = get_admin_user_row(int(row["sender_chat_id"]))
    receiver_id = int(row["receiver_chat_id"] or 0)
    receiver = get_admin_user_row(receiver_id) if receiver_id else None
    sender_html = user_link(sender) if sender else esc(row["sender_chat_id"])
    receiver_html = user_link(receiver) if receiver else '<span class="muted">Unclaimed</span>'
    img_url = qr_image_url(public_id)
    offer_state = str(row["offer_state"] or "old").replace("_", " ").title()
    status_html = f'{status_pill(row["status"])} <span class="muted small">{esc(offer_state)}</span>'
    expire_form = ""
    if str(row["status"]).lower() == "pending":
        expire_form = (
            f'<form class="inline" method="post" action="/admin/pending/{esc(public_id)}/expire" '
            'data-confirm-title="Expire this QR?" data-confirm-button="Expire" data-confirm-class="danger" '
            'data-confirm-message="Sender reserve will be released and this QR cannot be completed.">'
            '<button class="danger" type="submit">Expire pending QR</button></form>'
        )
    body = f'''
    <div class="card">
      <h2>🆔 QR Detail</h2>
      <div class="row">
        <div>
          <p><strong>ID:</strong> <code>{esc(public_id)}</code></p>
          <p><strong>Photo:</strong> {photo_no_html(row)}</p>
          <p><strong>Status:</strong> {status_html}</p>
          <p><strong>Created:</strong> {esc(display_datetime(row["created_at"]))}</p>
          <p><strong>Claimed:</strong> {esc(display_datetime(row["claimed_at"])) if row["claimed_at"] else "—"}</p>
          <p><strong>Completed:</strong> {esc(completed_value(row))}</p>
          <p><strong>Processing:</strong> {esc(row["processing_ms"] or 0)} ms</p>
          {expire_form}
        </div>
        <div>
          <p><strong>Sender:</strong><br>{sender_html}</p>
          <p><strong>Receiver:</strong><br>{receiver_html}</p>
          <p><strong>Sender rate:</strong> ${_money(row["sender_rate_usdt"])} USDT</p>
          <p><strong>Receiver rate:</strong> ${_money(row["receiver_rate_usdt"])} USDT</p>
          <p><strong>Reserved:</strong> ${_money(row["reserved_usdt"])} USDT</p>
        </div>
      </div>
    </div>
    <div class="card">
      <h3>QR image</h3>
      <p><a class="btn" href="{esc(img_url)}" target="_blank" rel="noopener">Open QR image</a></p>
      <img class="qr-detail-image" src="{esc(img_url)}" alt="Generated QR image for {esc(public_id)}">
    </div>
    '''
    with get_conn() as conn:
        disputes = conn.execute("SELECT * FROM disputes WHERE public_id = ? ORDER BY created_at DESC", (public_id,)).fetchall()
    body += '<div class="card"><h3>Linked disputes</h3>'
    if not disputes:
        body += '<p class="muted">No disputes linked to this QR.</p>'
    else:
        body += '<div class="table-wrap"><table><tr><th>ID</th><th>User</th><th>Role</th><th>Message</th><th>Status</th><th>Created</th></tr>'
        for d in disputes:
            d_user = get_admin_user_row(int(d["chat_id"]))
            ref = str(d["ref_id"] or f"DSP{int(d['id']):06d}")
            body += f'<tr><td>#{esc(ref)}</td><td>{user_link(d_user) if d_user else esc(d["chat_id"])}</td><td>{esc(d["role"] or "")}</td><td>{esc(d["message"])}</td><td>{dispute_status_pill(d["status"])}</td><td>{esc(display_datetime(d["created_at"]))}</td></tr>'
        body += '</table></div>'
    body += '</div>'
    return render_page("QR Detail", body, request)


@web_app.get("/admin/payments/{ref_id}/proof-image")
async def admin_payment_proof_image(request: Request, ref_id: str):
    if not admin_authed(request):
        raise HTTPException(status_code=403, detail="Admin login required")
    dep = get_deposit(ref_id.upper())
    if not dep or not dep["manual_proof_file_id"]:
        raise HTTPException(status_code=404, detail="Payment proof not found")
    if telegram_application is None:
        raise HTTPException(status_code=503, detail="Bot is not ready")
    try:
        tg_file = await telegram_application.bot.get_file(dep["manual_proof_file_id"])
        output = io.BytesIO()
        await tg_file.download_to_memory(output)
        return Response(content=output.getvalue(), media_type="image/jpeg")
    except TelegramError as exc:
        logger.warning("Could not load payment proof for %s: %s", ref_id, exc)
        raise HTTPException(status_code=502, detail="Could not load payment proof from Telegram") from exc


@web_app.get("/admin/login", response_class=HTMLResponse)
async def admin_login_page(request: Request):
    if admin_authed(request):
        return RedirectResponse(url="/admin", status_code=303)
    body = """
      <div class="card" style="max-width:480px;margin:0 auto;">
        <h2>🔐 Admin login</h2>
        <form method="post" action="/admin/login">
          <label>Username</label>
          <input name="username" required autocomplete="username" autofocus>
          <label>Password</label>
          <input type="password" name="password" required autocomplete="current-password">
          <button type="submit">Login</button>
        </form>
      </div>
    """
    return render_page("Login", body, request)


@web_app.post("/admin/login")
async def admin_login(request: Request):
    form = await request.form()
    username = str(form.get("username", ""))
    password = str(form.get("password", ""))
    if not verify_admin_login(username, password):
        return render_page("Login", '<div class="card" style="max-width:480px;margin:0 auto;"><h2>🔐 Admin login</h2><p>Wrong username or password.</p><a class="btn" href="/admin/login">Try again</a></div>', request)
    resp = RedirectResponse(url="/admin", status_code=303)
    resp.set_cookie(ADMIN_COOKIE_NAME, _admin_session_token(), httponly=True, secure=ADMIN_COOKIE_SECURE, samesite="lax", max_age=60 * 60 * 24 * 14)
    return resp


@web_app.get("/admin/logout")
async def admin_logout(request: Request):
    resp = RedirectResponse(url="/admin/login", status_code=303)
    resp.delete_cookie(ADMIN_COOKIE_NAME)
    return resp


@web_app.post("/admin/maintenance")
async def admin_maintenance_toggle(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    form = await request.form()
    mode = str(form.get("mode", "status")).strip().lower()
    if mode == "on":
        set_admin_setting("maintenance_mode", "true")
        return redirect_with_msg("/admin", "Maintenance mode is now ON. Normal users are blocked except payment checks.")
    if mode == "off":
        set_admin_setting("maintenance_mode", "false")
        return redirect_with_msg("/admin", "Maintenance mode is now OFF. Users can use the bot normally.")
    return redirect_with_msg("/admin", f"Maintenance mode is {'ON' if maintenance_mode_enabled() else 'OFF'}.")


@web_app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    receivers = online_receivers()
    capacity = sum(int(r["limit_remaining"] or 0) for r in receivers)
    maintenance_on = maintenance_mode_enabled()
    with get_conn() as conn:
        open_offers = int(conn.execute("SELECT COUNT(*) AS n FROM photos WHERE offer_state = 'open'").fetchone()["n"] or 0)
        claimed_pending = int(conn.execute("SELECT COUNT(*) AS n FROM photos WHERE offer_state = 'claimed' AND status = 'pending'").fetchone()["n"] or 0)
        pending_qr_total = int(conn.execute("SELECT COUNT(*) AS n FROM photos WHERE status = 'pending'").fetchone()["n"] or 0)
        today_done = int(conn.execute("SELECT COUNT(*) AS n FROM photos WHERE date = ? AND status = 'done'", (today_str(),)).fetchone()["n"] or 0)
        today_failed = int(conn.execute("SELECT COUNT(*) AS n FROM photos WHERE date = ? AND status = 'failed'", (today_str(),)).fetchone()["n"] or 0)
        open_disputes = int(conn.execute("SELECT COUNT(*) AS n FROM disputes WHERE status = 'open'").fetchone()["n"] or 0)
        review_disputes = int(conn.execute("SELECT COUNT(*) AS n FROM disputes WHERE status = 'under_review'").fetchone()["n"] or 0)
        pending_payout_total = int(conn.execute("SELECT COUNT(*) AS n FROM payout_requests WHERE status = 'pending'").fetchone()["n"] or 0)
        pending_payout_usdt = _dec(conn.execute("SELECT COALESCE(SUM(amount_usdt), 0) AS amount FROM payout_requests WHERE status = 'pending'").fetchone()["amount"])
        sender_wallet_total = _dec(conn.execute("SELECT COALESCE(SUM(w.balance_usdt - w.reserved_usdt), 0) AS amount FROM wallets w JOIN users u ON u.chat_id = w.chat_id WHERE u.role = 'sender'").fetchone()["amount"])
        receiver_earned_total = _dec(conn.execute("SELECT COALESCE(SUM(w.earned_usdt), 0) AS amount FROM wallets w JOIN users u ON u.chat_id = w.chat_id WHERE u.role = 'receiver'").fetchone()["amount"])
        receiver_paid_total = _dec(conn.execute("SELECT COALESCE(SUM(w.paid_usdt), 0) AS amount FROM wallets w JOIN users u ON u.chat_id = w.chat_id WHERE u.role = 'receiver'").fetchone()["amount"])
        pending_payment_reviews = pending_payment_review_count()
        receiver_due_total = max(Decimal("0"), receiver_earned_total - receiver_paid_total)
    next_mode = "off" if maintenance_on else "on"
    button_class = "success" if maintenance_on else "danger"
    button_text = "Turn maintenance OFF" if maintenance_on else "Turn maintenance ON"
    body = (
        '<div class="dashboard-top-actions">'
        '<form method="post" action="/admin/maintenance" class="inline">'
        f'<input type="hidden" name="mode" value="{esc(next_mode)}">'
        f'<button class="{esc(button_class)}" type="submit">{esc(button_text)}</button>'
        '</form></div>'
    )
    body += stat_cards_html("Overall stats")
    body += '<div class="cards two">'
    body += f'<div class="card"><h3>📡 Online receivers</h3><p style="font-size:34px;margin:0;">{len(receivers)}</p><p class="muted">Total capacity: {capacity} scans</p><a class="btn" href="/admin/marketplace">Open marketplace</a></div>'
    body += f'<div class="card"><h3>📥 Pending QR</h3><p style="font-size:34px;margin:0;">{pending_qr_total}</p><p class="muted">Open offers: {open_offers} · Claimed pending: {claimed_pending}</p><a class="btn" href="/admin/pending">View QRs</a></div>'
    body += f'<div class="card"><h3>✅ Today completed</h3><p style="font-size:34px;margin:0;">{today_done}</p><p class="muted">Failed today: {today_failed}</p><a class="btn" href="/admin/stats">Open stats</a></div>'
    body += f'<div class="card"><h3>💸 Payout requests</h3><p style="font-size:34px;margin:0;">{pending_payout_total}</p><p class="muted">Pending amount: ${_money(pending_payout_usdt)} USDT</p><a class="btn" href="/admin/payouts">Review payouts</a></div>'
    body += f'<div class="card"><h3>⚠️ Disputes</h3><p style="font-size:34px;margin:0;">{open_disputes + review_disputes}</p><p class="muted">Open: {open_disputes} · Under review: {review_disputes}</p><a class="btn" href="/admin/disputes">Review disputes</a></div>'
    body += f'<div class="card"><h3>🧾 Payment reviews</h3><p style="font-size:34px;margin:0;">{pending_payment_reviews}</p><p class="muted">Manual wallet top-ups waiting for admin</p><a class="btn" href="/admin/payment-reviews">Review payments</a></div>'
    body += f'<div class="card"><h3>👛 Sender wallet available</h3><p style="font-size:34px;margin:0;">${_money(sender_wallet_total)}</p><p class="muted">Total available sender balance</p><a class="btn" href="/admin/users">Open users</a></div>'
    body += f'<div class="card"><h3>💰 Receiver payable</h3><p style="font-size:34px;margin:0;">${_money(receiver_due_total)}</p><p class="muted">Earned: ${_money(receiver_earned_total)} · Paid: ${_money(receiver_paid_total)}</p><a class="btn" href="/admin/payouts">Open payouts</a></div>'
    body += '</div>'
    pending = pending_rows(limit=10)
    if pending:
        body += '<div class="card"><h3>Recent pending</h3><div class="table-wrap"><table class="compact-table"><tr><th class="cell-center">ID</th><th class="photo-cell">Photo</th><th>Sender</th><th>Receiver</th><th class="cell-center">Status</th><th class="created-cell">Created</th></tr>'
        for row in pending:
            sender = get_admin_user_row(int(row["sender_chat_id"]))
            receiver = get_admin_user_row(int(row["receiver_chat_id"] or 0))
            receiver_html = user_link(receiver) if receiver and int(row["receiver_chat_id"] or 0) != 0 else '<span class="muted">Unclaimed</span>'
            body += f'<tr><td class="cell-center">{qr_id_link(row["public_id"])}</td><td class="photo-cell">{photo_no_html(row)}</td><td>{user_link(sender) if sender else esc(row["sender_chat_id"])}</td><td>{receiver_html}</td><td class="cell-center">{status_pill(row["status"])}</td><td class="created-cell">{esc(display_datetime(row["created_at"]))}</td></tr>'
        body += '</table></div></div>'
    return render_page("Dashboard", body, request)


@web_app.get("/admin/users", response_class=HTMLResponse)
async def admin_users(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard

    q = str(request.query_params.get("q", "")).strip()
    role_filter = str(request.query_params.get("role", "all")).strip().lower()
    status_filter = str(request.query_params.get("status", "all")).strip().lower()

    role = role_filter if role_filter in {"sender", "receiver"} else None
    active = True if status_filter == "active" else False if status_filter == "disabled" else None

    users = list_users(role=role, active=active, search=q, limit=10000 if q or role or active is not None else 500)
    paged_users, pager_html = paginate_items(users, request)

    def selected(value: str, current: str) -> str:
        return " selected" if value == current else ""

    body = (
        '<div class="card"><h2>👥 Users</h2>'
        '<form method="post" action="/admin/users/add">'
        '<div class="row">'
        '<div><label>Role</label><select name="role"><option value="sender">Sender</option><option value="receiver">Receiver / Buyer</option></select></div>'
        '<div><label>ID/Username</label><input name="identifier" required placeholder="123456789 or @username"></div>'
        '<div><label>Admin alias</label><input name="alias" placeholder="Sender A / Buyer A"></div>'
        '</div>'
        '<button type="submit">➕ Add / update user</button>'
        '</form>'
        '<p class="muted small">New users who send /start are created as active senders automatically. Use this form to change a user to receiver or update their alias. Username lookup works after the user has sent /start or /myid to the bot at least once.</p>'
        '</div>'
    )

    body += (
        '<div class="card"><h3>🔎 Search users</h3>'
        '<form method="get" action="/admin/users">'
        '<div class="row">'
        f'<div><label>Search</label><input name="q" value="{esc(q)}" placeholder="ID, @username, name, alias, role"></div>'
        '<div><label>Role</label><select name="role">'
        f'<option value="all"{selected("all", role_filter)}>All roles</option>'
        f'<option value="sender"{selected("sender", role_filter)}>Sender</option>'
        f'<option value="receiver"{selected("receiver", role_filter)}>Receiver / Buyer</option>'
        '</select></div>'
        '<div><label>Status</label><select name="status">'
        f'<option value="all"{selected("all", status_filter)}>All statuses</option>'
        f'<option value="active"{selected("active", status_filter)}>Active only</option>'
        f'<option value="disabled"{selected("disabled", status_filter)}>Disabled only</option>'
        '</select></div>'
        '</div>'
        '<button type="submit">🔍 Search</button>'
        '<a class="btn secondary" href="/admin/users">Clear</a>'
        '</form>'
        '<p class="muted small">Search matches Telegram ID, username, first name, last name, admin alias, and role.</p>'
        '</div>'
    )

    body += '<div class="card"><h3>Registered users</h3>'
    if q or role is not None or active is not None:
        body += f'<p class="muted small">Showing {esc(len(users))} matching user(s).</p>'

    if not users:
        if q or role is not None or active is not None:
            body += '<p>No users matched your search/filter.</p>'
        else:
            body += '<p>No users yet. Ask users to send <code>/myid</code> to the bot, then add their ID/Username here.</p>'
    else:
        body += '<div class="table-wrap"><table><tr><th>Role</th><th>ID/Username</th><th>Alias</th><th>Name</th><th class="cell-center">Status</th><th class="cell-center">Actions</th></tr>'
        for u in paged_users:
            next_state = 'off' if u['active'] else 'on'
            action_label = 'Disable' if u['active'] else 'Enable'
            btn_class = 'danger' if u['active'] else 'secondary'
            full_name = " ".join([str(u["first_name"] or "").strip(), str(u["last_name"] or "").strip()]).strip()
            body += f'''
            <tr>
              <td>{esc(u['role'])}</td>
              <td>{user_link(u)}</td>
              <td>{esc(u['alias'] or '')}</td>
              <td>{esc(full_name or '—')}</td>
              <td class="cell-center">{badge(bool(u['active']))}</td>
              <td class="cell-center"><form class="inline" method="post" action="/admin/users/active"><input type="hidden" name="chat_id" value="{esc(u['chat_id'])}"><input type="hidden" name="state" value="{next_state}"><button class="{btn_class}" type="submit">{action_label}</button></form></td>
            </tr>'''
        body += '</table></div>' + pager_html
    body += '</div>'
    return render_page("Users", body, request)


@web_app.post("/admin/users/add")
async def admin_users_add(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    form = await request.form()
    try:
        chat_id = lookup_chat_id_from_identifier(str(form.get("identifier", "")))
        role = str(form.get("role", "")).strip().lower()
        alias = str(form.get("alias", "")).strip() or None
        upsert_user(chat_id, role, alias)
        if telegram_application is not None:
            await refresh_bot_commands_for_chat(telegram_application.bot, chat_id, get_user(chat_id))
    except Exception as exc:
        return redirect_with_msg("/admin/users", f"Could not add user: {exc}")
    return redirect_with_msg("/admin/users", "User saved.")


@web_app.post("/admin/users/active")
async def admin_users_active(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    form = await request.form()
    try:
        chat_id = int(str(form.get("chat_id", "")).strip())
        state = str(form.get("state", "")).strip().lower()
        ok = set_user_active(chat_id, state == "on")
        if telegram_application is not None:
            await refresh_bot_commands_for_chat(telegram_application.bot, chat_id, get_user(chat_id))
    except Exception as exc:
        return redirect_with_msg("/admin/users", f"Could not update user: {exc}")
    return redirect_with_msg("/admin/users", "User updated." if ok else "User not found.")


@web_app.get("/admin/users/{chat_id}/stats", response_class=HTMLResponse)
async def admin_user_stats(request: Request, chat_id: int):
    guard = admin_guard(request)
    if guard:
        return guard
    user = get_admin_user_row(chat_id)
    if not user:
        return render_page("User stats", '<div class="card"><p>User not found.</p></div>', request)
    scope_kwargs = {"sender_chat_id": chat_id} if user["role"] == "sender" else {"receiver_chat_id": chat_id}
    body = f'''
    <div class="card">
      <h2>👤 User</h2>
      <p><strong>Role:</strong> {esc(user['role'])}</p>
      <p><strong>ID/Username:</strong><br>{user_link(user)}</p>
      <p><strong>Status:</strong> {badge(bool(user['active']))}</p>
    </div>
    '''
    body += stat_cards_html(f"Stats for {user['role']} {chat_id}", **scope_kwargs, show_identity=False)
    wallet = get_wallet(chat_id)
    if user["role"] == "sender":
        balance = _dec(wallet["balance_usdt"])
        reserved = _dec(wallet["reserved_usdt"])
        available = max(Decimal("0"), balance - reserved)
        balance_cards = f'''
          <div><b>${_money(balance)}</b><span>Total balance</span></div>
          <div><b>${_money(reserved)}</b><span>Reserved</span></div>
          <div><b>${_money(available)}</b><span>Available</span></div>
        '''
        action_options = '<option value="add">Add balance</option><option value="remove">Remove balance</option>'
        adjust_title = "Adjust sender wallet"
        help_text = "Sender users only have wallet balance here. Receiver earnings cannot be adjusted from a sender profile."
    else:
        earned = _dec(wallet["earned_usdt"])
        paid = _dec(wallet["paid_usdt"])
        requested = pending_payout_amount(chat_id)
        available = max(Decimal("0"), earned - paid - requested)
        balance_cards = f'''
          <div><b>${_money(earned)}</b><span>Total earned</span></div>
          <div><b>${_money(paid)}</b><span>Paid</span></div>
          <div><b>${_money(requested)}</b><span>Requested</span></div>
          <div><b>${_money(available)}</b><span>Available earnings</span></div>
        '''
        action_options = '<option value="add">Add earnings</option><option value="remove">Remove earnings</option>'
        adjust_title = "Adjust receiver earnings"
        help_text = "Receiver users only have earnings here. Sender wallet balance cannot be adjusted from a receiver profile."
    body += f'''
    <div class="card">
      <h2>💰 Balance</h2>
      <div class="stats-grid">{balance_cards}</div>
    </div>
    <div class="card">
      <h2>💼 {esc(adjust_title)}</h2>
      <p class="muted small">{esc(help_text)}</p>
      <form method="post" action="/admin/users/{int(chat_id)}/wallet-adjust">
        <div class="row">
          <div><label>Action</label><select name="action">{action_options}</select></div>
          <div><label>Currency</label><select name="currency" disabled><option>USDT</option></select></div>
          <div><label>Amount</label><input name="amount" inputmode="decimal" required placeholder="0.00"></div>
          <div><label>Note</label><input name="note" placeholder="optional note"></div>
        </div>
        <button type="submit">Apply</button>
      </form>
    </div>
    '''
    with get_conn() as conn:
        field = "sender_chat_id" if user["role"] == "sender" else "receiver_chat_id"
        recent = conn.execute(f"SELECT * FROM photos WHERE {field} = ? ORDER BY created_at DESC LIMIT 500", (chat_id,)).fetchall()
    if recent:
        paged_recent, recent_pager = paginate_items(list(recent), request)
        body += '<div class="card recent-qrs"><h3>Recent QRs</h3><div class="table-wrap"><table class="compact-table"><tr><th class="cell-center">ID</th><th class="photo-cell">Photo</th><th>Sender</th><th>Receiver / Buyer</th><th class="cell-center">Status</th><th class="created-cell">Created</th><th class="completed-cell">Completed</th></tr>'
        for row in paged_recent:
            sender = get_admin_user_row(int(row["sender_chat_id"]))
            receiver = get_admin_user_row(int(row["receiver_chat_id"]))
            sender_html = user_link(sender) if sender else esc(row["sender_chat_id"])
            receiver_html = user_link(receiver) if receiver else esc(row["receiver_chat_id"])
            body += f'<tr><td class="cell-center">{qr_id_link(row["public_id"])}</td><td class="photo-cell">{photo_no_html(row)}</td><td>{sender_html}</td><td>{receiver_html}</td><td class="cell-center">{status_pill(row["status"])}</td><td class="created-cell">{esc(display_datetime(row["created_at"]))}</td><td class="completed-cell">{esc(completed_value(row))}</td></tr>'
        body += '</table></div>' + recent_pager + '</div>'
    return render_page("User stats", body, request)


@web_app.get("/admin/pairs", response_class=HTMLResponse)
async def admin_pairs(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    body = '\n    <div class="card"><h2>🔗 Pairing removed</h2>\n      <p>This version uses the open marketplace. Sender QRs are offered to all online receivers and the first receiver to accept gets the QR.</p>\n      <p><a class="btn" href="/admin/marketplace">Open Marketplace Settings</a></p>\n    </div>\n    '
    return render_page("Pairing removed", body, request)


@web_app.post("/admin/pairs/add")
async def admin_pairs_add(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    return redirect_with_msg("/admin/marketplace", "Pairing has been removed. Use Marketplace instead.")


@web_app.post("/admin/pairs/unpair")
async def admin_pairs_unpair(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    return redirect_with_msg("/admin/marketplace", "Pairing has been removed. Use Marketplace instead.")


@web_app.get("/admin/stats", response_class=HTMLResponse)
async def admin_stats(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    body = stat_cards_html("Overall stats")
    with get_conn() as conn:
        state_rows = conn.execute("""
            SELECT offer_state, status, COUNT(*) AS n
            FROM photos
            GROUP BY offer_state, status
            ORDER BY offer_state, status
        """).fetchall()
        qr_rows = conn.execute("""
            SELECT *
            FROM photos
            ORDER BY created_at DESC, id DESC
            LIMIT 1000
        """).fetchall()

    body += '<div class="card"><h3>📋 QR order history</h3>'
    body += '<p class="muted small">Detailed marketplace QR list with sender, receiver, status, created time, claim time, completed/failed time, and duration.</p>'
    if not qr_rows:
        body += '<p>No QR data yet.</p>'
    else:
        paged_qrs, qr_pager = paginate_items(list(qr_rows), request, key="orders_page")
        body += '<div class="table-wrap"><table class="compact-table"><tr><th class="cell-center">Order ID</th><th class="photo-cell">QR</th><th>Sender</th><th>Receiver</th><th class="cell-center">Offer</th><th class="cell-center">Status</th><th class="created-cell">Created</th><th class="created-cell">Claimed</th><th class="completed-cell">Completed / Failed</th><th class="cell-center">Duration</th><th>Failure reason</th></tr>'
        for row in paged_qrs:
            sender = get_admin_user_row(int(row["sender_chat_id"]))
            receiver_id = row["receiver_chat_id"]
            receiver = get_admin_user_row(int(receiver_id)) if receiver_id is not None else None
            sender_html = user_link(sender) if sender else esc(row["sender_chat_id"])
            receiver_html = user_link(receiver) if receiver else (esc(receiver_id) if receiver_id is not None else "—")
            offer_state = str(row["offer_state"] or "old").strip().lower()
            claimed_value = display_datetime(row["claimed_at"]) if row["claimed_at"] else "—"
            failure_reason = "—"
            if str(row["status"] or "").lower() == "failed" and row["failure_reason"]:
                failure_reason = esc(row["failure_reason"])
            body += (
                '<tr>'
                f'<td class="cell-center">{qr_id_link(row["public_id"])}</td>'
                f'<td class="photo-cell">{photo_no_html(row)}</td>'
                f'<td>{sender_html}</td>'
                f'<td>{receiver_html}</td>'
                f'<td class="cell-center">{esc(offer_state)}</td>'
                f'<td class="cell-center">{status_pill(row["status"])}</td>'
                f'<td class="created-cell">{esc(display_datetime(row["created_at"]))}</td>'
                f'<td class="created-cell">{esc(claimed_value)}</td>'
                f'<td class="completed-cell">{esc(completed_value(row))}</td>'
                f'<td class="cell-center">{esc(qr_duration_value(row))}</td>'
                f'<td>{failure_reason}</td>'
                '</tr>'
            )
        body += '</table></div>' + qr_pager
    body += '</div>'

    body += '<div class="card"><h3>📡 Marketplace QR summary</h3>'
    if not state_rows:
        body += '<p>No QR data yet.</p>'
    else:
        body += '<div class="table-wrap"><table><tr><th>Offer state</th><th>QR status</th><th>Count</th></tr>'
        for r in state_rows:
            body += f'<tr><td>{esc(r["offer_state"] or "old")}</td><td>{esc(r["status"])}</td><td>{esc(r["n"])}</td></tr>'
        body += '</table></div>'
    body += '</div>'
    return render_page("Stats", body, request)

@web_app.get("/admin/stats/pair/{sender_chat_id}", response_class=HTMLResponse)
async def admin_stats_pair(request: Request, sender_chat_id: int):
    guard = admin_guard(request)
    if guard:
        return guard
    pair = find_pair(sender_chat_id)
    if not pair:
        return render_page("Pair stats", '<div class="card"><p>Pair not found.</p></div>', request)
    sender = get_admin_user_row(int(pair["sender_chat_id"]))
    receiver = get_admin_user_row(int(pair["receiver_chat_id"]))
    body = f'''
    <div class="card"><h2>🔗 {esc(pair['label'] or 'Unnamed pair')}</h2>
      <div class="row">
        <div><h3>Sender</h3>{user_link(sender) if sender else esc(pair['sender_chat_id'])}</div>
        <div><h3>Receiver</h3>{user_link(receiver) if receiver else esc(pair['receiver_chat_id'])}</div>
      </div>
    </div>
    '''
    body += stat_cards_html("Pair stats", sender_chat_id=int(pair["sender_chat_id"]), receiver_chat_id=int(pair["receiver_chat_id"]))
    return render_page("Pair stats", body, request)


@web_app.get("/admin/pending", response_class=HTMLResponse)
async def admin_pending(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    rows = pending_rows(limit=500)
    paged_rows, pending_pager = paginate_items(rows, request)
    body = '<div class="card"><h2>⏳ Pending QRs</h2>'
    if not rows:
        body += '<p>No pending QRs.</p>'
    else:
        body += '<div class="table-wrap"><table><tr><th class="cell-center">ID</th><th class="photo-cell">Photo</th><th>Sender</th><th>Receiver</th><th class="cell-center">Status</th><th>Rates</th><th class="created-cell">Created</th><th class="completed-cell">Completed</th><th class="cell-center">Action</th></tr>'
        for r in paged_rows:
            sender = get_admin_user_row(int(r['sender_chat_id']))
            receiver_id = int(r['receiver_chat_id'] or 0)
            receiver = get_admin_user_row(receiver_id) if receiver_id else None
            receiver_html = user_link(receiver) if receiver else '<span class="muted">Unclaimed</span>'
            rates = f"Sender ${_money(r['sender_rate_usdt'])}<br>Receiver ${_money(r['receiver_rate_usdt'])}"
            state = esc(str(r["offer_state"] or "pending").replace("_", " ").title())
            status_html = f'{status_pill(r["status"])}<br><span class="muted small">{state}</span>'
            expire_form = (
                f'<form class="inline" method="post" action="/admin/pending/{esc(r["public_id"])}/expire" '
                'data-confirm-title="Expire this QR?" data-confirm-button="Expire" data-confirm-class="danger" '
                'data-confirm-message="Sender reserve will be released and this QR cannot be completed.">'
                '<button class="danger" type="submit">Expire</button></form>'
            )
            body += f'<tr><td class="cell-center">{qr_id_link(r["public_id"])}</td><td class="photo-cell">{photo_no_html(r)}</td><td>{user_link(sender) if sender else esc(r["sender_chat_id"])}</td><td>{receiver_html}</td><td class="cell-center">{status_html}</td><td>{rates}</td><td class="created-cell">{esc(display_datetime(r["created_at"]))}</td><td class="completed-cell">{esc(completed_value(r))}</td><td class="cell-center">{expire_form}</td></tr>' 
        body += '</table></div>' + pending_pager
    body += '</div>'
    return render_page("Pending QRs", body, request)


@web_app.post("/admin/pending/{public_id}/expire")
async def admin_pending_expire(request: Request, public_id: str):
    guard = admin_guard(request)
    if guard:
        return guard
    ok, msg, row = expire_pending_qr_in_db(public_id)
    if ok and row is not None and telegram_application is not None:
        await notify_admin_expired_qr(telegram_application.bot, public_id, row)
    return redirect_with_msg(admin_safe_return_path(request, "/admin/pending"), msg)


@web_app.get("/admin/marketplace", response_class=HTMLResponse)
async def admin_marketplace(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    settings = get_marketplace_settings()
    receivers = list_users("receiver", limit=500)
    receiver_options = ''.join(
        f'<option value="{esc(u["chat_id"])}">{esc(u["alias"] or u["username"] or u["chat_id"])}</option>'
        for u in receivers if u['chat_id'] != 0
    )
    body = f'''
    <div class="card"><h2>📡 Marketplace</h2>
      <p class="muted">Pairing is disabled. Sender QRs become open offers for online receivers.</p>
      <form method="post" action="/admin/marketplace/settings">
        <div class="row">
          <div><label>Sender charge / done scan (USDT)</label><input name="sender_rate_usdt" value="{esc(_money(settings['sender_rate_usdt']))}"></div>
          <div><label>Receiver earning / done scan (USDT)</label><input name="receiver_rate_usdt" value="{esc(_money(settings['receiver_rate_usdt']))}"></div>
          <div><label>Minimum payout request (USDT)</label><input name="min_payout_usdt" value="{esc(_money(settings['min_payout_usdt']))}"></div>
        </div>
        <button type="submit">💾 Save marketplace settings</button>
      </form>
    </div>
    <div class="card"><h3>Receiver online/offline toggle</h3>
      <form method="post" action="/admin/marketplace/receiver">
        <div class="row">
          <div><label>Receiver</label><select name="receiver_chat_id">{receiver_options}</select></div>
          <div><label>Status</label><select name="online"><option value="1">Online</option><option value="0">Offline</option></select></div>
          <div><label>Limit</label><input name="limit" value="25"></div>
        </div>
        <button type="submit">Update receiver</button>
      </form>
    </div>
    <div class="card"><h3>Receiver capacity</h3>
    '''
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT u.*, p.online, p.limit_total, p.limit_remaining, p.updated_at AS presence_updated_at, tp.username
            FROM users u
            LEFT JOIN receiver_presence p ON p.chat_id = u.chat_id
            LEFT JOIN telegram_profiles tp ON tp.chat_id = u.chat_id
            WHERE u.role = 'receiver' AND u.chat_id != 0
            ORDER BY u.updated_at DESC
        """).fetchall()
    if not rows:
        body += '<p>No receivers.</p>'
    else:
        body += '<div class="table-wrap"><table><tr><th>Receiver</th><th>Status</th><th>Limit</th><th>Remaining</th><th>Updated</th></tr>'
        for r in rows:
            state = bool(r['online']) and int(r['limit_remaining'] or 0) > 0 and bool(r['active'])
            updated = r['presence_updated_at'] or r['updated_at']
            body += f'<tr><td>{user_link(r)}</td><td>{badge(state)}</td><td>{esc(r["limit_total"] or 0)}</td><td>{esc(r["limit_remaining"] or 0)}</td><td>{esc(display_datetime(updated))}</td></tr>'
        body += '</table></div>'
    body += '</div>'
    return render_page("Marketplace", body, request)


@web_app.post("/admin/marketplace/settings")
async def admin_marketplace_settings(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    form = await request.form()
    for key in ("sender_rate_usdt", "receiver_rate_usdt", "min_payout_usdt"):
        set_admin_setting(key, str(form.get(key, "")).strip())
    return redirect_with_msg("/admin/marketplace", "Marketplace settings saved.")


@web_app.post("/admin/marketplace/receiver")
async def admin_marketplace_receiver(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    form = await request.form()
    receiver_chat_id = int(str(form.get("receiver_chat_id", "0")).strip())
    online = str(form.get("online", "0")).strip() == "1"
    limit = int(str(form.get("limit", "0")).strip() or 0)
    notify_text = ""
    if online:
        set_receiver_online(receiver_chat_id, limit)
        notify_text = f"🟢 A receiver is online now.\n📊 Current limit: {limit} scans.\n\nUse /status to see total live capacity."
    else:
        set_receiver_offline(receiver_chat_id)
        notify_text = "🔴 A receiver went offline.\nPlease check /status before sending more QRs."
    note = "Receiver status updated."
    if maintenance_mode_enabled():
        note += " Maintenance mode is ON, so sender notifications were not sent."
    elif telegram_application is not None and notify_text:
        sent = failed = 0
        for sender in active_senders():
            try:
                await telegram_application.bot.send_message(chat_id=int(sender["chat_id"]), text=notify_text, protect_content=PROTECT_CONTENT)
                sent += 1
                await asyncio.sleep(0.03)
            except TelegramError:
                failed += 1
        note += f" Sender notifications sent: {sent}, failed: {failed}."
    return redirect_with_msg("/admin/marketplace", note)


@web_app.get("/admin/wallets", response_class=HTMLResponse)
async def admin_wallets(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    return redirect_with_msg("/admin/users", "Wallet adjustments are now inside each user's stats page.")


@web_app.post("/admin/wallets/adjust")
async def admin_wallets_adjust(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    # Kept only for old bookmarked forms. Use the per-user stats page instead.
    return redirect_with_msg("/admin/users", "Wallet adjustments are now inside each user's stats page.")


@web_app.post("/admin/users/{chat_id}/wallet-adjust")
async def admin_user_wallet_adjust(request: Request, chat_id: int):
    guard = admin_guard(request)
    if guard:
        return guard
    user = get_admin_user_row(chat_id)
    if not user:
        return redirect_with_msg("/admin/users", "User not found.")
    form = await request.form()
    try:
        raw_amount = _dec(form.get("amount"))
        if raw_amount <= 0:
            raise ValueError("Amount must be greater than zero.")
        action = str(form.get("action", "add")).strip().lower()
        if action not in {"add", "remove"}:
            raise ValueError("Invalid action.")
        amount = raw_amount if action == "add" else -raw_amount
        note = str(form.get("note", "")).strip() or "Admin manual adjustment"
        target = "sender_balance" if str(user["role"]) == "sender" else "receiver_earned"
        adjustment = manual_adjust_wallet(chat_id, amount, target, note)
    except Exception as exc:
        return redirect_with_msg(f"/admin/users/{int(chat_id)}/stats", f"Could not adjust balance: {exc}")
    notify_note = ""
    if telegram_application is not None:
        try:
            await send_admin_wallet_adjustment_message(telegram_application.bot, adjustment)
            notify_note = " User was notified in the bot."
        except TelegramError:
            notify_note = " Balance changed, but the bot could not notify the user."
    return redirect_with_msg(f"/admin/users/{int(chat_id)}/stats", f"Balance adjusted.{notify_note}")


@web_app.get("/admin/payments", response_class=HTMLResponse)
async def admin_payments(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    settings = get_marketplace_settings()

    def method_card(method_key: str, title: str, enabled: bool, fields_html: str, off_note: str = "Disabled — users will not see this option.") -> str:
        checked = "checked" if enabled else ""
        return (
            '<div class="setting-card payment-method-card" data-payment-method>'
            '<div class="payment-method-header">'
            f'<strong>{esc(title)}</strong>'
            '<button type="button" class="payment-toggle-button" data-payment-toggle-button></button>'
            f'<input class="sr-only payment-toggle-input" type="checkbox" name="{esc(method_key)}_enabled" value="1" data-payment-toggle {checked}>'
            '</div>'
            f'<p class="method-off-note muted">{esc(off_note)}</p>'
            f'<div class="method-details" data-payment-details>{fields_html}</div>'
            '</div>'
        )

    bep20_fields = f'''
      <label>BEP20 wallet address
        <input name="bep20_wallet_address" value="{esc(settings['bep20_wallet_address'])}" placeholder="0x...">
      </label>
      <label>Manual TxHash auto-verification tolerance
        <div class="price-input-wrap"><input name="bep20_manual_tolerance_usdt" type="number" min="0" step="0.000001" value="{esc(settings['bep20_manual_tolerance_usdt'])}"><span>USDT</span></div>
        <small class="muted">Used when Manual Verify checks a BEP20 TxHash. API keys stay in Secret Settings.</small>
      </label>
    '''
    polygon_fields = f'''
      <label>Polygon wallet address
        <input name="polygon_wallet_address" value="{esc(settings['polygon_wallet_address'])}" placeholder="0x...">
      </label>
      <label>Manual TxHash auto-verification tolerance
        <div class="price-input-wrap"><input name="polygon_manual_tolerance_usdt" type="number" min="0" step="0.000001" value="{esc(settings['polygon_manual_tolerance_usdt'])}"><span>USDT</span></div>
        <small class="muted">Used when Manual Verify checks a Polygon TxHash. API keys stay in Secret Settings.</small>
      </label>
    '''
    binance_fields = f'''
      <label>Binance Pay ID
        <input name="binance_pay_id" value="{esc(settings['binance_pay_id'])}" placeholder="Pay ID">
      </label>
      <label>Binance Pay display name
        <input name="binance_pay_name" value="{esc(settings['binance_pay_name'])}" placeholder="Merchant name">
      </label>
      <label>Manual auto-verification tolerance
        <div class="price-input-wrap"><input name="binance_manual_tolerance_usdt" type="number" min="0" step="0.000001" value="{esc(settings['binance_manual_tolerance_usdt'])}"><span>USDT</span></div>
        <small class="muted">Used when Manual Verify checks Binance Pay history. API credentials stay in Secret Settings.</small>
      </label>
    '''
    body = f'''
    <div class="card"><h2>💳 Payment Settings</h2>
      <p class="muted">Enable or disable top-up methods and edit only user-visible payment details. API keys, timing, and verification internals stay in Secret Settings.</p>
      <form method="post" action="/admin/payments/settings">
        <div class="settings-grid">
          {method_card('bep20', 'USDT (BEP20)', bool(settings['bep20_enabled']), bep20_fields)}
          {method_card('polygon', 'USDT (POLYGON)', bool(settings['polygon_enabled']), polygon_fields)}
          {method_card('binance', 'Binance Pay', bool(settings['binance_enabled']), binance_fields)}
          <div class="setting-card">
            <h3>Wallet top-up limit</h3>
            <p class="muted">Applies to every wallet top-up method.</p>
            <label>Minimum wallet top-up
              <div class="price-input-wrap"><input name="wallet_min_usdt" type="number" min="0.0001" step="0.0001" value="{esc(settings['wallet_min_usdt'])}"><span>USDT</span></div>
            </label>
          </div>
        </div>
        <button type="submit">💾 Save payment settings</button>
      </form>
    </div>
    <script>
    function syncPaymentMethodCards() {{
      document.querySelectorAll('[data-payment-method]').forEach((card) => {{
        const toggle = card.querySelector('[data-payment-toggle]');
        const button = card.querySelector('[data-payment-toggle-button]');
        const details = card.querySelector('[data-payment-details]');
        const enabled = Boolean(toggle && toggle.checked);
        card.classList.toggle('is-disabled', !enabled);
        if (button) {{
          button.textContent = enabled ? 'Disable' : 'Enable';
          button.classList.toggle('enabled', enabled);
          button.classList.toggle('disabled', !enabled);
          button.setAttribute('aria-pressed', enabled ? 'true' : 'false');
        }}
        if (details) {{
          details.querySelectorAll('input, textarea, select').forEach((field) => {{
            field.readOnly = !enabled;
            field.tabIndex = enabled ? 0 : -1;
            field.setAttribute('aria-disabled', enabled ? 'false' : 'true');
          }});
        }}
      }});
    }}
    document.addEventListener('DOMContentLoaded', () => {{
      syncPaymentMethodCards();
      document.querySelectorAll('[data-payment-toggle-button]').forEach((button) => {{
        button.addEventListener('click', () => {{
          const card = button.closest('[data-payment-method]');
          const toggle = card ? card.querySelector('[data-payment-toggle]') : null;
          if (!toggle) return;
          toggle.checked = !toggle.checked;
          syncPaymentMethodCards();
        }});
      }});
    }});
    </script>
    '''
    return render_page("Payment Settings", body, request)


@web_app.get("/admin/payment-reviews", response_class=HTMLResponse)
async def admin_payment_reviews(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    status_filter = str(request.query_params.get("status", "needs_review")).strip().lower()
    where = "WHERE status = 'manual_pending' AND credited_at IS NULL"
    params: tuple = ()
    if status_filter == "all":
        where = "WHERE status IN ('manual_pending','rejected','credited') OR manual_submitted_at IS NOT NULL"
    elif status_filter == "approved":
        where = "WHERE status = 'credited' AND manual_submitted_at IS NOT NULL"
    elif status_filter == "rejected":
        where = "WHERE status = 'rejected' AND manual_submitted_at IS NOT NULL"
    with get_conn() as conn:
        rows = conn.execute(f"SELECT * FROM payment_deposits {where} ORDER BY COALESCE(manual_submitted_at, created_at) DESC LIMIT 500", params).fetchall()
    paged, pager = paginate_items(rows, request)

    body = f'''
    <p class="muted">Approve or reject Binance Pay and manual USDT submissions from the website.</p>
    <div class="card">
      <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:18px;">
        <form method="get" action="/admin/payment-reviews" style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
          <select name="status" style="min-width:240px;margin:0;">
            <option value="needs_review" {'selected' if status_filter == 'needs_review' else ''}>Needs review</option>
            <option value="approved" {'selected' if status_filter == 'approved' else ''}>Approved</option>
            <option value="rejected" {'selected' if status_filter == 'rejected' else ''}>Rejected</option>
            <option value="all" {'selected' if status_filter == 'all' else ''}>All manual submissions</option>
          </select>
          <button class="secondary" type="submit">Filter</button>
        </form>
        <div class="muted">{len(rows)} payment(s)</div>
      </div>
    '''
    if not rows:
        body += '<p>No payments found for this filter.</p>'
    else:
        body += '<div class="table-wrap"><table class="payments-table compact-table"><tr><th>Ref</th><th>User</th><th>Type</th><th>Method</th><th>Amount</th><th>Proof</th><th>Action</th></tr>'
        for idx, r in enumerate(paged, start=1):
            user = get_admin_user_row(int(r["chat_id"]))
            ref = str(r["ref_id"])
            template_id = f"proof_template_{idx}_{re.sub(r'[^A-Za-z0-9_-]', '_', ref)}"
            user_html = user_link(user) if user else esc(r["chat_id"])
            if user:
                _uname = user["username"] if "username" in user.keys() else None
                _alias = user["alias"] if "alias" in user.keys() else None
                user_plain = (f"@{_uname} " if _uname else "") + (f"{_alias} " if _alias else "") + f"({int(r['chat_id'])})"
            else:
                user_plain = str(r["chat_id"])
            submitted = display_datetime(r["manual_submitted_at"] or r["created_at"])
            proof_button = f'<button type="button" class="proof-button" data-proof-target="{esc(template_id)}">View proof</button>'
            actions = deposit_status_pill(r["status"])
            if str(r["status"]).lower() == "manual_pending" and not r["credited_at"]:
                _confirm_attrs = (
                    f'data-ref="{esc(ref)}" '
                    f'data-user="{esc(user_plain)}" '
                    f'data-type="Wallet" '
                    f'data-method="{esc(payment_method_label(r))}" '
                    f'data-amount="${_money(r["amount_usdt"])} USDT"'
                )
                actions = (
                    '<div class="payment-action-stack">'
                    f'<form class="inline payment-confirm-form" method="post" action="/admin/payments/{esc(ref)}/approve" data-confirm-kind="approve" {_confirm_attrs}><button class="success" type="submit">Approve</button></form>'
                    f'<form class="inline payment-confirm-form" method="post" action="/admin/payments/{esc(ref)}/reject" data-confirm-kind="reject" {_confirm_attrs}><button class="danger" type="submit">Reject</button></form>'
                    '</div>'
                )
            body += f'''<tr>
              <td><strong>{esc(ref)}</strong><br><span class="muted small">{esc(submitted)}</span></td>
              <td>{user_html}</td>
              <td>Wallet</td>
              <td>{esc(payment_method_label(r))}</td>
              <td>${_money(r['amount_usdt'])} USDT</td>
              <td>{proof_button}</td>
              <td>{actions}</td>
            </tr>'''

            tx = str(r["tx_hash"] or r["binance_tx_id"] or "").strip()
            explorer = payment_explorer_tx_url(r)
            tx_html = '<span class="muted">—</span>'
            if tx and explorer:
                tx_html = f'<a class="tx-hash-link" href="{esc(explorer)}" target="_blank" rel="noopener noreferrer">{esc(tx)}</a>'
            elif tx:
                tx_html = f'<strong class="tx-hash-link">{esc(tx)}</strong>'
            proof_src = f"/admin/payments/{quote(ref)}/proof-image" if r["manual_proof_file_id"] else ""
            if proof_src:
                proof_img = (
                    f'<button type="button" class="proof-image-button" data-proof-fullscreen-image="{esc(proof_src)}" aria-label="Open payment screenshot fullscreen">'
                    f'<img src="{esc(proof_src)}" alt="Payment screenshot" class="proof-image">'
                    '</button><p class="proof-image-hint">Click the image to view fullscreen.</p>'
                )
            else:
                proof_img = '<p class="muted">No screenshot proof uploaded.</p>'
            tolerance_key = str(r["network"] or r["method"] or "bep20").lower()
            if tolerance_key not in {"bep20", "polygon", "binance"}:
                tolerance_key = "bep20"
            tolerance_value = get_marketplace_settings().get(tolerance_key + "_manual_tolerance_usdt", "0")
            reason_text = _public_payment_error_text(r["manual_note"] or "Manual proof submitted")
            check_label = payment_manual_check_label(r)
            body += f'''
            <div id="{esc(template_id)}" class="proof-modal-template" hidden>
              <div class="proof-modal-header"><h3>Payment proof</h3></div>
              <div class="proof-modal-layout">
                <div class="proof-details-pane">
                  <div class="proof-overview-grid">
                    <div class="proof-card"><span class="proof-label">Reference</span><strong>{esc(ref)}</strong></div>
                    <div class="proof-card"><span class="proof-label">User</span><strong>{user_html}</strong></div>
                    <div class="proof-card"><span class="proof-label">Payment method</span><strong>{esc(payment_method_label(r))}</strong></div>
                    <div class="proof-card"><span class="proof-label">Type</span><strong>Wallet</strong></div>
                    <div class="proof-card"><span class="proof-label">Amount</span><strong>${_money(r['amount_usdt'])} USDT</strong></div>
                  </div>
                  <div class="proof-detail-list">
                    <div class="proof-detail-row"><span>USDT Tx hash</span><strong class="break-anywhere">{tx_html}</strong></div>
                    <div class="proof-detail-row"><span>TxHash auto-check</span><strong>{esc(check_label)}</strong></div>
                    <div class="proof-detail-row"><span>Why it needs review</span><strong class="break-anywhere warning-text">{esc(reason_text)}</strong></div>
                    <div class="proof-detail-row"><span>Expected / tolerance</span><strong>{_money3(r['expected_usdt'])} USDT ± {esc(str(tolerance_value))} USDT</strong></div>
                  </div>
                </div>
                <div class="proof-image-block">{proof_img}</div>
              </div>
            </div>'''
        body += '</table></div>' + pager
    body += '</div>'
    body += '''
    <div id="payment-confirm-modal" class="confirm-modal-shell" hidden>
      <div class="confirm-modal-backdrop" data-close-payment-confirm></div>
      <div class="confirm-modal-panel" role="dialog" aria-modal="true">
        <h2 id="payment-confirm-title">Approve payment request?</h2>
        <p id="payment-confirm-desc" class="confirm-modal-desc">This will approve the submitted proof and complete the payment flow.</p>
        <div class="confirm-detail-row"><span>Reference</span><strong id="payment-confirm-ref"></strong></div>
        <div class="confirm-detail-row"><span>User</span><strong id="payment-confirm-user"></strong></div>
        <div class="confirm-detail-row"><span>Type</span><strong id="payment-confirm-type"></strong></div>
        <div class="confirm-detail-row"><span>Method</span><strong id="payment-confirm-method"></strong></div>
        <div class="confirm-detail-row"><span>Amount</span><strong id="payment-confirm-amount"></strong></div>
        <form id="payment-confirm-submit-form" method="post" action="">
          <div class="confirm-actions">
            <button type="button" class="secondary" data-close-payment-confirm>Cancel</button>
            <button type="submit" id="payment-confirm-submit" class="success">Yes, approve</button>
          </div>
        </form>
      </div>
    </div>
    <div id="proof-modal" class="proof-modal-shell" hidden>
      <div class="proof-modal-backdrop" data-close-proof-modal></div>
      <div class="proof-modal-panel" role="dialog" aria-modal="true" aria-labelledby="proof-modal-title">
        <button type="button" class="proof-modal-close" aria-label="Close" data-close-proof-modal>&times;</button>
        <div id="proof-modal-body"></div>
      </div>
    </div>
    <div id="proof-image-fullscreen" class="proof-image-fullscreen" hidden>
      <button type="button" class="proof-image-fullscreen-close" aria-label="Close fullscreen image" data-close-proof-image>&times;</button>
      <img id="proof-image-fullscreen-img" src="" alt="Payment screenshot fullscreen">
    </div>
    <script>
    (function movePaymentModalsToBody() {
      ['payment-confirm-modal', 'proof-modal', 'proof-image-fullscreen'].forEach(function(id) {
        const el = document.getElementById(id);
        if (el && el.parentElement !== document.body) document.body.appendChild(el);
      });
    })();
    document.addEventListener('submit', function(event) {
      const form = event.target.closest && event.target.closest('.payment-confirm-form');
      if (!form) return;
      event.preventDefault();
      const kind = form.getAttribute('data-confirm-kind') || 'approve';
      const shell = document.getElementById('payment-confirm-modal');
      const submitForm = document.getElementById('payment-confirm-submit-form');
      const submitButton = document.getElementById('payment-confirm-submit');
      const title = document.getElementById('payment-confirm-title');
      const desc = document.getElementById('payment-confirm-desc');
      if (!shell || !submitForm || !submitButton || !title || !desc) { form.submit(); return; }
      if (kind === 'reject') {
        title.textContent = 'Reject payment request?';
        desc.textContent = 'This will reject the submitted proof. The user may need to submit payment proof again.';
        submitButton.textContent = 'Yes, reject';
        submitButton.className = 'danger';
      } else {
        title.textContent = 'Approve payment request?';
        desc.textContent = 'This will approve the submitted proof and complete the payment flow.';
        submitButton.textContent = 'Yes, approve';
        submitButton.className = 'success';
      }
      document.getElementById('payment-confirm-ref').textContent = form.getAttribute('data-ref') || '';
      document.getElementById('payment-confirm-user').textContent = form.getAttribute('data-user') || '';
      document.getElementById('payment-confirm-type').textContent = form.getAttribute('data-type') || '';
      document.getElementById('payment-confirm-method').textContent = form.getAttribute('data-method') || '';
      document.getElementById('payment-confirm-amount').textContent = form.getAttribute('data-amount') || '';
      submitForm.action = form.action;
      shell.hidden = false;
      document.body.classList.add('modal-open');
    });
    document.addEventListener('click', function(event) {
      if (event.target.hasAttribute && event.target.hasAttribute('data-close-payment-confirm')) {
        const shell = document.getElementById('payment-confirm-modal');
        if (shell) shell.hidden = true;
        const proofShell = document.getElementById('proof-modal');
        const imageShell = document.getElementById('proof-image-fullscreen');
        if ((!proofShell || proofShell.hidden) && (!imageShell || imageShell.hidden)) document.body.classList.remove('modal-open');
        return;
      }
      const proofButton = event.target.closest && event.target.closest('[data-proof-target]');
      if (proofButton) {
        const shell = document.getElementById('proof-modal');
        const body = document.getElementById('proof-modal-body');
        const source = document.getElementById(proofButton.getAttribute('data-proof-target'));
        if (shell && body && source) {
          body.innerHTML = source.innerHTML;
          shell.hidden = false;
          document.body.classList.add('modal-open');
        }
        return;
      }
      const fullscreenProofImage = event.target.closest && event.target.closest('[data-proof-fullscreen-image]');
      if (fullscreenProofImage) {
        const shell = document.getElementById('proof-image-fullscreen');
        const img = document.getElementById('proof-image-fullscreen-img');
        if (shell && img) {
          img.src = fullscreenProofImage.getAttribute('data-proof-fullscreen-image') || '';
          shell.hidden = false;
          document.body.classList.add('modal-open');
        }
        return;
      }
      if (event.target.hasAttribute && (event.target.hasAttribute('data-close-proof-image') || event.target.id === 'proof-image-fullscreen')) {
        const shell = document.getElementById('proof-image-fullscreen');
        const img = document.getElementById('proof-image-fullscreen-img');
        if (shell) shell.hidden = true;
        if (img) img.src = '';
        const proofShell = document.getElementById('proof-modal');
        if (!proofShell || proofShell.hidden) document.body.classList.remove('modal-open');
        return;
      }
      if (event.target.hasAttribute && event.target.hasAttribute('data-close-proof-modal')) {
        const imageShell = document.getElementById('proof-image-fullscreen');
        const image = document.getElementById('proof-image-fullscreen-img');
        if (imageShell && !imageShell.hidden) {
          imageShell.hidden = true;
          if (image) image.src = '';
          return;
        }
        const shell = document.getElementById('proof-modal');
        const body = document.getElementById('proof-modal-body');
        if (shell) shell.hidden = true;
        if (body) body.innerHTML = '';
        document.body.classList.remove('modal-open');
      }
    });
    document.addEventListener('keydown', function(event) {
      if (event.key !== 'Escape') return;
      const confirmShell = document.getElementById('payment-confirm-modal');
      if (confirmShell && !confirmShell.hidden) {
        confirmShell.hidden = true;
        document.body.classList.remove('modal-open');
        return;
      }
      const imageShell = document.getElementById('proof-image-fullscreen');
      const image = document.getElementById('proof-image-fullscreen-img');
      if (imageShell && !imageShell.hidden) {
        imageShell.hidden = true;
        if (image) image.src = '';
        const proofShell = document.getElementById('proof-modal');
        if (!proofShell || proofShell.hidden) document.body.classList.remove('modal-open');
        return;
      }
      const shell = document.getElementById('proof-modal');
      const body = document.getElementById('proof-modal-body');
      if (shell && !shell.hidden) {
        shell.hidden = true;
        if (body) body.innerHTML = '';
        document.body.classList.remove('modal-open');
      }
    });
    </script>
    '''
    return render_page("Payment Reviews", body, request)


@web_app.get("/admin/wallet-deposits", response_class=HTMLResponse)
async def admin_wallet_deposits(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    status_filter = str(request.query_params.get("status", "all")).strip().lower()
    where = ""
    if status_filter == "paid":
        where = "WHERE status = 'credited'"
    elif status_filter == "pending":
        where = "WHERE credited_at IS NULL AND status IN ('waiting','manual_pending')"
    elif status_filter == "expired":
        where = "WHERE status = 'expired'"
    elif status_filter == "failed":
        where = "WHERE status = 'rejected'"
    with get_conn() as conn:
        rows = conn.execute(f"SELECT * FROM payment_deposits {where} ORDER BY created_at DESC LIMIT 800").fetchall()
    paged, pager = paginate_items(rows, request)
    body = f'''
    <div class="card"><h2>🏦 Wallet Deposits</h2>
      <p class="muted">All sender wallet top-ups: paid, pending, expired, and failed.</p>
      <form method="get" action="/admin/wallet-deposits" style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:14px;">
        <select name="status" style="min-width:220px;margin:0;">
          <option value="all" {'selected' if status_filter == 'all' else ''}>All deposits</option>
          <option value="paid" {'selected' if status_filter == 'paid' else ''}>Paid</option>
          <option value="pending" {'selected' if status_filter == 'pending' else ''}>Pending</option>
          <option value="expired" {'selected' if status_filter == 'expired' else ''}>Expired</option>
          <option value="failed" {'selected' if status_filter == 'failed' else ''}>Failed / rejected</option>
        </select>
        <button class="secondary" type="submit">Filter</button>
        <span class="muted">{len(rows)} deposit(s)</span>
      </form>
    '''
    if not rows:
        body += '<p>No deposits found.</p>'
    else:
        body += '<div class="table-wrap"><table class="compact-table"><tr><th>Ref</th><th>User</th><th>Method</th><th>Amount</th><th>Expected</th><th>Status</th><th>TX</th><th>Created</th><th>Completed</th></tr>'
        for r in paged:
            user = get_admin_user_row(int(r['chat_id']))
            tx = str(r['tx_hash'] or r['binance_tx_id'] or '').strip()
            tx_url = payment_explorer_tx_url(r)
            tx_cell = '<span class="muted">—</span>'
            if tx and tx_url:
                tx_cell = f'<a href="{esc(tx_url)}" target="_blank" rel="noopener"><code>{esc(tx[:22])}</code></a>'
            elif tx:
                tx_cell = f'<code>{esc(tx[:22])}</code>'
            completed = r['credited_at'] or r['confirmed_at'] or ('—' if str(r['status']).lower() not in {'expired','rejected'} else r['expires_at'])
            body += f'''<tr>
              <td><code>{esc(r['ref_id'])}</code></td>
              <td>{user_link(user) if user else esc(r['chat_id'])}</td>
              <td>{esc(payment_method_label(r))}</td>
              <td>${_money(r['amount_usdt'])}</td>
              <td>${_money3(r['expected_usdt'])}</td>
              <td>{deposit_status_pill(r['status'])}</td>
              <td>{tx_cell}</td>
              <td>{esc(display_datetime(r['created_at']))}</td>
              <td>{esc(display_datetime(completed)) if completed and completed != '—' else '—'}</td>
            </tr>'''
        body += '</table></div>' + pager
    body += '</div>'
    return render_page("Wallet Deposits", body, request)


@web_app.post("/admin/payments/settings")
async def admin_payments_settings(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    form = await request.form()
    values = {
        "bep20_enabled": "true" if form.get("bep20_enabled") == "1" else "false",
        "polygon_enabled": "true" if form.get("polygon_enabled") == "1" else "false",
        "binance_enabled": "true" if form.get("binance_enabled") == "1" else "false",
        "bep20_wallet_address": str(form.get("bep20_wallet_address", "")).strip(),
        "polygon_wallet_address": str(form.get("polygon_wallet_address", "")).strip(),
        "binance_pay_id": str(form.get("binance_pay_id", "")).strip(),
        "binance_pay_name": str(form.get("binance_pay_name", "")).strip(),
        "bep20_manual_tolerance_usdt": str(form.get("bep20_manual_tolerance_usdt", DEFAULT_BEP20_MANUAL_TOLERANCE_USDT)).strip(),
        "polygon_manual_tolerance_usdt": str(form.get("polygon_manual_tolerance_usdt", DEFAULT_POLYGON_MANUAL_TOLERANCE_USDT)).strip(),
        "binance_manual_tolerance_usdt": str(form.get("binance_manual_tolerance_usdt", DEFAULT_BINANCE_MANUAL_TOLERANCE_USDT)).strip(),
        "wallet_min_usdt": str(form.get("wallet_min_usdt", DEFAULT_MIN_WALLET_TOPUP_USDT)).strip(),
    }
    errors: list[str] = []
    if values["bep20_enabled"] == "true" and not values["bep20_wallet_address"]:
        errors.append("BEP20 wallet address is required when BEP20 is enabled.")
    if values["polygon_enabled"] == "true" and not values["polygon_wallet_address"]:
        errors.append("Polygon wallet address is required when Polygon is enabled.")
    if values["binance_enabled"] == "true" and not values["binance_pay_id"]:
        errors.append("Binance Pay ID is required when Binance Pay is enabled.")
    for key, label in (("bep20_manual_tolerance_usdt", "BEP20 tolerance"), ("polygon_manual_tolerance_usdt", "Polygon tolerance"), ("binance_manual_tolerance_usdt", "Binance tolerance")):
        if _dec(values[key], "-1") < 0:
            errors.append(f"{label} must be a valid non-negative USDT number.")
    if _dec(values["wallet_min_usdt"], "0") <= 0:
        errors.append("Minimum wallet top-up must be greater than zero.")
    if errors:
        return redirect_with_msg("/admin/payments", " ".join(errors))
    for key, value in values.items():
        set_admin_setting(key, value)
    return redirect_with_msg("/admin/payments", "Payment settings saved.")


def admin_safe_return_path(request: Request, default: str = "/admin/payment-reviews") -> str:
    referer = str(request.headers.get("referer", "")).strip()
    if referer:
        parsed = urlparse(referer)
        if parsed.path.startswith("/admin"):
            return parsed.path + (("?" + parsed.query) if parsed.query else "")
    return default


@web_app.post("/admin/payments/{ref_id}/verify")
async def admin_payment_verify(request: Request, ref_id: str):
    guard = admin_guard(request)
    if guard:
        return guard
    dep_before = get_deposit(ref_id.upper())
    ok, reason = await verify_and_credit_deposit_async(ref_id.upper(), None, False, "admin_verify")
    if ok and dep_before is not None and telegram_application is not None:
        try:
            dep_after = get_deposit(ref_id.upper()) or dep_before
            await send_deposit_completed_message(telegram_application.bot, dep_after)
        except TelegramError:
            pass
    return redirect_with_msg(admin_safe_return_path(request), ("Verified and credited: " if ok else "Not verified: ") + reason)


@web_app.post("/admin/payments/{ref_id}/approve")
async def admin_payment_approve(request: Request, ref_id: str):
    guard = admin_guard(request)
    if guard:
        return guard
    dep_before = get_deposit(ref_id.upper())
    ok, reason = credit_deposit_if_confirmed(ref_id.upper(), {"admin_manual": True}, "admin_manual")
    if ok and dep_before is not None and telegram_application is not None:
        try:
            dep_after = get_deposit(ref_id.upper()) or dep_before
            await delete_deposit_payment_message(telegram_application.bot, dep_after)
            await send_deposit_completed_message(telegram_application.bot, dep_after)
        except TelegramError:
            pass
    return redirect_with_msg(admin_safe_return_path(request), reason)


@web_app.post("/admin/payments/{ref_id}/reject")
async def admin_payment_reject(request: Request, ref_id: str):
    guard = admin_guard(request)
    if guard:
        return guard
    dep_before = get_deposit(ref_id.upper())
    with get_conn() as conn:
        cur = conn.execute("UPDATE payment_deposits SET status = 'rejected', manual_note = 'Rejected by admin' WHERE ref_id = ? AND credited_at IS NULL", (ref_id.upper(),))
    if dep_before is not None and telegram_application is not None and cur.rowcount:
        try:
            await delete_deposit_payment_message(telegram_application.bot, dep_before)
            await send_wallet_topup_rejected_message(telegram_application.bot, int(dep_before["chat_id"]))
        except TelegramError:
            pass
    return redirect_with_msg(admin_safe_return_path(request), "Payment rejected." if cur.rowcount else "Payment was already processed or not found.")


@web_app.get("/admin/payouts", response_class=HTMLResponse)
async def admin_payouts(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT p.*, COALESCE(p.payout_details, d.details_text) AS visible_payout_details
            FROM payout_requests p
            LEFT JOIN receiver_payout_details d ON d.chat_id = p.receiver_chat_id
            ORDER BY p.created_at DESC LIMIT 500
            """
        ).fetchall()
    paged, pager = paginate_items(rows, request)
    body = '<div class="card"><h2>💸 Payout Requests</h2>'
    if not rows:
        body += '<p>No payout requests.</p>'
    else:
        body += '<div class="table-wrap"><table><tr><th>ID</th><th>Receiver</th><th>Amount</th><th>Payment details</th><th>Status</th><th>Created</th><th>Actions</th></tr>'
        for r in paged:
            receiver = get_admin_user_row(int(r['receiver_chat_id']))
            action = '<span class="muted">Completed</span>'
            if str(r["status"]) == "pending":
                action = (
                    f'<form class="inline" method="post" action="/admin/payouts/{esc(r["id"])}/paid"><button type="submit">Mark paid</button></form> '
                    f'<form class="inline" method="post" action="/admin/payouts/{esc(r["id"])}/reject"><button class="danger" type="submit">Reject</button></form>'
                )
            payout_details_text = str(r["visible_payout_details"] or "No details saved")
            payout_details_html = f'<button type="button" class="secondary" data-details="{esc(payout_details_text)}" onclick="showPayoutDetails(this)">View details</button>'
            body += f'<tr><td>#{esc(r["id"])}</td><td>{user_link(receiver) if receiver else esc(r["receiver_chat_id"])}</td><td>${_money(r["amount_usdt"])}</td><td>{payout_details_html}</td><td>{esc(r["status"])}</td><td>{esc(display_datetime(r["created_at"]))}</td><td>{action}</td></tr>'
        body += '</table></div>' + pager
    body += '</div>'
    return render_page("Payout Requests", body, request)


@web_app.post("/admin/payouts/{request_id}/paid")
async def admin_payout_paid(request: Request, request_id: int):
    guard = admin_guard(request)
    if guard:
        return guard
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM payout_requests WHERE id = ?", (request_id,)).fetchone()
    if row and row['status'] == 'pending':
        manual_adjust_wallet(int(row['receiver_chat_id']), _dec(row['amount_usdt']), 'receiver_paid', f'Payout request #{request_id} paid')
        with get_conn() as conn:
            conn.execute("UPDATE payout_requests SET status = 'paid', resolved_at = ? WHERE id = ?", (now_iso(), request_id))
        if telegram_application is not None:
            try:
                await telegram_application.bot.send_message(
                    chat_id=int(row['receiver_chat_id']),
                    text=(
                        "✅ Payout done.\n"
                        f"Amount: ${_money(row['amount_usdt'])} USDT\n\n"
                        "Your earnings balance has been updated. Use /earnings to view it."
                    ),
                    protect_content=PROTECT_CONTENT,
                )
            except TelegramError:
                pass
    return redirect_with_msg("/admin/payouts", "Payout marked paid.")


@web_app.post("/admin/payouts/{request_id}/reject")
async def admin_payout_reject(request: Request, request_id: int):
    guard = admin_guard(request)
    if guard:
        return guard
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM payout_requests WHERE id = ?", (request_id,)).fetchone()
        cur = conn.execute("UPDATE payout_requests SET status = 'rejected', resolved_at = ? WHERE id = ? AND status = 'pending'", (now_iso(), request_id))
    if row and cur.rowcount and telegram_application is not None:
        try:
            await telegram_application.bot.send_message(
                chat_id=int(row['receiver_chat_id']),
                text=(
                    "❌ Your payout request was rejected.\n"
                    f"Amount: ${_money(row['amount_usdt'])} USDT\n\n"
                    "The amount is available again in /earnings."
                ),
                protect_content=PROTECT_CONTENT,
            )
        except TelegramError:
            pass
    return redirect_with_msg("/admin/payouts", "Payout rejected.")


@web_app.get("/admin/disputes", response_class=HTMLResponse)
async def admin_disputes(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    status_filter = str(request.query_params.get("status", "attention")).strip().lower()
    allowed = {"all", "attention", "open", "under_review", "resolved", "rejected"}
    if status_filter not in allowed:
        status_filter = "attention"
    where = ""
    params: tuple = ()
    if status_filter == "attention":
        where = "WHERE status IN ('open','under_review')"
    elif status_filter != "all":
        where = "WHERE status = ?"
        params = (status_filter,)
    with get_conn() as conn:
        rows = conn.execute(f"SELECT * FROM disputes {where} ORDER BY created_at DESC LIMIT 500", params).fetchall()
        counts = {r["status"]: int(r["n"] or 0) for r in conn.execute("SELECT status, COUNT(*) AS n FROM disputes GROUP BY status").fetchall()}
    paged, pager = paginate_items(rows, request)
    def tab(label: str, value: str, count: int | None = None) -> str:
        active = ' class="btn"' if value == status_filter else ' class="btn secondary"'
        suffix = f" ({count})" if count is not None else ""
        return f'<a{active} href="/admin/disputes?status={esc(value)}">{esc(label)}{esc(suffix)}</a>'
    attention_count = int(counts.get('open', 0)) + int(counts.get('under_review', 0))
    body = '<div class="card"><h2>⚠️ Disputes</h2>'
    body += '<div class="button-row" style="margin-bottom:14px;">'
    body += tab('Needs attention', 'attention', attention_count)
    body += tab('Open', 'open', counts.get('open', 0))
    body += tab('Under review', 'under_review', counts.get('under_review', 0))
    body += tab('Resolved', 'resolved', counts.get('resolved', 0))
    body += tab('Rejected', 'rejected', counts.get('rejected', 0))
    body += tab('All', 'all', sum(int(v) for v in counts.values()))
    body += '</div>'
    if not rows:
        body += '<p>No disputes in this view.</p>'
    else:
        body += '<div class="table-wrap"><table><tr><th>ID</th><th>QR</th><th>User</th><th>Message</th><th>Status</th><th>Created</th><th>Action</th></tr>'
        for r in paged:
            user = get_admin_user_row(int(r['chat_id']))
            qr_public_id = str(r['public_id'] or '')
            qr = qr_id_link(qr_public_id) if qr_public_id else '<span class="muted">General</span>'
            ref = str(r['ref_id'] or f"DSP{int(r['id']):06d}")
            status = str(r['status'] or 'open').lower()
            action_parts: list[str] = []
            if status == 'open':
                action_parts.append(
                    f'<form class="inline" method="post" action="/admin/disputes/{esc(r["id"])}/review" '
                    'data-confirm-title="Mark under review?" data-confirm-button="Mark under review" data-confirm-class="secondary" '
                    'data-confirm-message="The user will be notified that the dispute is under review.">'
                    '<button class="secondary" type="submit">Under review</button></form>'
                )
            if status in {'open', 'under_review'}:
                action_parts.append(
                    f'<form class="inline dispute-message-form" method="post" action="/admin/disputes/{esc(r["id"])}/resolve" '
                    f'data-mode="resolve" data-ref="{esc(ref)}" data-user="{esc(strip_tags(user_link(user)) if user else r["chat_id"])}" '
                    f'data-qr="{esc(qr_public_id or "General")}"><button class="success" type="submit">Resolve</button></form>'
                )
                action_parts.append(
                    f'<form class="inline dispute-message-form" method="post" action="/admin/disputes/{esc(r["id"])}/reject" '
                    f'data-mode="reject" data-ref="{esc(ref)}" data-user="{esc(strip_tags(user_link(user)) if user else r["chat_id"])}" '
                    f'data-qr="{esc(qr_public_id or "General")}"><button class="danger" type="submit">Reject</button></form>'
                )
            action = ' '.join(action_parts) if action_parts else '<span class="muted">No action</span>'
            note = ''
            if r['admin_note']:
                note = f'<div class="muted" style="margin-top:6px;"><strong>Admin note:</strong> {esc(r["admin_note"])}</div>'
            body += (
                f'<tr><td>#{esc(ref)}</td><td>{qr}</td><td>{user_link(user) if user else esc(r["chat_id"])}</td>'
                f'<td>{esc(r["message"])}{note}</td><td>{dispute_status_pill(status)}</td><td>{esc(display_datetime(r["created_at"]))}</td><td>{action}</td></tr>'
            )
        body += '</table></div>' + pager
    body += '</div>'
    body += """
    <div id="dispute-message-modal" class="confirm-modal-shell" hidden>
      <div class="confirm-modal-backdrop" data-close-dispute-message></div>
      <div class="confirm-modal-panel" role="dialog" aria-modal="true" aria-labelledby="dispute-message-title">
        <h2 id="dispute-message-title">Update dispute</h2>
        <p id="dispute-message-desc" class="confirm-modal-desc">Enter the message that should be sent to the disputer.</p>
        <form id="dispute-message-submit-form" method="post" action="">
          <label>Message to disputer</label>
          <textarea name="admin_note" required placeholder="Example: We reviewed your dispute and resolved it."></textarea>
          <div class="confirm-actions">
            <button type="button" class="secondary" data-close-dispute-message>Cancel</button>
            <button type="submit" id="dispute-message-submit-button" class="success">Send</button>
          </div>
        </form>
      </div>
    </div>
    <script>
    document.addEventListener('DOMContentLoaded', function() {
      const shell = document.getElementById('dispute-message-modal');
      const submitForm = document.getElementById('dispute-message-submit-form');
      const title = document.getElementById('dispute-message-title');
      const desc = document.getElementById('dispute-message-desc');
      const button = document.getElementById('dispute-message-submit-button');
      if (!shell || !submitForm) return;
      function closeModal() { shell.hidden = true; submitForm.action = ''; }
      document.querySelectorAll('[data-close-dispute-message]').forEach(function(el) { el.addEventListener('click', closeModal); });
      document.querySelectorAll('.dispute-message-form').forEach(function(form) {
        form.addEventListener('submit', function(event) {
          event.preventDefault();
          const mode = form.getAttribute('data-mode') || 'resolve';
          const ref = form.getAttribute('data-ref') || '';
          const user = form.getAttribute('data-user') || '';
          const qr = form.getAttribute('data-qr') || '';
          submitForm.action = form.action;
          if (title) title.textContent = mode === 'reject' ? 'Reject dispute?' : 'Resolve dispute?';
          if (button) { button.textContent = mode === 'reject' ? 'Reject & Send' : 'Resolve & Send'; button.className = mode === 'reject' ? 'danger' : 'success'; }
          if (desc) desc.textContent = 'Dispute #' + ref + ' · ' + user + ' · QR: ' + qr;
          const textarea = submitForm.querySelector('textarea[name="admin_note"]');
          if (textarea) { textarea.value = ''; textarea.placeholder = mode === 'reject' ? 'Example: We reviewed your dispute, but could not approve it.' : 'Example: We reviewed your dispute and resolved it.'; textarea.focus(); }
          shell.hidden = false;
        });
      });
      document.addEventListener('keydown', function(event) { if (event.key === 'Escape' && !shell.hidden) closeModal(); });
    });
    </script>
    """
    return render_page("Disputes", body, request)


async def _notify_dispute_user(row: sqlite3.Row, text: str) -> bool:
    if telegram_application is None:
        return False
    try:
        await telegram_application.bot.send_message(chat_id=int(row['chat_id']), text=text, protect_content=PROTECT_CONTENT)
        return True
    except TelegramError:
        return False


@web_app.post("/admin/disputes/{dispute_id}/review")
async def admin_dispute_review(request: Request, dispute_id: int):
    guard = admin_guard(request)
    if guard:
        return guard
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM disputes WHERE id = ?", (dispute_id,)).fetchone()
        cur = conn.execute("UPDATE disputes SET status = 'under_review' WHERE id = ? AND status = 'open'", (dispute_id,))
    if row and cur.rowcount:
        ref = str(row['ref_id'] or f"DSP{int(row['id']):06d}")
        qr_line = f"\nQR ID: {row['public_id']}" if row['public_id'] else ""
        notified = await _notify_dispute_user(row, f"🔎 Your dispute #{ref} is now under review.{qr_line}\n\nAdmin will update you soon.")
        return redirect_with_msg("/admin/disputes", "Dispute marked under review." + ("" if notified else " Telegram notification failed."))
    return redirect_with_msg("/admin/disputes", "Dispute was already updated or not found.")


@web_app.post("/admin/disputes/{dispute_id}/resolve")
async def admin_dispute_resolve(request: Request, dispute_id: int):
    guard = admin_guard(request)
    if guard:
        return guard
    form = await request.form()
    admin_note = str(form.get("admin_note", "")).strip() or "Your dispute has been reviewed and resolved."
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM disputes WHERE id = ?", (dispute_id,)).fetchone()
        cur = conn.execute(
            "UPDATE disputes SET status = 'resolved', resolved_at = ?, admin_note = ? WHERE id = ? AND status IN ('open','under_review')",
            (now_iso(), admin_note, dispute_id),
        )
    if row and cur.rowcount:
        ref = str(row['ref_id'] or f"DSP{int(row['id']):06d}")
        qr_line = f"\nQR ID: {row['public_id']}" if row['public_id'] else ""
        notified = await _notify_dispute_user(row, f"✅ Your dispute #{ref} has been resolved.{qr_line}\n\nAdmin message:\n{admin_note}")
        return redirect_with_msg("/admin/disputes", "Dispute resolved and message sent." if notified else "Dispute resolved, but Telegram notification failed.")
    return redirect_with_msg("/admin/disputes", "Dispute was already updated or not found.")


@web_app.post("/admin/disputes/{dispute_id}/reject")
async def admin_dispute_reject(request: Request, dispute_id: int):
    guard = admin_guard(request)
    if guard:
        return guard
    form = await request.form()
    admin_note = str(form.get("admin_note", "")).strip() or "Your dispute has been reviewed and rejected."
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM disputes WHERE id = ?", (dispute_id,)).fetchone()
        cur = conn.execute(
            "UPDATE disputes SET status = 'rejected', resolved_at = ?, admin_note = ? WHERE id = ? AND status IN ('open','under_review')",
            (now_iso(), admin_note, dispute_id),
        )
    if row and cur.rowcount:
        ref = str(row['ref_id'] or f"DSP{int(row['id']):06d}")
        qr_line = f"\nQR ID: {row['public_id']}" if row['public_id'] else ""
        notified = await _notify_dispute_user(row, f"❌ Your dispute #{ref} has been rejected.{qr_line}\n\nAdmin message:\n{admin_note}")
        return redirect_with_msg("/admin/disputes", "Dispute rejected and message sent." if notified else "Dispute rejected, but Telegram notification failed.")
    return redirect_with_msg("/admin/disputes", "Dispute was already updated or not found.")


@web_app.get("/admin/messages", response_class=HTMLResponse)
async def admin_messages(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    # Show only active rows. Delete buttons now permanently erase rows instead of marking inactive.
    templates = list_message_templates(active_only=True, limit=500)
    paged_templates, templates_pager = paginate_items(templates, request)
    replies = list_message_replies(active_only=True)
    replies_by_template: dict[int, list[sqlite3.Row]] = {}
    for reply in replies:
        replies_by_template.setdefault(int(reply["template_id"]), []).append(reply)

    body = '''
    <div class="card"><h2>💬 Preset Messages</h2>
      <div class="button-row">
        <form method="post" action="/admin/messages/seed" class="inline"><button class="secondary" type="submit">🌱 Add starter presets</button></form>
        <a class="btn secondary" href="/admin/messages/export">⬇️ Export presets</a>
      </div>
    </div>
    <div class="card"><h3>⬆️ Import presets</h3>
      <form method="post" action="/admin/messages/import" enctype="multipart/form-data">
        <div class="row">
          <div><label>Import mode</label><select name="mode"><option value="replace">Replace current presets</option><option value="append">Append to current presets</option></select></div>
          <div><label>Upload JSON file</label><input type="file" name="preset_file" accept="application/json,.json"></div>
        </div>
        <label>Or paste preset JSON</label><textarea name="preset_json" placeholder="Paste exported preset JSON here"></textarea>
        <button type="submit">⬆️ Import presets</button>
      </form>
      <p class="muted small">Export creates a JSON backup of messages and reply buttons. Import can replace everything or append to the current list.</p>
    </div>
    <div class="card"><h3>➕ Add message/question</h3>
      <form method="post" action="/admin/messages/add">
        <div class="row">
          <div><label>Who can send it?</label><select name="audience"><option value="sender">Sender</option><option value="receiver">Receiver / Buyer</option><option value="both">Both</option></select></div>
          <div><label>Button text</label><input name="button_text" required placeholder="🟢 Anyone working?"></div>
        </div>
        <label>Message text delivered</label><textarea name="message_text" required placeholder="Any receiver available for QR work right now?"></textarea>
        <button type="submit">➕ Add message</button>
      </form>
    </div>
    <div class="card"><h3>↩️ Add reply button</h3>
      <form method="post" action="/admin/messages/addreply">
        <div class="row">
          <div><label>Message ID</label><input name="message_id" required placeholder="1"></div>
          <div><label>Who can reply?</label><select name="audience"><option value="sender">Sender</option><option value="receiver">Receiver / Buyer</option><option value="both">Both</option></select></div>
          <div><label>Reply button</label><input name="button_text" placeholder="✅ Yes" required></div>
        </div>
        <label>Reply text delivered back</label><textarea name="reply_text" required placeholder="I am available right now."></textarea>
        <button type="submit">➕ Add reply</button>
      </form>
    </div>
    '''

    body += '<div class="card"><h3>Existing messages</h3>'
    if not templates:
        body += '<p>No preset messages yet.</p>'
    else:
        body += '<div class="message-list">'
        for t in paged_templates:
            delete_msg_form = f'<form class="inline" method="post" action="/admin/messages/delmsg"><input type="hidden" name="message_id" value="{esc(t["id"])}"><button class="danger" type="submit">Delete message</button></form>'
            body += f'''
            <div class="message-card">
              <div class="message-head">
                <div><span class="muted small">ID</span><div class="message-id">#{esc(t["id"])}</div></div>
                <div><span class="muted small">Audience</span><div>{esc(t["audience"])}</div></div>
                <div><span class="muted small">Button</span><div class="message-button">{esc(t["button_text"])}</div></div>
                <div><span class="muted small">Message</span><div class="message-text">{esc(t["message_text"])}</div><div class="muted small">Created: {esc(display_datetime(t["created_at"]))}</div></div>
                <div>{delete_msg_form}</div>
              </div>
            '''
            replies = replies_by_template.get(int(t["id"]), [])
            if replies:
                body += '<div class="reply-list">'
                for r in replies:
                    delete_reply_form = f'<form class="inline" method="post" action="/admin/messages/delreply"><input type="hidden" name="reply_id" value="{esc(r["id"])}"><button class="danger" type="submit">Delete reply</button></form>'
                    body += f'''
                    <div class="reply-card">
                      <div><span class="muted small">Reply ID</span><div class="message-id">#{esc(r["id"])}</div></div>
                      <div><span class="muted small">Audience</span><div>{esc(r["audience"])}</div></div>
                      <div><span class="muted small">Button</span><div class="message-button">{esc(r["button_text"])}</div></div>
                      <div><span class="muted small">Reply text</span><div class="message-text">{esc(r["reply_text"])}</div><div class="muted small">Created: {esc(display_datetime(r["created_at"]))}</div></div>
                      <div>{delete_reply_form}</div>
                    </div>
                    '''
                body += '</div>'
            else:
                body += '<div class="reply-list"><p class="muted">No replies added yet.</p></div>'
            body += '</div>'
        body += '</div>' + templates_pager
    body += '</div>'
    return render_page("Preset Messages", body, request)


@web_app.get("/admin/messages/export")
async def admin_messages_export(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    payload = export_preset_messages_payload()
    data = json.dumps(payload, ensure_ascii=False, indent=2)
    filename = f"upi_autopay_presets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    return Response(
        content=data,
        media_type="application/json; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@web_app.post("/admin/messages/import")
async def admin_messages_import(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    form = await request.form()
    mode = str(form.get("mode", "replace")).strip().lower()
    raw = ""
    upload = form.get("preset_file")
    try:
        if upload is not None and getattr(upload, "filename", ""):
            data = await upload.read()
            if len(data) > 2_000_000:
                raise ValueError("Import file is too large.")
            raw = data.decode("utf-8-sig")
        else:
            raw = str(form.get("preset_json", "")).strip()
        if not raw:
            raise ValueError("Upload a JSON file or paste preset JSON.")
        payload = json.loads(raw)
        message_count, reply_count = import_preset_messages_payload(payload, mode=mode)
    except Exception as exc:
        return redirect_with_msg("/admin/messages", f"Could not import presets: {exc}")
    action = "replaced" if mode == "replace" else "imported"
    return redirect_with_msg("/admin/messages", f"Presets {action}: {message_count} messages and {reply_count} replies.")


@web_app.post("/admin/messages/add")
async def admin_messages_add(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    form = await request.form()
    try:
        add_message_template(str(form.get("audience", "")), str(form.get("button_text", "")), str(form.get("message_text", "")))
    except Exception as exc:
        return redirect_with_msg("/admin/messages", f"Could not add message: {exc}")
    return redirect_with_msg("/admin/messages", "Message added.")


@web_app.post("/admin/messages/addreply")
async def admin_messages_addreply(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    form = await request.form()
    try:
        add_message_reply(int(str(form.get("message_id", "")).strip()), str(form.get("audience", "")), str(form.get("button_text", "")), str(form.get("reply_text", "")))
    except Exception as exc:
        return redirect_with_msg("/admin/messages", f"Could not add reply: {exc}")
    return redirect_with_msg("/admin/messages", "Reply added.")


@web_app.post("/admin/messages/delmsg")
async def admin_messages_delmsg(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    form = await request.form()
    try:
        ok = delete_message_template_permanent(int(str(form.get("message_id", "")).strip()))
    except Exception as exc:
        return redirect_with_msg("/admin/messages", f"Could not delete message: {exc}")
    return redirect_with_msg("/admin/messages", "Message permanently deleted." if ok else "Message not found.")


@web_app.post("/admin/messages/delreply")
async def admin_messages_delreply(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    form = await request.form()
    try:
        ok = delete_message_reply_permanent(int(str(form.get("reply_id", "")).strip()))
    except Exception as exc:
        return redirect_with_msg("/admin/messages", f"Could not delete reply: {exc}")
    return redirect_with_msg("/admin/messages", "Reply permanently deleted." if ok else "Reply not found.")


@web_app.post("/admin/messages/seed")
async def admin_messages_seed(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    seed = [
        ("sender", "🟢 Anyone working?", "Any receiver available for QR work right now?", [("receiver", "✅ Available", "I am available for QR work right now."), ("receiver", "⏳ Later", "I can work after some time."), ("receiver", "❌ Busy", "I am not available right now.")]),
        ("sender", "📲 QR ready", "QR work is available. Who can accept now?", [("receiver", "✅ Send QR", "I can accept QR work now. Send it."), ("receiver", "1️⃣ One only", "I can accept one QR only right now."), ("receiver", "❌ Cannot", "I cannot accept QR work right now.")]),
        ("sender", "⚡ Urgent work", "Urgent QR work available. Reply only if you can start immediately.", [("receiver", "⚡ Ready now", "I am ready now and can start immediately."), ("receiver", "⏳ 5 min", "I can start in about 5 minutes."), ("receiver", "❌ No", "I cannot take urgent work right now.")]),
        ("receiver", "🧾 Any work?", "Any sender have QR work available right now?", [("sender", "✅ Yes", "Yes, QR work is available right now."), ("sender", "⏳ Soon", "QR work may be available soon."), ("sender", "❌ No", "No QR work is available right now.")]),
        ("receiver", "⚡ Ready now", "I am ready for QR work now. Send if available.", [("sender", "📲 Sending", "I am sending QR work now."), ("sender", "⏳ Wait", "Please wait for the next QR."), ("sender", "❌ None", "No QR work is available right now.")]),
        ("receiver", "📷 QR issue", "There is an issue with the QR. Please resend or update.", [("sender", "🔁 Resending", "I am resending it now."), ("sender", "✅ Updated", "I have updated it."), ("sender", "⏳ Shortly", "I will send it shortly.")]),
    ]
    created = 0
    replies_created = 0
    try:
        for audience, button, text, replies in seed:
            mid = add_message_template(audience, button, text)
            created += 1
            for ra, rb, rt in replies:
                add_message_reply(mid, ra, rb, rt)
                replies_created += 1
    except Exception as exc:
        return redirect_with_msg("/admin/messages", f"Could not seed messages: {exc}")
    return redirect_with_msg("/admin/messages", f"Seeded {created} messages and {replies_created} replies.")


@web_app.get("/admin/settings", response_class=HTMLResponse)
async def admin_settings(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    source = active_admin_credential_source()
    username = active_admin_username()
    settings = get_marketplace_settings()
    body = f"""
    <div class="card"><h2>🔐 Secret Settings</h2>
      <p class="muted">Current login source: <strong>{esc(source)}</strong></p>
      <p>Current admin username: <code>{esc(username)}</code></p>
      <form method="post" action="/admin/settings/credentials">
        <div class="row">
          <div><label>New admin username</label><input name="username" required value="{esc(username)}"></div>
          <div><label>New admin password</label><input type="password" name="password" required></div>
          <div><label>Confirm password</label><input type="password" name="confirm_password" required></div>
        </div>
        <button type="submit">💾 Save website login</button>
      </form>
    </div>

    <div class="card"><h3>🔑 Payment verification APIs</h3>
      <p class="muted">These keys are used only for auto/manual verification. Wallet addresses, tolerances, and top-up limits are on the Payments page.</p>
      <form method="post" action="/admin/settings/payment-apis">
        <div class="row">
          <div><label>BscScan API key</label><input name="bscscan_api_key" value="{esc(settings['bscscan_api_key'])}"></div>
          <div><label>PolygonScan API key</label><input name="polygonscan_api_key" value="{esc(settings['polygonscan_api_key'])}"></div>
          <div><label>BEP20 RPC fallback URL</label><input name="bep20_rpc_url" value="{esc(settings['bep20_rpc_url'])}"></div>
          <div><label>Polygon RPC fallback URL</label><input name="polygon_rpc_url" value="{esc(settings['polygon_rpc_url'])}"></div>
          <div><label>BEP20 RPC fallback URLs (comma separated)</label><input name="bep20_rpc_urls" value="{esc(settings['bep20_rpc_urls'])}"></div>
          <div><label>Polygon RPC fallback URLs (comma separated)</label><input name="polygon_rpc_urls" value="{esc(settings['polygon_rpc_urls'])}"></div>
          <div><label>Etherscan V2 API key (optional)</label><input name="etherscan_api_key" value="{esc(settings['etherscan_api_key'])}"></div>
          <div><label>BEP20 confirmations</label><input name="bep20_required_confirmations" value="{esc(settings['bep20_required_confirmations'])}"></div>
          <div><label>Polygon confirmations</label><input name="polygon_required_confirmations" value="{esc(settings['polygon_required_confirmations'])}"></div>
          <div><label>Binance API key</label><input name="binance_api_key" value="{esc(settings['binance_api_key'])}"></div>
          <div><label>Binance API secret</label><input type="password" name="binance_api_secret" value="{esc(settings['binance_api_secret'])}"></div>
          <div><label>Binance API base URL</label><input name="binance_api_base_url" value="{esc(settings['binance_api_base_url'])}"></div>
          <div><label>Binance recv window (ms)</label><input name="binance_recv_window_ms" value="{esc(settings['binance_recv_window_ms'])}"></div>
          <div><label>Binance history lookback (seconds)</label><input name="binance_pay_history_lookback_seconds" value="{esc(settings['binance_pay_history_lookback_seconds'])}"></div>
        </div>
        <button type="submit">💾 Save verification APIs</button>
      </form>
    </div>

    <div class="card"><h3>⏱ Bot timing/settings</h3>
      <form method="post" action="/admin/settings/bot-timing">
        <div class="row">
          <div><label>QR expire minutes</label><input name="qr_expire_minutes" value="{esc(settings['qr_expire_minutes'])}"></div>
          <div><label>Payment timeout minutes</label><input name="payment_timeout_minutes" value="{esc(settings['payment_timeout_minutes'])}"></div>
          <div><label>Payment reminder minutes</label><input name="payment_reminder_minutes" value="{esc(settings['payment_reminder_minutes'])}"></div>
          <div><label>USDT verify interval seconds</label><input name="payment_watch_interval_seconds" value="{esc(settings['payment_watch_interval_seconds'])}"></div>
          <div><label>Manual verification delay minutes</label><input name="manual_verification_delay_minutes" value="{esc(settings['manual_verification_delay_minutes'])}"></div>
        </div>
        <button type="submit">💾 Save bot timing</button>
      </form>
      <p class="muted small">QR expire minutes applies to each QR from sender upload time and expires it even if a receiver already accepted it. Payment timeout/reminder and verification interval apply to wallet top-up sessions.</p>
    </div>

    <div class="card"><h3>💸 Receiver withdrawal settings</h3>
      <form method="post" action="/admin/settings/withdrawals">
        <div class="row">
          <div><label>Minimum payout request (USDT)</label><input name="min_payout_usdt" value="{esc(_money(settings['min_payout_usdt']))}"></div>
        </div>
        <button type="submit">💾 Save withdrawal settings</button>
      </form>
      <p class="muted small">Receivers can request withdrawal only when their available balance is at least this amount.</p>
    </div>

    <div class="card"><h3>Fallback login</h3>
      <p class="muted">The website uses the environment username/password only when no website login has been saved here.</p>
      <form method="post" action="/admin/settings/reset" class="inline">
        <button class="danger" type="submit">Reset to environment login</button>
      </form>
    </div>
    """
    return render_page("Secret Settings", body, request)


@web_app.post("/admin/settings/credentials")
async def admin_settings_credentials(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    form = await request.form()
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", ""))
    confirm = str(form.get("confirm_password", ""))
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{3,64}", username):
        return redirect_with_msg("/admin/settings", "Username must be 3-64 characters and use letters, numbers, dot, underscore, @ or hyphen.")
    if len(password) < 8:
        return redirect_with_msg("/admin/settings", "Password must be at least 8 characters.")
    if password != confirm:
        return redirect_with_msg("/admin/settings", "Passwords do not match.")
    set_admin_setting(ADMIN_USERNAME_KEY, username)
    set_admin_setting(ADMIN_PASSWORD_HASH_KEY, _hash_password(password))
    resp = redirect_with_msg("/admin/login", "Login changed. Please sign in again.")
    resp.delete_cookie(ADMIN_COOKIE_NAME)
    return resp


@web_app.post("/admin/settings/payment-apis")
async def admin_settings_payment_apis(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    form = await request.form()
    values = {
        "bscscan_api_key": str(form.get("bscscan_api_key", "")).strip(),
        "polygonscan_api_key": str(form.get("polygonscan_api_key", "")).strip(),
        "bep20_rpc_url": str(form.get("bep20_rpc_url", BEP20_RPC_URL)).strip() or BEP20_RPC_URL,
        "polygon_rpc_url": str(form.get("polygon_rpc_url", POLYGON_RPC_URL)).strip() or POLYGON_RPC_URL,
        "bep20_rpc_urls": str(form.get("bep20_rpc_urls", BEP20_RPC_URLS)).strip() or BEP20_RPC_URLS,
        "polygon_rpc_urls": str(form.get("polygon_rpc_urls", POLYGON_RPC_URLS)).strip() or POLYGON_RPC_URLS,
        "etherscan_api_key": str(form.get("etherscan_api_key", ETHERSCAN_API_KEY)).strip(),
        "bep20_required_confirmations": str(form.get("bep20_required_confirmations", BEP20_REQUIRED_CONFIRMATIONS)).strip(),
        "polygon_required_confirmations": str(form.get("polygon_required_confirmations", POLYGON_REQUIRED_CONFIRMATIONS)).strip(),
        "binance_api_key": str(form.get("binance_api_key", "")).strip(),
        "binance_api_secret": str(form.get("binance_api_secret", "")).strip(),
        "binance_api_base_url": str(form.get("binance_api_base_url", BINANCE_API_BASE_URL)).strip().rstrip("/") or BINANCE_API_BASE_URL,
        "binance_recv_window_ms": str(form.get("binance_recv_window_ms", BINANCE_RECV_WINDOW_MS)).strip(),
        "binance_pay_history_lookback_seconds": str(form.get("binance_pay_history_lookback_seconds", BINANCE_PAY_HISTORY_LOOKBACK_SECONDS)).strip(),
    }
    for key in ("bep20_required_confirmations", "polygon_required_confirmations", "binance_recv_window_ms", "binance_pay_history_lookback_seconds"):
        try:
            if int(values[key]) < 0:
                raise ValueError
        except Exception:
            return redirect_with_msg("/admin/settings", f"{key} must be a valid non-negative integer.")
    for key, value in values.items():
        set_admin_setting(key, value)
    return redirect_with_msg("/admin/settings", "Payment verification API settings saved.")


@web_app.post("/admin/settings/withdrawals")
async def admin_settings_withdrawals(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    form = await request.form()
    min_payout = str(form.get("min_payout_usdt", DEFAULT_MIN_PAYOUT_USDT)).strip()
    if _dec(min_payout, "0") <= 0:
        return redirect_with_msg("/admin/settings", "Minimum payout request must be greater than zero.")
    set_admin_setting("min_payout_usdt", min_payout)
    return redirect_with_msg("/admin/settings", "Withdrawal settings saved.")


@web_app.post("/admin/settings/bot-timing")
async def admin_settings_bot_timing(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    form = await request.form()
    values = {
        "qr_expire_minutes": str(form.get("qr_expire_minutes", QR_EXPIRE_MINUTES)).strip(),
        "payment_timeout_minutes": str(form.get("payment_timeout_minutes", PAYMENT_TIMEOUT_MINUTES)).strip(),
        "payment_reminder_minutes": str(form.get("payment_reminder_minutes", PAYMENT_REMINDER_MINUTES)).strip(),
        "payment_watch_interval_seconds": str(form.get("payment_watch_interval_seconds", PAYMENT_WATCH_INTERVAL_SECONDS)).strip(),
        "manual_verification_delay_minutes": str(form.get("manual_verification_delay_minutes", MANUAL_VERIFICATION_DELAY_MINUTES)).strip(),
    }
    minimums = {
        "qr_expire_minutes": 1,
        "payment_timeout_minutes": 1,
        "payment_reminder_minutes": 0,
        "payment_watch_interval_seconds": 10,
        "manual_verification_delay_minutes": 0,
    }
    for key, min_value in minimums.items():
        try:
            if int(values[key]) < min_value:
                raise ValueError
        except Exception:
            return redirect_with_msg("/admin/settings", f"{key} must be a valid integer greater than or equal to {min_value}.")
    for key, value in values.items():
        set_admin_setting(key, value)
    return redirect_with_msg("/admin/settings", "Bot timing settings saved.")


@web_app.post("/admin/settings/reset")
async def admin_settings_reset(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    delete_admin_setting(ADMIN_USERNAME_KEY)
    delete_admin_setting(ADMIN_PASSWORD_HASH_KEY)
    resp = redirect_with_msg("/admin/login", "Saved website login removed. Environment login is active now.")
    resp.delete_cookie(ADMIN_COOKIE_NAME)
    return resp


@web_app.post("/telegram-webhook")
async def telegram_webhook(request: Request):
    if MODE != "webhook":
        raise HTTPException(status_code=404, detail="Webhook mode is not enabled")
    if WEBHOOK_SECRET_TOKEN:
        incoming = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
        if not hmac.compare_digest(incoming, WEBHOOK_SECRET_TOKEN):
            raise HTTPException(status_code=403, detail="Bad secret token")
    if telegram_application is None:
        raise HTTPException(status_code=503, detail="Telegram app not ready")
    data = await request.json()
    update = Update.de_json(data, telegram_application.bot)
    await telegram_application.process_update(update)
    return {"ok": True}


@web_app.on_event("startup")
async def web_startup() -> None:
    global telegram_application, polling_started, marketplace_background_task, payment_background_task
    _mongo_available_or_raise()
    restore_mongo_snapshot_if_configured()
    init_db()
    validate_config()
    sync_db_to_mongo(force=True)
    telegram_application = build_application()
    await telegram_application.initialize()
    await set_bot_commands(telegram_application)
    await telegram_application.start()

    if MODE == "webhook":
        if not WEBHOOK_URL:
            raise BotConfigError("MODE=webhook requires WEBHOOK_URL, e.g. https://your-app.up.railway.app")
        webhook_url = f"{WEBHOOK_URL.rstrip('/')}/telegram-webhook"
        logger.info("Setting Telegram webhook to %s", webhook_url)
        await telegram_application.bot.set_webhook(url=webhook_url, secret_token=WEBHOOK_SECRET_TOKEN or None, allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)
    else:
        logger.info("Starting Telegram polling inside the admin web process. Do not run a second bot instance.")
        if telegram_application.updater is None:
            raise BotConfigError("Polling mode requires Application.updater, but it is not available.")
        await telegram_application.updater.start_polling(drop_pending_updates=True, allowed_updates=Update.ALL_TYPES)
        polling_started = True

    marketplace_background_task = asyncio.create_task(marketplace_watcher(telegram_application), name="marketplace_watcher")
    payment_background_task = asyncio.create_task(payment_watcher(telegram_application), name="payment_watcher")
    marketplace_background_task.add_done_callback(_background_task_done("Marketplace watcher"))
    payment_background_task.add_done_callback(_background_task_done("Payment watcher"))
    logger.info("Background watchers started")


@web_app.on_event("shutdown")
async def web_shutdown() -> None:
    global telegram_application, polling_started, marketplace_background_task, payment_background_task
    try:
        if telegram_application is not None:
            for task in (marketplace_background_task, payment_background_task):
                if task is not None:
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
            marketplace_background_task = None
            payment_background_task = None
            if polling_started and telegram_application.updater is not None:
                await telegram_application.updater.stop()
                polling_started = False
            if MODE == "webhook":
                await telegram_application.bot.delete_webhook(drop_pending_updates=False)
            await telegram_application.stop()
            await telegram_application.shutdown()
    finally:
        telegram_application = None
        close_mongo_storage()

# -----------------------------
# App entrypoint
# -----------------------------


def validate_config() -> None:
    _mongo_available_or_raise()
    if not BOT_TOKEN:
        raise BotConfigError("BOT_TOKEN is missing. Put it in .env or Railway variables.")
    if not ADMIN_IDS:
        logger.warning("ADMIN_IDS is empty. Keep it set as the main admin/owner record even though admin actions are website-only.")
    if not stored_admin_credentials_configured() and not ADMIN_PANEL_PASSWORD:
        raise BotConfigError("ADMIN_PANEL_PASSWORD is missing and no admin-panel login is saved in the database.")
    try:
        ZoneInfo(BOT_TZ)
    except Exception as exc:
        raise BotConfigError(f"Invalid BOT_TZ: {BOT_TZ}") from exc


def bot_commands_for_role(role: str | None) -> list[tuple[str, str]]:
    common = [
        ("start", "Open main menu"),
        ("commands", "Show commands"),
        ("support", "Open support contact"),
        ("messages", "Preset marketplace messages"),
        ("myid", "Show your chat ID"),
        ("history", "Show QR history"),
        ("stats", "Show your stats"),
        ("dispute", "Open a dispute"),
    ]
    if role == "sender":
        return common + [
            ("status", "Show marketplace capacity"),
            ("wallet", "Show wallet balance"),
            ("loadwallet", "Top-up your wallet"),
        ]
    if role == "receiver":
        return common + [
            ("on", "Go online with limit"),
            ("off", "Go offline"),
            ("pending", "Show pending QRs"),
            ("done", "Mark replied QR done"),
            ("failed", "Mark replied QR failed"),
            ("earnings", "Show earnings"),
            ("withdraw", "Request payout"),
        ]
    return common


async def refresh_bot_commands_for_chat(bot, chat_id: int, user: UserRow | None) -> None:
    try:
        scope = BotCommandScopeChat(chat_id=chat_id)
        if user and user.active:
            await bot.set_my_commands(bot_commands_for_role(user.role), scope=scope)
        else:
            await bot.delete_my_commands(scope=scope)
    except TelegramError as exc:
        logger.debug("Could not refresh bot commands for %s: %s", chat_id, exc)


async def set_bot_commands(application: Application) -> None:
    try:
        await application.bot.set_my_commands(bot_commands_for_role(None))
    except TelegramError as exc:
        logger.warning("Could not set default bot commands: %s", exc)

    with get_conn() as conn:
        users = conn.execute("SELECT * FROM users WHERE chat_id != 0 LIMIT 10000").fetchall()
    for row in users:
        user = UserRow(chat_id=int(row['chat_id']), role=str(row['role']), alias=row['alias'], active=bool(row['active']))
        await refresh_bot_commands_for_chat(application.bot, int(row['chat_id']), user)
        await asyncio.sleep(0.02)


def build_application() -> Application:
    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(MessageHandler(filters.ALL, maintenance_guard), group=-1)
    app.add_handler(CallbackQueryHandler(maintenance_guard), group=-1)

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("commands", commands_cmd))
    app.add_handler(CommandHandler("support", support_cmd))
    app.add_handler(CommandHandler("messages", messages_cmd))
    app.add_handler(CommandHandler("myid", myid))
    app.add_handler(CommandHandler("status", marketplace_status_cmd))
    app.add_handler(CommandHandler("wallet", wallet_cmd))
    app.add_handler(CommandHandler("loadwallet", loadwallet_cmd))
    app.add_handler(CommandHandler("on", on_cmd))
    app.add_handler(CommandHandler("off", off_cmd))
    app.add_handler(CommandHandler("earnings", earnings_cmd))
    app.add_handler(CommandHandler("withdraw", withdraw_cmd))
    app.add_handler(CommandHandler("dispute", dispute_cmd))
    app.add_handler(CommandHandler("history", history_cmd))
    app.add_handler(CommandHandler("stats", stats_cmd))
    app.add_handler(CommandHandler("pending", pending_cmd))
    app.add_handler(CommandHandler("done", done_cmd))
    app.add_handler(CommandHandler("failed", failed_cmd))
    app.add_handler(CallbackQueryHandler(wallet_nav_button, pattern=r"^nav:(wallet|loadwallet|status|pending|history|dispute|stats|messages|commands|support|home)$"))
    app.add_handler(CallbackQueryHandler(wallet_currency_button, pattern=r"^wallet_currency:"))
    app.add_handler(CallbackQueryHandler(wallet_history_button, pattern=r"^wallet_history:"))
    app.add_handler(CallbackQueryHandler(qr_history_button, pattern=r"^qr_history:"))
    app.add_handler(CallbackQueryHandler(withdraw_button, pattern=r"^withdraw:"))
    app.add_handler(CallbackQueryHandler(preset_send_button, pattern=r"^msgsend:"))
    app.add_handler(CallbackQueryHandler(preset_reply_button, pattern=r"^msgreply:"))
    app.add_handler(CallbackQueryHandler(fail_reason_button, pattern=r"^failreason:"))
    app.add_handler(CallbackQueryHandler(dispute_qr_button, pattern=r"^disputeqr:"))
    app.add_handler(CallbackQueryHandler(check_payment_button, pattern=r"^checkpay:"))
    app.add_handler(CallbackQueryHandler(manual_payment_button, pattern=r"^manualpay:"))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, wallet_text_flow))
    app.add_handler(CallbackQueryHandler(claim_offer_button, pattern=r"^claim:"))
    app.add_handler(CallbackQueryHandler(pending_qr_button, pattern=r"^pendingqr:"))
    app.add_handler(CallbackQueryHandler(button_status, pattern=r"^(done|failed):"))
    app.add_handler(MessageHandler(filters.PHOTO, handle_photo))
    app.add_handler(MessageHandler(filters.Document.IMAGE, reject_document))
    app.add_error_handler(error_handler)

    return app


def main() -> None:
    # One process starts both the admin website and the Telegram bot.
    # This avoids accidentally polling Telegram from a separate website process.
    uvicorn.run(web_app, host="0.0.0.0", port=PORT)


if __name__ == "__main__":
    try:
        main()
    except BotConfigError as exc:
        logger.error("Configuration error: %s", exc)
        raise SystemExit(1)
