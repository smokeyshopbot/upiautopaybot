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
# Keep the sender QR path fast. The bot first tries cheap decode paths and only
# uses stronger screenshot fallbacks when needed. Increase this only if you prefer
# accepting very bad screenshots over 2-3 second QR delivery.
QR_DECODE_TIMEOUT_SECONDS = float(os.getenv("QR_DECODE_TIMEOUT_SECONDS", "2.4"))
QR_FAST_ONLY = os.getenv("QR_FAST_ONLY", "false").strip().lower() in {"1", "true", "yes", "on"}
QR_MAX_UPSCALE_DIMENSION = int(os.getenv("QR_MAX_UPSCALE_DIMENSION", "2200"))

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
SENDER_CANCEL_WAIT_SECONDS = int(os.getenv("SENDER_CANCEL_WAIT_SECONDS", "120"))
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
DEFAULT_SENDER_RATE_USDT = os.getenv("DEFAULT_SENDER_RATE_USDT", "0.50").strip() or "0.50"
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


def support_display_text(chat_id: int | None = None) -> str:
    contact = support_contact_value()
    if not contact:
        return tr_chat(chat_id, "support_not_configured")
    return contact


def support_keyboard(include_back: bool = True, chat_id: int | None = None) -> InlineKeyboardMarkup | None:
    rows: list[list[InlineKeyboardButton]] = []
    url = support_chat_url()
    if url:
        rows.append([InlineKeyboardButton(tr_chat(chat_id, "btn_open_support"), url=url)])
    if include_back:
        rows.append([InlineKeyboardButton(tr_chat(chat_id, "btn_back"), callback_data="nav:home")])
    return InlineKeyboardMarkup(rows) if rows else None


# -----------------------------
# User language support
# -----------------------------

SUPPORTED_LANGUAGES: dict[str, dict[str, str]] = {
    "en": {"name": "English", "native": "English"},
    "id": {"name": "Indonesian", "native": "Bahasa Indonesia"},
    "vi": {"name": "Vietnamese", "native": "Tiếng Việt"},
    "zh": {"name": "Chinese", "native": "中文"},
    "es": {"name": "Spanish", "native": "Español"},
}
DEFAULT_LANGUAGE = "en"

_TRANSLATIONS: dict[str, dict[str, str]] = {
    "en": {
        "private_only": "Please use this bot only in private chat.",
        "choose_language": "🌐 Please choose your language.",
        "language_saved": "✅ Language updated to English.",
        "language_menu_hint": "You can change this anytime with /language.",
        "btn_language_en": "English",
        "btn_language_id": "Bahasa Indonesia",
        "btn_language_vi": "Tiếng Việt",
        "btn_language_zh": "中文",
        "btn_language_es": "Español",
        "btn_back": "⬅️ Back",
        "btn_back_menu": "⬅️ Back to Menu",
        "btn_open_support": "💬 Open Support Chat",
        "btn_language": "🌐 Language",
        "btn_commands": "📋 Commands",
        "btn_support": "🛟 Support",
        "btn_wallet": "👛 Wallet",
        "btn_status": "📡 Status",
        "btn_messages": "💬 Messages",
        "btn_history": "📜 QR History",
        "btn_stats": "📊 Stats",
        "btn_dispute": "⚠️ Dispute",
        "btn_earnings": "💰 Earnings",
        "btn_pending_qr": "📥 Pending QR",
        "btn_topup_wallet": "➕ Top-up Wallet",
        "btn_wallet_history": "👛 Wallet History",
        "btn_withdraw": "💸 Withdraw",
        "registered_sender": "✅ You are registered as a <b>sender</b>.\n\n📤 Send a photo containing exactly one UPI AutoPay QR code.\n🧼 I will rebuild it as a clean QR and post it as an open offer to online receivers.\n\nUse the menu below for wallet, marketplace messages, QR history, disputes, stats, commands, language, and support.",
        "registered_receiver": "✅ You are registered as a <b>receiver/buyer</b>.\n\n🟢 Go online when you are ready to receive QR offers.\n📥 Accepted QRs will appear here with Done/Failed buttons.\n\nUse the menu below for earnings, pending QRs, marketplace messages, QR history, disputes, stats, commands, language, and support.",
        "not_registered_menu": "👋 You are not registered yet.\n\n🆔 Your chat ID: <code>{chat_id}</code>\n\n📩 Send this ID to support/admin to get access.\n\n👤 Support: {support}",
        "commands_title": "📋 Available commands and usage",
        "commands_role": "Role: {role}",
        "commands_general": "General:",
        "cmd_start": "• /start — open the main menu",
        "cmd_commands": "• /commands — show this command list",
        "cmd_language": "• /language — change your language",
        "cmd_myid": "• /myid — show your Telegram chat ID and username",
        "cmd_support": "• /support — show support contact and open-chat button",
        "cmd_messages": "• /messages — send a preset marketplace broadcast",
        "cmd_history": "• /history — show your QR history",
        "cmd_dispute": "• /dispute — open a support dispute",
        "cmd_stats": "• /stats — show your totals",
        "commands_sender": "Sender:",
        "cmd_send_qr": "• Send a QR photo — create a new open QR scan offer",
        "cmd_status": "• /status — show marketplace receiver capacity",
        "cmd_wallet": "• /wallet — show your wallet balance",
        "cmd_loadwallet": "• /loadwallet — top up your wallet",
        "commands_receiver": "Receiver:",
        "cmd_on": "• /on LIMIT — go online, example: /on 25",
        "cmd_off": "• /off — go offline",
        "cmd_pending": "• /pending — show your claimed pending QRs",
        "cmd_done": "• /done — mark the QR you replied to as done",
        "cmd_failed": "• /failed — mark the QR you replied to as failed by selecting a reason",
        "cmd_earnings": "• /earnings — show receiver earnings",
        "cmd_withdraw": "• /withdraw — request payout",
        "commands_after_activation": "After admin activates your account, this list will show only the commands for your role.",
        "support_text": "🛟 Support\n\nContact: {support}\n\nUse the button below to open the support chat directly.",
        "myid_text": "Your ID is:\n`{chat_id}`{suffix}",
        "username_set": "\nUsername: @{username}",
        "username_hidden": "\nUsername: not set / hidden",
        "not_registered": "You are not registered yet.",
        "not_registered_support": "You are not registered yet. Use Support below to request access.",
        "only_active_receivers": "Only active receivers can use this.",
        "only_active_receivers_on": "Only active receivers can use /on.",
        "only_active_receivers_off": "Only active receivers can use /off.",
        "on_usage": "Usage: /on LIMIT\nExample: /on 25",
        "receiver_online": "🟢 You are online. Current limit: {limit} scans.",
        "receiver_offline": "🔴 You are offline. New offers will stop until you use /on LIMIT again.",
        "sender_status_only": "/status is only for senders. Use /pending for your QR tasks and /earnings for your balance.",
        "sender_status_only_menu": "/status is only for senders. Use Pending QR and Earnings from the receiver menu.",
        "notify_receiver_online": "🟢 A receiver is online now.\n📊 Total limit now: {capacity} scans.\n\nUse /status to see total live capacity.",
        "notify_receiver_offline": "🔴 A receiver went offline.\nCheck /status before sending more QR codes.",
        "no_pending_qrs": "No claimed pending QRs.",
        "pending_header": "Your claimed pending QRs:\nTap an ID below to reopen that specific QR.\n",
        "history_title": "📜 QR History",
        "history_page": "<b>📜 QR History — Page {page}/{total_pages}</b>",
        "history_showing": "Showing 10 QR logs per page, newest first.",
        "history_empty": "No QR history yet.",
        "qr_id": "QR ID",
        "date_time": "Date/Time",
        "photo_no": "Photo No",
        "status": "Status",
        "charged": "Charged",
        "earned": "Earned",
        "status_done": "✅ Done",
        "status_failed": "❌ Failed",
        "status_expired": "⌛ Expired",
        "status_pending": "⏳ Pending",
        "btn_prev": "⬅️ Previous",
        "btn_next": "Next ➡️",
        "marketplace_messages_title": "💬 Marketplace preset messages",
        "marketplace_messages_text": "Choose a preset below. It will be sent to all active {target}.\nAny reply button they tap will come back only to you.",
        "target_receivers": "receivers",
        "target_senders": "senders",
        "preset_private_only": "Please use preset messages only in private chat.",
        "no_presets": "No preset messages are available for your role right now.",
        "preset_menu_wrong_user": "This preset menu belongs to another account.",
        "invalid_preset_button": "Invalid preset button.",
        "preset_not_active": "This preset message is no longer active.",
        "preset_not_for_role": "This preset is not available for your role.",
        "no_active_recipients": "No active {role}s found right now.",
        "could_not_send_any": "Could not send to any active {role} right now.",
        "sent_failed": "Sent to {sent}. {failed} failed.",
        "sent_ok": "Sent ✅",
        "already_answered_closed": "✅ Already answered.\nThis marketplace message is closed.",
        "invalid_reply_button": "Invalid reply button.",
        "reply_no_longer_available": "This preset reply is no longer available.",
        "reply_not_for_account": "This reply button is not for your account.",
        "reply_mismatch": "This reply does not match the original message.",
        "reply_not_for_role": "This reply is not available for your role.",
        "already_answered_other": "Already answered by someone else.",
        "marketplace_msg_unavailable": "This marketplace message is no longer available.",
        "reply_saved_notify_failed": "Reply saved, but the sender could not be notified right now.",
        "reply_sent": "Reply sent ✅",
        "receiver_earnings_title": "💰 *Receiver earnings*",
        "total_earned": "Total earned",
        "paid": "Paid",
        "requested": "Requested",
        "available_withdraw": "Available to withdraw",
        "wallet_title": "👛 *Your Wallet*",
        "usdt_balance": "💵 USDT Balance",
        "reserved": "🔒 Reserved",
        "available": "✅ Available",
        "only_active_senders_wallet": "Only active senders can use /wallet.",
        "only_active_senders_load": "Only active senders can load wallet.",
        "only_senders_load": "Only senders can load wallet.",
        "loadwallet_hint": "Use /loadwallet to top up your wallet.",
        "amount_gt_zero": "Amount must be greater than 0.",
        "could_not_create_deposit": "Could not create deposit: {error}",
        "topup_no_methods": "👛 *Top-up Wallet*\n\n⚠️ No top-up payment methods are configured right now. Please contact support.",
        "topup_choose": "👛 *Top-up Wallet*\n\nChoose how you want to add funds:",
        "only_receivers_pending": "Only receivers have pending QR tasks.",
        "only_senders_status": "Only senders can use this.",
    },
    "id": {
        "private_only": "Silakan gunakan bot ini hanya di chat pribadi.",
        "choose_language": "🌐 Silakan pilih bahasa Anda.",
        "language_saved": "✅ Bahasa diperbarui ke Bahasa Indonesia.",
        "language_menu_hint": "Anda dapat mengubahnya kapan saja dengan /language.",
        "btn_open_support": "💬 Buka Chat Dukungan", "btn_back": "⬅️ Kembali", "btn_back_menu": "⬅️ Kembali ke Menu", "btn_language": "🌐 Bahasa",
        "btn_commands": "📋 Perintah", "btn_support": "🛟 Dukungan", "btn_wallet": "👛 Dompet", "btn_status": "📡 Status", "btn_messages": "💬 Pesan", "btn_history": "📜 Riwayat QR", "btn_stats": "📊 Statistik", "btn_dispute": "⚠️ Sengketa", "btn_earnings": "💰 Penghasilan", "btn_pending_qr": "📥 QR Tertunda", "btn_topup_wallet": "➕ Isi Saldo Dompet", "btn_wallet_history": "👛 Riwayat Dompet", "btn_withdraw": "💸 Tarik Dana",
        "registered_sender": "✅ Anda terdaftar sebagai <b>pengirim</b>.\n\n📤 Kirim foto yang berisi tepat satu kode QR UPI AutoPay.\n🧼 Saya akan membuat ulang QR itu menjadi QR yang bersih dan menawarkannya secara terbuka kepada penerima yang online.\n\nGunakan menu di bawah untuk dompet, pesan marketplace, riwayat QR, sengketa, statistik, perintah, bahasa, dan dukungan.",
        "registered_receiver": "✅ Anda terdaftar sebagai <b>penerima/pembeli</b>.\n\n🟢 Aktifkan status online saat Anda siap menerima penawaran QR.\n📥 QR yang diterima akan muncul di sini dengan tombol Done/Failed.\n\nGunakan menu di bawah untuk penghasilan, QR tertunda, pesan marketplace, riwayat QR, sengketa, statistik, perintah, bahasa, dan dukungan.",
        "not_registered_menu": "👋 Anda belum terdaftar.\n\n🆔 ID chat Anda: <code>{chat_id}</code>\n\n📩 Kirim ID ini ke dukungan/admin untuk mendapatkan akses.\n\n👤 Dukungan: {support}",
        "commands_title": "📋 Perintah yang tersedia dan cara penggunaan", "commands_role": "Peran: {role}", "commands_general": "Umum:", "cmd_start": "• /start — buka menu utama", "cmd_commands": "• /commands — tampilkan daftar perintah ini", "cmd_language": "• /language — ubah bahasa Anda", "cmd_myid": "• /myid — tampilkan ID chat Telegram dan username Anda", "cmd_support": "• /support — tampilkan kontak dukungan dan tombol buka chat", "cmd_messages": "• /messages — kirim broadcast marketplace preset", "cmd_history": "• /history — tampilkan riwayat QR Anda", "cmd_dispute": "• /dispute — buka sengketa dukungan", "cmd_stats": "• /stats — tampilkan total Anda", "commands_sender": "Pengirim:", "cmd_send_qr": "• Kirim foto QR — buat penawaran scan QR terbuka baru", "cmd_status": "• /status — tampilkan kapasitas penerima marketplace", "cmd_wallet": "• /wallet — tampilkan saldo dompet Anda", "cmd_loadwallet": "• /loadwallet — isi saldo dompet Anda", "commands_receiver": "Penerima:", "cmd_on": "• /on LIMIT — online, contoh: /on 25", "cmd_off": "• /off — offline", "cmd_pending": "• /pending — tampilkan QR tertunda yang sudah Anda klaim", "cmd_done": "• /done — tandai QR yang Anda balas sebagai selesai", "cmd_failed": "• /failed — tandai QR yang Anda balas sebagai gagal dengan memilih alasan", "cmd_earnings": "• /earnings — tampilkan penghasilan penerima", "cmd_withdraw": "• /withdraw — ajukan penarikan", "commands_after_activation": "Setelah admin mengaktifkan akun Anda, daftar ini hanya akan menampilkan perintah sesuai peran Anda.",
        "support_text": "🛟 Dukungan\n\nKontak: {support}\n\nGunakan tombol di bawah untuk membuka chat dukungan secara langsung.", "username_hidden": "\nUsername: tidak disetel / disembunyikan", "not_registered": "Anda belum terdaftar.", "not_registered_support": "Anda belum terdaftar. Gunakan Dukungan di bawah untuk meminta akses.", "only_active_receivers": "Hanya penerima aktif yang dapat menggunakan ini.", "only_active_receivers_on": "Hanya penerima aktif yang dapat menggunakan /on.", "only_active_receivers_off": "Hanya penerima aktif yang dapat menggunakan /off.", "on_usage": "Penggunaan: /on LIMIT\nContoh: /on 25", "receiver_online": "🟢 Anda online. Limit saat ini: {limit} scan.", "receiver_offline": "🔴 Anda offline. Penawaran baru akan berhenti sampai Anda menggunakan /on LIMIT lagi.", "sender_status_only": "/status hanya untuk pengirim. Gunakan /pending untuk tugas QR Anda dan /earnings untuk saldo Anda.", "sender_status_only_menu": "/status hanya untuk pengirim. Gunakan QR Tertunda dan Penghasilan dari menu penerima.", "notify_receiver_online": "🟢 Ada penerima yang online sekarang.\n📊 Total limit sekarang: {capacity} scan.\n\nGunakan /status untuk melihat total kapasitas aktif.", "notify_receiver_offline": "🔴 Seorang penerima offline.\nSilakan cek /status sebelum mengirim QR lagi.",
        "no_pending_qrs": "Tidak ada QR tertunda yang diklaim.", "pending_header": "QR tertunda yang Anda klaim:\nKetuk ID di bawah untuk membuka kembali QR tertentu.\n", "history_title": "📜 Riwayat QR", "history_page": "<b>📜 Riwayat QR — Halaman {page}/{total_pages}</b>", "history_showing": "Menampilkan 10 log QR per halaman, terbaru terlebih dahulu.", "history_empty": "Belum ada riwayat QR.", "qr_id": "ID QR", "date_time": "Tanggal/Waktu", "photo_no": "No. Foto", "status": "Status", "charged": "Ditagih", "earned": "Diperoleh", "status_done": "✅ Selesai", "status_failed": "❌ Gagal", "status_expired": "⌛ Kedaluwarsa", "status_pending": "⏳ Tertunda", "btn_prev": "⬅️ Sebelumnya", "btn_next": "Berikutnya ➡️",
        "marketplace_messages_title": "💬 Pesan preset marketplace", "marketplace_messages_text": "Pilih preset di bawah. Pesan akan dikirim ke semua {target} aktif.\nTombol balasan yang mereka ketuk hanya akan kembali kepada Anda.", "target_receivers": "penerima", "target_senders": "pengirim", "preset_private_only": "Silakan gunakan pesan preset hanya di chat pribadi.", "no_presets": "Tidak ada pesan preset yang tersedia untuk peran Anda saat ini.", "preset_menu_wrong_user": "Menu preset ini milik akun lain.", "invalid_preset_button": "Tombol preset tidak valid.", "preset_not_active": "Pesan preset ini tidak aktif lagi.", "preset_not_for_role": "Preset ini tidak tersedia untuk peran Anda.", "no_active_recipients": "Tidak ada {role} aktif saat ini.", "could_not_send_any": "Tidak dapat mengirim ke {role} aktif saat ini.", "sent_failed": "Terkirim ke {sent}. {failed} gagal.", "sent_ok": "Terkirim ✅", "already_answered_closed": "✅ Sudah dijawab.\nPesan marketplace ini ditutup.", "invalid_reply_button": "Tombol balasan tidak valid.", "reply_no_longer_available": "Balasan preset ini tidak tersedia lagi.", "reply_not_for_account": "Tombol balasan ini bukan untuk akun Anda.", "reply_mismatch": "Balasan ini tidak cocok dengan pesan asli.", "reply_not_for_role": "Balasan ini tidak tersedia untuk peran Anda.", "already_answered_other": "Sudah dijawab oleh orang lain.", "marketplace_msg_unavailable": "Pesan marketplace ini tidak tersedia lagi.", "reply_saved_notify_failed": "Balasan disimpan, tetapi pengirim tidak dapat diberi tahu sekarang.", "reply_sent": "Balasan terkirim ✅",
        "receiver_earnings_title": "💰 *Penghasilan penerima*", "total_earned": "Total diperoleh", "paid": "Dibayar", "requested": "Diminta", "available_withdraw": "Tersedia untuk ditarik", "wallet_title": "👛 *Dompet Anda*", "usdt_balance": "💵 Saldo USDT", "reserved": "🔒 Direservasi", "available": "✅ Tersedia", "only_active_senders_wallet": "Hanya pengirim aktif yang dapat menggunakan /wallet.", "only_active_senders_load": "Hanya pengirim aktif yang dapat mengisi saldo dompet.", "only_senders_load": "Hanya pengirim yang dapat mengisi saldo dompet.", "loadwallet_hint": "Gunakan /loadwallet untuk mengisi saldo dompet Anda.", "amount_gt_zero": "Jumlah harus lebih besar dari 0.", "could_not_create_deposit": "Tidak dapat membuat deposit: {error}", "topup_no_methods": "👛 *Isi Saldo Dompet*\n\n⚠️ Belum ada metode pembayaran isi saldo yang dikonfigurasi. Silakan hubungi dukungan.", "topup_choose": "👛 *Isi Saldo Dompet*\n\nPilih cara menambahkan dana:", "only_receivers_pending": "Hanya penerima yang memiliki tugas QR tertunda.", "only_senders_status": "Hanya pengirim yang dapat menggunakan ini."
    },
    "vi": {
        "private_only": "Vui lòng chỉ sử dụng bot này trong cuộc trò chuyện riêng.", "choose_language": "🌐 Vui lòng chọn ngôn ngữ của bạn.", "language_saved": "✅ Đã đổi ngôn ngữ sang Tiếng Việt.", "language_menu_hint": "Bạn có thể thay đổi bất cứ lúc nào bằng /language.", "btn_open_support": "💬 Mở chat hỗ trợ", "btn_back": "⬅️ Quay lại", "btn_back_menu": "⬅️ Quay lại Menu", "btn_language": "🌐 Ngôn ngữ", "btn_commands": "📋 Lệnh", "btn_support": "🛟 Hỗ trợ", "btn_wallet": "👛 Ví", "btn_status": "📡 Trạng thái", "btn_messages": "💬 Tin nhắn", "btn_history": "📜 Lịch sử QR", "btn_stats": "📊 Thống kê", "btn_dispute": "⚠️ Khiếu nại", "btn_earnings": "💰 Thu nhập", "btn_pending_qr": "📥 QR đang chờ", "btn_topup_wallet": "➕ Nạp ví", "btn_wallet_history": "👛 Lịch sử ví", "btn_withdraw": "💸 Rút tiền",
        "registered_sender": "✅ Bạn đã được đăng ký là <b>người gửi</b>.\n\n📤 Gửi ảnh chứa đúng một mã QR UPI AutoPay.\n🧼 Tôi sẽ tạo lại mã QR sạch và đăng nó dưới dạng lời mời mở cho các người nhận đang online.\n\nDùng menu bên dưới cho ví, tin nhắn marketplace, lịch sử QR, khiếu nại, thống kê, lệnh, ngôn ngữ và hỗ trợ.", "registered_receiver": "✅ Bạn đã được đăng ký là <b>người nhận/người mua</b>.\n\n🟢 Hãy bật online khi bạn sẵn sàng nhận các lời mời QR.\n📥 QR đã nhận sẽ xuất hiện ở đây với các nút Done/Failed.\n\nDùng menu bên dưới cho thu nhập, QR đang chờ, tin nhắn marketplace, lịch sử QR, khiếu nại, thống kê, lệnh, ngôn ngữ và hỗ trợ.", "not_registered_menu": "👋 Bạn chưa được đăng ký.\n\n🆔 ID chat của bạn: <code>{chat_id}</code>\n\n📩 Gửi ID này cho hỗ trợ/admin để được cấp quyền truy cập.\n\n👤 Hỗ trợ: {support}",
        "commands_title": "📋 Các lệnh có sẵn và cách dùng", "commands_role": "Vai trò: {role}", "commands_general": "Chung:", "cmd_start": "• /start — mở menu chính", "cmd_commands": "• /commands — hiển thị danh sách lệnh", "cmd_language": "• /language — đổi ngôn ngữ", "cmd_myid": "• /myid — hiển thị ID chat Telegram và username", "cmd_support": "• /support — hiển thị liên hệ hỗ trợ và nút mở chat", "cmd_messages": "• /messages — gửi broadcast marketplace preset", "cmd_history": "• /history — hiển thị lịch sử QR", "cmd_dispute": "• /dispute — mở khiếu nại hỗ trợ", "cmd_stats": "• /stats — hiển thị tổng của bạn", "commands_sender": "Người gửi:", "cmd_send_qr": "• Gửi ảnh QR — tạo lời mời quét QR mở mới", "cmd_status": "• /status — hiển thị sức chứa người nhận trên marketplace", "cmd_wallet": "• /wallet — hiển thị số dư ví", "cmd_loadwallet": "• /loadwallet — nạp ví", "commands_receiver": "Người nhận:", "cmd_on": "• /on LIMIT — bật online, ví dụ: /on 25", "cmd_off": "• /off — tắt online", "cmd_pending": "• /pending — hiển thị QR đang chờ bạn đã nhận", "cmd_done": "• /done — đánh dấu QR bạn đã trả lời là hoàn tất", "cmd_failed": "• /failed — đánh dấu QR bạn đã trả lời là thất bại bằng cách chọn lý do", "cmd_earnings": "• /earnings — hiển thị thu nhập người nhận", "cmd_withdraw": "• /withdraw — yêu cầu rút tiền", "commands_after_activation": "Sau khi admin kích hoạt tài khoản, danh sách này sẽ chỉ hiển thị các lệnh cho vai trò của bạn.",
        "support_text": "🛟 Hỗ trợ\n\nLiên hệ: {support}\n\nDùng nút bên dưới để mở chat hỗ trợ trực tiếp.", "username_hidden": "\nUsername: chưa đặt / bị ẩn", "not_registered": "Bạn chưa được đăng ký.", "not_registered_support": "Bạn chưa được đăng ký. Dùng Hỗ trợ bên dưới để yêu cầu truy cập.", "only_active_receivers": "Chỉ người nhận đang hoạt động mới có thể dùng mục này.", "only_active_receivers_on": "Chỉ người nhận đang hoạt động mới có thể dùng /on.", "only_active_receivers_off": "Chỉ người nhận đang hoạt động mới có thể dùng /off.", "on_usage": "Cách dùng: /on LIMIT\nVí dụ: /on 25", "receiver_online": "🟢 Bạn đang online. Giới hạn hiện tại: {limit} lượt scan.", "receiver_offline": "🔴 Bạn đã offline. Lời mời mới sẽ dừng cho đến khi bạn dùng /on LIMIT lại.", "sender_status_only": "/status chỉ dành cho người gửi. Dùng /pending cho tác vụ QR và /earnings cho số dư của bạn.", "sender_status_only_menu": "/status chỉ dành cho người gửi. Dùng QR đang chờ và Thu nhập trong menu người nhận.", "notify_receiver_online": "🟢 Hiện có người nhận đang online.\n📊 Tổng hạn mức hiện tại: {capacity} lượt quét.\n\nDùng /status để xem tổng sức chứa đang hoạt động.", "notify_receiver_offline": "🔴 Một người nhận đã offline.\nVui lòng kiểm tra /status trước khi gửi thêm QR.",
        "no_pending_qrs": "Không có QR đang chờ đã nhận.", "pending_header": "Các QR đang chờ bạn đã nhận:\nNhấn một ID bên dưới để mở lại QR cụ thể đó.\n", "history_title": "📜 Lịch sử QR", "history_page": "<b>📜 Lịch sử QR — Trang {page}/{total_pages}</b>", "history_showing": "Hiển thị 10 nhật ký QR mỗi trang, mới nhất trước.", "history_empty": "Chưa có lịch sử QR.", "qr_id": "ID QR", "date_time": "Ngày/Giờ", "photo_no": "Số ảnh", "status": "Trạng thái", "charged": "Đã tính phí", "earned": "Đã kiếm", "status_done": "✅ Hoàn tất", "status_failed": "❌ Thất bại", "status_expired": "⌛ Hết hạn", "status_pending": "⏳ Đang chờ", "btn_prev": "⬅️ Trước", "btn_next": "Tiếp ➡️",
        "marketplace_messages_title": "💬 Tin nhắn preset marketplace", "marketplace_messages_text": "Chọn một preset bên dưới. Tin nhắn sẽ được gửi đến tất cả {target} đang hoạt động.\nBất kỳ nút trả lời nào họ nhấn sẽ chỉ gửi lại cho bạn.", "target_receivers": "người nhận", "target_senders": "người gửi", "preset_private_only": "Vui lòng chỉ dùng tin nhắn preset trong chat riêng.", "no_presets": "Hiện không có tin nhắn preset nào cho vai trò của bạn.", "preset_menu_wrong_user": "Menu preset này thuộc về tài khoản khác.", "invalid_preset_button": "Nút preset không hợp lệ.", "preset_not_active": "Tin nhắn preset này không còn hoạt động.", "preset_not_for_role": "Preset này không khả dụng cho vai trò của bạn.", "no_active_recipients": "Hiện không có {role} đang hoạt động.", "could_not_send_any": "Không thể gửi cho bất kỳ {role} đang hoạt động nào lúc này.", "sent_failed": "Đã gửi cho {sent}. {failed} lỗi.", "sent_ok": "Đã gửi ✅", "already_answered_closed": "✅ Đã được trả lời.\nTin nhắn marketplace này đã đóng.", "invalid_reply_button": "Nút trả lời không hợp lệ.", "reply_no_longer_available": "Trả lời preset này không còn khả dụng.", "reply_not_for_account": "Nút trả lời này không dành cho tài khoản của bạn.", "reply_mismatch": "Trả lời này không khớp với tin nhắn gốc.", "reply_not_for_role": "Trả lời này không khả dụng cho vai trò của bạn.", "already_answered_other": "Đã có người khác trả lời.", "marketplace_msg_unavailable": "Tin nhắn marketplace này không còn khả dụng.", "reply_saved_notify_failed": "Đã lưu trả lời, nhưng hiện không thể thông báo cho người gửi.", "reply_sent": "Đã gửi trả lời ✅",
        "receiver_earnings_title": "💰 *Thu nhập người nhận*", "total_earned": "Tổng thu nhập", "paid": "Đã trả", "requested": "Đã yêu cầu", "available_withdraw": "Có thể rút", "wallet_title": "👛 *Ví của bạn*", "usdt_balance": "💵 Số dư USDT", "reserved": "🔒 Đang giữ", "available": "✅ Khả dụng", "only_active_senders_wallet": "Chỉ người gửi đang hoạt động mới có thể dùng /wallet.", "only_active_senders_load": "Chỉ người gửi đang hoạt động mới có thể nạp ví.", "only_senders_load": "Chỉ người gửi mới có thể nạp ví.", "loadwallet_hint": "Dùng /loadwallet để nạp ví.", "amount_gt_zero": "Số tiền phải lớn hơn 0.", "could_not_create_deposit": "Không thể tạo khoản nạp: {error}", "topup_no_methods": "👛 *Nạp ví*\n\n⚠️ Hiện chưa cấu hình phương thức nạp ví. Vui lòng liên hệ hỗ trợ.", "topup_choose": "👛 *Nạp ví*\n\nChọn cách bạn muốn thêm tiền:", "only_receivers_pending": "Chỉ người nhận mới có tác vụ QR đang chờ.", "only_senders_status": "Chỉ người gửi mới có thể dùng mục này."
    },
    "zh": {
        "private_only": "请只在私聊中使用此机器人。", "choose_language": "🌐 请选择您的语言。", "language_saved": "✅ 语言已更新为中文。", "language_menu_hint": "您可以随时使用 /language 更改。", "btn_open_support": "💬 打开客服聊天", "btn_back": "⬅️ 返回", "btn_back_menu": "⬅️ 返回菜单", "btn_language": "🌐 语言", "btn_commands": "📋 命令", "btn_support": "🛟 客服", "btn_wallet": "👛 钱包", "btn_status": "📡 状态", "btn_messages": "💬 消息", "btn_history": "📜 QR 历史", "btn_stats": "📊 统计", "btn_dispute": "⚠️ 申诉", "btn_earnings": "💰 收益", "btn_pending_qr": "📥 待处理 QR", "btn_topup_wallet": "➕ 钱包充值", "btn_wallet_history": "👛 钱包历史", "btn_withdraw": "💸 提现",
        "registered_sender": "✅ 您已注册为<b>发送方</b>。\n\n📤 请发送一张只包含一个 UPI AutoPay QR 码的照片。\n🧼 我会把它重新生成干净的 QR，并作为公开任务发送给在线接收方。\n\n请使用下方菜单查看钱包、市场消息、QR 历史、申诉、统计、命令、语言和客服。", "registered_receiver": "✅ 您已注册为<b>接收方/买家</b>。\n\n🟢 准备好接收 QR 任务时请上线。\n📥 接收的 QR 会显示在这里，并带有 Done/Failed 按钮。\n\n请使用下方菜单查看收益、待处理 QR、市场消息、QR 历史、申诉、统计、命令、语言和客服。", "not_registered_menu": "👋 您尚未注册。\n\n🆔 您的聊天 ID：<code>{chat_id}</code>\n\n📩 请把此 ID 发送给客服/admin 以获取访问权限。\n\n👤 客服：{support}",
        "commands_title": "📋 可用命令和用法", "commands_role": "角色：{role}", "commands_general": "通用：", "cmd_start": "• /start — 打开主菜单", "cmd_commands": "• /commands — 显示此命令列表", "cmd_language": "• /language — 更改语言", "cmd_myid": "• /myid — 显示您的 Telegram 聊天 ID 和用户名", "cmd_support": "• /support — 显示客服联系方式和打开聊天按钮", "cmd_messages": "• /messages — 发送预设市场广播", "cmd_history": "• /history — 显示您的 QR 历史", "cmd_dispute": "• /dispute — 打开客服申诉", "cmd_stats": "• /stats — 显示您的总计", "commands_sender": "发送方：", "cmd_send_qr": "• 发送 QR 照片 — 创建新的公开 QR 扫描任务", "cmd_status": "• /status — 显示市场接收方容量", "cmd_wallet": "• /wallet — 显示钱包余额", "cmd_loadwallet": "• /loadwallet — 给钱包充值", "commands_receiver": "接收方：", "cmd_on": "• /on LIMIT — 上线，例如：/on 25", "cmd_off": "• /off — 下线", "cmd_pending": "• /pending — 显示您已领取的待处理 QR", "cmd_done": "• /done — 将您回复的 QR 标记为完成", "cmd_failed": "• /failed — 选择原因并将您回复的 QR 标记为失败", "cmd_earnings": "• /earnings — 显示接收方收益", "cmd_withdraw": "• /withdraw — 申请提现", "commands_after_activation": "管理员激活您的账户后，此列表将只显示适合您角色的命令。",
        "support_text": "🛟 客服\n\n联系方式：{support}\n\n使用下方按钮直接打开客服聊天。", "username_hidden": "\n用户名：未设置 / 已隐藏", "not_registered": "您尚未注册。", "not_registered_support": "您尚未注册。请使用下方客服申请访问权限。", "only_active_receivers": "只有活跃接收方可以使用此功能。", "only_active_receivers_on": "只有活跃接收方可以使用 /on。", "only_active_receivers_off": "只有活跃接收方可以使用 /off。", "on_usage": "用法：/on LIMIT\n示例：/on 25", "receiver_online": "🟢 您已上线。当前限制：{limit} 次扫描。", "receiver_offline": "🔴 您已下线。新任务会停止，直到您再次使用 /on LIMIT。", "sender_status_only": "/status 仅供发送方使用。请使用 /pending 查看 QR 任务，使用 /earnings 查看余额。", "sender_status_only_menu": "/status 仅供发送方使用。请从接收方菜单使用待处理 QR 和收益。", "notify_receiver_online": "🟢 现在有接收方在线。\n📊 当前总额度：{capacity} 次扫描。\n\n使用 /status 查看总实时容量。", "notify_receiver_offline": "🔴 一位接收方已下线。\n发送更多 QR 前请检查 /status。",
        "no_pending_qrs": "没有已领取的待处理 QR。", "pending_header": "您已领取的待处理 QR：\n点击下方 ID 重新打开对应 QR。\n", "history_title": "📜 QR 历史", "history_page": "<b>📜 QR 历史 — 第 {page}/{total_pages} 页</b>", "history_showing": "每页显示 10 条 QR 记录，最新优先。", "history_empty": "暂无 QR 历史。", "qr_id": "QR ID", "date_time": "日期/时间", "photo_no": "照片编号", "status": "状态", "charged": "已扣款", "earned": "已赚取", "status_done": "✅ 已完成", "status_failed": "❌ 失败", "status_expired": "⌛ 已过期", "status_pending": "⏳ 待处理", "btn_prev": "⬅️ 上一页", "btn_next": "下一页 ➡️",
        "marketplace_messages_title": "💬 市场预设消息", "marketplace_messages_text": "请选择下方预设。它会发送给所有活跃的{target}。\n他们点击的任何回复按钮只会返回给您。", "target_receivers": "接收方", "target_senders": "发送方", "preset_private_only": "请只在私聊中使用预设消息。", "no_presets": "目前没有适合您角色的预设消息。", "preset_menu_wrong_user": "此预设菜单属于另一个账户。", "invalid_preset_button": "无效的预设按钮。", "preset_not_active": "此预设消息不再可用。", "preset_not_for_role": "此预设不适用于您的角色。", "no_active_recipients": "目前没有活跃{role}。", "could_not_send_any": "目前无法发送给任何活跃{role}。", "sent_failed": "已发送给 {sent} 个用户，{failed} 个失败。", "sent_ok": "已发送 ✅", "already_answered_closed": "✅ 已回复。\n此市场消息已关闭。", "invalid_reply_button": "无效的回复按钮。", "reply_no_longer_available": "此预设回复不再可用。", "reply_not_for_account": "此回复按钮不属于您的账户。", "reply_mismatch": "此回复与原始消息不匹配。", "reply_not_for_role": "此回复不适用于您的角色。", "already_answered_other": "已被其他人回复。", "marketplace_msg_unavailable": "此市场消息不再可用。", "reply_saved_notify_failed": "回复已保存，但现在无法通知发送方。", "reply_sent": "回复已发送 ✅",
        "receiver_earnings_title": "💰 *接收方收益*", "total_earned": "总收益", "paid": "已支付", "requested": "已申请", "available_withdraw": "可提现", "wallet_title": "👛 *您的钱包*", "usdt_balance": "💵 USDT 余额", "reserved": "🔒 已预留", "available": "✅ 可用", "only_active_senders_wallet": "只有活跃发送方可以使用 /wallet。", "only_active_senders_load": "只有活跃发送方可以给钱包充值。", "only_senders_load": "只有发送方可以给钱包充值。", "loadwallet_hint": "请使用 /loadwallet 给钱包充值。", "amount_gt_zero": "金额必须大于 0。", "could_not_create_deposit": "无法创建充值：{error}", "topup_no_methods": "👛 *钱包充值*\n\n⚠️ 目前没有配置钱包充值付款方式。请联系客服。", "topup_choose": "👛 *钱包充值*\n\n请选择添加资金的方式：", "only_receivers_pending": "只有接收方有待处理 QR 任务。", "only_senders_status": "只有发送方可以使用此功能。"
    },
    "es": {
        "private_only": "Usa este bot solo en un chat privado.", "choose_language": "🌐 Elige tu idioma.", "language_saved": "✅ Idioma actualizado a español.", "language_menu_hint": "Puedes cambiarlo en cualquier momento con /language.", "btn_open_support": "💬 Abrir chat de soporte", "btn_back": "⬅️ Volver", "btn_back_menu": "⬅️ Volver al menú", "btn_language": "🌐 Idioma", "btn_commands": "📋 Comandos", "btn_support": "🛟 Soporte", "btn_wallet": "👛 Billetera", "btn_status": "📡 Estado", "btn_messages": "💬 Mensajes", "btn_history": "📜 Historial QR", "btn_stats": "📊 Estadísticas", "btn_dispute": "⚠️ Disputa", "btn_earnings": "💰 Ganancias", "btn_pending_qr": "📥 QR pendientes", "btn_topup_wallet": "➕ Recargar billetera", "btn_wallet_history": "👛 Historial de billetera", "btn_withdraw": "💸 Retirar",
        "registered_sender": "✅ Estás registrado como <b>remitente</b>.\n\n📤 Envía una foto que contenga exactamente un código QR de UPI AutoPay.\n🧼 Lo reconstruiré como un QR limpio y lo publicaré como una oferta abierta para los receptores en línea.\n\nUsa el menú de abajo para billetera, mensajes del marketplace, historial QR, disputas, estadísticas, comandos, idioma y soporte.", "registered_receiver": "✅ Estás registrado como <b>receptor/comprador</b>.\n\n🟢 Ponte en línea cuando estés listo para recibir ofertas QR.\n📥 Los QR aceptados aparecerán aquí con botones Done/Failed.\n\nUsa el menú de abajo para ganancias, QR pendientes, mensajes del marketplace, historial QR, disputas, estadísticas, comandos, idioma y soporte.", "not_registered_menu": "👋 Aún no estás registrado.\n\n🆔 Tu ID de chat: <code>{chat_id}</code>\n\n📩 Envía este ID a soporte/admin para obtener acceso.\n\n👤 Soporte: {support}",
        "commands_title": "📋 Comandos disponibles y uso", "commands_role": "Rol: {role}", "commands_general": "General:", "cmd_start": "• /start — abrir el menú principal", "cmd_commands": "• /commands — mostrar esta lista de comandos", "cmd_language": "• /language — cambiar tu idioma", "cmd_myid": "• /myid — mostrar tu ID de chat de Telegram y usuario", "cmd_support": "• /support — mostrar contacto de soporte y botón para abrir chat", "cmd_messages": "• /messages — enviar un broadcast predefinido del marketplace", "cmd_history": "• /history — mostrar tu historial QR", "cmd_dispute": "• /dispute — abrir una disputa de soporte", "cmd_stats": "• /stats — mostrar tus totales", "commands_sender": "Remitente:", "cmd_send_qr": "• Enviar una foto QR — crear una nueva oferta abierta de escaneo QR", "cmd_status": "• /status — mostrar la capacidad de receptores del marketplace", "cmd_wallet": "• /wallet — mostrar el saldo de tu billetera", "cmd_loadwallet": "• /loadwallet — recargar tu billetera", "commands_receiver": "Receptor:", "cmd_on": "• /on LIMIT — ponerse en línea, ejemplo: /on 25", "cmd_off": "• /off — ponerse fuera de línea", "cmd_pending": "• /pending — mostrar tus QR pendientes reclamados", "cmd_done": "• /done — marcar como hecho el QR al que respondiste", "cmd_failed": "• /failed — marcar como fallido el QR al que respondiste eligiendo un motivo", "cmd_earnings": "• /earnings — mostrar ganancias del receptor", "cmd_withdraw": "• /withdraw — solicitar retiro", "commands_after_activation": "Después de que el admin active tu cuenta, esta lista mostrará solo los comandos de tu rol.",
        "support_text": "🛟 Soporte\n\nContacto: {support}\n\nUsa el botón de abajo para abrir directamente el chat de soporte.", "username_hidden": "\nUsuario: no configurado / oculto", "not_registered": "Aún no estás registrado.", "not_registered_support": "Aún no estás registrado. Usa Soporte abajo para solicitar acceso.", "only_active_receivers": "Solo los receptores activos pueden usar esto.", "only_active_receivers_on": "Solo los receptores activos pueden usar /on.", "only_active_receivers_off": "Solo los receptores activos pueden usar /off.", "on_usage": "Uso: /on LIMIT\nEjemplo: /on 25", "receiver_online": "🟢 Estás en línea. Límite actual: {limit} escaneos.", "receiver_offline": "🔴 Estás fuera de línea. Las nuevas ofertas se detendrán hasta que uses /on LIMIT otra vez.", "sender_status_only": "/status es solo para remitentes. Usa /pending para tus tareas QR y /earnings para tu saldo.", "sender_status_only_menu": "/status es solo para remitentes. Usa QR pendientes y Ganancias desde el menú de receptor.", "notify_receiver_online": "🟢 Un receptor está en línea ahora.\n📊 Límite total ahora: {capacity} escaneos.\n\nUsa /status para ver la capacidad total en vivo.", "notify_receiver_offline": "🔴 Un receptor se desconectó.\nRevisa /status antes de enviar más QR.",
        "no_pending_qrs": "No hay QR pendientes reclamados.", "pending_header": "Tus QR pendientes reclamados:\nToca un ID abajo para volver a abrir ese QR específico.\n", "history_title": "📜 Historial QR", "history_page": "<b>📜 Historial QR — Página {page}/{total_pages}</b>", "history_showing": "Mostrando 10 registros QR por página, los más nuevos primero.", "history_empty": "Aún no hay historial QR.", "qr_id": "ID QR", "date_time": "Fecha/Hora", "photo_no": "N.º de foto", "status": "Estado", "charged": "Cobrado", "earned": "Ganado", "status_done": "✅ Hecho", "status_failed": "❌ Fallido", "status_expired": "⌛ Vencido", "status_pending": "⏳ Pendiente", "btn_prev": "⬅️ Anterior", "btn_next": "Siguiente ➡️",
        "marketplace_messages_title": "💬 Mensajes predefinidos del marketplace", "marketplace_messages_text": "Elige un preset abajo. Se enviará a todos los {target} activos.\nCualquier botón de respuesta que toquen volverá solo a ti.", "target_receivers": "receptores", "target_senders": "remitentes", "preset_private_only": "Usa los mensajes predefinidos solo en chat privado.", "no_presets": "No hay mensajes predefinidos disponibles para tu rol ahora mismo.", "preset_menu_wrong_user": "Este menú predefinido pertenece a otra cuenta.", "invalid_preset_button": "Botón predefinido inválido.", "preset_not_active": "Este mensaje predefinido ya no está activo.", "preset_not_for_role": "Este preset no está disponible para tu rol.", "no_active_recipients": "No se encontraron {role} activos ahora mismo.", "could_not_send_any": "No se pudo enviar a ningún {role} activo ahora mismo.", "sent_failed": "Enviado a {sent}. {failed} fallaron.", "sent_ok": "Enviado ✅", "already_answered_closed": "✅ Ya respondido.\nEste mensaje del marketplace está cerrado.", "invalid_reply_button": "Botón de respuesta inválido.", "reply_no_longer_available": "Esta respuesta predefinida ya no está disponible.", "reply_not_for_account": "Este botón de respuesta no es para tu cuenta.", "reply_mismatch": "Esta respuesta no coincide con el mensaje original.", "reply_not_for_role": "Esta respuesta no está disponible para tu rol.", "already_answered_other": "Ya respondió otra persona.", "marketplace_msg_unavailable": "Este mensaje del marketplace ya no está disponible.", "reply_saved_notify_failed": "Respuesta guardada, pero no se pudo notificar al remitente ahora mismo.", "reply_sent": "Respuesta enviada ✅",
        "receiver_earnings_title": "💰 *Ganancias del receptor*", "total_earned": "Total ganado", "paid": "Pagado", "requested": "Solicitado", "available_withdraw": "Disponible para retirar", "wallet_title": "👛 *Tu billetera*", "usdt_balance": "💵 Saldo USDT", "reserved": "🔒 Reservado", "available": "✅ Disponible", "only_active_senders_wallet": "Solo los remitentes activos pueden usar /wallet.", "only_active_senders_load": "Solo los remitentes activos pueden recargar la billetera.", "only_senders_load": "Solo los remitentes pueden recargar la billetera.", "loadwallet_hint": "Usa /loadwallet para recargar tu billetera.", "amount_gt_zero": "El monto debe ser mayor que 0.", "could_not_create_deposit": "No se pudo crear el depósito: {error}", "topup_no_methods": "👛 *Recargar billetera*\n\n⚠️ No hay métodos de pago de recarga configurados ahora mismo. Contacta con soporte.", "topup_choose": "👛 *Recargar billetera*\n\nElige cómo quieres añadir fondos:", "only_receivers_pending": "Solo los receptores tienen tareas QR pendientes.", "only_senders_status": "Solo los remitentes pueden usar esto."
    }
}

# Use Indonesian/Vietnamese/Chinese/Spanish translations above and fall back to English for unchanged keys.
for _code, _meta in SUPPORTED_LANGUAGES.items():
    _TRANSLATIONS.setdefault(_code, {})
    for _k, _v in _TRANSLATIONS["en"].items():
        _TRANSLATIONS[_code].setdefault(_k, _v)


_CANCEL_TRANSLATIONS: dict[str, dict[str, str]] = {
    "en": {
        "btn_cancel_open_order": "❌ Cancel Order",
        "cancel_order_wait": "This order can be canceled only after 2 minutes from submission, and only if no receiver has accepted it. Please try again in about {seconds} seconds.",
        "cancel_order_sender_only": "Only the QR sender can cancel this order.",
        "cancel_order_not_found": "QR order not found.",
        "cancel_order_already_accepted": "This order has already been accepted by a receiver, so it cannot be canceled.",
        "cancel_order_already_processed": "This QR is already marked {status}.",
        "cancel_order_expired": "This QR has already expired.",
        "cancel_order_done": "Order canceled. Reserved balance has been released.",
        "cancel_order_failed": "Could not cancel this order right now.",
        "cancel_order_status_line": "🚫 Order canceled by sender. Reserved balance has been released.",
        "offer_canceled_receiver_text": "🚫 Offer canceled by sender.\n🆔 Offer ID: {public_id}\nThis QR can no longer be accepted.",
        "claim_offer_canceled": "Offer canceled by sender.",
    },
    "id": {
        "btn_cancel_open_order": "❌ Batalkan Pesanan",
        "cancel_order_wait": "Pesanan ini hanya dapat dibatalkan setelah 2 menit sejak dikirim, dan hanya jika belum ada penerima yang menerimanya. Silakan coba lagi sekitar {seconds} detik.",
        "cancel_order_sender_only": "Hanya pengirim QR yang dapat membatalkan pesanan ini.",
        "cancel_order_not_found": "Pesanan QR tidak ditemukan.",
        "cancel_order_already_accepted": "Pesanan ini sudah diterima oleh penerima, jadi tidak dapat dibatalkan.",
        "cancel_order_already_processed": "QR ini sudah ditandai {status}.",
        "cancel_order_expired": "QR ini sudah kedaluwarsa.",
        "cancel_order_done": "Pesanan dibatalkan. Saldo yang direservasi telah dilepaskan.",
        "cancel_order_failed": "Tidak dapat membatalkan pesanan ini sekarang.",
        "cancel_order_status_line": "🚫 Pesanan dibatalkan oleh pengirim. Saldo yang direservasi telah dilepaskan.",
        "offer_canceled_receiver_text": "🚫 Penawaran dibatalkan oleh pengirim.\n🆔 ID Penawaran: {public_id}\nQR ini tidak dapat diterima lagi.",
        "claim_offer_canceled": "Penawaran dibatalkan oleh pengirim.",
    },
    "vi": {
        "btn_cancel_open_order": "❌ Hủy đơn",
        "cancel_order_wait": "Đơn này chỉ có thể được hủy sau 2 phút kể từ khi gửi, và chỉ khi chưa có người nhận nào chấp nhận. Vui lòng thử lại sau khoảng {seconds} giây.",
        "cancel_order_sender_only": "Chỉ người gửi QR mới có thể hủy đơn này.",
        "cancel_order_not_found": "Không tìm thấy đơn QR.",
        "cancel_order_already_accepted": "Đơn này đã được người nhận chấp nhận nên không thể hủy.",
        "cancel_order_already_processed": "QR này đã được đánh dấu {status}.",
        "cancel_order_expired": "QR này đã hết hạn.",
        "cancel_order_done": "Đã hủy đơn. Số dư đã giữ đã được giải phóng.",
        "cancel_order_failed": "Hiện không thể hủy đơn này.",
        "cancel_order_status_line": "🚫 Đơn đã được người gửi hủy. Số dư đã giữ đã được giải phóng.",
        "offer_canceled_receiver_text": "🚫 Ưu đãi đã bị người gửi hủy.\n🆔 ID ưu đãi: {public_id}\nQR này không thể được nhận nữa.",
        "claim_offer_canceled": "Ưu đãi đã bị người gửi hủy.",
    },
    "zh": {
        "btn_cancel_open_order": "❌ 取消订单",
        "cancel_order_wait": "此订单只能在提交 2 分钟后取消，并且前提是尚未被接收方接受。请约 {seconds} 秒后重试。",
        "cancel_order_sender_only": "只有 QR 发送方可以取消此订单。",
        "cancel_order_not_found": "未找到 QR 订单。",
        "cancel_order_already_accepted": "此订单已被接收方接受，因此不能取消。",
        "cancel_order_already_processed": "此 QR 已标记为 {status}。",
        "cancel_order_expired": "此 QR 已过期。",
        "cancel_order_done": "订单已取消。预留余额已释放。",
        "cancel_order_failed": "现在无法取消此订单。",
        "cancel_order_status_line": "🚫 订单已由发送方取消。预留余额已释放。",
        "offer_canceled_receiver_text": "🚫 报价已由发送方取消。\n🆔 报价 ID：{public_id}\n此 QR 不能再被接受。",
        "claim_offer_canceled": "报价已由发送方取消。",
    },
    "es": {
        "btn_cancel_open_order": "❌ Cancelar pedido",
        "cancel_order_wait": "Este pedido solo se puede cancelar 2 minutos después de enviarlo, y solo si ningún receptor lo ha aceptado. Inténtalo de nuevo en unos {seconds} segundos.",
        "cancel_order_sender_only": "Solo el remitente del QR puede cancelar este pedido.",
        "cancel_order_not_found": "Pedido QR no encontrado.",
        "cancel_order_already_accepted": "Este pedido ya fue aceptado por un receptor, por lo que no se puede cancelar.",
        "cancel_order_already_processed": "Este QR ya está marcado como {status}.",
        "cancel_order_expired": "Este QR ya venció.",
        "cancel_order_done": "Pedido cancelado. El saldo reservado se ha liberado.",
        "cancel_order_failed": "No se pudo cancelar este pedido ahora mismo.",
        "cancel_order_status_line": "🚫 Pedido cancelado por el remitente. El saldo reservado se ha liberado.",
        "offer_canceled_receiver_text": "🚫 Oferta cancelada por el remitente.\n🆔 ID de oferta: {public_id}\nEste QR ya no se puede aceptar.",
        "claim_offer_canceled": "Oferta cancelada por el remitente.",
    },
}
for _code, _items in _CANCEL_TRANSLATIONS.items():
    _TRANSLATIONS.setdefault(_code, {}).update(_items)
for _code in SUPPORTED_LANGUAGES:
    for _k, _v in _CANCEL_TRANSLATIONS["en"].items():
        _TRANSLATIONS[_code].setdefault(_k, _v)


_ADDITIONAL_USER_TRANSLATIONS: dict[str, dict[str, str]] = {
    "en": {
        "stats_sender_title": "Your sender stats",
        "stats_receiver_title": "Your receiver stats",
        "stats_today": "📅 Today — {date}",
        "stats_lifetime": "🏁 Lifetime",
        "stats_total": "Total",
        "stats_pending": "Pending",
        "stats_done": "Done",
        "stats_failed": "Failed",
        "caption_date": "Date",
        "caption_photo_today": "Photo #{daily_no} today",
        "caption_id": "ID",
        "caption_expires": "Expires",
        "caption_time_left": "Time left",
        "caption_reserved": "Reserved",
        "caption_status": "Status",
        "caption_updated": "Updated",
        "caption_reason": "Reason",
        "caption_sender_reserve_released": "Sender reserve released.",
        "btn_accept_scan": "✅ Accept Scan",
        "btn_done": "✅ Done",
        "btn_failed": "❌ Failed",
        "btn_notify_receiver": "🔔 Notify Receiver",
        "btn_open_pending_qr": "📥 Open pending QR",
        "btn_cancel": "⬅️ Cancel",
        "offer_new": "📥 New QR scan available",
        "offer_id": "Offer ID",
        "offer_tap_to_claim": "Tap Accept Scan to claim it. The QR will be sent only if you win the claim.",
        "sender_offer_created": "📡 Marketplace offer created.",
        "sender_offer_sent": "📡 Offer sent to online receiver(s)",
        "sender_offer_accepted": "⏳ Your QR offer was accepted. Waiting for receiver update.",
        "offer_failed_no_receiver": "❌ Offer failed. No online receiver could be notified. Reserved balance was released.",
        "receiver_qr_timer_hint": "Please mark Done or Failed before this QR expires.",
        "receiver_expiry_warning": "⚠️ This QR will expire in about {time_left}. Please mark Done or Failed before expiry.",
        "receiver_time_left_line": "⏳ Time left: {time_left}",
        "time_expired": "expired",
        "time_seconds": "{seconds}s",
        "time_minutes_seconds": "{minutes}m {seconds}s",
        "status_expired_caps": "EXPIRED",
        "status_expired_by_admin_caps": "EXPIRED BY ADMIN",
        "expired_offer_text": "⏱ Offer expired.\n🆔 Offer ID: {public_id}\nThis QR can no longer be accepted or completed.",
        "expired_caption_status_line": "⏱ Status: EXPIRED",
        "qr_marked_failed": "❌ QR marked failed",
        "select_failure_reason": "❌ Select failure reason.\n🆔 ID: {public_id}",
        "select_failure_reason_alert": "Select failure reason.",
        "marked_failed_alert": "Marked failed.",
        "fail_reason_qr_not_working": "❌ QR not working",
        "fail_reason_qr_expired": "⏱ QR expired",
        "fail_reason_limit_over": "🚫 My limit is over",
        "only_active_sender_photos": "Only an active registered sender can send QR photos.",
        "maintenance_paused": "🚧 Maintenance mode is ON. New QR submissions are paused by admin.",
        "no_receiver_online": "No receiver is online right now. Use /status to check capacity before sending.",
        "insufficient_wallet": "Insufficient wallet balance. Required per scan: ${required} USDT.\nAvailable: ${available} USDT.\n\nUse /wallet and /loadwallet to add balance.",
        "photo_rejected_clear_qr": "Photo rejected: {error}\n\nSend a clear photo containing exactly one readable QR code. Captions/text are ignored.",
        "photo_rejected_process": "Photo rejected: I could not process that QR image.",
        "clean_qr_send_failed": "I generated the clean QR, but could not save/send it back to you. Please try again.",
        "send_photo_not_document": "Please send the QR as a Telegram photo, not as a document. Photos are faster to process.",
        "auto_off_limit_zero": "🔴 Your scan limit reached zero, so you were set offline automatically. Use /on LIMIT to go online again.",
        "sender_notify_limit_zero": "🔴 A receiver reached their limit and is now offline. Use /status for current capacity.",
        "sender_reminder": "🔔 Sender reminder\n🆔 QR ID: {public_id}\n⏱ Expires: {expires}\n⏳ Time left: {time_left}\n\nPlease complete this pending QR or mark it failed.",
        "receiver_notified": "Receiver notified.",
        "qr_opened_below": "QR opened below.",
        "qr_expired_alert": "This QR has expired.",
    },
    "id": {
        "stats_sender_title": "Statistik pengirim Anda", "stats_receiver_title": "Statistik penerima Anda", "stats_today": "📅 Hari ini — {date}", "stats_lifetime": "🏁 Sepanjang waktu", "stats_total": "Total", "stats_pending": "Tertunda", "stats_done": "Selesai", "stats_failed": "Gagal",
        "caption_date": "Tanggal", "caption_photo_today": "Foto #{daily_no} hari ini", "caption_id": "ID", "caption_expires": "Kedaluwarsa", "caption_time_left": "Sisa waktu", "caption_reserved": "Direservasi", "caption_status": "Status", "caption_updated": "Diperbarui", "caption_reason": "Alasan", "caption_sender_reserve_released": "Saldo pengirim yang direservasi telah dilepaskan.",
        "btn_accept_scan": "✅ Terima Scan", "btn_done": "✅ Selesai", "btn_failed": "❌ Gagal", "btn_notify_receiver": "🔔 Beri tahu penerima", "btn_open_pending_qr": "📥 Buka QR tertunda", "btn_cancel": "⬅️ Batal",
        "offer_new": "📥 Scan QR baru tersedia", "offer_id": "ID Penawaran", "offer_tap_to_claim": "Ketuk Terima Scan untuk mengambilnya. QR hanya akan dikirim jika Anda berhasil mendapatkannya.",
        "sender_offer_created": "📡 Penawaran marketplace dibuat.", "sender_offer_sent": "📡 Penawaran dikirim ke penerima online", "sender_offer_accepted": "⏳ Penawaran QR Anda diterima. Menunggu pembaruan dari penerima.", "offer_failed_no_receiver": "❌ Penawaran gagal. Tidak ada penerima online yang dapat diberi tahu. Saldo yang direservasi telah dilepaskan.",
        "receiver_qr_timer_hint": "Harap tandai Selesai atau Gagal sebelum QR ini kedaluwarsa.", "receiver_expiry_warning": "⚠️ QR ini akan kedaluwarsa sekitar {time_left}. Harap tandai Selesai atau Gagal sebelum kedaluwarsa.", "receiver_time_left_line": "⏳ Sisa waktu: {time_left}",
        "time_expired": "kedaluwarsa", "time_seconds": "{seconds} dtk", "time_minutes_seconds": "{minutes} mnt {seconds} dtk", "status_expired_caps": "KEDALUWARSA", "status_expired_by_admin_caps": "DIKEDALUWARSAKAN ADMIN",
        "expired_offer_text": "⏱ Penawaran kedaluwarsa.\n🆔 ID Penawaran: {public_id}\nQR ini tidak dapat diterima atau diselesaikan lagi.", "expired_caption_status_line": "⏱ Status: KEDALUWARSA",
        "qr_marked_failed": "❌ QR ditandai gagal", "select_failure_reason": "❌ Pilih alasan kegagalan.\n🆔 ID: {public_id}", "select_failure_reason_alert": "Pilih alasan kegagalan.", "marked_failed_alert": "Ditandai gagal.",
        "fail_reason_qr_not_working": "❌ QR tidak berfungsi", "fail_reason_qr_expired": "⏱ QR kedaluwarsa", "fail_reason_limit_over": "🚫 Limit saya habis",
        "only_active_sender_photos": "Hanya pengirim terdaftar yang aktif yang dapat mengirim foto QR.", "maintenance_paused": "🚧 Mode pemeliharaan AKTIF. Pengiriman QR baru dijeda oleh admin.", "no_receiver_online": "Tidak ada penerima yang online saat ini. Gunakan /status untuk memeriksa kapasitas sebelum mengirim.",
        "insufficient_wallet": "Saldo wallet tidak cukup. Diperlukan per scan: ${required} USDT.\nTersedia: ${available} USDT.\n\nGunakan /wallet dan /loadwallet untuk menambah saldo.",
        "photo_rejected_clear_qr": "Foto ditolak: {error}\n\nKirim foto yang jelas berisi tepat satu kode QR yang dapat dibaca. Caption/teks diabaikan.", "photo_rejected_process": "Foto ditolak: saya tidak dapat memproses gambar QR tersebut.", "clean_qr_send_failed": "Saya sudah membuat QR bersih, tetapi tidak dapat menyimpan/mengirimkannya kepada Anda. Silakan coba lagi.", "send_photo_not_document": "Harap kirim QR sebagai foto Telegram, bukan sebagai dokumen. Foto lebih cepat diproses.",
        "auto_off_limit_zero": "🔴 Limit scan Anda mencapai nol, jadi Anda otomatis dibuat offline. Gunakan /on LIMIT untuk online lagi.", "sender_notify_limit_zero": "🔴 Seorang penerima mencapai limit dan sekarang offline. Gunakan /status untuk kapasitas saat ini.",
        "sender_reminder": "🔔 Pengingat dari pengirim\n🆔 ID QR: {public_id}\n⏱ Kedaluwarsa: {expires}\n⏳ Sisa waktu: {time_left}\n\nHarap selesaikan QR tertunda ini atau tandai gagal.", "receiver_notified": "Penerima diberi tahu.", "qr_opened_below": "QR dibuka di bawah.", "qr_expired_alert": "QR ini sudah kedaluwarsa.",
    },
    "vi": {
        "stats_sender_title": "Thống kê người gửi của bạn", "stats_receiver_title": "Thống kê người nhận của bạn", "stats_today": "📅 Hôm nay — {date}", "stats_lifetime": "🏁 Toàn thời gian", "stats_total": "Tổng", "stats_pending": "Đang chờ", "stats_done": "Hoàn tất", "stats_failed": "Thất bại",
        "caption_date": "Ngày", "caption_photo_today": "Ảnh #{daily_no} hôm nay", "caption_id": "ID", "caption_expires": "Hết hạn", "caption_time_left": "Thời gian còn lại", "caption_reserved": "Đã giữ", "caption_status": "Trạng thái", "caption_updated": "Đã cập nhật", "caption_reason": "Lý do", "caption_sender_reserve_released": "Số dư đã giữ của người gửi đã được giải phóng.",
        "btn_accept_scan": "✅ Nhận lượt quét", "btn_done": "✅ Hoàn tất", "btn_failed": "❌ Thất bại", "btn_notify_receiver": "🔔 Nhắc người nhận", "btn_open_pending_qr": "📥 Mở QR đang chờ", "btn_cancel": "⬅️ Hủy",
        "offer_new": "📥 Có QR mới để quét", "offer_id": "ID ưu đãi", "offer_tap_to_claim": "Nhấn Nhận lượt quét để nhận. QR chỉ được gửi nếu bạn nhận thành công.",
        "sender_offer_created": "📡 Đã tạo ưu đãi marketplace.", "sender_offer_sent": "📡 Ưu đãi đã gửi đến người nhận đang online", "sender_offer_accepted": "⏳ Ưu đãi QR của bạn đã được nhận. Đang chờ người nhận cập nhật.", "offer_failed_no_receiver": "❌ Ưu đãi thất bại. Không thể thông báo cho người nhận online nào. Số dư đã giữ đã được giải phóng.",
        "receiver_qr_timer_hint": "Vui lòng đánh dấu Hoàn tất hoặc Thất bại trước khi QR này hết hạn.", "receiver_expiry_warning": "⚠️ QR này sẽ hết hạn sau khoảng {time_left}. Vui lòng đánh dấu Hoàn tất hoặc Thất bại trước khi hết hạn.", "receiver_time_left_line": "⏳ Thời gian còn lại: {time_left}",
        "time_expired": "đã hết hạn", "time_seconds": "{seconds} giây", "time_minutes_seconds": "{minutes} phút {seconds} giây", "status_expired_caps": "ĐÃ HẾT HẠN", "status_expired_by_admin_caps": "ADMIN ĐÃ CHO HẾT HẠN",
        "expired_offer_text": "⏱ Ưu đãi đã hết hạn.\n🆔 ID ưu đãi: {public_id}\nQR này không thể được nhận hoặc hoàn tất nữa.", "expired_caption_status_line": "⏱ Trạng thái: ĐÃ HẾT HẠN",
        "qr_marked_failed": "❌ QR đã được đánh dấu thất bại", "select_failure_reason": "❌ Chọn lý do thất bại.\n🆔 ID: {public_id}", "select_failure_reason_alert": "Chọn lý do thất bại.", "marked_failed_alert": "Đã đánh dấu thất bại.",
        "fail_reason_qr_not_working": "❌ QR không hoạt động", "fail_reason_qr_expired": "⏱ QR đã hết hạn", "fail_reason_limit_over": "🚫 Tôi đã hết hạn mức",
        "only_active_sender_photos": "Chỉ người gửi đã đăng ký và đang hoạt động mới có thể gửi ảnh QR.", "maintenance_paused": "🚧 Chế độ bảo trì đang BẬT. Admin đã tạm dừng gửi QR mới.", "no_receiver_online": "Hiện không có người nhận nào online. Dùng /status để kiểm tra sức chứa trước khi gửi.",
        "insufficient_wallet": "Số dư ví không đủ. Cần cho mỗi lượt quét: ${required} USDT.\nKhả dụng: ${available} USDT.\n\nDùng /wallet và /loadwallet để nạp thêm.",
        "photo_rejected_clear_qr": "Ảnh bị từ chối: {error}\n\nGửi ảnh rõ ràng chứa đúng một mã QR có thể đọc được. Chú thích/văn bản sẽ bị bỏ qua.", "photo_rejected_process": "Ảnh bị từ chối: tôi không thể xử lý ảnh QR đó.", "clean_qr_send_failed": "Tôi đã tạo QR sạch nhưng không thể lưu/gửi lại cho bạn. Vui lòng thử lại.", "send_photo_not_document": "Vui lòng gửi QR dưới dạng ảnh Telegram, không phải tài liệu. Ảnh được xử lý nhanh hơn.",
        "auto_off_limit_zero": "🔴 Hạn mức quét của bạn đã về 0 nên bạn tự động chuyển offline. Dùng /on LIMIT để online lại.", "sender_notify_limit_zero": "🔴 Một người nhận đã hết hạn mức và hiện offline. Dùng /status để xem sức chứa hiện tại.",
        "sender_reminder": "🔔 Nhắc nhở từ người gửi\n🆔 ID QR: {public_id}\n⏱ Hết hạn: {expires}\n⏳ Thời gian còn lại: {time_left}\n\nVui lòng hoàn tất QR đang chờ này hoặc đánh dấu thất bại.", "receiver_notified": "Đã nhắc người nhận.", "qr_opened_below": "QR đã được mở bên dưới.", "qr_expired_alert": "QR này đã hết hạn.",
    },
    "zh": {
        "stats_sender_title": "您的发送方统计", "stats_receiver_title": "您的接收方统计", "stats_today": "📅 今日 — {date}", "stats_lifetime": "🏁 全部历史", "stats_total": "总计", "stats_pending": "待处理", "stats_done": "完成", "stats_failed": "失败",
        "caption_date": "日期", "caption_photo_today": "今日照片 #{daily_no}", "caption_id": "ID", "caption_expires": "有效期至", "caption_time_left": "剩余时间", "caption_reserved": "已预留", "caption_status": "状态", "caption_updated": "更新时间", "caption_reason": "原因", "caption_sender_reserve_released": "发送方预留余额已释放。",
        "btn_accept_scan": "✅ 接受扫描", "btn_done": "✅ 完成", "btn_failed": "❌ 失败", "btn_notify_receiver": "🔔 提醒接收方", "btn_open_pending_qr": "📥 打开待处理 QR", "btn_cancel": "⬅️ 取消",
        "offer_new": "📥 有新的 QR 扫描任务", "offer_id": "报价 ID", "offer_tap_to_claim": "点击“接受扫描”领取。只有抢单成功后才会发送 QR。",
        "sender_offer_created": "📡 Marketplace 报价已创建。", "sender_offer_sent": "📡 报价已发送给在线接收方", "sender_offer_accepted": "⏳ 您的 QR 报价已被接受，正在等待接收方更新。", "offer_failed_no_receiver": "❌ 报价失败。无法通知任何在线接收方。预留余额已释放。",
        "receiver_qr_timer_hint": "请在此 QR 过期前标记完成或失败。", "receiver_expiry_warning": "⚠️ 此 QR 大约将在 {time_left} 后过期。请在过期前标记完成或失败。", "receiver_time_left_line": "⏳ 剩余时间：{time_left}",
        "time_expired": "已过期", "time_seconds": "{seconds}秒", "time_minutes_seconds": "{minutes}分 {seconds}秒", "status_expired_caps": "已过期", "status_expired_by_admin_caps": "管理员已设为过期",
        "expired_offer_text": "⏱ 报价已过期。\n🆔 报价 ID：{public_id}\n此 QR 不能再被接受或完成。", "expired_caption_status_line": "⏱ 状态：已过期",
        "qr_marked_failed": "❌ QR 已标记为失败", "select_failure_reason": "❌ 请选择失败原因。\n🆔 ID：{public_id}", "select_failure_reason_alert": "请选择失败原因。", "marked_failed_alert": "已标记为失败。",
        "fail_reason_qr_not_working": "❌ QR 无法使用", "fail_reason_qr_expired": "⏱ QR 已过期", "fail_reason_limit_over": "🚫 我的额度已用完",
        "only_active_sender_photos": "只有已激活的注册发送方可以发送 QR 照片。", "maintenance_paused": "🚧 维护模式已开启。管理员已暂停新的 QR 提交。", "no_receiver_online": "当前没有接收方在线。发送前请使用 /status 查看容量。",
        "insufficient_wallet": "钱包余额不足。每次扫描需要：${required} USDT。\n可用：${available} USDT。\n\n请使用 /wallet 和 /loadwallet 充值。",
        "photo_rejected_clear_qr": "照片被拒绝：{error}\n\n请发送一张清晰照片，且只包含一个可读取的 QR 码。说明文字/文本会被忽略。", "photo_rejected_process": "照片被拒绝：我无法处理该 QR 图片。", "clean_qr_send_failed": "我已生成干净的 QR，但无法保存/发送给您。请重试。", "send_photo_not_document": "请将 QR 作为 Telegram 照片发送，不要作为文件发送。照片处理更快。",
        "auto_off_limit_zero": "🔴 您的扫描额度已归零，因此已自动下线。请使用 /on LIMIT 重新上线。", "sender_notify_limit_zero": "🔴 一位接收方额度已用完并已离线。请使用 /status 查看当前容量。",
        "sender_reminder": "🔔 发送方提醒\n🆔 QR ID：{public_id}\n⏱ 有效期至：{expires}\n⏳ 剩余时间：{time_left}\n\n请完成此待处理 QR，或将其标记为失败。", "receiver_notified": "已提醒接收方。", "qr_opened_below": "QR 已在下方打开。", "qr_expired_alert": "此 QR 已过期。",
    },
    "es": {
        "stats_sender_title": "Tus estadísticas como remitente", "stats_receiver_title": "Tus estadísticas como receptor", "stats_today": "📅 Hoy — {date}", "stats_lifetime": "🏁 Histórico", "stats_total": "Total", "stats_pending": "Pendiente", "stats_done": "Completado", "stats_failed": "Fallido",
        "caption_date": "Fecha", "caption_photo_today": "Foto #{daily_no} de hoy", "caption_id": "ID", "caption_expires": "Vence", "caption_time_left": "Tiempo restante", "caption_reserved": "Reservado", "caption_status": "Estado", "caption_updated": "Actualizado", "caption_reason": "Motivo", "caption_sender_reserve_released": "La reserva del remitente se ha liberado.",
        "btn_accept_scan": "✅ Aceptar escaneo", "btn_done": "✅ Completado", "btn_failed": "❌ Fallido", "btn_notify_receiver": "🔔 Notificar receptor", "btn_open_pending_qr": "📥 Abrir QR pendiente", "btn_cancel": "⬅️ Cancelar",
        "offer_new": "📥 Nuevo QR disponible para escanear", "offer_id": "ID de oferta", "offer_tap_to_claim": "Toca Aceptar escaneo para reclamarlo. El QR se enviará solo si ganas la asignación.",
        "sender_offer_created": "📡 Oferta creada en el marketplace.", "sender_offer_sent": "📡 Oferta enviada a receptores en línea", "sender_offer_accepted": "⏳ Tu oferta QR fue aceptada. Esperando actualización del receptor.", "offer_failed_no_receiver": "❌ La oferta falló. No se pudo notificar a ningún receptor en línea. El saldo reservado se liberó.",
        "receiver_qr_timer_hint": "Marca Completado o Fallido antes de que venza este QR.", "receiver_expiry_warning": "⚠️ Este QR vencerá en aproximadamente {time_left}. Marca Completado o Fallido antes del vencimiento.", "receiver_time_left_line": "⏳ Tiempo restante: {time_left}",
        "time_expired": "vencido", "time_seconds": "{seconds} s", "time_minutes_seconds": "{minutes} min {seconds} s", "status_expired_caps": "VENCIDO", "status_expired_by_admin_caps": "VENCIDO POR ADMIN",
        "expired_offer_text": "⏱ Oferta vencida.\n🆔 ID de oferta: {public_id}\nEste QR ya no se puede aceptar ni completar.", "expired_caption_status_line": "⏱ Estado: VENCIDO",
        "qr_marked_failed": "❌ QR marcado como fallido", "select_failure_reason": "❌ Selecciona el motivo del fallo.\n🆔 ID: {public_id}", "select_failure_reason_alert": "Selecciona el motivo del fallo.", "marked_failed_alert": "Marcado como fallido.",
        "fail_reason_qr_not_working": "❌ El QR no funciona", "fail_reason_qr_expired": "⏱ El QR venció", "fail_reason_limit_over": "🚫 Mi límite se agotó",
        "only_active_sender_photos": "Solo un remitente registrado y activo puede enviar fotos QR.", "maintenance_paused": "🚧 El modo de mantenimiento está ACTIVADO. El admin pausó los nuevos envíos de QR.", "no_receiver_online": "No hay ningún receptor en línea ahora. Usa /status para revisar la capacidad antes de enviar.",
        "insufficient_wallet": "Saldo insuficiente en la billetera. Requerido por escaneo: ${required} USDT.\nDisponible: ${available} USDT.\n\nUsa /wallet y /loadwallet para añadir saldo.",
        "photo_rejected_clear_qr": "Foto rechazada: {error}\n\nEnvía una foto clara que contenga exactamente un código QR legible. Los textos/captions se ignoran.", "photo_rejected_process": "Foto rechazada: no pude procesar esa imagen QR.", "clean_qr_send_failed": "Generé el QR limpio, pero no pude guardarlo/enviártelo. Inténtalo de nuevo.", "send_photo_not_document": "Envía el QR como foto de Telegram, no como documento. Las fotos se procesan más rápido.",
        "auto_off_limit_zero": "🔴 Tu límite de escaneos llegó a cero, así que fuiste puesto fuera de línea automáticamente. Usa /on LIMIT para volver a estar en línea.", "sender_notify_limit_zero": "🔴 Un receptor alcanzó su límite y ahora está fuera de línea. Usa /status para ver la capacidad actual.",
        "sender_reminder": "🔔 Recordatorio del remitente\n🆔 ID QR: {public_id}\n⏱ Vence: {expires}\n⏳ Tiempo restante: {time_left}\n\nCompleta este QR pendiente o márcalo como fallido.", "receiver_notified": "Receptor notificado.", "qr_opened_below": "QR abierto abajo.", "qr_expired_alert": "Este QR ya venció.",
    },
}
for _code, _items in _ADDITIONAL_USER_TRANSLATIONS.items():
    _TRANSLATIONS.setdefault(_code, {}).update(_items)
for _code in SUPPORTED_LANGUAGES:
    for _k, _v in _ADDITIONAL_USER_TRANSLATIONS["en"].items():
        _TRANSLATIONS[_code].setdefault(_k, _v)


_LIMIT_TRANSLATIONS: dict[str, dict[str, str]] = {
    "en": {
        "cmd_limit": "• /limit +5 or /limit -5 — add or reduce your current receiver scan limit",
        "limit_usage": "Usage: /limit +5 or /limit -5\nUse this to add or reduce your current receiver scan limit.",
        "only_active_receivers_limit": "Only active receivers can use /limit.",
        "limit_no_current": "You do not have an active receiver limit yet. Use /on LIMIT first, for example /on 25.",
        "limit_adjusted": "✅ Receiver limit updated.\nChange: {delta} scans\nCurrent remaining limit: {remaining} / {total} scans.",
        "limit_adjusted_offline": "✅ Receiver limit updated.\nChange: {delta} scans\nCurrent remaining limit is 0, so you are now offline. Use /on LIMIT to go online again.",
        "limit_delta_zero": "Limit change cannot be 0. Use /limit +5 or /limit -5.",
        "notify_receiver_limit_added": "🟢 Receiver limit added.\n➕ Limit added: {change} scans\n📊 Total limit now: {capacity} scans.\n\nUse /status to see total live capacity.",
        "notify_receiver_limit_reduced": "🟠 Receiver limit reduced.\n➖ Limit reduced: {change} scans\n📊 Total limit now: {capacity} scans.\n\nUse /status to see total live capacity.",
    },
    "id": {
        "cmd_limit": "• /limit +5 atau /limit -5 — tambah atau kurangi limit scan penerima saat ini",
        "limit_usage": "Penggunaan: /limit +5 atau /limit -5\nGunakan ini untuk menambah atau mengurangi limit scan penerima saat ini.",
        "only_active_receivers_limit": "Hanya penerima aktif yang dapat menggunakan /limit.",
        "limit_no_current": "Anda belum memiliki limit penerima yang aktif. Gunakan /on LIMIT terlebih dahulu, contoh /on 25.",
        "limit_adjusted": "✅ Limit penerima diperbarui.\nPerubahan: {delta} scan\nSisa limit saat ini: {remaining} / {total} scan.",
        "limit_adjusted_offline": "✅ Limit penerima diperbarui.\nPerubahan: {delta} scan\nSisa limit saat ini 0, jadi Anda sekarang offline. Gunakan /on LIMIT untuk online lagi.",
        "limit_delta_zero": "Perubahan limit tidak boleh 0. Gunakan /limit +5 atau /limit -5.",
        "notify_receiver_limit_added": "🟢 Limit penerima ditambahkan.\n➕ Limit ditambahkan: {change} scan\n📊 Total limit sekarang: {capacity} scan.\n\nGunakan /status untuk melihat total kapasitas aktif.",
        "notify_receiver_limit_reduced": "🟠 Limit penerima dikurangi.\n➖ Limit dikurangi: {change} scan\n📊 Total limit sekarang: {capacity} scan.\n\nGunakan /status untuk melihat total kapasitas aktif.",
    },
    "vi": {
        "cmd_limit": "• /limit +5 hoặc /limit -5 — tăng hoặc giảm hạn mức quét hiện tại của người nhận",
        "limit_usage": "Cách dùng: /limit +5 hoặc /limit -5\nDùng lệnh này để tăng hoặc giảm hạn mức quét hiện tại của người nhận.",
        "only_active_receivers_limit": "Chỉ người nhận đang hoạt động mới có thể dùng /limit.",
        "limit_no_current": "Bạn chưa có hạn mức người nhận đang hoạt động. Hãy dùng /on LIMIT trước, ví dụ /on 25.",
        "limit_adjusted": "✅ Hạn mức người nhận đã được cập nhật.\nThay đổi: {delta} lượt quét\nHạn mức còn lại hiện tại: {remaining} / {total} lượt quét.",
        "limit_adjusted_offline": "✅ Hạn mức người nhận đã được cập nhật.\nThay đổi: {delta} lượt quét\nHạn mức còn lại hiện tại là 0, nên bạn hiện đang offline. Dùng /on LIMIT để online lại.",
        "limit_delta_zero": "Mức thay đổi không được là 0. Dùng /limit +5 hoặc /limit -5.",
        "notify_receiver_limit_added": "🟢 Hạn mức người nhận đã được tăng.\n➕ Đã tăng hạn mức: {change} lượt quét\n📊 Tổng hạn mức hiện tại: {capacity} lượt quét.\n\nDùng /status để xem tổng sức chứa đang hoạt động.",
        "notify_receiver_limit_reduced": "🟠 Hạn mức người nhận đã được giảm.\n➖ Đã giảm hạn mức: {change} lượt quét\n📊 Tổng hạn mức hiện tại: {capacity} lượt quét.\n\nDùng /status để xem tổng sức chứa đang hoạt động.",
    },
    "zh": {
        "cmd_limit": "• /limit +5 或 /limit -5 — 增加或减少当前接收方扫描额度",
        "limit_usage": "用法：/limit +5 或 /limit -5\n使用此命令增加或减少您当前的接收方扫描额度。",
        "only_active_receivers_limit": "只有活跃接收方可以使用 /limit。",
        "limit_no_current": "您还没有有效的接收方额度。请先使用 /on LIMIT，例如 /on 25。",
        "limit_adjusted": "✅ 接收方额度已更新。\n变化：{delta} 次扫描\n当前剩余额度：{remaining} / {total} 次扫描。",
        "limit_adjusted_offline": "✅ 接收方额度已更新。\n变化：{delta} 次扫描\n当前剩余额度为 0，因此您现在已下线。请使用 /on LIMIT 重新上线。",
        "limit_delta_zero": "额度变化不能为 0。请使用 /limit +5 或 /limit -5。",
        "notify_receiver_limit_added": "🟢 接收方额度已增加。\n➕ 已增加额度：{change} 次扫描\n📊 当前总额度：{capacity} 次扫描。\n\n使用 /status 查看总实时容量。",
        "notify_receiver_limit_reduced": "🟠 接收方额度已减少。\n➖ 已减少额度：{change} 次扫描\n📊 当前总额度：{capacity} 次扫描。\n\n使用 /status 查看总实时容量。",
    },
    "es": {
        "cmd_limit": "• /limit +5 o /limit -5 — añadir o reducir tu límite actual de escaneos como receptor",
        "limit_usage": "Uso: /limit +5 o /limit -5\nUsa esto para añadir o reducir tu límite actual de escaneos como receptor.",
        "only_active_receivers_limit": "Solo los receptores activos pueden usar /limit.",
        "limit_no_current": "Aún no tienes un límite de receptor activo. Usa /on LIMIT primero, por ejemplo /on 25.",
        "limit_adjusted": "✅ Límite de receptor actualizado.\nCambio: {delta} escaneos\nLímite restante actual: {remaining} / {total} escaneos.",
        "limit_adjusted_offline": "✅ Límite de receptor actualizado.\nCambio: {delta} escaneos\nEl límite restante actual es 0, así que ahora estás fuera de línea. Usa /on LIMIT para volver a estar en línea.",
        "limit_delta_zero": "El cambio de límite no puede ser 0. Usa /limit +5 o /limit -5.",
        "notify_receiver_limit_added": "🟢 Límite de receptor añadido.\n➕ Límite añadido: {change} escaneos\n📊 Límite total ahora: {capacity} escaneos.\n\nUsa /status para ver la capacidad total en vivo.",
        "notify_receiver_limit_reduced": "🟠 Límite de receptor reducido.\n➖ Límite reducido: {change} escaneos\n📊 Límite total ahora: {capacity} escaneos.\n\nUsa /status para ver la capacidad total en vivo.",
    },
}
for _code, _items in _LIMIT_TRANSLATIONS.items():
    _TRANSLATIONS.setdefault(_code, {}).update(_items)
for _code in SUPPORTED_LANGUAGES:
    for _k, _v in _LIMIT_TRANSLATIONS["en"].items():
        _TRANSLATIONS[_code].setdefault(_k, _v)



_USER_TEXT_AUDIT_TRANSLATIONS: dict[str, dict[str, str]] = {
    "en": {
        "marketplace_status_title": "📡 Marketplace status",
        "marketplace_online_receivers": "🟢 Online receivers: {count}",
        "marketplace_capacity": "📊 Current scan capacity: {capacity}",
        "marketplace_qr_expiry": "⏱ QR expiry: {minutes} minutes",
        "marketplace_maintenance_on": "🚧 Maintenance mode is ON. New QR submissions are paused.",
        "marketplace_your_available_balance": "💼 Your available balance: ${amount} USDT",
        "marketplace_estimated_scans": "🧾 Estimated scans available: {scans}",
        "marketplace_receiver_online_status": "Your receiver status: 🟢 online, {remaining} / {total} scans left.",
        "marketplace_receiver_offline_status": "Your receiver status: 🔴 offline. Use /on LIMIT to go online.",
        "wallet_history_title": "👛 Wallet History — Page {page}/{total_pages}",
        "wallet_history_showing": "Showing wallet top-ups and admin balance updates, newest first.",
        "wallet_history_empty": "No wallet history yet.",
        "wallet_topup_id": "Wallet Top-up ID",
        "payment_method_label": "Payment Method",
        "amount_label": "Amount",
        "related_id_label": "Related ID",
        "btn_topup_again": "➕ Top-up Again",
        "payment_status_completed": "✅ Completed",
        "payment_status_expired": "❌ Expired",
        "payment_status_rejected": "❌ Rejected",
        "payment_status_review": "📝 Submitted for review",
        "payment_status_pending": "⏳ Pending",
        "wallet_label_admin_add": "Admin Wallet Add",
        "wallet_label_admin_remove": "Admin Wallet Remove",
        "wallet_method_admin_add": "Admin wallet add",
        "wallet_method_admin_remove": "Admin wallet remove",
        "topup_enter_amount": "💰 Enter the amount you want to top up in *$ (USDT)*.",
        "topup_payment_method": "Payment method: *{method}*",
        "topup_minimum": "_(Minimum: ${amount})_",
        "press_back_abort": "Press Back to abort.",
        "btn_check_payment": "🔄 Check Payment",
        "btn_manual_verify": "✍️ Manual Verify",
        "manual_verify_unlocked": "Manual Verify is unlocked now.",
        "manual_verify_unlocks": "Manual Verify unlocks in about {minutes} minute(s).",
        "wallet_topup_expired": "⏰ *Wallet Top-up Expired*\n\nWallet Top-up ID: `{ref_id}`\nThe payment was not completed within *{minutes} minutes*.\n\nPlease start a new wallet top-up.",
        "wallet_topup_still_pending": "⌛ Wallet Top-up Still Pending\n\nWallet Top-up ID: `{ref_id}`\n\nYour payment is still pending. It will expire in about *{minutes} minutes* if payment is not completed.\n\nIf you already paid, use the payment buttons in the original message or contact support.",
        "wallet_topup_completed": "✅ Wallet Top-up Completed!\n\n💰 ${amount} USDT added to your wallet.\n👛 Current USDT Balance: ${balance}\n\nUse /wallet to check your balance.",
        "wallet_topup_rejected": "❌ Your payment could not be verified. Please contact support if you believe this is a mistake.",
        "admin_wallet_added": "✅ Wallet balance added by admin.\nAdded: ${amount} USDT\nNew USDT balance: ${balance} USDT\nUse /wallet to check your balance.",
        "admin_wallet_removed": "⚠️ Wallet balance adjusted by admin.\nRemoved: ${amount} USDT\nNew USDT balance: ${balance} USDT\nUse /wallet to check your balance.",
        "payment_title_bep20": "🟡 *USDT (BEP20) Payment*",
        "payment_title_polygon": "🟣 *USDT (POLYGON) Payment*",
        "payment_title_binance": "🟡 *Binance Pay*",
        "network_polygon": "🌐 Network: *Polygon PoS*",
        "network_binance": "🌐 Network: *Binance Pay*",
        "network_bep20": "🌐 Network: *BNB Smart Chain (BEP20)*",
        "network_confirm_after": "✅ Payment will be confirmed after *{confirmations} network confirmations*.",
        "payment_binance_details": "🆔 Binance Pay ID: `{pay_to}`\n👤 Name: {name}\n\n*Steps:*\n1️⃣ Open Binance app → Pay → Send\n2️⃣ Search Pay ID: `{pay_to}`\n3️⃣ Send exactly the unique USDT amount above\n\n⚠️ Do not round the amount. The unique decimals identify your wallet top-up automatically.\n🌐 Network: *Binance Pay*\n",
        "payment_wallet_details": "To this wallet:\n`{pay_to}`\n\n⚠️ Send the exact amount shown above. The final USDT received must be exact; do not let exchange/network fees reduce this amount.\n{network_line}\n",
        "payment_template": "{title}\n\n📋 Wallet Top-up ID `{ref_id}` | ${amount} USDT\n\nSend this amount:\n```\n{expected} USDT\n```\n{details}\n⏳ Time left: *{{TIME_LEFT}}*\n🔄 Bot checks automatically every {interval_seconds} seconds until this top-up is credited or expired.\n🧾 If you already paid and it is not verified, tap *Manual Verify* below.",
        "payment_not_found": "Payment session not found.",
        "payment_not_yours": "This payment session is not yours.",
        "payment_screenshot_first": "Please send the screenshot proof first.",
        "topup_already_completed": "✅ Wallet top-up already completed.",
        "topup_processed_or_expired": "⚠️ This payment session is already processed or expired.",
        "checking_binance_history": "Checking Binance Pay history...",
        "checking_payment": "🔄 Checking payment...",
        "manual_hash_prompt": "✍️ Please send your USDT transaction hash / TxID for this wallet top-up.",
        "select_failure_buttons_only": "Please select one of the failure reason buttons.",
        "send_screenshot_not_text": "📸 Please send a screenshot/photo proof, not text.",
        "payment_session_gone": "Payment session not found anymore.",
        "invalid_tx_hash": "❌ Please send a valid USDT transaction hash / TxID. It should look like `0x...` or a valid exchange transaction ID.",
        "checking_tx_hash": "🔎 Checking transaction hash...",
        "txhash_admin_review": "📸 Please send a screenshot proof of this USDT payment.\n\nYour TxHash needs admin review before this wallet top-up can be approved.",
        "txhash_already_used": "❌ This transaction hash has already been used for a wallet top-up.\n\nPlease submit a different, unused USDT transaction hash.",
        "txhash_incorrect": "❌ The transaction hash you submitted is incorrect.\n\nPlease send the correct USDT transaction hash / TxID for this wallet top-up.",
        "screenshot_proof_next": "📸 Now send a screenshot proof of this USDT payment.\n\nIf the TxHash could not be auto-verified, support will review the proof.",
        "enter_valid_number": "❌ Enter a valid number.",
        "minimum_topup_amount": "❌ Minimum top-up amount is ${amount}.",
        "send_screenshot_proof": "📸 Please send a screenshot/photo proof.",
        "txhash_used_other": "❌ This transaction hash has already been used for another wallet top-up.",
        "manual_verification_submitted": "⏳ Manual verification submitted for admin review.\nReference: {ref_id}",
        "only_active_receivers_earnings": "Only active receivers can use /earnings.",
        "only_active_receivers_payout": "Only active receivers can request payout.",
        "withdraw_prompt": "💸 Withdraw\nAvailable: ${available} USDT\nMinimum: ${minimum} USDT\n\nSend quantity.",
        "withdraw_no_available": "💸 Withdraw\nAvailable: ${available} USDT\nMinimum: ${minimum} USDT",
        "send_payment_details": "💳 Send payment details.",
        "payment_details_question": "💳 Payment details?\nQuantity: ${amount} USDT",
        "btn_enter_new_payment_details": "✏️ Enter new payment details",
        "payment_details_saved": "✅ Payment details saved.",
        "send_valid_quantity": "Send a valid quantity.",
        "minimum_payout": "Minimum payout is ${amount} USDT.",
        "withdraw_available_due": "Available: ${available} USDT\nDue: ${due} USDT · Requested: ${requested} USDT",
        "withdraw_submitted": "✅ Withdrawal request #{payout_id} submitted for ${amount} USDT.",
        "payout_done": "✅ Payout done.\nAmount: ${amount} USDT\n\nYour earnings balance has been updated. Use /earnings to view it.",
        "payout_rejected": "❌ Your payout request was rejected.\nAmount: ${amount} USDT\n\nThe amount is available again in /earnings.",
        "dispute_open": "⚠️ *Open dispute*\n{qr_line}\n\nPlease send the reason for this dispute now.",
        "dispute_cancelled": "Dispute cancelled.",
        "dispute_reason_clear": "Please send a clear reason for the dispute.",
        "dispute_submitted": "✅ Dispute #{ref_id} submitted. Admin will review it soon.",
        "dispute_not_found": "Dispute not found.",
        "dispute_not_yours": "This dispute is not yours.",
        "dispute_closed": "This dispute is already closed.",
        "dispute_reply_prompt": "💬 Reply to dispute #{ref}\n\nSend your message now.",
        "dispute_reply_cancelled": "Dispute reply cancelled.",
        "dispute_reply_clear": "Please send a clear reply.",
        "dispute_reply_added": "✅ Reply added to dispute #{ref}.",
        "dispute_reply_usage": "Use: /disputereply DISPUTE_ID your message",
        "dispute_reply_send_now": "💬 Send your reply for dispute #{ref} now.",
        "could_not_start_dispute": "Could not start that dispute.",
        "qr_id_not_found": "I could not find that QR ID.",
        "qr_not_linked_sender": "That QR ID is not linked to your sender account.",
        "qr_not_linked_receiver": "That QR ID is not linked to your receiver account.",
        "invalid_failure_reason": "Invalid failure reason.",
        "invalid_offer_button": "Invalid offer button.",
        "offer_claimed": "✅ You got this QR",
        "claim_saved_delivery_failed": "Claim saved, but QR delivery failed. Ask admin to review.",
        "invalid_notify_button": "Invalid notify button.",
        "qr_not_found": "QR not found.",
        "only_sender_notify_receiver": "Only the QR sender can notify the receiver.",
        "qr_already_marked": "This QR is already marked {status}.",
        "no_receiver_accepted": "No receiver has accepted this QR yet.",
        "notify_receiver_failed": "Could not notify the receiver right now.",
        "invalid_qr_button": "Invalid QR button.",
        "only_receivers_open_pending": "Only active receivers can open pending QRs.",
        "qr_not_found_for_account": "QR not found for your account.",
        "qr_no_longer_pending": "This QR is no longer pending.",
        "qr_open_failed": "Could not open that QR right now.",
        "invalid_button": "Invalid button.",
        "invalid_action": "Invalid action.",
        "qr_not_found_generic": "I could not find that QR.",
        "maintenance_on_alert": "Bot is under maintenance.",
        "document_reject": "Please send the QR as a Telegram photo, not as a document. Photos are faster to process.",
    },
    "id": {
        "marketplace_status_title": "📡 Status marketplace", "marketplace_online_receivers": "🟢 Penerima online: {count}", "marketplace_capacity": "📊 Kapasitas scan saat ini: {capacity}", "marketplace_qr_expiry": "⏱ Kedaluwarsa QR: {minutes} menit", "marketplace_maintenance_on": "🚧 Mode pemeliharaan AKTIF. Pengiriman QR baru dijeda.", "marketplace_your_available_balance": "💼 Saldo tersedia Anda: ${amount} USDT", "marketplace_estimated_scans": "🧾 Perkiraan scan tersedia: {scans}", "marketplace_receiver_online_status": "Status penerima Anda: 🟢 online, sisa {remaining} / {total} scan.", "marketplace_receiver_offline_status": "Status penerima Anda: 🔴 offline. Gunakan /on LIMIT untuk online.",
        "wallet_history_title": "👛 Riwayat Wallet — Halaman {page}/{total_pages}", "wallet_history_showing": "Menampilkan top-up wallet dan pembaruan saldo oleh admin, terbaru lebih dulu.", "wallet_history_empty": "Belum ada riwayat wallet.", "wallet_topup_id": "ID Top-up Wallet", "payment_method_label": "Metode Pembayaran", "amount_label": "Jumlah", "related_id_label": "ID Terkait", "btn_topup_again": "➕ Top-up Lagi", "payment_status_completed": "✅ Selesai", "payment_status_expired": "❌ Kedaluwarsa", "payment_status_rejected": "❌ Ditolak", "payment_status_review": "📝 Dikirim untuk ditinjau", "payment_status_pending": "⏳ Tertunda", "wallet_label_admin_add": "Admin Menambah Wallet", "wallet_label_admin_remove": "Admin Mengurangi Wallet", "wallet_method_admin_add": "Penambahan wallet admin", "wallet_method_admin_remove": "Pengurangan wallet admin",
        "topup_enter_amount": "💰 Masukkan jumlah yang ingin Anda top-up dalam *$ (USDT)*.", "topup_payment_method": "Metode pembayaran: *{method}*", "topup_minimum": "_(Minimum: ${amount})_", "press_back_abort": "Tekan Kembali untuk membatalkan.", "btn_check_payment": "🔄 Cek Pembayaran", "btn_manual_verify": "✍️ Verifikasi Manual", "manual_verify_unlocked": "Verifikasi Manual sudah terbuka sekarang.", "manual_verify_unlocks": "Verifikasi Manual terbuka sekitar {minutes} menit lagi.",
        "wallet_topup_expired": "⏰ *Top-up Wallet Kedaluwarsa*\n\nID Top-up Wallet: `{ref_id}`\nPembayaran tidak selesai dalam *{minutes} menit*.\n\nSilakan mulai top-up wallet baru.", "wallet_topup_still_pending": "⌛ Top-up Wallet Masih Tertunda\n\nID Top-up Wallet: `{ref_id}`\n\nPembayaran Anda masih tertunda. Ini akan kedaluwarsa sekitar *{minutes} menit* jika pembayaran belum selesai.\n\nJika Anda sudah membayar, gunakan tombol pembayaran pada pesan asli atau hubungi dukungan.", "wallet_topup_completed": "✅ Top-up Wallet Selesai!\n\n💰 ${amount} USDT ditambahkan ke wallet Anda.\n👛 Saldo USDT Saat Ini: ${balance}\n\nGunakan /wallet untuk memeriksa saldo.", "wallet_topup_rejected": "❌ Pembayaran Anda tidak dapat diverifikasi. Hubungi dukungan jika menurut Anda ini kesalahan.", "admin_wallet_added": "✅ Saldo wallet ditambahkan oleh admin.\nDitambahkan: ${amount} USDT\nSaldo USDT baru: ${balance} USDT\nGunakan /wallet untuk memeriksa saldo.", "admin_wallet_removed": "⚠️ Saldo wallet disesuaikan oleh admin.\nDikurangi: ${amount} USDT\nSaldo USDT baru: ${balance} USDT\nGunakan /wallet untuk memeriksa saldo.",
        "payment_title_bep20": "🟡 *Pembayaran USDT (BEP20)*", "payment_title_polygon": "🟣 *Pembayaran USDT (POLYGON)*", "payment_title_binance": "🟡 *Binance Pay*", "network_polygon": "🌐 Jaringan: *Polygon PoS*", "network_binance": "🌐 Jaringan: *Binance Pay*", "network_bep20": "🌐 Jaringan: *BNB Smart Chain (BEP20)*", "network_confirm_after": "✅ Pembayaran akan dikonfirmasi setelah *{confirmations} konfirmasi jaringan*.",
        "payment_binance_details": "🆔 Binance Pay ID: `{pay_to}`\n👤 Nama: {name}\n\n*Langkah:*\n1️⃣ Buka aplikasi Binance → Pay → Send\n2️⃣ Cari Pay ID: `{pay_to}`\n3️⃣ Kirim jumlah USDT unik persis seperti di atas\n\n⚠️ Jangan membulatkan jumlah. Desimal unik tersebut mengidentifikasi top-up wallet Anda secara otomatis.\n🌐 Jaringan: *Binance Pay*\n", "payment_wallet_details": "Ke wallet ini:\n`{pay_to}`\n\n⚠️ Kirim jumlah persis seperti yang ditampilkan. USDT akhir yang diterima harus persis; jangan biarkan biaya exchange/jaringan mengurangi jumlah ini.\n{network_line}\n", "payment_template": "{title}\n\n📋 ID Top-up Wallet `{ref_id}` | ${amount} USDT\n\nKirim jumlah ini:\n```\n{expected} USDT\n```\n{details}\n⏳ Sisa waktu: *{{TIME_LEFT}}*\n🔄 Bot memeriksa otomatis setiap {interval_seconds} detik sampai top-up ini dikreditkan atau kedaluwarsa.\n🧾 Jika Anda sudah membayar dan belum terverifikasi, ketuk *Verifikasi Manual* di bawah.",
        "payment_not_found": "Sesi pembayaran tidak ditemukan.", "payment_not_yours": "Sesi pembayaran ini bukan milik Anda.", "payment_screenshot_first": "Harap kirim bukti screenshot terlebih dahulu.", "topup_already_completed": "✅ Top-up wallet sudah selesai.", "topup_processed_or_expired": "⚠️ Sesi pembayaran ini sudah diproses atau kedaluwarsa.", "checking_binance_history": "Memeriksa riwayat Binance Pay...", "checking_payment": "🔄 Memeriksa pembayaran...", "manual_hash_prompt": "🔍 *Verifikasi USDT Manual*\n\nHarap kirim *hash transaksi USDT / TxID* terlebih dahulu.\nSetelah itu, Anda akan diminta mengirim bukti screenshot.", "select_failure_buttons_only": "Harap pilih salah satu tombol alasan kegagalan.", "send_screenshot_not_text": "📸 Harap kirim screenshot/foto bukti, bukan teks.", "payment_session_gone": "Sesi pembayaran tidak ditemukan lagi.", "invalid_tx_hash": "❌ Harap kirim hash transaksi USDT / TxID yang valid. Seharusnya terlihat seperti `0x...` atau ID transaksi exchange yang valid.", "checking_tx_hash": "🔎 Memeriksa hash transaksi...", "txhash_admin_review": "📸 Harap kirim bukti screenshot pembayaran USDT ini.\n\nTxHash Anda perlu ditinjau admin sebelum top-up wallet ini dapat disetujui.", "txhash_already_used": "❌ Hash transaksi ini sudah digunakan untuk top-up wallet.\n\nHarap kirim hash transaksi USDT lain yang belum digunakan.", "txhash_incorrect": "❌ Hash transaksi yang Anda kirim tidak benar.\n\nHarap kirim hash transaksi USDT / TxID yang benar untuk top-up wallet ini.", "screenshot_proof_next": "📸 Sekarang kirim bukti screenshot pembayaran USDT ini.\n\nJika TxHash tidak dapat diverifikasi otomatis, dukungan akan meninjau buktinya.", "enter_valid_number": "❌ Masukkan angka yang valid.", "minimum_topup_amount": "❌ Jumlah top-up minimum adalah ${amount}.", "send_screenshot_proof": "📸 Harap kirim screenshot/foto bukti.", "txhash_used_other": "❌ Hash transaksi ini sudah digunakan untuk top-up wallet lain.", "manual_verification_submitted": "⏳ Verifikasi manual dikirim untuk ditinjau admin.\nReferensi: {ref_id}",
        "only_active_receivers_earnings": "Hanya penerima aktif yang dapat menggunakan /earnings.", "only_active_receivers_payout": "Hanya penerima aktif yang dapat meminta payout.", "withdraw_prompt": "💸 Withdraw\nTersedia: ${available} USDT\nMinimum: ${minimum} USDT\n\nKirim jumlah.", "withdraw_no_available": "💸 Withdraw\nTersedia: ${available} USDT\nMinimum: ${minimum} USDT", "send_payment_details": "💳 Kirim detail pembayaran.", "payment_details_question": "💳 Detail pembayaran?\nJumlah: ${amount} USDT", "btn_enter_new_payment_details": "✏️ Masukkan detail pembayaran baru", "payment_details_saved": "✅ Detail pembayaran disimpan.", "send_valid_quantity": "Kirim jumlah yang valid.", "minimum_payout": "Payout minimum adalah ${amount} USDT.", "withdraw_available_due": "Tersedia: ${available} USDT\nJatuh tempo: ${due} USDT · Diminta: ${requested} USDT", "withdraw_submitted": "✅ Permintaan withdraw #{payout_id} diajukan untuk ${amount} USDT.", "payout_done": "✅ Payout selesai.\nJumlah: ${amount} USDT\n\nSaldo earnings Anda telah diperbarui. Gunakan /earnings untuk melihatnya.", "payout_rejected": "❌ Permintaan payout Anda ditolak.\nJumlah: ${amount} USDT\n\nJumlah tersebut tersedia kembali di /earnings.",
        "dispute_open": "⚠️ *Buka sengketa*\n{qr_line}\n\nHarap kirim alasan sengketa ini sekarang.", "dispute_cancelled": "Sengketa dibatalkan.", "dispute_reason_clear": "Harap kirim alasan sengketa yang jelas.", "dispute_submitted": "✅ Sengketa #{ref_id} dikirim. Admin akan segera meninjaunya.", "dispute_not_found": "Sengketa tidak ditemukan.", "dispute_not_yours": "Sengketa ini bukan milik Anda.", "dispute_closed": "Sengketa ini sudah ditutup.", "dispute_reply_prompt": "💬 Balas sengketa #{ref}\n\nKirim pesan Anda sekarang.", "dispute_reply_cancelled": "Balasan sengketa dibatalkan.", "dispute_reply_clear": "Harap kirim balasan yang jelas.", "dispute_reply_added": "✅ Balasan ditambahkan ke sengketa #{ref}.", "dispute_reply_usage": "Gunakan: /disputereply DISPUTE_ID pesan Anda", "dispute_reply_send_now": "💬 Kirim balasan Anda untuk sengketa #{ref} sekarang.", "could_not_start_dispute": "Tidak dapat memulai sengketa tersebut.", "qr_id_not_found": "Saya tidak dapat menemukan ID QR tersebut.", "qr_not_linked_sender": "ID QR tersebut tidak terhubung ke akun pengirim Anda.", "qr_not_linked_receiver": "ID QR tersebut tidak terhubung ke akun penerima Anda.",
        "invalid_failure_reason": "Alasan kegagalan tidak valid.", "invalid_offer_button": "Tombol penawaran tidak valid.", "offer_claimed": "✅ Anda mendapatkan QR ini", "claim_saved_delivery_failed": "Claim disimpan, tetapi pengiriman QR gagal. Minta admin meninjau.", "invalid_notify_button": "Tombol notifikasi tidak valid.", "qr_not_found": "QR tidak ditemukan.", "only_sender_notify_receiver": "Hanya pengirim QR yang dapat memberi tahu penerima.", "qr_already_marked": "QR ini sudah ditandai {status}.", "no_receiver_accepted": "Belum ada penerima yang menerima QR ini.", "notify_receiver_failed": "Tidak dapat memberi tahu penerima saat ini.", "invalid_qr_button": "Tombol QR tidak valid.", "only_receivers_open_pending": "Hanya penerima aktif yang dapat membuka QR tertunda.", "qr_not_found_for_account": "QR tidak ditemukan untuk akun Anda.", "qr_no_longer_pending": "QR ini tidak lagi tertunda.", "qr_open_failed": "Tidak dapat membuka QR tersebut saat ini.", "invalid_button": "Tombol tidak valid.", "invalid_action": "Aksi tidak valid.", "qr_not_found_generic": "Saya tidak dapat menemukan QR tersebut.", "maintenance_on_alert": "Bot sedang dalam pemeliharaan.", "document_reject": "Harap kirim QR sebagai foto Telegram, bukan sebagai dokumen. Foto lebih cepat diproses.",
    },
    "vi": {
        "marketplace_status_title": "📡 Trạng thái marketplace", "marketplace_online_receivers": "🟢 Người nhận online: {count}", "marketplace_capacity": "📊 Sức chứa quét hiện tại: {capacity}", "marketplace_qr_expiry": "⏱ QR hết hạn: {minutes} phút", "marketplace_maintenance_on": "🚧 Chế độ bảo trì đang BẬT. Tạm dừng gửi QR mới.", "marketplace_your_available_balance": "💼 Số dư khả dụng của bạn: ${amount} USDT", "marketplace_estimated_scans": "🧾 Số lượt quét ước tính còn dùng được: {scans}", "marketplace_receiver_online_status": "Trạng thái người nhận của bạn: 🟢 online, còn {remaining} / {total} lượt quét.", "marketplace_receiver_offline_status": "Trạng thái người nhận của bạn: 🔴 offline. Dùng /on LIMIT để online.",
        "wallet_history_title": "👛 Lịch sử ví — Trang {page}/{total_pages}", "wallet_history_showing": "Hiển thị nạp ví và cập nhật số dư từ admin, mới nhất trước.", "wallet_history_empty": "Chưa có lịch sử ví.", "wallet_topup_id": "ID nạp ví", "payment_method_label": "Phương thức thanh toán", "amount_label": "Số tiền", "related_id_label": "ID liên quan", "btn_topup_again": "➕ Nạp lại", "payment_status_completed": "✅ Hoàn tất", "payment_status_expired": "❌ Hết hạn", "payment_status_rejected": "❌ Bị từ chối", "payment_status_review": "📝 Đã gửi để xét duyệt", "payment_status_pending": "⏳ Đang chờ", "wallet_label_admin_add": "Admin cộng ví", "wallet_label_admin_remove": "Admin trừ ví", "wallet_method_admin_add": "Admin cộng ví", "wallet_method_admin_remove": "Admin trừ ví",
        "topup_enter_amount": "💰 Nhập số tiền bạn muốn nạp bằng *$ (USDT)*.", "topup_payment_method": "Phương thức thanh toán: *{method}*", "topup_minimum": "_(Tối thiểu: ${amount})_", "press_back_abort": "Nhấn Quay lại để hủy.", "btn_check_payment": "🔄 Kiểm tra thanh toán", "btn_manual_verify": "✍️ Xác minh thủ công", "manual_verify_unlocked": "Xác minh thủ công hiện đã mở.", "manual_verify_unlocks": "Xác minh thủ công sẽ mở sau khoảng {minutes} phút.",
        "wallet_topup_expired": "⏰ *Nạp ví đã hết hạn*\n\nID nạp ví: `{ref_id}`\nThanh toán không hoàn tất trong *{minutes} phút*.\n\nVui lòng bắt đầu một lần nạp ví mới.", "wallet_topup_still_pending": "⌛ Nạp ví vẫn đang chờ\n\nID nạp ví: `{ref_id}`\n\nThanh toán của bạn vẫn đang chờ. Nó sẽ hết hạn sau khoảng *{minutes} phút* nếu chưa hoàn tất.\n\nNếu bạn đã thanh toán, hãy dùng các nút thanh toán trong tin nhắn gốc hoặc liên hệ hỗ trợ.", "wallet_topup_completed": "✅ Nạp ví hoàn tất!\n\n💰 ${amount} USDT đã được cộng vào ví của bạn.\n👛 Số dư USDT hiện tại: ${balance}\n\nDùng /wallet để kiểm tra số dư.", "wallet_topup_rejected": "❌ Không thể xác minh khoản thanh toán của bạn. Vui lòng liên hệ hỗ trợ nếu bạn cho rằng đây là lỗi.", "admin_wallet_added": "✅ Admin đã cộng số dư ví.\nĐã cộng: ${amount} USDT\nSố dư USDT mới: ${balance} USDT\nDùng /wallet để kiểm tra số dư.", "admin_wallet_removed": "⚠️ Admin đã điều chỉnh số dư ví.\nĐã trừ: ${amount} USDT\nSố dư USDT mới: ${balance} USDT\nDùng /wallet để kiểm tra số dư.",
        "payment_title_bep20": "🟡 *Thanh toán USDT (BEP20)*", "payment_title_polygon": "🟣 *Thanh toán USDT (POLYGON)*", "payment_title_binance": "🟡 *Binance Pay*", "network_polygon": "🌐 Mạng: *Polygon PoS*", "network_binance": "🌐 Mạng: *Binance Pay*", "network_bep20": "🌐 Mạng: *BNB Smart Chain (BEP20)*", "network_confirm_after": "✅ Thanh toán sẽ được xác nhận sau *{confirmations} xác nhận mạng*.",
        "payment_binance_details": "🆔 Binance Pay ID: `{pay_to}`\n👤 Tên: {name}\n\n*Các bước:*\n1️⃣ Mở ứng dụng Binance → Pay → Send\n2️⃣ Tìm Pay ID: `{pay_to}`\n3️⃣ Gửi đúng số USDT duy nhất ở trên\n\n⚠️ Không làm tròn số tiền. Các chữ số thập phân duy nhất sẽ tự động nhận diện lần nạp ví của bạn.\n🌐 Mạng: *Binance Pay*\n", "payment_wallet_details": "Đến ví này:\n`{pay_to}`\n\n⚠️ Gửi đúng số tiền hiển thị ở trên. Số USDT cuối cùng nhận được phải chính xác; đừng để phí sàn/mạng làm giảm số tiền này.\n{network_line}\n", "payment_template": "{title}\n\n📋 ID nạp ví `{ref_id}` | ${amount} USDT\n\nGửi số tiền này:\n```\n{expected} USDT\n```\n{details}\n⏳ Thời gian còn lại: *{{TIME_LEFT}}*\n🔄 Bot tự động kiểm tra mỗi {interval_seconds} giây cho đến khi khoản nạp được ghi có hoặc hết hạn.\n🧾 Nếu bạn đã thanh toán nhưng chưa được xác minh, hãy nhấn *Xác minh thủ công* bên dưới.",
        "payment_not_found": "Không tìm thấy phiên thanh toán.", "payment_not_yours": "Phiên thanh toán này không phải của bạn.", "payment_screenshot_first": "Vui lòng gửi ảnh chụp bằng chứng trước.", "topup_already_completed": "✅ Nạp ví đã hoàn tất.", "topup_processed_or_expired": "⚠️ Phiên thanh toán này đã được xử lý hoặc đã hết hạn.", "checking_binance_history": "Đang kiểm tra lịch sử Binance Pay...", "checking_payment": "🔄 Đang kiểm tra thanh toán...", "manual_hash_prompt": "🔍 *Xác minh USDT thủ công*\n\nVui lòng gửi *hash giao dịch USDT / TxID* trước.\nSau đó bạn sẽ được yêu cầu gửi ảnh chụp bằng chứng.", "select_failure_buttons_only": "Vui lòng chọn một trong các nút lý do thất bại.", "send_screenshot_not_text": "📸 Vui lòng gửi ảnh chụp/ảnh bằng chứng, không gửi văn bản.", "payment_session_gone": "Phiên thanh toán không còn tồn tại.", "invalid_tx_hash": "❌ Vui lòng gửi hash giao dịch USDT / TxID hợp lệ. Nó nên có dạng `0x...` hoặc ID giao dịch sàn hợp lệ.", "checking_tx_hash": "🔎 Đang kiểm tra hash giao dịch...", "txhash_admin_review": "📸 Vui lòng gửi ảnh chụp bằng chứng thanh toán USDT này.\n\nTxHash của bạn cần admin xét duyệt trước khi lần nạp ví này được phê duyệt.", "txhash_already_used": "❌ Hash giao dịch này đã được dùng cho một lần nạp ví.\n\nVui lòng gửi một hash giao dịch USDT khác chưa được dùng.", "txhash_incorrect": "❌ Hash giao dịch bạn gửi không đúng.\n\nVui lòng gửi đúng hash giao dịch USDT / TxID cho lần nạp ví này.", "screenshot_proof_next": "📸 Bây giờ hãy gửi ảnh chụp bằng chứng thanh toán USDT này.\n\nNếu TxHash không thể xác minh tự động, bộ phận hỗ trợ sẽ xem xét bằng chứng.", "enter_valid_number": "❌ Nhập một số hợp lệ.", "minimum_topup_amount": "❌ Số tiền nạp tối thiểu là ${amount}.", "send_screenshot_proof": "📸 Vui lòng gửi ảnh chụp/ảnh bằng chứng.", "txhash_used_other": "❌ Hash giao dịch này đã được dùng cho một lần nạp ví khác.", "manual_verification_submitted": "⏳ Xác minh thủ công đã được gửi để admin xét duyệt.\nTham chiếu: {ref_id}",
        "only_active_receivers_earnings": "Chỉ người nhận đang hoạt động mới có thể dùng /earnings.", "only_active_receivers_payout": "Chỉ người nhận đang hoạt động mới có thể yêu cầu thanh toán.", "withdraw_prompt": "💸 Rút tiền\nKhả dụng: ${available} USDT\nTối thiểu: ${minimum} USDT\n\nGửi số lượng.", "withdraw_no_available": "💸 Rút tiền\nKhả dụng: ${available} USDT\nTối thiểu: ${minimum} USDT", "send_payment_details": "💳 Gửi chi tiết thanh toán.", "payment_details_question": "💳 Chi tiết thanh toán?\nSố lượng: ${amount} USDT", "btn_enter_new_payment_details": "✏️ Nhập chi tiết thanh toán mới", "payment_details_saved": "✅ Đã lưu chi tiết thanh toán.", "send_valid_quantity": "Gửi số lượng hợp lệ.", "minimum_payout": "Thanh toán tối thiểu là ${amount} USDT.", "withdraw_available_due": "Khả dụng: ${available} USDT\nĐến hạn: ${due} USDT · Đã yêu cầu: ${requested} USDT", "withdraw_submitted": "✅ Yêu cầu rút tiền #{payout_id} đã được gửi với ${amount} USDT.", "payout_done": "✅ Đã thanh toán.\nSố tiền: ${amount} USDT\n\nSố dư thu nhập của bạn đã được cập nhật. Dùng /earnings để xem.", "payout_rejected": "❌ Yêu cầu thanh toán của bạn đã bị từ chối.\nSố tiền: ${amount} USDT\n\nSố tiền này hiện lại khả dụng trong /earnings.",
        "dispute_open": "⚠️ *Mở tranh chấp*\n{qr_line}\n\nVui lòng gửi lý do tranh chấp này ngay bây giờ.", "dispute_cancelled": "Đã hủy tranh chấp.", "dispute_reason_clear": "Vui lòng gửi lý do tranh chấp rõ ràng.", "dispute_submitted": "✅ Tranh chấp #{ref_id} đã được gửi. Admin sẽ sớm xem xét.", "dispute_not_found": "Không tìm thấy tranh chấp.", "dispute_not_yours": "Tranh chấp này không phải của bạn.", "dispute_closed": "Tranh chấp này đã đóng.", "dispute_reply_prompt": "💬 Trả lời tranh chấp #{ref}\n\nGửi tin nhắn của bạn ngay bây giờ.", "dispute_reply_cancelled": "Đã hủy trả lời tranh chấp.", "dispute_reply_clear": "Vui lòng gửi câu trả lời rõ ràng.", "dispute_reply_added": "✅ Đã thêm trả lời vào tranh chấp #{ref}.", "dispute_reply_usage": "Dùng: /disputereply DISPUTE_ID tin nhắn của bạn", "dispute_reply_send_now": "💬 Gửi trả lời của bạn cho tranh chấp #{ref} ngay bây giờ.", "could_not_start_dispute": "Không thể bắt đầu tranh chấp đó.", "qr_id_not_found": "Tôi không tìm thấy ID QR đó.", "qr_not_linked_sender": "ID QR đó không liên kết với tài khoản người gửi của bạn.", "qr_not_linked_receiver": "ID QR đó không liên kết với tài khoản người nhận của bạn.",
        "invalid_failure_reason": "Lý do thất bại không hợp lệ.", "invalid_offer_button": "Nút ưu đãi không hợp lệ.", "offer_claimed": "✅ Bạn đã nhận QR này", "claim_saved_delivery_failed": "Đã lưu nhận QR, nhưng gửi QR thất bại. Hãy yêu cầu admin kiểm tra.", "invalid_notify_button": "Nút thông báo không hợp lệ.", "qr_not_found": "Không tìm thấy QR.", "only_sender_notify_receiver": "Chỉ người gửi QR mới có thể nhắc người nhận.", "qr_already_marked": "QR này đã được đánh dấu {status}.", "no_receiver_accepted": "Chưa có người nhận nào chấp nhận QR này.", "notify_receiver_failed": "Hiện không thể nhắc người nhận.", "invalid_qr_button": "Nút QR không hợp lệ.", "only_receivers_open_pending": "Chỉ người nhận đang hoạt động mới có thể mở QR đang chờ.", "qr_not_found_for_account": "Không tìm thấy QR cho tài khoản của bạn.", "qr_no_longer_pending": "QR này không còn đang chờ.", "qr_open_failed": "Hiện không thể mở QR đó.", "invalid_button": "Nút không hợp lệ.", "invalid_action": "Hành động không hợp lệ.", "qr_not_found_generic": "Tôi không tìm thấy QR đó.", "maintenance_on_alert": "Bot đang bảo trì.", "document_reject": "Vui lòng gửi QR dưới dạng ảnh Telegram, không phải tài liệu. Ảnh được xử lý nhanh hơn.",
    },
    "zh": {
        "marketplace_status_title": "📡 市场状态", "marketplace_online_receivers": "🟢 在线接收方：{count}", "marketplace_capacity": "📊 当前扫描容量：{capacity}", "marketplace_qr_expiry": "⏱ QR 过期时间：{minutes} 分钟", "marketplace_maintenance_on": "🚧 维护模式已开启。新的 QR 提交已暂停。", "marketplace_your_available_balance": "💼 您的可用余额：${amount} USDT", "marketplace_estimated_scans": "🧾 预计可用扫描次数：{scans}", "marketplace_receiver_online_status": "您的接收方状态：🟢 在线，剩余 {remaining} / {total} 次扫描。", "marketplace_receiver_offline_status": "您的接收方状态：🔴 离线。使用 /on LIMIT 上线。",
        "wallet_history_title": "👛 钱包历史 — 第 {page}/{total_pages} 页", "wallet_history_showing": "显示钱包充值和管理员余额更新，最新在前。", "wallet_history_empty": "暂无钱包历史。", "wallet_topup_id": "钱包充值 ID", "payment_method_label": "付款方式", "amount_label": "金额", "related_id_label": "关联 ID", "btn_topup_again": "➕ 再次充值", "payment_status_completed": "✅ 已完成", "payment_status_expired": "❌ 已过期", "payment_status_rejected": "❌ 已拒绝", "payment_status_review": "📝 已提交审核", "payment_status_pending": "⏳ 待处理", "wallet_label_admin_add": "管理员增加钱包余额", "wallet_label_admin_remove": "管理员扣减钱包余额", "wallet_method_admin_add": "管理员增加钱包", "wallet_method_admin_remove": "管理员扣减钱包",
        "topup_enter_amount": "💰 请输入您要充值的金额，单位为 *$ (USDT)*。", "topup_payment_method": "付款方式：*{method}*", "topup_minimum": "_(最低：${amount})_", "press_back_abort": "按返回可取消。", "btn_check_payment": "🔄 检查付款", "btn_manual_verify": "✍️ 手动验证", "manual_verify_unlocked": "现在可以进行手动验证。", "manual_verify_unlocks": "手动验证约 {minutes} 分钟后解锁。",
        "wallet_topup_expired": "⏰ *钱包充值已过期*\n\n钱包充值 ID：`{ref_id}`\n付款未在 *{minutes} 分钟* 内完成。\n\n请重新开始钱包充值。", "wallet_topup_still_pending": "⌛ 钱包充值仍在等待\n\n钱包充值 ID：`{ref_id}`\n\n您的付款仍在等待中。如果未完成付款，大约 *{minutes} 分钟* 后会过期。\n\n如果您已经付款，请使用原消息中的付款按钮，或联系支持。", "wallet_topup_completed": "✅ 钱包充值完成！\n\n💰 ${amount} USDT 已添加到您的钱包。\n👛 当前 USDT 余额：${balance}\n\n使用 /wallet 查看余额。", "wallet_topup_rejected": "❌ 无法验证您的付款。如果您认为这是错误，请联系支持。", "admin_wallet_added": "✅ 管理员已添加钱包余额。\n添加：${amount} USDT\n新的 USDT 余额：${balance} USDT\n使用 /wallet 查看余额。", "admin_wallet_removed": "⚠️ 管理员已调整钱包余额。\n扣除：${amount} USDT\n新的 USDT 余额：${balance} USDT\n使用 /wallet 查看余额。",
        "payment_title_bep20": "🟡 *USDT (BEP20) 付款*", "payment_title_polygon": "🟣 *USDT (POLYGON) 付款*", "payment_title_binance": "🟡 *Binance Pay*", "network_polygon": "🌐 网络：*Polygon PoS*", "network_binance": "🌐 网络：*Binance Pay*", "network_bep20": "🌐 网络：*BNB Smart Chain (BEP20)*", "network_confirm_after": "✅ 付款将在 *{confirmations} 次网络确认* 后确认。",
        "payment_binance_details": "🆔 Binance Pay ID：`{pay_to}`\n👤 名称：{name}\n\n*步骤：*\n1️⃣ 打开 Binance 应用 → Pay → Send\n2️⃣ 搜索 Pay ID：`{pay_to}`\n3️⃣ 准确发送上方唯一的 USDT 金额\n\n⚠️ 不要四舍五入金额。唯一的小数会自动识别您的钱包充值。\n🌐 网络：*Binance Pay*\n", "payment_wallet_details": "发送到此钱包：\n`{pay_to}`\n\n⚠️ 请发送上方显示的准确金额。最终收到的 USDT 必须完全一致；不要让交易所/网络手续费减少该金额。\n{network_line}\n", "payment_template": "{title}\n\n📋 钱包充值 ID `{ref_id}` | ${amount} USDT\n\n发送此金额：\n```\n{expected} USDT\n```\n{details}\n⏳ 剩余时间：*{{TIME_LEFT}}*\n🔄 Bot 每 {interval_seconds} 秒自动检查一次，直到此充值到账或过期。\n🧾 如果您已经付款但未验证，请点击下方的 *手动验证*。",
        "payment_not_found": "未找到付款会话。", "payment_not_yours": "此付款会话不属于您。", "payment_screenshot_first": "请先发送截图证明。", "topup_already_completed": "✅ 钱包充值已完成。", "topup_processed_or_expired": "⚠️ 此付款会话已处理或已过期。", "checking_binance_history": "正在检查 Binance Pay 历史...", "checking_payment": "🔄 正在检查付款...", "manual_hash_prompt": "🔍 *手动 USDT 验证*\n\n请先发送您的 *USDT 交易哈希 / TxID*。\n之后会要求您发送截图证明。", "select_failure_buttons_only": "请从失败原因按钮中选择一个。", "send_screenshot_not_text": "📸 请发送截图/照片证明，不要发送文字。", "payment_session_gone": "付款会话已不存在。", "invalid_tx_hash": "❌ 请发送有效的 USDT 交易哈希 / TxID。格式应类似 `0x...` 或有效的交易所交易 ID。", "checking_tx_hash": "🔎 正在检查交易哈希...", "txhash_admin_review": "📸 请发送此 USDT 付款的截图证明。\n\n您的 TxHash 需要管理员审核后才能批准此钱包充值。", "txhash_already_used": "❌ 此交易哈希已用于钱包充值。\n\n请提交另一个未使用的 USDT 交易哈希。", "txhash_incorrect": "❌ 您提交的交易哈希不正确。\n\n请发送此钱包充值的正确 USDT 交易哈希 / TxID。", "screenshot_proof_next": "📸 现在请发送此 USDT 付款的截图证明。\n\n如果 TxHash 无法自动验证，支持人员会审核证明。", "enter_valid_number": "❌ 请输入有效数字。", "minimum_topup_amount": "❌ 最低充值金额为 ${amount}。", "send_screenshot_proof": "📸 请发送截图/照片证明。", "txhash_used_other": "❌ 此交易哈希已用于另一次钱包充值。", "manual_verification_submitted": "⏳ 手动验证已提交给管理员审核。\n参考：{ref_id}",
        "only_active_receivers_earnings": "只有活跃接收方可以使用 /earnings。", "only_active_receivers_payout": "只有活跃接收方可以申请付款。", "withdraw_prompt": "💸 提现\n可用：${available} USDT\n最低：${minimum} USDT\n\n发送数量。", "withdraw_no_available": "💸 提现\n可用：${available} USDT\n最低：${minimum} USDT", "send_payment_details": "💳 发送付款详情。", "payment_details_question": "💳 付款详情？\n数量：${amount} USDT", "btn_enter_new_payment_details": "✏️ 输入新的付款详情", "payment_details_saved": "✅ 付款详情已保存。", "send_valid_quantity": "请发送有效数量。", "minimum_payout": "最低付款金额为 ${amount} USDT。", "withdraw_available_due": "可用：${available} USDT\n应付：${due} USDT · 已申请：${requested} USDT", "withdraw_submitted": "✅ 提现申请 #{payout_id} 已提交，金额 ${amount} USDT。", "payout_done": "✅ 付款已完成。\n金额：${amount} USDT\n\n您的收益余额已更新。使用 /earnings 查看。", "payout_rejected": "❌ 您的付款申请已被拒绝。\n金额：${amount} USDT\n\n该金额已重新在 /earnings 中可用。",
        "dispute_open": "⚠️ *开启争议*\n{qr_line}\n\n请现在发送此争议的原因。", "dispute_cancelled": "争议已取消。", "dispute_reason_clear": "请发送明确的争议原因。", "dispute_submitted": "✅ 争议 #{ref_id} 已提交。管理员会尽快审核。", "dispute_not_found": "未找到争议。", "dispute_not_yours": "此争议不属于您。", "dispute_closed": "此争议已关闭。", "dispute_reply_prompt": "💬 回复争议 #{ref}\n\n请现在发送您的消息。", "dispute_reply_cancelled": "争议回复已取消。", "dispute_reply_clear": "请发送明确的回复。", "dispute_reply_added": "✅ 回复已添加到争议 #{ref}。", "dispute_reply_usage": "用法：/disputereply DISPUTE_ID 您的消息", "dispute_reply_send_now": "💬 请现在发送您对争议 #{ref} 的回复。", "could_not_start_dispute": "无法开启该争议。", "qr_id_not_found": "我找不到该 QR ID。", "qr_not_linked_sender": "该 QR ID 未关联到您的发送方账户。", "qr_not_linked_receiver": "该 QR ID 未关联到您的接收方账户。",
        "invalid_failure_reason": "失败原因无效。", "invalid_offer_button": "报价按钮无效。", "offer_claimed": "✅ 您已获得此 QR", "claim_saved_delivery_failed": "领取已保存，但 QR 发送失败。请让管理员检查。", "invalid_notify_button": "通知按钮无效。", "qr_not_found": "未找到 QR。", "only_sender_notify_receiver": "只有 QR 发送方可以提醒接收方。", "qr_already_marked": "此 QR 已标记为 {status}。", "no_receiver_accepted": "尚无接收方接受此 QR。", "notify_receiver_failed": "现在无法提醒接收方。", "invalid_qr_button": "QR 按钮无效。", "only_receivers_open_pending": "只有活跃接收方可以打开待处理 QR。", "qr_not_found_for_account": "未找到属于您账户的 QR。", "qr_no_longer_pending": "此 QR 不再处于待处理状态。", "qr_open_failed": "现在无法打开该 QR。", "invalid_button": "按钮无效。", "invalid_action": "操作无效。", "qr_not_found_generic": "我找不到该 QR。", "maintenance_on_alert": "Bot 正在维护。", "document_reject": "请将 QR 作为 Telegram 照片发送，不要作为文件发送。照片处理更快。",
    },
    "es": {
        "marketplace_status_title": "📡 Estado del marketplace", "marketplace_online_receivers": "🟢 Receptores en línea: {count}", "marketplace_capacity": "📊 Capacidad actual de escaneos: {capacity}", "marketplace_qr_expiry": "⏱ Vencimiento del QR: {minutes} minutos", "marketplace_maintenance_on": "🚧 El modo de mantenimiento está ACTIVADO. Los nuevos envíos de QR están pausados.", "marketplace_your_available_balance": "💼 Tu saldo disponible: ${amount} USDT", "marketplace_estimated_scans": "🧾 Escaneos estimados disponibles: {scans}", "marketplace_receiver_online_status": "Tu estado como receptor: 🟢 en línea, quedan {remaining} / {total} escaneos.", "marketplace_receiver_offline_status": "Tu estado como receptor: 🔴 fuera de línea. Usa /on LIMIT para estar en línea.",
        "wallet_history_title": "👛 Historial de billetera — Página {page}/{total_pages}", "wallet_history_showing": "Mostrando recargas de billetera y actualizaciones de saldo del admin, primero las más recientes.", "wallet_history_empty": "Aún no hay historial de billetera.", "wallet_topup_id": "ID de recarga de billetera", "payment_method_label": "Método de pago", "amount_label": "Cantidad", "related_id_label": "ID relacionado", "btn_topup_again": "➕ Recargar otra vez", "payment_status_completed": "✅ Completado", "payment_status_expired": "❌ Vencido", "payment_status_rejected": "❌ Rechazado", "payment_status_review": "📝 Enviado a revisión", "payment_status_pending": "⏳ Pendiente", "wallet_label_admin_add": "Admin agregó saldo", "wallet_label_admin_remove": "Admin quitó saldo", "wallet_method_admin_add": "Saldo agregado por admin", "wallet_method_admin_remove": "Saldo quitado por admin",
        "topup_enter_amount": "💰 Ingresa la cantidad que quieres recargar en *$ (USDT)*.", "topup_payment_method": "Método de pago: *{method}*", "topup_minimum": "_(Mínimo: ${amount})_", "press_back_abort": "Pulsa Volver para cancelar.", "btn_check_payment": "🔄 Verificar pago", "btn_manual_verify": "✍️ Verificación manual", "manual_verify_unlocked": "La verificación manual ya está disponible.", "manual_verify_unlocks": "La verificación manual se desbloquea en aproximadamente {minutes} minuto(s).",
        "wallet_topup_expired": "⏰ *Recarga de billetera vencida*\n\nID de recarga de billetera: `{ref_id}`\nEl pago no se completó en *{minutes} minutos*.\n\nInicia una nueva recarga de billetera.", "wallet_topup_still_pending": "⌛ La recarga de billetera sigue pendiente\n\nID de recarga de billetera: `{ref_id}`\n\nTu pago sigue pendiente. Vencerá en aproximadamente *{minutes} minutos* si no se completa.\n\nSi ya pagaste, usa los botones de pago en el mensaje original o contacta con soporte.", "wallet_topup_completed": "✅ ¡Recarga de billetera completada!\n\n💰 ${amount} USDT agregado a tu billetera.\n👛 Saldo USDT actual: ${balance}\n\nUsa /wallet para revisar tu saldo.", "wallet_topup_rejected": "❌ No se pudo verificar tu pago. Contacta con soporte si crees que es un error.", "admin_wallet_added": "✅ Saldo de billetera agregado por admin.\nAgregado: ${amount} USDT\nNuevo saldo USDT: ${balance} USDT\nUsa /wallet para revisar tu saldo.", "admin_wallet_removed": "⚠️ Saldo de billetera ajustado por admin.\nQuitado: ${amount} USDT\nNuevo saldo USDT: ${balance} USDT\nUsa /wallet para revisar tu saldo.",
        "payment_title_bep20": "🟡 *Pago USDT (BEP20)*", "payment_title_polygon": "🟣 *Pago USDT (POLYGON)*", "payment_title_binance": "🟡 *Binance Pay*", "network_polygon": "🌐 Red: *Polygon PoS*", "network_binance": "🌐 Red: *Binance Pay*", "network_bep20": "🌐 Red: *BNB Smart Chain (BEP20)*", "network_confirm_after": "✅ El pago se confirmará después de *{confirmations} confirmaciones de red*.",
        "payment_binance_details": "🆔 Binance Pay ID: `{pay_to}`\n👤 Nombre: {name}\n\n*Pasos:*\n1️⃣ Abre la app de Binance → Pay → Send\n2️⃣ Busca Pay ID: `{pay_to}`\n3️⃣ Envía exactamente la cantidad única de USDT indicada arriba\n\n⚠️ No redondees la cantidad. Los decimales únicos identifican automáticamente tu recarga de billetera.\n🌐 Red: *Binance Pay*\n", "payment_wallet_details": "A esta billetera:\n`{pay_to}`\n\n⚠️ Envía exactamente la cantidad mostrada arriba. El USDT final recibido debe ser exacto; no permitas que las comisiones de exchange/red reduzcan esta cantidad.\n{network_line}\n", "payment_template": "{title}\n\n📋 ID de recarga de billetera `{ref_id}` | ${amount} USDT\n\nEnvía esta cantidad:\n```\n{expected} USDT\n```\n{details}\n⏳ Tiempo restante: *{{TIME_LEFT}}*\n🔄 El bot verifica automáticamente cada {interval_seconds} segundos hasta que esta recarga se acredite o venza.\n🧾 Si ya pagaste y no se verifica, toca *Verificación manual* abajo.",
        "payment_not_found": "Sesión de pago no encontrada.", "payment_not_yours": "Esta sesión de pago no es tuya.", "payment_screenshot_first": "Envía primero la captura de pantalla como prueba.", "topup_already_completed": "✅ La recarga de billetera ya está completada.", "topup_processed_or_expired": "⚠️ Esta sesión de pago ya fue procesada o venció.", "checking_binance_history": "Revisando historial de Binance Pay...", "checking_payment": "🔄 Verificando pago...", "manual_hash_prompt": "🔍 *Verificación manual de USDT*\n\nEnvía primero tu *hash de transacción USDT / TxID*.\nDespués se te pedirá una captura de pantalla como prueba.", "select_failure_buttons_only": "Selecciona uno de los botones de motivo de fallo.", "send_screenshot_not_text": "📸 Envía una captura/foto de prueba, no texto.", "payment_session_gone": "La sesión de pago ya no existe.", "invalid_tx_hash": "❌ Envía un hash de transacción USDT / TxID válido. Debe parecerse a `0x...` o a un ID de transacción de exchange válido.", "checking_tx_hash": "🔎 Revisando hash de transacción...", "txhash_admin_review": "📸 Envía una captura de pantalla como prueba de este pago USDT.\n\nTu TxHash necesita revisión del admin antes de aprobar esta recarga.", "txhash_already_used": "❌ Este hash de transacción ya se usó para una recarga de billetera.\n\nEnvía un hash de transacción USDT diferente y sin usar.", "txhash_incorrect": "❌ El hash de transacción enviado es incorrecto.\n\nEnvía el hash de transacción USDT / TxID correcto para esta recarga.", "screenshot_proof_next": "📸 Ahora envía una captura de pantalla como prueba de este pago USDT.\n\nSi el TxHash no se pudo verificar automáticamente, soporte revisará la prueba.", "enter_valid_number": "❌ Ingresa un número válido.", "minimum_topup_amount": "❌ La recarga mínima es ${amount}.", "send_screenshot_proof": "📸 Envía una captura/foto de prueba.", "txhash_used_other": "❌ Este hash de transacción ya fue usado para otra recarga de billetera.", "manual_verification_submitted": "⏳ Verificación manual enviada para revisión del admin.\nReferencia: {ref_id}",
        "only_active_receivers_earnings": "Solo los receptores activos pueden usar /earnings.", "only_active_receivers_payout": "Solo los receptores activos pueden solicitar payout.", "withdraw_prompt": "💸 Retirar\nDisponible: ${available} USDT\nMínimo: ${minimum} USDT\n\nEnvía la cantidad.", "withdraw_no_available": "💸 Retirar\nDisponible: ${available} USDT\nMínimo: ${minimum} USDT", "send_payment_details": "💳 Envía los detalles de pago.", "payment_details_question": "💳 ¿Detalles de pago?\nCantidad: ${amount} USDT", "btn_enter_new_payment_details": "✏️ Ingresar nuevos detalles de pago", "payment_details_saved": "✅ Detalles de pago guardados.", "send_valid_quantity": "Envía una cantidad válida.", "minimum_payout": "El payout mínimo es ${amount} USDT.", "withdraw_available_due": "Disponible: ${available} USDT\nPendiente: ${due} USDT · Solicitado: ${requested} USDT", "withdraw_submitted": "✅ Solicitud de retiro #{payout_id} enviada por ${amount} USDT.", "payout_done": "✅ Payout realizado.\nCantidad: ${amount} USDT\n\nTu saldo de ganancias se ha actualizado. Usa /earnings para verlo.", "payout_rejected": "❌ Tu solicitud de payout fue rechazada.\nCantidad: ${amount} USDT\n\nLa cantidad vuelve a estar disponible en /earnings.",
        "dispute_open": "⚠️ *Abrir disputa*\n{qr_line}\n\nEnvía ahora el motivo de esta disputa.", "dispute_cancelled": "Disputa cancelada.", "dispute_reason_clear": "Envía un motivo claro para la disputa.", "dispute_submitted": "✅ Disputa #{ref_id} enviada. El admin la revisará pronto.", "dispute_not_found": "Disputa no encontrada.", "dispute_not_yours": "Esta disputa no es tuya.", "dispute_closed": "Esta disputa ya está cerrada.", "dispute_reply_prompt": "💬 Responder a disputa #{ref}\n\nEnvía tu mensaje ahora.", "dispute_reply_cancelled": "Respuesta de disputa cancelada.", "dispute_reply_clear": "Envía una respuesta clara.", "dispute_reply_added": "✅ Respuesta agregada a la disputa #{ref}.", "dispute_reply_usage": "Uso: /disputereply DISPUTE_ID tu mensaje", "dispute_reply_send_now": "💬 Envía ahora tu respuesta para la disputa #{ref}.", "could_not_start_dispute": "No se pudo iniciar esa disputa.", "qr_id_not_found": "No pude encontrar ese ID de QR.", "qr_not_linked_sender": "Ese ID de QR no está vinculado a tu cuenta de remitente.", "qr_not_linked_receiver": "Ese ID de QR no está vinculado a tu cuenta de receptor.",
        "invalid_failure_reason": "Motivo de fallo inválido.", "invalid_offer_button": "Botón de oferta inválido.", "offer_claimed": "✅ Obtuviste este QR", "claim_saved_delivery_failed": "Asignación guardada, pero falló el envío del QR. Pide al admin que lo revise.", "invalid_notify_button": "Botón de notificación inválido.", "qr_not_found": "QR no encontrado.", "only_sender_notify_receiver": "Solo el remitente del QR puede notificar al receptor.", "qr_already_marked": "Este QR ya está marcado como {status}.", "no_receiver_accepted": "Ningún receptor ha aceptado este QR todavía.", "notify_receiver_failed": "No se pudo notificar al receptor ahora mismo.", "invalid_qr_button": "Botón de QR inválido.", "only_receivers_open_pending": "Solo los receptores activos pueden abrir QRs pendientes.", "qr_not_found_for_account": "QR no encontrado para tu cuenta.", "qr_no_longer_pending": "Este QR ya no está pendiente.", "qr_open_failed": "No se pudo abrir ese QR ahora mismo.", "invalid_button": "Botón inválido.", "invalid_action": "Acción inválida.", "qr_not_found_generic": "No pude encontrar ese QR.", "maintenance_on_alert": "El bot está en mantenimiento.", "document_reject": "Envía el QR como foto de Telegram, no como documento. Las fotos se procesan más rápido.",
    },
}
for _code, _items in _USER_TEXT_AUDIT_TRANSLATIONS.items():
    _TRANSLATIONS.setdefault(_code, {}).update(_items)
for _code in SUPPORTED_LANGUAGES:
    for _k, _v in _USER_TEXT_AUDIT_TRANSLATIONS["en"].items():
        _TRANSLATIONS[_code].setdefault(_k, _v)


_STATUS_FLOW_TRANSLATIONS: dict[str, dict[str, str]] = {
    "en": {
        "payment_check_running": "Payment check is still running.\n{unlock_text}",
        "txid_hint": "_(TxID usually starts with 0x... — find it in your wallet's transaction history)_",
        "status_invalid": "Invalid status.",
        "select_failure_first": "Please select the failure reason first.",
        "qr_photo_not_found": "I could not find that photo.",
        "status_update_failed": "Could not update status. It may have already been marked.",
        "status_marked_caption_update_failed": "Marked {status}, but I could not update the QR caption for: {targets}.",
        "qr_failed_notice": "❌ QR failed\n🆔 ID: {public_id}\n📝 Reason: {reason}",
        "qr_done_notice": "✅ QR marked done\n🆔 ID: {public_id}\n💳 Balance has been updated.",
        "qr_status_caption_fallback": "{emoji} QR marked {status}\n🆔 ID: {public_id}\nThe status is saved, but I could not update the old QR caption, so this message confirms the final status.",
        "qr_marked_failed_sender_notice": "❌ QR marked failed. Reason sent to sender.",
        "qr_status_updated_caption": "{emoji} Status updated in the QR caption: {status}.",
        "offer_taken_text": "⛔ Offer expired. Another receiver already accepted this QR.\n🆔 {offer_id_label}: {public_id}",
    },
    "id": {
        "payment_check_running": "Pemeriksaan pembayaran masih berjalan.\n{unlock_text}",
        "txid_hint": "_(TxID biasanya dimulai dengan 0x... — temukan di riwayat transaksi wallet Anda)_",
        "status_invalid": "Status tidak valid.",
        "select_failure_first": "Harap pilih alasan kegagalan terlebih dahulu.",
        "qr_photo_not_found": "Saya tidak dapat menemukan foto QR tersebut.",
        "status_update_failed": "Tidak dapat memperbarui status. Mungkin sudah ditandai.",
        "status_marked_caption_update_failed": "Ditandai {status}, tetapi saya tidak dapat memperbarui caption QR untuk: {targets}.",
        "qr_failed_notice": "❌ QR gagal\n🆔 ID: {public_id}\n📝 Alasan: {reason}",
        "qr_done_notice": "✅ QR ditandai selesai\n🆔 ID: {public_id}\n💳 Saldo telah diperbarui.",
        "qr_status_caption_fallback": "{emoji} QR ditandai {status}\n🆔 ID: {public_id}\nStatus sudah tersimpan, tetapi caption QR lama tidak dapat diperbarui, jadi pesan ini mengonfirmasi status akhir.",
        "qr_marked_failed_sender_notice": "❌ QR ditandai gagal. Alasan dikirim ke pengirim.",
        "qr_status_updated_caption": "{emoji} Status diperbarui di caption QR: {status}.",
        "offer_taken_text": "⛔ Penawaran kedaluwarsa. Penerima lain sudah menerima QR ini.\n🆔 {offer_id_label}: {public_id}",
    },
    "vi": {
        "payment_check_running": "Quá trình kiểm tra thanh toán vẫn đang chạy.\n{unlock_text}",
        "txid_hint": "_(TxID thường bắt đầu bằng 0x... — tìm trong lịch sử giao dịch ví của bạn)_",
        "status_invalid": "Trạng thái không hợp lệ.",
        "select_failure_first": "Vui lòng chọn lý do thất bại trước.",
        "qr_photo_not_found": "Tôi không tìm thấy ảnh QR đó.",
        "status_update_failed": "Không thể cập nhật trạng thái. Có thể nó đã được đánh dấu.",
        "status_marked_caption_update_failed": "Đã đánh dấu {status}, nhưng tôi không thể cập nhật chú thích QR cho: {targets}.",
        "qr_failed_notice": "❌ QR thất bại\n🆔 ID: {public_id}\n📝 Lý do: {reason}",
        "qr_done_notice": "✅ QR đã được đánh dấu hoàn tất\n🆔 ID: {public_id}\n💳 Số dư đã được cập nhật.",
        "qr_status_caption_fallback": "{emoji} QR đã được đánh dấu {status}\n🆔 ID: {public_id}\nTrạng thái đã được lưu, nhưng tôi không thể cập nhật chú thích QR cũ, nên tin nhắn này xác nhận trạng thái cuối cùng.",
        "qr_marked_failed_sender_notice": "❌ QR đã được đánh dấu thất bại. Lý do đã được gửi cho người gửi.",
        "qr_status_updated_caption": "{emoji} Trạng thái đã được cập nhật trong chú thích QR: {status}.",
        "offer_taken_text": "⛔ Ưu đãi đã hết hạn. Một người nhận khác đã chấp nhận QR này.\n🆔 {offer_id_label}: {public_id}",
    },
    "zh": {
        "payment_check_running": "付款检查仍在运行。\n{unlock_text}",
        "txid_hint": "_(TxID 通常以 0x... 开头 — 可在您的钱包交易历史中找到)_",
        "status_invalid": "状态无效。",
        "select_failure_first": "请先选择失败原因。",
        "qr_photo_not_found": "我找不到该 QR 照片。",
        "status_update_failed": "无法更新状态。它可能已经被标记。",
        "status_marked_caption_update_failed": "已标记为 {status}，但我无法更新以下 QR 说明：{targets}。",
        "qr_failed_notice": "❌ QR 失败\n🆔 ID：{public_id}\n📝 原因：{reason}",
        "qr_done_notice": "✅ QR 已标记为完成\n🆔 ID：{public_id}\n💳 余额已更新。",
        "qr_status_caption_fallback": "{emoji} QR 已标记为{status}\n🆔 ID：{public_id}\n状态已保存，但旧的 QR 说明无法更新，因此此消息确认最终状态。",
        "qr_marked_failed_sender_notice": "❌ QR 已标记为失败。原因已发送给发送方。",
        "qr_status_updated_caption": "{emoji} 状态已在 QR 说明中更新：{status}。",
        "offer_taken_text": "⛔ 报价已过期。另一位接收方已经接受了此 QR。\n🆔 {offer_id_label}：{public_id}",
    },
    "es": {
        "payment_check_running": "La verificación del pago sigue en curso.\n{unlock_text}",
        "txid_hint": "_(El TxID normalmente empieza con 0x... — búscalo en el historial de transacciones de tu billetera)_",
        "status_invalid": "Estado inválido.",
        "select_failure_first": "Selecciona primero el motivo del fallo.",
        "qr_photo_not_found": "No pude encontrar esa foto QR.",
        "status_update_failed": "No se pudo actualizar el estado. Puede que ya haya sido marcado.",
        "status_marked_caption_update_failed": "Marcado {status}, pero no pude actualizar el caption del QR para: {targets}.",
        "qr_failed_notice": "❌ QR fallido\n🆔 ID: {public_id}\n📝 Motivo: {reason}",
        "qr_done_notice": "✅ QR marcado como completado\n🆔 ID: {public_id}\n💳 El saldo se ha actualizado.",
        "qr_status_caption_fallback": "{emoji} QR marcado como {status}\n🆔 ID: {public_id}\nEl estado se guardó, pero no pude actualizar el caption antiguo del QR, así que este mensaje confirma el estado final.",
        "qr_marked_failed_sender_notice": "❌ QR marcado como fallido. El motivo fue enviado al remitente.",
        "qr_status_updated_caption": "{emoji} Estado actualizado en el caption del QR: {status}.",
        "offer_taken_text": "⛔ Oferta vencida. Otro receptor ya aceptó este QR.\n🆔 {offer_id_label}: {public_id}",
    },
}
for _code, _items in _STATUS_FLOW_TRANSLATIONS.items():
    _TRANSLATIONS.setdefault(_code, {}).update(_items)
for _code in SUPPORTED_LANGUAGES:
    for _k, _v in _STATUS_FLOW_TRANSLATIONS["en"].items():
        _TRANSLATIONS[_code].setdefault(_k, _v)


_ADMIN_ORDER_USER_NOTICE_TRANSLATIONS: dict[str, dict[str, str]] = {
    "en": {
        "admin_order_status_changed": "🛠 QR order status changed by admin",
        "order_id_label": "Order ID",
        "status_change_line": "Status: {old_status} → {new_status}",
        "sender_wallet_refunded": "💳 ${amount} USDT has been added back to your wallet balance.",
        "sender_reserve_released": "💳 ${amount} USDT reserve has been released back to your available balance.",
        "sender_wallet_charged": "💳 ${amount} USDT has been deducted from your wallet balance.",
        "use_wallet_balance": "Use /wallet to view your balance.",
        "receiver_earnings_deducted": "💰 ${amount} USDT has been deducted from your earnings for this order.",
        "receiver_earnings_credited": "💰 ${amount} USDT has been credited to your earnings for this order.",
        "receiver_earnings_no_change": "No receiver earnings change was needed for this order.",
        "use_earnings_balance": "Use /earnings to view your balance.",
    },
    "id": {
        "admin_order_status_changed": "🛠 Status pesanan QR diubah oleh admin",
        "order_id_label": "ID Pesanan",
        "status_change_line": "Status: {old_status} → {new_status}",
        "sender_wallet_refunded": "💳 ${amount} USDT telah ditambahkan kembali ke saldo wallet Anda.",
        "sender_reserve_released": "💳 Cadangan ${amount} USDT telah dilepaskan kembali ke saldo tersedia Anda.",
        "sender_wallet_charged": "💳 ${amount} USDT telah dipotong dari saldo wallet Anda.",
        "use_wallet_balance": "Gunakan /wallet untuk melihat saldo Anda.",
        "receiver_earnings_deducted": "💰 ${amount} USDT telah dipotong dari earnings Anda untuk pesanan ini.",
        "receiver_earnings_credited": "💰 ${amount} USDT telah dikreditkan ke earnings Anda untuk pesanan ini.",
        "receiver_earnings_no_change": "Tidak diperlukan perubahan earnings penerima untuk pesanan ini.",
        "use_earnings_balance": "Gunakan /earnings untuk melihat saldo Anda.",
    },
    "vi": {
        "admin_order_status_changed": "🛠 Admin đã thay đổi trạng thái đơn QR",
        "order_id_label": "ID đơn hàng",
        "status_change_line": "Trạng thái: {old_status} → {new_status}",
        "sender_wallet_refunded": "💳 ${amount} USDT đã được cộng lại vào số dư ví của bạn.",
        "sender_reserve_released": "💳 Khoản giữ ${amount} USDT đã được giải phóng về số dư khả dụng của bạn.",
        "sender_wallet_charged": "💳 ${amount} USDT đã bị trừ khỏi số dư ví của bạn.",
        "use_wallet_balance": "Dùng /wallet để xem số dư.",
        "receiver_earnings_deducted": "💰 ${amount} USDT đã bị trừ khỏi thu nhập của bạn cho đơn này.",
        "receiver_earnings_credited": "💰 ${amount} USDT đã được cộng vào thu nhập của bạn cho đơn này.",
        "receiver_earnings_no_change": "Không cần thay đổi thu nhập người nhận cho đơn này.",
        "use_earnings_balance": "Dùng /earnings để xem số dư.",
    },
    "zh": {
        "admin_order_status_changed": "🛠 管理员已更改 QR 订单状态",
        "order_id_label": "订单 ID",
        "status_change_line": "状态：{old_status} → {new_status}",
        "sender_wallet_refunded": "💳 ${amount} USDT 已退回到您的钱包余额。",
        "sender_reserve_released": "💳 ${amount} USDT 预留金额已释放回您的可用余额。",
        "sender_wallet_charged": "💳 ${amount} USDT 已从您的钱包余额中扣除。",
        "use_wallet_balance": "使用 /wallet 查看您的余额。",
        "receiver_earnings_deducted": "💰 此订单已从您的收益中扣除 ${amount} USDT。",
        "receiver_earnings_credited": "💰 此订单已向您的收益中计入 ${amount} USDT。",
        "receiver_earnings_no_change": "此订单不需要更改接收方收益。",
        "use_earnings_balance": "使用 /earnings 查看您的余额。",
    },
    "es": {
        "admin_order_status_changed": "🛠 El admin cambió el estado del pedido QR",
        "order_id_label": "ID de pedido",
        "status_change_line": "Estado: {old_status} → {new_status}",
        "sender_wallet_refunded": "💳 ${amount} USDT se agregó de vuelta a tu saldo de billetera.",
        "sender_reserve_released": "💳 La reserva de ${amount} USDT se liberó de vuelta a tu saldo disponible.",
        "sender_wallet_charged": "💳 ${amount} USDT se dedujo de tu saldo de billetera.",
        "use_wallet_balance": "Usa /wallet para ver tu saldo.",
        "receiver_earnings_deducted": "💰 ${amount} USDT se dedujo de tus ganancias por este pedido.",
        "receiver_earnings_credited": "💰 ${amount} USDT se acreditó a tus ganancias por este pedido.",
        "receiver_earnings_no_change": "No fue necesario cambiar las ganancias del receptor para este pedido.",
        "use_earnings_balance": "Usa /earnings para ver tu saldo.",
    },
}
for _code, _items in _ADMIN_ORDER_USER_NOTICE_TRANSLATIONS.items():
    _TRANSLATIONS.setdefault(_code, {}).update(_items)
for _code in SUPPORTED_LANGUAGES:
    for _k, _v in _ADMIN_ORDER_USER_NOTICE_TRANSLATIONS["en"].items():
        _TRANSLATIONS[_code].setdefault(_k, _v)

_CLAIM_ALERT_TRANSLATIONS = {
    "en": {
        "claim_only_active_receivers": "Only active receivers can accept offers.",
        "claim_admin_not_active": "Admin account is not active in the bot. Send /start first.",
        "claim_offline_or_limit_zero": "You are offline or your limit is 0. Use /on LIMIT first.",
        "claim_offer_not_found": "Offer not found.",
        "claim_offer_expired": "Offer expired.",
        "claim_offer_taken": "Offer expired. Another receiver already accepted this QR.",
        "claim_success": "Claimed.",
    },
    "id": {
        "claim_only_active_receivers": "Hanya penerima aktif yang dapat menerima penawaran.",
        "claim_admin_not_active": "Akun admin belum aktif di bot. Kirim /start terlebih dahulu.",
        "claim_offline_or_limit_zero": "Anda sedang offline atau limit Anda 0. Gunakan /on LIMIT terlebih dahulu.",
        "claim_offer_not_found": "Penawaran tidak ditemukan.",
        "claim_offer_expired": "Penawaran kedaluwarsa.",
        "claim_offer_taken": "Penawaran kedaluwarsa. Penerima lain sudah menerima QR ini.",
        "claim_success": "Diklaim.",
    },
    "vi": {
        "claim_only_active_receivers": "Chỉ người nhận đang hoạt động mới có thể nhận ưu đãi.",
        "claim_admin_not_active": "Tài khoản admin chưa hoạt động trong bot. Hãy gửi /start trước.",
        "claim_offline_or_limit_zero": "Bạn đang offline hoặc giới hạn của bạn là 0. Hãy dùng /on LIMIT trước.",
        "claim_offer_not_found": "Không tìm thấy ưu đãi.",
        "claim_offer_expired": "Ưu đãi đã hết hạn.",
        "claim_offer_taken": "Ưu đãi đã hết hạn. Một người nhận khác đã chấp nhận QR này.",
        "claim_success": "Đã nhận.",
    },
    "zh": {
        "claim_only_active_receivers": "只有在线接收方可以接受报价。",
        "claim_admin_not_active": "管理员账号尚未在 bot 中激活。请先发送 /start。",
        "claim_offline_or_limit_zero": "您当前离线或限额为 0。请先使用 /on LIMIT。",
        "claim_offer_not_found": "未找到报价。",
        "claim_offer_expired": "报价已过期。",
        "claim_offer_taken": "报价已过期。另一位接收方已经接受了此 QR。",
        "claim_success": "已接受。",
    },
    "es": {
        "claim_only_active_receivers": "Solo los receptores activos pueden aceptar ofertas.",
        "claim_admin_not_active": "La cuenta admin no está activa en el bot. Envía /start primero.",
        "claim_offline_or_limit_zero": "Estás offline o tu límite es 0. Usa /on LIMIT primero.",
        "claim_offer_not_found": "Oferta no encontrada.",
        "claim_offer_expired": "Oferta vencida.",
        "claim_offer_taken": "Oferta vencida. Otro receptor ya aceptó este QR.",
        "claim_success": "Aceptado.",
    },
}
for _code, _items in _CLAIM_ALERT_TRANSLATIONS.items():
    _TRANSLATIONS.setdefault(_code, {}).update(_items)
for _code in SUPPORTED_LANGUAGES:
    for _k, _v in _CLAIM_ALERT_TRANSLATIONS["en"].items():
        _TRANSLATIONS[_code].setdefault(_k, _v)

_PAYMENT_ALERT_TRANSLATIONS = {
    "en": {
        "payment_detected_processing": "✅ Payment detected! Processing...",
        "payment_not_found_yet_running": "❌ Payment not found yet. Payment check is still running. {unlock_text}",
    },
    "id": {
        "payment_detected_processing": "✅ Pembayaran terdeteksi! Sedang diproses...",
        "payment_not_found_yet_running": "❌ Pembayaran belum ditemukan. Pemeriksaan pembayaran masih berjalan. {unlock_text}",
    },
    "vi": {
        "payment_detected_processing": "✅ Đã phát hiện thanh toán! Đang xử lý...",
        "payment_not_found_yet_running": "❌ Chưa tìm thấy thanh toán. Việc kiểm tra thanh toán vẫn đang chạy. {unlock_text}",
    },
    "zh": {
        "payment_detected_processing": "✅ 已检测到付款！正在处理...",
        "payment_not_found_yet_running": "❌ 尚未找到付款。付款检查仍在进行中。{unlock_text}",
    },
    "es": {
        "payment_detected_processing": "✅ ¡Pago detectado! Procesando...",
        "payment_not_found_yet_running": "❌ Pago aún no encontrado. La verificación del pago sigue en curso. {unlock_text}",
    },
}
for _code, _items in _PAYMENT_ALERT_TRANSLATIONS.items():
    _TRANSLATIONS.setdefault(_code, {}).update(_items)
for _code in SUPPORTED_LANGUAGES:
    for _k, _v in _PAYMENT_ALERT_TRANSLATIONS["en"].items():
        _TRANSLATIONS[_code].setdefault(_k, _v)

_DISPUTE_TIMING_TRANSLATIONS = {
    "en": {"dispute_only_after_finished": "You can open a dispute only after this QR order is marked Done or Failed."},
    "id": {"dispute_only_after_finished": "Anda hanya dapat membuka sengketa setelah pesanan QR ini ditandai Selesai atau Gagal."},
    "vi": {"dispute_only_after_finished": "Bạn chỉ có thể mở tranh chấp sau khi đơn QR này được đánh dấu Hoàn tất hoặc Thất bại."},
    "zh": {"dispute_only_after_finished": "只有在此 QR 订单标记为完成或失败后，才能开启争议。"},
    "es": {"dispute_only_after_finished": "Solo puedes abrir una disputa después de que este pedido QR esté marcado como Completado o Fallido."},
}
for _code, _items in _DISPUTE_TIMING_TRANSLATIONS.items():
    _TRANSLATIONS.setdefault(_code, {}).update(_items)
for _code in SUPPORTED_LANGUAGES:
    for _k, _v in _DISPUTE_TIMING_TRANSLATIONS["en"].items():
        _TRANSLATIONS[_code].setdefault(_k, _v)


_SUPPORT_FALLBACK_TRANSLATIONS = {
    "en": {"support_not_configured": "Support is not configured yet. Please contact the owner."},
    "id": {"support_not_configured": "Dukungan belum dikonfigurasi. Silakan hubungi pemilik."},
    "vi": {"support_not_configured": "Hỗ trợ chưa được cấu hình. Vui lòng liên hệ chủ sở hữu."},
    "zh": {"support_not_configured": "尚未配置支持信息。请联系所有者。"},
    "es": {"support_not_configured": "El soporte aún no está configurado. Contacta con el propietario."},
}
for _code, _items in _SUPPORT_FALLBACK_TRANSLATIONS.items():
    _TRANSLATIONS.setdefault(_code, {}).update(_items)
for _code in SUPPORTED_LANGUAGES:
    for _k, _v in _SUPPORT_FALLBACK_TRANSLATIONS["en"].items():
        _TRANSLATIONS[_code].setdefault(_k, _v)


def normalize_language_code(value: str | None) -> str:
    code = str(value or "").strip().lower()
    if code in {"english", "eng"}:
        return "en"
    if code in {"indonesian", "indo", "bahasa", "bahasa indonesia"}:
        return "id"
    if code in {"vietnamese", "viet", "tiếng việt", "tieng viet"}:
        return "vi"
    if code in {"chinese", "zh-cn", "zh_hans", "mandarin", "中文"}:
        return "zh"
    if code in {"spanish", "español", "espanol"}:
        return "es"
    return code if code in SUPPORTED_LANGUAGES else DEFAULT_LANGUAGE


def tr_lang(lang: str | None, key: str, **kwargs) -> str:
    lang = normalize_language_code(lang)
    text = _TRANSLATIONS.get(lang, {}).get(key) or _TRANSLATIONS[DEFAULT_LANGUAGE].get(key) or key
    try:
        return text.format(**kwargs)
    except Exception:
        return text


def get_user_language(chat_id: int | None) -> str:
    if chat_id is None:
        return DEFAULT_LANGUAGE
    try:
        with get_conn() as conn:
            row = conn.execute("SELECT language FROM user_languages WHERE chat_id = ?", (int(chat_id),)).fetchone()
        if row:
            return normalize_language_code(row["language"])
    except Exception:
        pass
    return DEFAULT_LANGUAGE


def tr_chat(chat_id: int | None, key: str, **kwargs) -> str:
    return tr_lang(get_user_language(chat_id), key, **kwargs)


def mark_first_start_seen(chat_id: int) -> bool:
    """Return True when this is the first /start we have seen for this chat."""
    with get_conn() as conn:
        row = conn.execute("SELECT first_start_seen FROM user_languages WHERE chat_id = ?", (int(chat_id),)).fetchone()
        if row:
            if int(row["first_start_seen"] or 0):
                return False
            conn.execute(
                "UPDATE user_languages SET first_start_seen = 1, updated_at = ? WHERE chat_id = ?",
                (now_iso(), int(chat_id)),
            )
            return True
        conn.execute(
            "INSERT INTO user_languages(chat_id, language, first_start_seen, updated_at) VALUES (?, ?, 1, ?)",
            (int(chat_id), DEFAULT_LANGUAGE, now_iso()),
        )
    return True


def set_user_language(chat_id: int, language: str) -> str:
    code = normalize_language_code(language)
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO user_languages(chat_id, language, first_start_seen, updated_at)
            VALUES (?, ?, 1, ?)
            ON CONFLICT(chat_id) DO UPDATE SET
                language = excluded.language,
                first_start_seen = 1,
                updated_at = excluded.updated_at
            """,
            (int(chat_id), code, now_iso()),
        )
    return code


def language_selection_keyboard(chat_id: int | None = None, include_back: bool = False) -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton("🇬🇧 English", callback_data="language:set:en")],
        [InlineKeyboardButton("🇮🇩 Bahasa Indonesia", callback_data="language:set:id")],
        [InlineKeyboardButton("🇻🇳 Tiếng Việt", callback_data="language:set:vi")],
        [InlineKeyboardButton("🇨🇳 中文", callback_data="language:set:zh")],
        [InlineKeyboardButton("🇪🇸 Español", callback_data="language:set:es")],
    ]
    if include_back:
        rows.append([InlineKeyboardButton(tr_chat(chat_id, "btn_back"), callback_data="nav:home")])
    return InlineKeyboardMarkup(rows)


def language_selection_text(chat_id: int | None = None) -> str:
    return f"{tr_chat(chat_id, 'choose_language')}\n\n{tr_chat(chat_id, 'language_menu_hint')}"


def language_options_html(selected: str | None = None, include_all: bool = False) -> str:
    selected = normalize_language_code(selected)
    options = []
    if include_all:
        options.append('<option value="all">All languages</option>')
    for code, meta in SUPPORTED_LANGUAGES.items():
        sel = ' selected' if code == selected and not include_all else ''
        options.append(f'<option value="{html.escape(code)}"{sel}>{html.escape(meta["name"])} / {html.escape(meta["native"])}</option>')
    return "".join(options)


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
        "receiver_warning_sent_at": "TEXT",
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
    _add_column_if_missing(conn, "disputes", "admin_seen_message_id", "INTEGER NOT NULL DEFAULT 0")
    try:
        rows = conn.execute("SELECT id FROM disputes WHERE ref_id IS NULL OR ref_id = ''").fetchall()
        for row in rows:
            conn.execute("UPDATE disputes SET ref_id = ? WHERE id = ?", (generate_dispute_ref(conn), row["id"]))
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_disputes_ref_id ON disputes(ref_id)")
    except Exception:
        logger.exception("Could not backfill dispute references")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS dispute_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            dispute_id INTEGER NOT NULL,
            sender_type TEXT NOT NULL CHECK(sender_type IN ('user','admin')),
            sender_chat_id INTEGER,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(dispute_id) REFERENCES disputes(id) ON DELETE CASCADE
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_dispute_messages_dispute ON dispute_messages(dispute_id, created_at)")
    try:
        rows = conn.execute(
            """
            SELECT d.id, d.chat_id, d.message, d.created_at
            FROM disputes d
            LEFT JOIN dispute_messages m ON m.dispute_id = d.id
            WHERE m.id IS NULL
            """
        ).fetchall()
        for row in rows:
            conn.execute(
                "INSERT INTO dispute_messages(dispute_id, sender_type, sender_chat_id, message, created_at) VALUES (?, 'user', ?, ?, ?)",
                (row["id"], row["chat_id"], row["message"], row["created_at"] or now_iso()),
            )
    except Exception:
        logger.exception("Could not backfill dispute chat messages")

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

            CREATE TABLE IF NOT EXISTS user_languages (
                chat_id INTEGER PRIMARY KEY,
                language TEXT NOT NULL DEFAULT 'en',
                first_start_seen INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
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
                receiver_warning_sent_at TEXT,
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
                admin_note TEXT,
                admin_seen_message_id INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS dispute_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dispute_id INTEGER NOT NULL,
                sender_type TEXT NOT NULL CHECK(sender_type IN ('user','admin')),
                sender_chat_id INTEGER,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(dispute_id) REFERENCES disputes(id) ON DELETE CASCADE
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
            CREATE INDEX IF NOT EXISTS idx_dispute_messages_dispute ON dispute_messages(dispute_id, created_at);
            """
        )
        _migrate_db(conn)


def now_dt() -> datetime:
    return datetime.now(ZoneInfo(BOT_TZ))


def now_iso() -> str:
    # Keep ISO only for database storage. User-facing messages use display_datetime().
    return now_dt().isoformat(timespec="seconds")


def parse_bot_datetime(value: str | datetime | None) -> datetime | None:
    """Parse bot/database timestamps safely in BOT_TZ.

    SQLite stores timestamps as ISO strings.  Comparing those strings directly can
    be wrong if an offset or timezone format changes, so all QR expiry checks go
    through this parser and compare real datetimes instead.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value or "").strip()
        if not text:
            return None
        try:
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            dt = datetime.fromisoformat(text)
        except Exception:
            return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=ZoneInfo(BOT_TZ))
    return dt.astimezone(ZoneInfo(BOT_TZ))


def iso_is_due(value: str | datetime | None, now_value: datetime | None = None) -> bool:
    dt = parse_bot_datetime(value)
    if dt is None:
        return False
    return dt <= (now_value or now_dt())


def seconds_until_iso(value: str | datetime | None) -> int:
    dt = parse_bot_datetime(value)
    if dt is None:
        return 0
    return max(0, int(dt.timestamp() - now_dt().timestamp()))


def seconds_since_iso(value: str | datetime | None) -> int:
    dt = parse_bot_datetime(value)
    if dt is None:
        return 0
    return max(0, int(now_dt().timestamp() - dt.timestamp()))

def format_time_left_for_chat(chat_id: int | None, expires_at: str | datetime | None) -> str:
    seconds = seconds_until_iso(expires_at)
    if seconds <= 0:
        return tr_chat(chat_id, "time_expired")
    minutes, secs = divmod(seconds, 60)
    if minutes <= 0:
        return tr_chat(chat_id, "time_seconds", seconds=secs)
    return tr_chat(chat_id, "time_minutes_seconds", minutes=minutes, seconds=secs)


def format_time_left_for_lang(lang: str | None, expires_at: str | datetime | None) -> str:
    seconds = seconds_until_iso(expires_at)
    if seconds <= 0:
        return tr_lang(lang, "time_expired")
    minutes, secs = divmod(seconds, 60)
    if minutes <= 0:
        return tr_lang(lang, "time_seconds", seconds=secs)
    return tr_lang(lang, "time_minutes_seconds", minutes=minutes, seconds=secs)


def qr_expiry_status_at(row: sqlite3.Row | None) -> str:
    """Return the timestamp that should be used when a QR expires.

    Even if the background watcher processes an expired QR late, the admin panel
    should show the configured expiry time, not the delayed processing time.
    """
    if row is not None:
        try:
            expires_at = str(row["offer_expires_at"] or "").strip()
            if expires_at:
                return expires_at
        except Exception:
            pass
    return now_iso()


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


def _admin_id_clause(column: str = "u.chat_id") -> tuple[str, list[int]]:
    """Return a SQL clause/params for configured Telegram admin IDs.

    Admins are a virtual permission layer. They are not removed from user-facing
    recipient lists; this helper lets role-based lists include them when needed.
    """
    ids = sorted(int(x) for x in ADMIN_IDS)
    if not ids:
        return "0", []
    return f"{column} IN ({','.join(['?'] * len(ids))})", ids


def get_user_for_chat(chat_id: int | None) -> UserRow | None:
    if chat_id is None:
        return None
    user = get_user(chat_id)
    if user:
        return user
    if is_admin(chat_id):
        return ensure_default_sender_user(chat_id)
    return None


def is_active_user_or_admin(chat_id: int | None, user: UserRow | None = None) -> bool:
    if chat_id is not None and is_admin(chat_id):
        return True
    return bool(user and user.active)


def can_use_sender_features(chat_id: int | None, user: UserRow | None = None) -> bool:
    if chat_id is not None and is_admin(chat_id):
        return True
    return bool(user and user.active and user.role == "sender")


def can_use_receiver_features(chat_id: int | None, user: UserRow | None = None) -> bool:
    if chat_id is not None and is_admin(chat_id):
        return True
    return bool(user and user.active and user.role == "receiver")


def effective_role_label(chat_id: int | None, user: UserRow | None = None) -> str:
    if chat_id is not None and is_admin(chat_id):
        return "admin"
    if user and user.active:
        return user.role
    return "unregistered"


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


def _user_search_terms(search: str | None) -> list[str]:
    """Build forgiving search terms for admin user search.

    Handles common admin inputs such as @username, username, full names,
    Telegram IDs copied with spaces, and partial fragments.
    """
    raw = (search or "").strip().lower()
    if not raw:
        return []
    candidates: list[str] = [raw]

    no_at = raw.lstrip("@").strip()
    if no_at and no_at != raw:
        candidates.append(no_at)

    compact = re.sub(r"[\s@+()\-_.]+", "", raw)
    if compact and compact != raw:
        candidates.append(compact)

    digits = re.sub(r"\D+", "", raw)
    if len(digits) >= 3:
        candidates.append(digits)

    # Also match individual words/tokens so searching "@user", "first last",
    # or copied labels like "ID: 123456" still works.
    for token in re.split(r"[\s,;:/|]+", raw):
        token = token.strip().lstrip("@").strip()
        if token:
            candidates.append(token)
            token_digits = re.sub(r"\D+", "", token)
            if len(token_digits) >= 3:
                candidates.append(token_digits)

    seen: set[str] = set()
    terms: list[str] = []
    for item in candidates:
        item = item.strip().lower()
        if not item or item in seen:
            continue
        seen.add(item)
        terms.append(item)
    return terms[:12]


def list_users(
    role: str | None = None,
    limit: int = 100,
    search: str | None = None,
    active: bool | None = None,
) -> list[sqlite3.Row]:
    with get_conn() as conn:
        base = """
            SELECT
                u.*,
                p.username,
                p.first_name,
                p.last_name,
                p.last_seen_at,
                COALESCE(w.balance_usdt, 0) AS wallet_balance_usdt,
                COALESCE(w.reserved_usdt, 0) AS wallet_reserved_usdt,
                COALESCE(w.earned_usdt, 0) AS wallet_earned_usdt,
                COALESCE(w.paid_usdt, 0) AS wallet_paid_usdt,
                COALESCE(pr.pending_payout_usdt, 0) AS wallet_pending_payout_usdt
            FROM users u
            LEFT JOIN telegram_profiles p ON p.chat_id = u.chat_id
            LEFT JOIN wallets w ON w.chat_id = u.chat_id
            LEFT JOIN (
                SELECT receiver_chat_id, COALESCE(SUM(amount_usdt), 0) AS pending_payout_usdt
                FROM payout_requests
                WHERE status = 'pending'
                GROUP BY receiver_chat_id
            ) pr ON pr.receiver_chat_id = u.chat_id
        """
        where: list[str] = []
        params: list[object] = []

        if role in {"sender", "receiver"}:
            where.append("u.role = ?")
            params.append(role)

        if active is not None:
            where.append("u.active = ?")
            params.append(1 if active else 0)

        terms = _user_search_terms(search)
        if terms:
            term_clauses: list[str] = []
            searchable_fields = [
                "LOWER(CAST(u.chat_id AS TEXT))",
                "LOWER(COALESCE(u.alias, ''))",
                "LOWER(COALESCE(u.role, ''))",
                "LOWER(COALESCE(p.username, ''))",
                "LOWER('@' || COALESCE(p.username, ''))",
                "LOWER(COALESCE(p.first_name, ''))",
                "LOWER(COALESCE(p.last_name, ''))",
                "LOWER(TRIM(COALESCE(p.first_name, '') || ' ' || COALESCE(p.last_name, '')))",
                "LOWER(TRIM(COALESCE(p.last_name, '') || ' ' || COALESCE(p.first_name, '')))",
            ]
            for term in terms:
                like = f"%{term}%"
                term_clauses.append("(" + " OR ".join(f"{field} LIKE ?" for field in searchable_fields) + ")")
                params.extend([like] * len(searchable_fields))
            where.append("(" + " OR ".join(term_clauses) + ")")

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


def sender_lifetime_balance_used(chat_id: int) -> Decimal:
    """Total sender wallet balance actually used on currently completed QR orders."""
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT COALESCE(SUM(charged_usdt), 0) AS total
            FROM photos
            WHERE sender_chat_id = ? AND status = 'done'
            """,
            (int(chat_id),),
        ).fetchone()
    return _dec(row["total"] if row else 0)


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


def normalize_status_callback_action(value: object) -> str:
    """Accept only Done/Failed status actions while tolerating older localized callback data."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    compact = re.sub(r"[^a-z0-9]+", "_", raw.lower()).strip("_")
    if compact in {"done", "complete", "completed", "success", "successful", "ok"}:
        return "done"
    if compact in {"failed", "fail", "failure", "reject", "rejected"}:
        return "failed"
    text = raw.lower()
    done_markers = ("done", "complete", "completed", "success", "selesai", "hoàn tất", "hoan tat", "完成", "completado", "hecho")
    failed_markers = ("failed", "fail", "gagal", "thất bại", "that bai", "失败", "fallido")
    if any(marker in text for marker in done_markers):
        return "done"
    if any(marker in text for marker in failed_markers):
        return "failed"
    return ""


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


def _stats_block(label: str, counts: dict[str, int | str], chat_id: int | None = None) -> str:
    return (
        f"{label}\n"
        f"📦 {tr_chat(chat_id, 'stats_total')}: {counts['total']}\n"
        f"⏳ {tr_chat(chat_id, 'stats_pending')}: {counts['pending']}\n"
        f"✅ {tr_chat(chat_id, 'stats_done')}: {counts['done']}\n"
        f"❌ {tr_chat(chat_id, 'stats_failed')}: {counts['failed']}"
    )


def _localized_stats_title(title: str, chat_id: int | None = None) -> str:
    clean_title = str(title or "").strip().rstrip(":")
    low = clean_title.lower()
    if low == "your sender stats":
        return tr_chat(chat_id, "stats_sender_title")
    if low == "your receiver stats":
        return tr_chat(chat_id, "stats_receiver_title")
    return clean_title


def stats_summary_text(
    title: str,
    *,
    sender_chat_id: int | None = None,
    receiver_chat_id: int | None = None,
    chat_id: int | None = None,
) -> str:
    today = stats_for_filters(scope="today", sender_chat_id=sender_chat_id, receiver_chat_id=receiver_chat_id)
    lifetime = stats_for_filters(scope="lifetime", sender_chat_id=sender_chat_id, receiver_chat_id=receiver_chat_id)

    clean_title = _localized_stats_title(title, chat_id)
    today_label = tr_chat(chat_id, "stats_today", date=display_date(str(today['scope'])))
    lifetime_label = tr_chat(chat_id, "stats_lifetime")
    return (
        f"📊 {clean_title}\n\n"
        f"{_stats_block(today_label, today, chat_id)}\n\n"
        f"{_stats_block(lifetime_label, lifetime, chat_id)}"
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


# SQLite stores monetary values as REAL in this project. Repeated 0.50/0.10 style
# additions can come back as values such as 9.999999999 even though the UI correctly
# displays them as $10.00. Use a tiny tolerance only for eligibility checks so a
# receiver with a displayed $10.00 balance can withdraw against a $10.00 minimum.
USDT_COMPARE_EPSILON = Decimal("0.000001")


def _usdt_lt(left, right) -> bool:
    return _dec(left) < (_dec(right) - USDT_COMPARE_EPSILON)


def _usdt_gt(left, right) -> bool:
    return _dec(left) > (_dec(right) + USDT_COMPARE_EPSILON)


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


def setting_sender_rate_decimal() -> Decimal:
    """Sender charge per completed scan.

    Older installs/settings can contain sender_rate_usdt=0 because the original
    environment default was 0.  That made QR captions show Reserved $0.00 and
    could make completion settle at $0.00.  Treat a zero/blank saved sender rate
    as the configured default charge (0.50 USDT unless DEFAULT_SENDER_RATE_USDT
    is explicitly changed).  This preserves the intended per-order charge while
    still allowing operators to change the rate from the admin Marketplace page.
    """
    amount = setting_decimal("sender_rate_usdt", DEFAULT_SENDER_RATE_USDT)
    default_amount = _dec(DEFAULT_SENDER_RATE_USDT, "0.50")
    if amount <= 0 and default_amount > 0:
        return default_amount
    return max(Decimal("0"), amount)


def get_marketplace_settings() -> dict[str, Decimal | int | bool | str]:
    return {
        "maintenance_mode": setting_bool("maintenance_mode", False),
        "sender_rate_usdt": setting_sender_rate_decimal(),
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


def _row_dec(row, key: str, default: Decimal | str | int | float = "0") -> Decimal:
    """Safely read a Decimal from sqlite rows/dicts without crashing on older schemas."""
    try:
        if row is not None and hasattr(row, "keys") and key in row.keys():
            return _dec(row[key], default)
        if isinstance(row, dict) and key in row:
            return _dec(row.get(key), default)
    except Exception:
        pass
    return _dec(default)


def effective_sender_charge_amount(row, *, use_current_setting_if_missing: bool = False) -> Decimal:
    """Return the money that belongs to this QR order.

    Some older/in-progress rows can have sender_rate_usdt saved as 0 after UI/text
    changes, even though a reserve exists in photos.reserved_usdt or the sender wallet.
    For settlement and captions, use the strongest order snapshot available instead of
    trusting only sender_rate_usdt.  This keeps language translations from affecting
    monetary values and prevents showing/charging $0.00 for a $0.50 reserved order.
    """
    candidates = [
        _row_dec(row, "charged_usdt"),
        _row_dec(row, "reserved_usdt"),
        _row_dec(row, "sender_rate_usdt"),
    ]
    amount = max([c for c in candidates if c is not None] or [Decimal("0")])
    if amount <= 0 and use_current_setting_if_missing:
        try:
            amount = _dec(get_marketplace_settings().get("sender_rate_usdt", "0"))
        except Exception:
            amount = Decimal("0")
    return max(Decimal("0"), amount)


def effective_sender_reserved_display(row, fallback_amount: Decimal | str | float | int | None = None) -> Decimal:
    """Amount to show on sender QR captions as Reserved.

    Prefer the per-order reserved/charged snapshot.  If the row is not available, use
    the supplied fallback amount.  As a last resort for still-pending QR captions, use
    the current admin sender rate so users never see $0.00 when the configured charge
    is $0.50.
    """
    amount = effective_sender_charge_amount(row, use_current_setting_if_missing=False) if row is not None else Decimal("0")
    if amount <= 0 and fallback_amount is not None:
        amount = _dec(fallback_amount)
    if amount <= 0:
        try:
            amount = _dec(get_marketplace_settings().get("sender_rate_usdt", "0"))
        except Exception:
            amount = Decimal("0")
    return max(Decimal("0"), amount)

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
        sender_rate = effective_sender_charge_amount(row, use_current_setting_if_missing=True)
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


def normalize_admin_order_status(value: object) -> str:
    """Return the internal QR status value accepted by admin override forms.

    Older/mobile browsers, custom buttons, or copied UI labels may submit values such as
    "✅ Done", "❌ Failed", "Done → Failed", or "mark_failed" instead of the exact
    internal database values.  Keep the public UI forgiving while storing only canonical
    values in the database.  If both Done and Failed appear in one label, the last
    matching word wins, so "Done → Failed" becomes "failed".
    """
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    compact = re.sub(r"[^a-z0-9]+", "_", raw).strip("_")
    done_words = {"done", "complete", "completed", "success", "successful", "ok", "approved"}
    failed_words = {"failed", "fail", "failure", "rejected", "reject", "cancelled", "canceled"}
    matches: list[tuple[int, str]] = []
    for word in done_words:
        idx = compact.rfind(word)
        if idx >= 0:
            matches.append((idx, "done"))
    for word in failed_words:
        idx = compact.rfind(word)
        if idx >= 0:
            matches.append((idx, "failed"))
    if not matches:
        return ""
    return max(matches, key=lambda item: item[0])[1]

def admin_override_photo_status(public_id: str, new_status: str, *, failure_reason: str | None = None, status_by: int | None = None) -> tuple[bool, str, dict | None]:
    """Change any QR order status from the admin panel and keep wallet balances in sync.

    Supported admin transitions:
    - pending -> done: charge the sender reserve and credit receiver earnings;
    - pending -> failed: release the sender reserve;
    - done -> failed: refund the sender and deduct that order's receiver earning;
    - failed -> done: charge the sender again and credit the receiver.
    """
    public_id = str(public_id or "").strip()
    target_status = normalize_admin_order_status(new_status)
    if not public_id:
        return False, "QR ID is missing.", None
    if target_status not in {"done", "failed"}:
        return False, "Admin can change an order only to Done or Failed.", None

    clean_reason = clean_failure_reason_text(failure_reason or "Changed by admin") if target_status == "failed" else None
    admin_chat_id = int(status_by or 0)

    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM photos WHERE public_id = ?", (public_id,)).fetchone()
        if not row:
            conn.rollback()
            return False, "QR order not found.", None

        old_status = str(row["status"] or "pending").strip().lower()
        if old_status == target_status:
            conn.rollback()
            return False, f"QR order is already marked {target_status.upper()}.", {"row_before": row, "row_after": row, "old_status": old_status, "new_status": target_status}
        if old_status not in {"pending", "done", "failed"}:
            conn.rollback()
            return False, f"Cannot change unsupported current status: {old_status}.", None

        sender_chat_id = int(row["sender_chat_id"])
        receiver_chat_id = int(row["receiver_chat_id"] or 0)
        sender_rate = effective_sender_charge_amount(row, use_current_setting_if_missing=True)
        receiver_rate = _dec(row["receiver_rate_usdt"])
        charged_prev = _dec(row["charged_usdt"])
        earned_prev = _dec(row["earned_usdt"])
        charge_amount = charged_prev if charged_prev > 0 else sender_rate
        earn_amount = earned_prev if earned_prev > 0 else receiver_rate

        if target_status == "done" and receiver_chat_id <= 0:
            conn.rollback()
            return False, "Cannot mark an unclaimed QR as Done because there is no receiver to credit.", None

        now = now_iso()
        _wallet_snapshot(conn, sender_chat_id)
        if receiver_chat_id:
            _wallet_snapshot(conn, receiver_chat_id)

        sender_amount = Decimal("0")
        receiver_amount = Decimal("0")
        sender_effect = "none"
        receiver_effect = "none"
        sender_balance_after = Decimal("0")
        receiver_balance_after = Decimal("0")

        if old_status == "pending" and target_status == "done":
            sender_wallet = conn.execute("SELECT * FROM wallets WHERE chat_id = ?", (sender_chat_id,)).fetchone()
            if _dec(sender_wallet["balance_usdt"]) < charge_amount:
                conn.rollback()
                return False, f"Sender wallet balance is too low to mark Done. Required: ${_money(charge_amount)} USDT.", None
            reserve_release = min(_dec(sender_wallet["reserved_usdt"]), charge_amount)
            conn.execute(
                "UPDATE wallets SET reserved_usdt = MAX(0, reserved_usdt - ?), balance_usdt = balance_usdt - ?, updated_at = ? WHERE chat_id = ?",
                (float(reserve_release), float(charge_amount), now, sender_chat_id),
            )
            updated_sender = conn.execute("SELECT * FROM wallets WHERE chat_id = ?", (sender_chat_id,)).fetchone()
            sender_balance_after = _dec(updated_sender["balance_usdt"])
            sender_amount = -charge_amount
            sender_effect = "charged"
            conn.execute(
                "INSERT INTO wallet_ledger(chat_id, kind, amount_usdt, balance_after, note, related_id, created_at) VALUES (?, 'admin_order_charge', ?, ?, ?, ?, ?)",
                (sender_chat_id, -float(charge_amount), float(sender_balance_after), "Admin changed QR order to done", public_id, now),
            )
            if receiver_chat_id and earn_amount > 0:
                conn.execute(
                    "UPDATE wallets SET earned_usdt = earned_usdt + ?, updated_at = ? WHERE chat_id = ?",
                    (float(earn_amount), now, receiver_chat_id),
                )
                updated_receiver = conn.execute("SELECT * FROM wallets WHERE chat_id = ?", (receiver_chat_id,)).fetchone()
                receiver_balance_after = _dec(updated_receiver["earned_usdt"]) - _dec(updated_receiver["paid_usdt"])
                receiver_amount = earn_amount
                receiver_effect = "credited"
                conn.execute(
                    "INSERT INTO wallet_ledger(chat_id, kind, amount_usdt, balance_after, note, related_id, created_at) VALUES (?, 'admin_order_earning', ?, ?, ?, ?, ?)",
                    (receiver_chat_id, float(earn_amount), float(receiver_balance_after), "Admin changed QR order to done", public_id, now),
                )
            charged_value = charge_amount
            earned_value = earn_amount if receiver_chat_id else Decimal("0")

        elif old_status == "pending" and target_status == "failed":
            sender_wallet = conn.execute("SELECT * FROM wallets WHERE chat_id = ?", (sender_chat_id,)).fetchone()
            reserve_release = min(_dec(sender_wallet["reserved_usdt"]), charge_amount)
            conn.execute(
                "UPDATE wallets SET reserved_usdt = MAX(0, reserved_usdt - ?), updated_at = ? WHERE chat_id = ?",
                (float(reserve_release), now, sender_chat_id),
            )
            updated_sender = conn.execute("SELECT * FROM wallets WHERE chat_id = ?", (sender_chat_id,)).fetchone()
            sender_balance_after = _dec(updated_sender["balance_usdt"]) - _dec(updated_sender["reserved_usdt"])
            sender_amount = reserve_release
            sender_effect = "reserve_released"
            conn.execute(
                "INSERT INTO wallet_ledger(chat_id, kind, amount_usdt, balance_after, note, related_id, created_at) VALUES (?, 'admin_order_release', ?, ?, ?, ?, ?)",
                (sender_chat_id, float(reserve_release), float(sender_balance_after), "Admin changed QR order to failed", public_id, now),
            )
            charged_value = Decimal("0")
            earned_value = Decimal("0")

        elif old_status == "done" and target_status == "failed":
            refund_amount = charge_amount
            deduct_amount = earn_amount if receiver_chat_id else Decimal("0")
            if receiver_chat_id and deduct_amount > 0:
                receiver_wallet = conn.execute("SELECT * FROM wallets WHERE chat_id = ?", (receiver_chat_id,)).fetchone()
                new_earned = _dec(receiver_wallet["earned_usdt"]) - deduct_amount
                paid = _dec(receiver_wallet["paid_usdt"])
                if new_earned < paid:
                    conn.rollback()
                    return False, (
                        "Cannot deduct this receiver earning because it would go below already-paid payout amount. "
                        "Adjust/review the receiver payout first."
                    ), None
            if refund_amount > 0:
                conn.execute(
                    "UPDATE wallets SET balance_usdt = balance_usdt + ?, updated_at = ? WHERE chat_id = ?",
                    (float(refund_amount), now, sender_chat_id),
                )
                updated_sender = conn.execute("SELECT * FROM wallets WHERE chat_id = ?", (sender_chat_id,)).fetchone()
                sender_balance_after = _dec(updated_sender["balance_usdt"])
                sender_amount = refund_amount
                sender_effect = "refunded"
                conn.execute(
                    "INSERT INTO wallet_ledger(chat_id, kind, amount_usdt, balance_after, note, related_id, created_at) VALUES (?, 'admin_order_refund', ?, ?, ?, ?, ?)",
                    (sender_chat_id, float(refund_amount), float(sender_balance_after), "Admin changed QR order from done to failed", public_id, now),
                )
            if receiver_chat_id and deduct_amount > 0:
                conn.execute(
                    "UPDATE wallets SET earned_usdt = earned_usdt - ?, updated_at = ? WHERE chat_id = ?",
                    (float(deduct_amount), now, receiver_chat_id),
                )
                updated_receiver = conn.execute("SELECT * FROM wallets WHERE chat_id = ?", (receiver_chat_id,)).fetchone()
                receiver_balance_after = _dec(updated_receiver["earned_usdt"]) - _dec(updated_receiver["paid_usdt"])
                receiver_amount = -deduct_amount
                receiver_effect = "deducted"
                conn.execute(
                    "INSERT INTO wallet_ledger(chat_id, kind, amount_usdt, balance_after, note, related_id, created_at) VALUES (?, 'admin_order_earning_reversal', ?, ?, ?, ?, ?)",
                    (receiver_chat_id, -float(deduct_amount), float(receiver_balance_after), "Admin changed QR order from done to failed", public_id, now),
                )
            charged_value = Decimal("0")
            earned_value = Decimal("0")

        elif old_status == "failed" and target_status == "done":
            sender_wallet = conn.execute("SELECT * FROM wallets WHERE chat_id = ?", (sender_chat_id,)).fetchone()
            available = _dec(sender_wallet["balance_usdt"]) - _dec(sender_wallet["reserved_usdt"])
            if available < charge_amount:
                conn.rollback()
                return False, f"Sender available balance is too low to mark Done. Available: ${_money(available)} USDT, required: ${_money(charge_amount)} USDT.", None
            if charge_amount > 0:
                conn.execute(
                    "UPDATE wallets SET balance_usdt = balance_usdt - ?, updated_at = ? WHERE chat_id = ?",
                    (float(charge_amount), now, sender_chat_id),
                )
                updated_sender = conn.execute("SELECT * FROM wallets WHERE chat_id = ?", (sender_chat_id,)).fetchone()
                sender_balance_after = _dec(updated_sender["balance_usdt"])
                sender_amount = -charge_amount
                sender_effect = "charged"
                conn.execute(
                    "INSERT INTO wallet_ledger(chat_id, kind, amount_usdt, balance_after, note, related_id, created_at) VALUES (?, 'admin_order_charge', ?, ?, ?, ?, ?)",
                    (sender_chat_id, -float(charge_amount), float(sender_balance_after), "Admin changed QR order from failed to done", public_id, now),
                )
            if receiver_chat_id and earn_amount > 0:
                conn.execute(
                    "UPDATE wallets SET earned_usdt = earned_usdt + ?, updated_at = ? WHERE chat_id = ?",
                    (float(earn_amount), now, receiver_chat_id),
                )
                updated_receiver = conn.execute("SELECT * FROM wallets WHERE chat_id = ?", (receiver_chat_id,)).fetchone()
                receiver_balance_after = _dec(updated_receiver["earned_usdt"]) - _dec(updated_receiver["paid_usdt"])
                receiver_amount = earn_amount
                receiver_effect = "credited"
                conn.execute(
                    "INSERT INTO wallet_ledger(chat_id, kind, amount_usdt, balance_after, note, related_id, created_at) VALUES (?, 'admin_order_earning', ?, ?, ?, ?, ?)",
                    (receiver_chat_id, float(earn_amount), float(receiver_balance_after), "Admin changed QR order from failed to done", public_id, now),
                )
            charged_value = charge_amount
            earned_value = earn_amount if receiver_chat_id else Decimal("0")
        else:
            conn.rollback()
            return False, f"Unsupported status change: {old_status.upper()} → {target_status.upper()}.", None

        current_offer_state = str(row["offer_state"] or "claimed")
        if target_status == "done" and receiver_chat_id:
            new_offer_state = "claimed"
        elif target_status == "failed" and old_status == "pending":
            new_offer_state = "expired"
        else:
            new_offer_state = current_offer_state

        conn.execute(
            """
            UPDATE photos
            SET status = ?, status_by = ?, status_at = ?, failure_reason = ?,
                offer_state = ?, charged_usdt = ?, earned_usdt = ?, settled_at = ?
            WHERE public_id = ?
            """,
            (
                target_status,
                admin_chat_id,
                now,
                clean_reason,
                new_offer_state,
                float(charged_value),
                float(earned_value),
                now,
                public_id,
            ),
        )
        row_after = conn.execute("SELECT * FROM photos WHERE public_id = ?", (public_id,)).fetchone()
        conn.commit()

    msg = f"QR order {public_id} changed from {old_status.upper()} to {target_status.upper()}."
    if sender_effect == "refunded":
        msg += f" Sender refunded ${_money(abs(sender_amount))} USDT."
    elif sender_effect == "reserve_released":
        msg += f" Sender reserve released ${_money(abs(sender_amount))} USDT."
    elif sender_effect == "charged":
        msg += f" Sender charged ${_money(abs(sender_amount))} USDT."
    if receiver_effect == "deducted":
        msg += f" Receiver earnings deducted ${_money(abs(receiver_amount))} USDT."
    elif receiver_effect == "credited":
        msg += f" Receiver credited ${_money(abs(receiver_amount))} USDT."

    return True, msg, {
        "public_id": public_id,
        "row_before": row,
        "row_after": row_after,
        "old_status": old_status,
        "new_status": target_status,
        "failure_reason": clean_reason,
        "sender_chat_id": sender_chat_id,
        "receiver_chat_id": receiver_chat_id,
        "sender_amount": sender_amount,
        "receiver_amount": receiver_amount,
        "sender_effect": sender_effect,
        "receiver_effect": receiver_effect,
        "sender_balance_after": sender_balance_after,
        "receiver_balance_after": receiver_balance_after,
    }


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
    admin_clause, admin_params = _admin_id_clause("u.chat_id")
    role_clause = f"(u.role = 'receiver' OR {admin_clause})"
    with get_conn() as conn:
        return conn.execute(
            f"""
            SELECT r.*, u.alias, u.active, p.username, p.first_name, p.last_name
            FROM receiver_presence r
            JOIN users u ON u.chat_id = r.chat_id
            LEFT JOIN telegram_profiles p ON p.chat_id = r.chat_id
            WHERE r.online = 1 AND r.limit_remaining > 0 AND {role_clause} AND u.active = 1
            ORDER BY r.updated_at ASC
            LIMIT ?
            """,
            [*admin_params, limit],
        ).fetchall()


def active_receivers(limit: int = 1000) -> list[sqlite3.Row]:
    """All active receiver-side recipients for marketplace preset-message broadcasts.

    Admin IDs are included as virtual admins, not excluded from user-facing delivery.
    QR offers still require /on LIMIT and use online_receivers().
    """
    admin_clause, admin_params = _admin_id_clause("u.chat_id")
    role_clause = f"(u.role = 'receiver' OR {admin_clause})"
    with get_conn() as conn:
        return conn.execute(
            f"""
            SELECT u.*, p.username, p.first_name, p.last_name
            FROM users u
            LEFT JOIN telegram_profiles p ON p.chat_id = u.chat_id
            WHERE {role_clause} AND u.active = 1 AND u.chat_id != 0
            ORDER BY u.updated_at DESC
            LIMIT ?
            """,
            [*admin_params, limit],
        ).fetchall()


def total_marketplace_capacity() -> int:
    """Return total live marketplace capacity across all online receivers.

    This is intentionally an aggregate number only. It does not expose which
    receiver changed their limit, nor any receiver name, username, or chat ID.
    """
    return sum(int(r["limit_remaining"] or 0) for r in online_receivers())


def active_senders(limit: int = 1000) -> list[sqlite3.Row]:
    admin_clause, admin_params = _admin_id_clause("u.chat_id")
    role_clause = f"(u.role = 'sender' OR {admin_clause})"
    with get_conn() as conn:
        return conn.execute(
            f"""
            SELECT u.*, p.username, p.first_name, p.last_name
            FROM users u
            LEFT JOIN telegram_profiles p ON p.chat_id = u.chat_id
            WHERE {role_clause} AND u.active = 1 AND u.chat_id != 0
            ORDER BY u.updated_at DESC
            LIMIT ?
            """,
            [*admin_params, limit],
        ).fetchall()


def users_for_language_broadcast(language: str = "all", role: str = "all", limit: int = 10000) -> list[sqlite3.Row]:
    language = str(language or "all").strip().lower()
    if language != "all":
        language = normalize_language_code(language)
    role = str(role or "all").strip().lower()
    if role not in {"all", "sender", "receiver", "admin"}:
        role = "all"
    clauses = ["u.active = 1", "u.chat_id != 0"]
    params: list[Any] = []
    if role == "admin":
        admin_clause, admin_params = _admin_id_clause("u.chat_id")
        clauses.append(admin_clause)
        params.extend(admin_params)
    elif role != "all":
        admin_clause, admin_params = _admin_id_clause("u.chat_id")
        clauses.append(f"(u.role = ? OR {admin_clause})")
        params.append(role)
        params.extend(admin_params)
    if language != "all":
        clauses.append("COALESCE(ul.language, ?) = ?")
        params.extend([DEFAULT_LANGUAGE, language])
    where = " AND ".join(clauses)
    params.append(max(1, int(limit or 10000)))
    with get_conn() as conn:
        return conn.execute(
            f"""
            SELECT u.*, COALESCE(ul.language, ?) AS language, p.username, p.first_name, p.last_name
            FROM users u
            LEFT JOIN user_languages ul ON ul.chat_id = u.chat_id
            LEFT JOIN telegram_profiles p ON p.chat_id = u.chat_id
            WHERE {where}
            ORDER BY u.updated_at DESC
            LIMIT ?
            """,
            [DEFAULT_LANGUAGE] + params,
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


def adjust_receiver_limit(chat_id: int, delta: int) -> tuple[int, int, bool]:
    """Adjust a receiver's current scan limit.

    Returns (limit_remaining, limit_total, online). The same delta is applied to
    both the session total and remaining count so /limit +5 adds five more
    possible scans and /limit -5 removes five from the current capacity.
    """
    delta = int(delta)
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM receiver_presence WHERE chat_id = ?", (int(chat_id),)).fetchone()
        if not row:
            if delta <= 0:
                return 0, 0, False
            total = delta
            remaining = delta
            online = True
            conn.execute(
                """
                INSERT INTO receiver_presence(chat_id, online, limit_total, limit_remaining, updated_at)
                VALUES (?, 1, ?, ?, ?)
                """,
                (int(chat_id), total, remaining, now_iso()),
            )
            return remaining, total, online
        total = max(0, int(row["limit_total"] or 0) + delta)
        remaining = max(0, int(row["limit_remaining"] or 0) + delta)
        if remaining > total:
            total = remaining
        online = remaining > 0
        conn.execute(
            "UPDATE receiver_presence SET limit_total = ?, limit_remaining = ?, online = ?, updated_at = ? WHERE chat_id = ?",
            (total, remaining, 1 if online else 0, now_iso(), int(chat_id)),
        )
        return remaining, total, online


def marketplace_status_text(for_chat_id: int | None = None) -> str:
    receivers = online_receivers()
    capacity = sum(int(r["limit_remaining"] or 0) for r in receivers)
    settings = get_marketplace_settings()
    text = (
        f"{tr_chat(for_chat_id, 'marketplace_status_title')}\n\n"
        f"{tr_chat(for_chat_id, 'marketplace_online_receivers', count=len(receivers))}\n"
        f"{tr_chat(for_chat_id, 'marketplace_capacity', capacity=capacity)}\n"
        f"{tr_chat(for_chat_id, 'marketplace_qr_expiry', minutes=settings['qr_expire_minutes'])}\n"
    )
    if settings["maintenance_mode"]:
        text += f"\n{tr_chat(for_chat_id, 'marketplace_maintenance_on')}\n"
    if for_chat_id:
        user = get_user(for_chat_id)
        if user and user.role == "sender":
            wallet = get_wallet(for_chat_id)
            rate = _dec(settings["sender_rate_usdt"])
            available = _dec(wallet["balance_usdt"]) - _dec(wallet["reserved_usdt"])
            text += f"\n{tr_chat(for_chat_id, 'marketplace_your_available_balance', amount=_money(available))}\n"
            if rate > 0:
                scans = str(max(0, int(available // rate)))
                text += f"{tr_chat(for_chat_id, 'marketplace_estimated_scans', scans=scans)}\n"
        elif user and user.role == "receiver":
            presence = receiver_presence_row(for_chat_id)
            if presence and presence["online"]:
                text += f"\n{tr_chat(for_chat_id, 'marketplace_receiver_online_status', remaining=presence['limit_remaining'], total=presence['limit_total'])}\n"
            else:
                text += f"\n{tr_chat(for_chat_id, 'marketplace_receiver_offline_status')}\n"
    return text


def build_offer_keyboard(public_id: str, chat_id: int | None = None) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[InlineKeyboardButton(tr_chat(chat_id, "btn_accept_scan"), callback_data=f"claim:{public_id}")]])


def build_offer_text(public_id: str, daily_no: int, sender_rate: Decimal, receiver_rate: Decimal, expires_at: str, chat_id: int | None = None) -> str:
    return (
        f"{tr_chat(chat_id, 'offer_new')}\n"
        f"🆔 {tr_chat(chat_id, 'offer_id')}: {public_id}\n"
        f"📷 {tr_chat(chat_id, 'caption_photo_today', daily_no=daily_no)}\n"
        f"⏱ {tr_chat(chat_id, 'caption_expires')}: {display_datetime(expires_at)}\n"
        f"{tr_chat(chat_id, 'receiver_time_left_line', time_left=format_time_left_for_chat(chat_id, expires_at))}\n\n"
        f"{tr_chat(chat_id, 'offer_tap_to_claim')}"
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


def list_open_offers_to_expire(now_value: str | datetime | None = None, limit: int = 100) -> list[sqlite3.Row]:
    due_now = parse_bot_datetime(now_value) if now_value is not None else now_dt()
    fetch_limit = max(int(limit or 100) * 5, int(limit or 100), 100)
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT * FROM photos
            WHERE offer_state = 'open' AND offer_expires_at IS NOT NULL
            ORDER BY offer_expires_at ASC LIMIT ?
            """,
            (fetch_limit,),
        ).fetchall()
    return [row for row in rows if iso_is_due(row["offer_expires_at"], due_now)][: max(1, int(limit or 100))]


def list_pending_qrs_to_expire(now_value: str | datetime | None = None, limit: int = 100) -> list[sqlite3.Row]:
    due_now = parse_bot_datetime(now_value) if now_value is not None else now_dt()
    fetch_limit = max(int(limit or 100) * 5, int(limit or 100), 100)
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT * FROM photos
            WHERE status = 'pending'
              AND offer_state IN ('open', 'claimed')
              AND offer_expires_at IS NOT NULL
            ORDER BY offer_expires_at ASC LIMIT ?
            """,
            (fetch_limit,),
        ).fetchall()
    return [row for row in rows if iso_is_due(row["offer_expires_at"], due_now)][: max(1, int(limit or 100))]


def list_claimed_qrs_needing_expiry_warning(now_value: str | datetime | None = None, limit: int = 100) -> list[sqlite3.Row]:
    due_now = parse_bot_datetime(now_value) if now_value is not None else now_dt()
    if due_now is None:
        due_now = now_dt()
    fetch_limit = max(int(limit or 100) * 5, int(limit or 100), 100)
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT * FROM photos
            WHERE status = 'pending'
              AND offer_state = 'claimed'
              AND receiver_chat_id IS NOT NULL
              AND receiver_chat_id != 0
              AND offer_expires_at IS NOT NULL
              AND receiver_warning_sent_at IS NULL
            ORDER BY offer_expires_at ASC LIMIT ?
            """,
            (fetch_limit,),
        ).fetchall()
    due_rows: list[sqlite3.Row] = []
    for row in rows:
        expires_dt = parse_bot_datetime(row["offer_expires_at"])
        if expires_dt is None:
            continue
        seconds_left = int(expires_dt.timestamp() - due_now.timestamp())
        if 0 < seconds_left <= 60:
            due_rows.append(row)
    return due_rows[: max(1, int(limit or 100))]


def mark_receiver_expiry_warning_sent(public_id: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute(
            """
            UPDATE photos
            SET receiver_warning_sent_at = ?
            WHERE public_id = ?
              AND receiver_warning_sent_at IS NULL
              AND status = 'pending'
              AND offer_state = 'claimed'
            """,
            (now_iso(), public_id),
        )
        return cur.rowcount > 0


def expire_offer_in_db(public_id: str, reason: str = "expired") -> sqlite3.Row | None:
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM photos WHERE public_id = ?", (public_id,)).fetchone()
        if not row or row["offer_state"] != "open":
            conn.rollback()
            return None
        now = now_iso()
        conn.execute(
            """
            UPDATE photos
            SET offer_state = ?, status = 'failed', status_at = ?, settled_at = ?, charged_usdt = 0, earned_usdt = 0,
                failure_reason = COALESCE(NULLIF(failure_reason, ''), 'No receiver could be notified')
            WHERE public_id = ? AND offer_state = 'open'
            """,
            (reason, now, now, public_id),
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
        if not is_admin(receiver_chat_id) and (not actor or actor["role"] != "receiver" or not actor["active"]):
            conn.rollback()
            return False, "Only active receivers can accept offers.", None, False
        if is_admin(receiver_chat_id) and (not actor or not actor["active"]):
            conn.rollback()
            return False, "Admin account is not active in the bot. Send /start first.", None, False
        presence = conn.execute("SELECT * FROM receiver_presence WHERE chat_id = ?", (receiver_chat_id,)).fetchone()
        if not presence or not presence["online"] or int(presence["limit_remaining"] or 0) <= 0:
            conn.rollback()
            return False, "You are offline or your limit is 0. Use /on LIMIT first.", None, False
        row = conn.execute("SELECT * FROM photos WHERE public_id = ?", (public_id,)).fetchone()
        if not row:
            conn.rollback()
            return False, "Offer not found.", None, False
        if str(row["offer_state"] or "").lower() == "canceled":
            conn.rollback()
            return False, "claim_offer_canceled", row, False
        if row["offer_state"] != "open" or int(row["receiver_chat_id"] or 0) != 0:
            conn.rollback()
            return False, "Offer expired. Another receiver already accepted this QR.", row, False
        if iso_is_due(row["offer_expires_at"]):
            conn.rollback()
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


def cancel_open_order_in_db(public_id: str, sender_chat_id: int) -> tuple[bool, str, sqlite3.Row | None, int]:
    """Cancel an unaccepted/open QR order after the sender cancel wait period.

    Returns (ok, message_key, original_row, seconds_left).  The wallet reserve is
    released in the same transaction so a canceled order cannot leave funds stuck.
    """
    public_id = str(public_id or "").strip()
    if not public_id:
        return False, "cancel_order_not_found", None, 0
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM photos WHERE public_id = ?", (public_id,)).fetchone()
        if not row:
            conn.rollback()
            return False, "cancel_order_not_found", None, 0
        if int(row["sender_chat_id"] or 0) != int(sender_chat_id):
            conn.rollback()
            return False, "cancel_order_sender_only", row, 0
        status = str(row["status"] or "").lower()
        if status != "pending":
            conn.rollback()
            return False, "cancel_order_already_processed", row, 0
        if str(row["offer_state"] or "").lower() != "open" or int(row["receiver_chat_id"] or 0) != 0:
            conn.rollback()
            return False, "cancel_order_already_accepted", row, 0
        if iso_is_due(row["offer_expires_at"]):
            conn.rollback()
            return False, "cancel_order_expired", row, 0

        age_seconds = seconds_since_iso(row["created_at"])
        seconds_left = max(0, SENDER_CANCEL_WAIT_SECONDS - age_seconds)
        if seconds_left > 0:
            conn.rollback()
            return False, "cancel_order_wait", row, seconds_left

        now = now_iso()
        sender_rate = effective_sender_charge_amount(row, use_current_setting_if_missing=True)
        release_amount = Decimal("0")
        _wallet_snapshot(conn, sender_chat_id)
        if sender_rate > 0:
            wallet_before = conn.execute("SELECT * FROM wallets WHERE chat_id = ?", (sender_chat_id,)).fetchone()
            release_amount = min(_dec(wallet_before["reserved_usdt"]), sender_rate)
            conn.execute(
                "UPDATE wallets SET reserved_usdt = MAX(0, reserved_usdt - ?), updated_at = ? WHERE chat_id = ?",
                (float(release_amount), now, sender_chat_id),
            )
            wallet_after = conn.execute("SELECT * FROM wallets WHERE chat_id = ?", (sender_chat_id,)).fetchone()
            available_after = _dec(wallet_after["balance_usdt"]) - _dec(wallet_after["reserved_usdt"])
            conn.execute(
                "INSERT INTO wallet_ledger(chat_id, kind, amount_usdt, balance_after, note, related_id, created_at) VALUES (?, 'scan_release', ?, ?, ?, ?, ?)",
                (sender_chat_id, float(release_amount), float(available_after), "Sender canceled QR before acceptance", public_id, now),
            )

        cur = conn.execute(
            """
            UPDATE photos
            SET status = 'failed', offer_state = 'canceled', status_by = ?, status_at = ?, settled_at = ?, charged_usdt = 0, earned_usdt = 0
            WHERE public_id = ? AND status = 'pending' AND offer_state = 'open' AND COALESCE(receiver_chat_id, 0) = 0
            """,
            (sender_chat_id, now, now, public_id),
        )
        if cur.rowcount <= 0:
            conn.rollback()
            return False, "cancel_order_failed", row, 0
        conn.commit()
        return True, "cancel_order_done", row, 0


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
    clean_message = message.strip()
    created = now_iso()
    with get_conn() as conn:
        ref_id = generate_dispute_ref(conn)
        cur = conn.execute(
            "INSERT INTO disputes(ref_id, public_id, chat_id, role, message, status, created_at) VALUES (?, ?, ?, ?, ?, 'open', ?)",
            (ref_id, public_id, chat_id, role, clean_message, created),
        )
        dispute_id = int(cur.lastrowid)
        conn.execute(
            "INSERT INTO dispute_messages(dispute_id, sender_type, sender_chat_id, message, created_at) VALUES (?, 'user', ?, ?, ?)",
            (dispute_id, chat_id, clean_message, created),
        )
        return ref_id


def get_dispute_by_id(dispute_id: int) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM disputes WHERE id = ?", (dispute_id,)).fetchone()


def get_dispute_by_ref(ref_id: str) -> sqlite3.Row | None:
    ref = str(ref_id or "").strip().upper().lstrip("#")
    if not ref:
        return None
    with get_conn() as conn:
        return conn.execute("SELECT * FROM disputes WHERE UPPER(ref_id) = ?", (ref,)).fetchone()


def add_dispute_chat_message(dispute_id: int, sender_type: str, sender_chat_id: int | None, message: str) -> int:
    clean_message = str(message or "").strip()
    if not clean_message:
        raise ValueError("message is empty")
    if sender_type not in {"user", "admin"}:
        raise ValueError("invalid dispute sender type")
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO dispute_messages(dispute_id, sender_type, sender_chat_id, message, created_at) VALUES (?, ?, ?, ?, ?)",
            (dispute_id, sender_type, sender_chat_id, clean_message, now_iso()),
        )
        if sender_type == "admin":
            conn.execute("UPDATE disputes SET status = 'under_review', admin_note = ? WHERE id = ? AND status IN ('open','under_review')", (clean_message, dispute_id))
        elif sender_type == "user":
            conn.execute("UPDATE disputes SET status = 'under_review' WHERE id = ? AND status IN ('open','under_review')", (dispute_id,))
        return int(cur.lastrowid)


def list_dispute_chat_messages(dispute_id: int) -> list[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM dispute_messages WHERE dispute_id = ? ORDER BY created_at ASC, id ASC", (dispute_id,)).fetchall()


def latest_dispute_message_id(dispute_id: int) -> int:
    with get_conn() as conn:
        row = conn.execute("SELECT COALESCE(MAX(id), 0) AS latest_id FROM dispute_messages WHERE dispute_id = ?", (dispute_id,)).fetchone()
    return int(row["latest_id"] or 0) if row else 0


def mark_dispute_admin_seen(dispute_id: int) -> int:
    latest_id = latest_dispute_message_id(dispute_id)
    with get_conn() as conn:
        conn.execute("UPDATE disputes SET admin_seen_message_id = ? WHERE id = ?", (latest_id, dispute_id))
    return latest_id


def dispute_chat_html(dispute_id: int, limit: int | None = 100) -> str:
    messages = list_dispute_chat_messages(dispute_id)
    if not messages:
        return '<div class="muted">No chat messages yet.</div>'
    shown_messages = messages[-limit:] if limit and len(messages) > limit else messages
    out = ['<div class="dispute-chat-log">']
    if limit and len(messages) > limit:
        out.append(f'<div class="muted small">Showing latest {limit} of {len(messages)} messages.</div>')
    for msg in shown_messages:
        side = 'Admin' if str(msg['sender_type']) == 'admin' else 'User'
        cls = 'admin' if str(msg['sender_type']) == 'admin' else 'user'
        out.append(
            f'<div class="dispute-chat-bubble {cls}">'
            f'<strong>{esc(side)}</strong>'
            f'<span class="muted small"> · {esc(display_datetime(msg["created_at"]))}</span>'
            f'<div>{esc(msg["message"])}</div>'
            f'</div>'
        )
    out.append('</div>')
    return ''.join(out)


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


def update_message_template(template_id: int, audience: str, button_text: str, message_text: str) -> bool:
    audience = _normalize_audience(audience)
    button_text = _validate_button_text(button_text)
    message_text = _validate_preset_text(message_text, "message")
    with get_conn() as conn:
        cur = conn.execute(
            """
            UPDATE message_templates
            SET audience = ?, button_text = ?, message_text = ?, updated_at = ?
            WHERE id = ?
            """,
            (audience, button_text, message_text, now_iso(), template_id),
        )
        return cur.rowcount > 0


def update_message_reply(reply_id: int, audience: str, button_text: str, reply_text: str) -> bool:
    audience = _normalize_audience(audience)
    button_text = _validate_button_text(button_text)
    reply_text = _validate_preset_text(reply_text, "reply")
    with get_conn() as conn:
        cur = conn.execute(
            """
            UPDATE message_replies
            SET audience = ?, button_text = ?, reply_text = ?, updated_at = ?
            WHERE id = ?
            """,
            (audience, button_text, reply_text, now_iso(), reply_id),
        )
        return cur.rowcount > 0


def _audience_options_html(selected: str) -> str:
    labels = {"sender": "Sender", "receiver": "Receiver / Buyer", "both": "Both"}
    selected = str(selected or "").strip().lower()
    return "".join(
        f'<option value="{esc(value)}" {"selected" if value == selected else ""}>{esc(label)}</option>'
        for value, label in labels.items()
    )


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

    txn_type = _first_param(params, "txntype").upper()
    # PSPs normally send txnType=CREATE. Some decoders/PSP variants may expose
    # the creation value in shortened form while still representing a mandate
    # creation QR, so allow CREATE and CRE instead of rejecting valid Stripe/Cashfree
    # UPI mandate QRs too aggressively.
    if txn_type not in {"CREATE", "CRE"}:
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


def _decode_single_fast(detector: cv2.QRCodeDetector, image: np.ndarray) -> str | None:
    """Fast single-QR decode path used before expensive screenshot fallbacks."""
    try:
        data, points, _straight = detector.detectAndDecode(image)
        if data and points is not None:
            return data.strip()
    except Exception:
        pass
    return None


def _decode_with_detector(detector: cv2.QRCodeDetector, image: np.ndarray, *, include_heavy: bool = False) -> str | None:
    # Fast path first. For the normal sender flow this usually succeeds in milliseconds.
    data = _decode_single_fast(detector, image)
    if data:
        return data

    # Multi decode is useful to reject images with more than one readable QR, but it is
    # slower than detectAndDecode. Run it only after the fast path did not decode.
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
        pass

    # Curved decode is comparatively expensive. Keep it as fallback only.
    if include_heavy:
        try:
            data, points, _straight = detector.detectAndDecodeCurved(image)
            if data and points is not None:
                return data.strip()
        except Exception:
            pass

    return None


def _try_decoded_data(data: str | None, last_error: ValueError | None) -> tuple[str | None, ValueError | None]:
    if not data:
        return None, last_error
    try:
        return validate_qr_data(data), None
    except ValueError as exc:
        return None, exc


def _gray_image(image: np.ndarray) -> np.ndarray | None:
    try:
        if len(image.shape) == 3:
            return cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        return image
    except Exception:
        return None


def _decode_attempt_and_validate(
    detector: cv2.QRCodeDetector,
    image: np.ndarray,
    *,
    started_at: float,
    timeout_seconds: float,
    include_heavy: bool = False,
    last_error: ValueError | None = None,
) -> tuple[str | None, ValueError | None, bool]:
    """Return (valid_data, last_error, timed_out)."""
    if time.perf_counter() - started_at > timeout_seconds:
        return None, last_error, True
    try:
        data = _decode_with_detector(detector, image, include_heavy=include_heavy)
    except ValueError as exc:
        return None, exc, False
    valid, err = _try_decoded_data(data, last_error)
    if valid:
        return valid, None, False
    return None, err, False


def _iter_fast_scaled_images(image: np.ndarray):
    """
    Yield a small number of practical enlarged attempts lazily.

    The previous decoder built many large denoised/threshold images before trying
    any of them, which made time-limited UPI mandate QRs feel slow. This generator
    creates one attempt at a time and stops as soon as decoding succeeds.
    """
    try:
        height, width = image.shape[:2]
    except Exception:
        return
    largest = max(width, height)
    if largest <= 0:
        return

    # Real UPI mandate QR crops generally decode well at these sizes. Keep the
    # cap modest so the sender gets the rebuilt QR quickly.
    target_sizes = (700, 1000, 1400, min(QR_MAX_UPSCALE_DIMENSION, 1800), QR_MAX_UPSCALE_DIMENSION)
    seen: set[int] = set()
    for target_largest in target_sizes:
        if target_largest <= largest:
            continue
        if target_largest > QR_MAX_UPSCALE_DIMENSION:
            continue
        scale = target_largest / largest
        scale_key = int(round(scale * 100))
        if scale_key in seen or scale <= 1.05:
            continue
        seen.add(scale_key)
        try:
            upscaled = cv2.resize(image, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)
        except Exception:
            continue
        yield upscaled
        gray = _gray_image(upscaled)
        if gray is not None:
            yield gray


def decode_qr_data_from_bytes(image_bytes: bytes) -> str:
    started_at = time.perf_counter()
    np_bytes = np.frombuffer(image_bytes, np.uint8)
    image = cv2.imdecode(np_bytes, cv2.IMREAD_COLOR)
    if image is None:
        raise ValueError("Could not read the image.")

    detector = cv2.QRCodeDetector()
    resized = resize_for_fast_qr_detection(image)
    timeout_seconds = max(0.8, QR_DECODE_TIMEOUT_SECONDS)
    last_error: ValueError | None = None

    # 1) Ultra-fast path: normal QR photos/crops should finish here.
    quick_images: list[np.ndarray] = [resized]
    gray = _gray_image(resized)
    if gray is not None:
        quick_images.append(gray)
    if resized.shape[:2] != image.shape[:2]:
        quick_images.append(image)
        original_gray = _gray_image(image)
        if original_gray is not None:
            quick_images.append(original_gray)

    for attempt in quick_images:
        valid, last_error, timed_out = _decode_attempt_and_validate(
            detector,
            attempt,
            started_at=started_at,
            timeout_seconds=timeout_seconds,
            include_heavy=False,
            last_error=last_error,
        )
        if valid:
            return valid
        if timed_out:
            if last_error:
                raise last_error
            raise ValueError("QR decode timed out. Send a clearer crop of the QR code.")

    if QR_FAST_ONLY:
        if last_error:
            raise last_error
        raise ValueError("No readable QR code found. Send a clearer crop of the QR code.")

    # 2) Limited screenshot fallback: useful for small QR crops, but lazy and capped.
    for base in (resized, image) if resized.shape[:2] != image.shape[:2] else (resized,):
        for attempt in _iter_fast_scaled_images(base):
            valid, last_error, timed_out = _decode_attempt_and_validate(
                detector,
                attempt,
                started_at=started_at,
                timeout_seconds=timeout_seconds,
                include_heavy=False,
                last_error=last_error,
            )
            if valid:
                return valid
            if timed_out:
                if last_error:
                    raise last_error
                raise ValueError("QR decode timed out. Send a clearer crop of the QR code.")

    # 3) Last fallback: try curved decode on the resized/original image, still bounded.
    for attempt in quick_images[:2]:
        valid, last_error, timed_out = _decode_attempt_and_validate(
            detector,
            attempt,
            started_at=started_at,
            timeout_seconds=timeout_seconds,
            include_heavy=True,
            last_error=last_error,
        )
        if valid:
            return valid
        if timed_out:
            break

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


def build_caption(date_str: str, daily_no: int, public_id: str, chat_id: int | None = None) -> str:
    return (
        f"📅 {tr_chat(chat_id, 'caption_date')}: {display_date(date_str)}\n"
        f"📷 {tr_chat(chat_id, 'caption_photo_today', daily_no=daily_no)}\n"
        f"🆔 {tr_chat(chat_id, 'caption_id')}: {public_id}"
    )


def build_receiver_qr_caption(date_str: str, daily_no: int, public_id: str, expires_at: str | None = None, chat_id: int | None = None) -> str:
    lines = [build_caption(date_str, daily_no, public_id, chat_id)]
    if expires_at:
        lines.extend([
            "",
            f"⏱ {tr_chat(chat_id, 'caption_expires')}: {display_datetime(expires_at)}",
            tr_chat(chat_id, "receiver_time_left_line", time_left=format_time_left_for_chat(chat_id, expires_at)),
            tr_chat(chat_id, "receiver_qr_timer_hint"),
        ])
    return "\n".join(lines)


def build_status_caption(photo: PhotoRow, status: str, failure_reason: str | None = None, chat_id: int | None = None) -> str:
    emoji = "✅" if status == "done" else "❌"
    status_text = tr_chat(chat_id, "stats_done") if status == "done" else tr_chat(chat_id, "stats_failed")
    lines = [
        build_caption(photo.date, photo.daily_no, photo.public_id, chat_id),
        "",
        f"{emoji} {tr_chat(chat_id, 'caption_status')}: {status_text}",
        f"🕒 {tr_chat(chat_id, 'caption_updated')}: {display_datetime()}",
    ]
    if status == "failed":
        reason = clean_failure_reason_text(failure_reason)
        if reason:
            lines.append(f"📝 {tr_chat(chat_id, 'caption_reason')}: {reason}")
    return "\n".join(lines)


def build_sender_offer_caption(
    date_str: str,
    daily_no: int,
    public_id: str,
    status_line: str,
    *,
    expires_at: str | None = None,
    sender_rate: Decimal | str | float | int | None = None,
    order_row=None,
    chat_id: int | None = None,
) -> str:
    lines = [build_caption(date_str, daily_no, public_id, chat_id), "", status_line]
    if expires_at:
        lines.append(f"⏱ {tr_chat(chat_id, 'caption_expires')}: {display_datetime(expires_at)}")
        lines.append(tr_chat(chat_id, "receiver_time_left_line", time_left=format_time_left_for_chat(chat_id, expires_at)))
    if sender_rate is not None or order_row is not None:
        reserved_amount = effective_sender_reserved_display(order_row, sender_rate)
        lines.append(f"💳 {tr_chat(chat_id, 'caption_reserved')}: ${_money(reserved_amount)} USDT")
    return "\n".join(lines)


async def edit_sender_offer_caption(
    bot,
    chat_id: int,
    message_id: int | None,
    caption: str,
    reply_markup: InlineKeyboardMarkup | None = None,
) -> bool:
    if not message_id:
        return False
    try:
        await bot.edit_message_caption(
            chat_id=chat_id,
            message_id=message_id,
            caption=caption,
            reply_markup=reply_markup,
        )
        return True
    except TelegramError as exc:
        logger.warning("Could not edit sender offer caption %s/%s: %s", chat_id, message_id, exc)
        return False


def receiver_status_keyboard(public_id: str, chat_id: int | None = None) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(tr_chat(chat_id, "btn_done"), callback_data=f"done:{public_id}"),
                InlineKeyboardButton(tr_chat(chat_id, "btn_failed"), callback_data=f"failed:{public_id}"),
            ],
        ]
    )


def qr_dispute_keyboard(public_id: str, chat_id: int | None = None) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton(tr_chat(chat_id, "btn_dispute"), callback_data=f"disputeqr:{public_id}")],
        ]
    )


def failure_reason_keyboard(public_id: str, chat_id: int | None = None) -> InlineKeyboardMarkup:
    label_keys = {
        "qr_not_working": "fail_reason_qr_not_working",
        "qr_expired": "fail_reason_qr_expired",
        "limit_over": "fail_reason_limit_over",
    }
    rows = [[InlineKeyboardButton(tr_chat(chat_id, label_keys.get(key, key)), callback_data=f"failreason:{public_id}:{key}")] for key, _label in FAIL_REASON_BUTTONS]
    rows.append([InlineKeyboardButton(tr_chat(chat_id, "btn_cancel"), callback_data="nav:home")])
    return InlineKeyboardMarkup(rows)


def sender_open_offer_keyboard(public_id: str, chat_id: int | None = None) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton(tr_chat(chat_id, "btn_cancel_open_order"), callback_data=f"cancelorder:{public_id}")],
        ]
    )


def sender_notify_keyboard(public_id: str, chat_id: int | None = None) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton(tr_chat(chat_id, "btn_notify_receiver"), callback_data=f"notify:{public_id}")],
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


def main_menu_keyboard(user: UserRow | None = None, chat_id: int | None = None) -> InlineKeyboardMarkup:
    if is_admin(chat_id):
        return InlineKeyboardMarkup(
            [
                [
                    InlineKeyboardButton(tr_chat(chat_id, "btn_wallet"), callback_data="nav:wallet"),
                    InlineKeyboardButton(tr_chat(chat_id, "btn_earnings"), callback_data="nav:earnings"),
                ],
                [
                    InlineKeyboardButton(tr_chat(chat_id, "btn_status"), callback_data="nav:status"),
                    InlineKeyboardButton(tr_chat(chat_id, "btn_pending_qr"), callback_data="nav:pending"),
                ],
                [
                    InlineKeyboardButton(tr_chat(chat_id, "btn_messages"), callback_data="nav:messages"),
                    InlineKeyboardButton(tr_chat(chat_id, "btn_history"), callback_data="nav:history"),
                ],
                [
                    InlineKeyboardButton(tr_chat(chat_id, "btn_stats"), callback_data="nav:stats"),
                    InlineKeyboardButton(tr_chat(chat_id, "btn_dispute"), callback_data="nav:dispute"),
                ],
                [
                    InlineKeyboardButton(tr_chat(chat_id, "btn_commands"), callback_data="nav:commands"),
                    InlineKeyboardButton(tr_chat(chat_id, "btn_language"), callback_data="nav:language"),
                ],
                [InlineKeyboardButton(tr_chat(chat_id, "btn_support"), callback_data="nav:support")],
            ]
        )
    if user and user.active and user.role == "receiver":
        return InlineKeyboardMarkup(
            [
                [
                    InlineKeyboardButton(tr_chat(chat_id, "btn_earnings"), callback_data="nav:wallet"),
                    InlineKeyboardButton(tr_chat(chat_id, "btn_pending_qr"), callback_data="nav:pending"),
                ],
                [
                    InlineKeyboardButton(tr_chat(chat_id, "btn_messages"), callback_data="nav:messages"),
                    InlineKeyboardButton(tr_chat(chat_id, "btn_history"), callback_data="nav:history"),
                ],
                [
                    InlineKeyboardButton(tr_chat(chat_id, "btn_stats"), callback_data="nav:stats"),
                    InlineKeyboardButton(tr_chat(chat_id, "btn_dispute"), callback_data="nav:dispute"),
                ],
                [
                    InlineKeyboardButton(tr_chat(chat_id, "btn_commands"), callback_data="nav:commands"),
                    InlineKeyboardButton(tr_chat(chat_id, "btn_language"), callback_data="nav:language"),
                ],
                [InlineKeyboardButton(tr_chat(chat_id, "btn_support"), callback_data="nav:support")],
            ]
        )
    if user and user.active and user.role == "sender":
        return InlineKeyboardMarkup(
            [
                [
                    InlineKeyboardButton(tr_chat(chat_id, "btn_wallet"), callback_data="nav:wallet"),
                    InlineKeyboardButton(tr_chat(chat_id, "btn_status"), callback_data="nav:status"),
                ],
                [
                    InlineKeyboardButton(tr_chat(chat_id, "btn_messages"), callback_data="nav:messages"),
                    InlineKeyboardButton(tr_chat(chat_id, "btn_history"), callback_data="nav:history"),
                ],
                [
                    InlineKeyboardButton(tr_chat(chat_id, "btn_stats"), callback_data="nav:stats"),
                    InlineKeyboardButton(tr_chat(chat_id, "btn_dispute"), callback_data="nav:dispute"),
                ],
                [
                    InlineKeyboardButton(tr_chat(chat_id, "btn_commands"), callback_data="nav:commands"),
                    InlineKeyboardButton(tr_chat(chat_id, "btn_language"), callback_data="nav:language"),
                ],
                [InlineKeyboardButton(tr_chat(chat_id, "btn_support"), callback_data="nav:support")],
            ]
        )
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton(tr_chat(chat_id, "btn_commands"), callback_data="nav:commands")],
            [InlineKeyboardButton(tr_chat(chat_id, "btn_language"), callback_data="nav:language")],
            [InlineKeyboardButton(tr_chat(chat_id, "btn_support"), callback_data="nav:support")],
        ]
    )


def main_menu_text(user: UserRow | None, chat_id: int) -> str:
    if is_admin(chat_id):
        return (
            "🛡️ <b>Admin account</b>\n\n"
            "You can use sender and receiver bot commands. Admin IDs are not excluded from broadcasts, marketplace offers, or marketplace messages."
        )
    if user and user.active and user.role == "sender":
        return tr_chat(chat_id, "registered_sender")
    if user and user.active and user.role == "receiver":
        return tr_chat(chat_id, "registered_receiver")
    return tr_chat(chat_id, "not_registered_menu", chat_id=chat_id, support=html.escape(support_display_text(chat_id)))


def commands_help_text(user: UserRow | None = None, chat_id: int | None = None) -> str:
    lines = [tr_chat(chat_id, "commands_title")]
    if is_admin(chat_id):
        lines.append(tr_chat(chat_id, "commands_role", role="admin"))
    elif user and user.active:
        lines.append(tr_chat(chat_id, "commands_role", role=user.role))
    lines.extend([
        "",
        tr_chat(chat_id, "commands_general"),
        tr_chat(chat_id, "cmd_start"),
        tr_chat(chat_id, "cmd_commands"),
        tr_chat(chat_id, "cmd_language"),
        tr_chat(chat_id, "cmd_myid"),
        tr_chat(chat_id, "cmd_support"),
        tr_chat(chat_id, "cmd_messages"),
        tr_chat(chat_id, "cmd_history"),
        tr_chat(chat_id, "cmd_dispute"),
        tr_chat(chat_id, "cmd_stats"),
    ])
    if is_admin(chat_id) or (user and user.active and user.role == "sender"):
        lines.extend([
            "",
            tr_chat(chat_id, "commands_sender"),
            tr_chat(chat_id, "cmd_send_qr"),
            tr_chat(chat_id, "cmd_status"),
            tr_chat(chat_id, "cmd_wallet"),
            tr_chat(chat_id, "cmd_loadwallet"),
        ])
    if is_admin(chat_id) or (user and user.active and user.role == "receiver"):
        lines.extend([
            "",
            tr_chat(chat_id, "commands_receiver"),
            tr_chat(chat_id, "cmd_on"),
            tr_chat(chat_id, "cmd_limit"),
            tr_chat(chat_id, "cmd_off"),
            tr_chat(chat_id, "cmd_pending"),
            tr_chat(chat_id, "cmd_done"),
            tr_chat(chat_id, "cmd_failed"),
            tr_chat(chat_id, "cmd_earnings"),
            tr_chat(chat_id, "cmd_withdraw"),
        ])
    if not is_admin(chat_id) and not (user and user.active):
        lines.extend(["", tr_chat(chat_id, "commands_after_activation")])
    return "\n".join(lines)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    observe_telegram_profile(update.effective_user)
    if not update.effective_chat or not update.message:
        return
    if update.effective_chat.type != ChatType.PRIVATE:
        await update.message.reply_text(tr_chat(update.effective_chat.id, "private_only"))
        return

    chat_id = update.effective_chat.id
    first_start = mark_first_start_seen(chat_id)
    user = ensure_default_sender_user(chat_id)
    await refresh_bot_commands_for_chat(context.bot, chat_id, user)

    if first_start:
        await update.message.reply_text(
            language_selection_text(chat_id),
            reply_markup=language_selection_keyboard(chat_id, include_back=False),
        )
        return

    await update.message.reply_text(
        main_menu_text(user, chat_id),
        parse_mode="HTML",
        reply_markup=main_menu_keyboard(user, chat_id),
    )


async def myid(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    observe_telegram_profile(update.effective_user)
    if update.message and update.effective_chat:
        chat_id = update.effective_chat.id
        username = getattr(update.effective_user, "username", None) if update.effective_user else None
        suffix = tr_chat(chat_id, "username_set", username=username) if username else tr_chat(chat_id, "username_hidden")
        await update.message.reply_text(tr_chat(chat_id, "myid_text", chat_id=chat_id, suffix=suffix), parse_mode="Markdown")


async def commands_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    observe_telegram_profile(update.effective_user)
    if not update.message or not update.effective_chat:
        return
    user = get_user(update.effective_chat.id)
    await update.message.reply_text(
        commands_help_text(user, update.effective_chat.id),
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(tr_chat(update.effective_chat.id, "btn_back_menu"), callback_data="nav:home")]]),
    )


async def support_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    observe_telegram_profile(update.effective_user)
    if not update.message or not update.effective_chat:
        return
    chat_id = update.effective_chat.id
    await update.message.reply_text(
        tr_chat(chat_id, "support_text", support=support_display_text(chat_id)),
        reply_markup=support_keyboard(include_back=False, chat_id=chat_id),
    )


async def language_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    observe_telegram_profile(update.effective_user)
    if not update.message or not update.effective_chat:
        return
    chat_id = update.effective_chat.id
    mark_first_start_seen(chat_id)
    await update.message.reply_text(
        language_selection_text(chat_id),
        reply_markup=language_selection_keyboard(chat_id, include_back=True),
    )


async def language_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.message:
        return
    chat_id = query.message.chat.id
    data = query.data or ""
    code = normalize_language_code(data.rsplit(":", 1)[-1])
    set_user_language(chat_id, code)
    user = get_user(chat_id) or ensure_default_sender_user(chat_id)
    await refresh_bot_commands_for_chat(context.bot, chat_id, user)
    await query.answer(tr_lang(code, "language_saved"), show_alert=False)
    await query.edit_message_text(
        f"{tr_lang(code, 'language_saved')}\n\n{main_menu_text(user, chat_id)}",
        parse_mode="HTML",
        reply_markup=main_menu_keyboard(user, chat_id),
    )


async def stats_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    observe_telegram_profile(update.effective_user)
    if not update.message or not update.effective_chat:
        return

    chat_id = update.effective_chat.id
    user = get_user_for_chat(chat_id)
    if not is_active_user_or_admin(chat_id, user):
        await update.message.reply_text(tr_chat(chat_id, "not_registered"))
        return

    if is_admin(chat_id):
        text = (
            stats_summary_text("Your sender stats", sender_chat_id=chat_id, chat_id=chat_id)
            + "\n\n"
            + stats_summary_text("Your receiver stats", receiver_chat_id=chat_id, chat_id=chat_id)
        )
        await update.message.reply_text(text)
    elif user and user.role == "sender":
        await update.message.reply_text(stats_summary_text("Your sender stats", sender_chat_id=chat_id, chat_id=chat_id))
    else:
        await update.message.reply_text(stats_summary_text("Your receiver stats", receiver_chat_id=chat_id, chat_id=chat_id))






def _receiver_pending_text_keyboard(chat_id: int) -> tuple[str, InlineKeyboardMarkup | None]:
    rows = user_recent_claimed_pending(chat_id)
    if not rows:
        return tr_chat(chat_id, "no_pending_qrs"), None

    lines = [tr_chat(chat_id, "pending_header"), ""]
    keyboard: list[list[InlineKeyboardButton]] = []
    for row in rows:
        public_id = str(row["public_id"])
        lines.append(f"{public_id} | 📷 {tr_chat(chat_id, 'caption_photo_today', daily_no=row['daily_no'])} | 📅 {display_date(row['date'])}")
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


def _qr_history_entry_lines(row: sqlite3.Row, role: str, chat_id: int | None = None) -> list[str]:
    status = str(row["status"] or "pending").lower()
    offer_state = str(row["offer_state"] or "").replace("_", " ").strip().title()
    if status == "done":
        status_text = tr_chat(chat_id, "status_done")
    elif status == "failed":
        status_text = tr_chat(chat_id, "status_failed")
    elif offer_state.lower() == "expired":
        status_text = tr_chat(chat_id, "status_expired")
    elif offer_state:
        status_text = f"{tr_chat(chat_id, 'status_pending')} — {offer_state}"
    else:
        status_text = tr_chat(chat_id, "status_pending")
    amount_label = tr_chat(chat_id, "charged") if role == "sender" else tr_chat(chat_id, "earned")
    amount_value = row["charged_usdt"] if role == "sender" else row["earned_usdt"]
    # Privacy rule: never show the opposite party identity in user-facing QR history.
    # Senders and receivers/buyers must not see each other's chat IDs, aliases, usernames, or links.
    return [
        f"<b>{tr_chat(chat_id, 'qr_id')}:</b> <code>{esc(row['public_id'])}</code>",
        f"<b>{tr_chat(chat_id, 'date_time')}:</b> {esc(_history_datetime(row['created_at']))}",
        f"<b>{tr_chat(chat_id, 'photo_no')}:</b> #{esc(row['daily_no'])}",
        f"<b>{tr_chat(chat_id, 'status')}:</b> {esc(status_text)}",
        f"<b>{amount_label}:</b> ${_money(amount_value)} USDT",
    ]


def _qr_history_text_keyboard(chat_id: int, user: UserRow, page: int = 0, page_size: int = 10) -> tuple[str, InlineKeyboardMarkup]:
    total = user_qr_history_count(chat_id, user.role)
    total_pages = max(1, (total + page_size - 1) // page_size) if total else 1
    page = max(0, min(int(page or 0), total_pages - 1))
    rows = user_qr_history_rows(chat_id, user.role, page_size, page * page_size)
    title = tr_chat(chat_id, "history_title")
    lines = [tr_chat(chat_id, "history_page", page=page + 1, total_pages=total_pages), tr_chat(chat_id, "history_showing"), ""]
    if not rows:
        lines.append(tr_chat(chat_id, "history_empty"))
    else:
        for idx, row in enumerate(rows, start=1):
            if idx > 1:
                lines.append("")
            lines.extend(_qr_history_entry_lines(row, user.role, chat_id))
    buttons: list[list[InlineKeyboardButton]] = []
    nav: list[InlineKeyboardButton] = []
    if page > 0:
        nav.append(InlineKeyboardButton(tr_chat(chat_id, "btn_prev"), callback_data=f"qr_history:{page-1}"))
    if page + 1 < total_pages:
        nav.append(InlineKeyboardButton(tr_chat(chat_id, "btn_next"), callback_data=f"qr_history:{page+1}"))
    if nav:
        buttons.append(nav)
    buttons.append([InlineKeyboardButton(tr_chat(chat_id, "btn_back"), callback_data="nav:home")])
    return "\n".join(lines), InlineKeyboardMarkup(buttons)


def _qr_history_text(chat_id: int, user: UserRow) -> str:
    text, _markup = _qr_history_text_keyboard(chat_id, user, 0)
    return text


async def history_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    observe_telegram_profile(update.effective_user)
    if not update.message or not update.effective_chat:
        return
    chat_id = update.effective_chat.id
    user = get_user_for_chat(chat_id)
    if not is_active_user_or_admin(chat_id, user):
        await update.message.reply_text(tr_chat(chat_id, "not_registered"))
        return
    text, markup = _qr_history_text_keyboard(chat_id, user, 0)
    await update.message.reply_text(text, parse_mode="HTML", reply_markup=markup)


async def pending_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message or not update.effective_chat:
        return

    chat_id = update.effective_chat.id

    user = get_user_for_chat(chat_id)
    if not can_use_receiver_features(chat_id, user):
        await update.message.reply_text(tr_chat(chat_id, "only_active_receivers"))
        return
    text, markup = _receiver_pending_text_keyboard(chat_id)
    await update.message.reply_text(text, reply_markup=markup)



# -----------------------------
# Preset message command handlers
# -----------------------------


def _audience_allows(audience: str, role: str) -> bool:
    role = str(role or "").strip().lower()
    if role == "admin":
        return True
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


def _messages_menu_text(user: UserRow, chat_id: int | None = None) -> str:
    menu_role = "sender" if is_admin(chat_id) else user.role
    target_key = "target_receivers" if menu_role == "sender" else "target_senders"
    target = tr_chat(chat_id, target_key)
    return (
        f"{tr_chat(chat_id, 'marketplace_messages_title')}\n\n"
        f"{tr_chat(chat_id, 'marketplace_messages_text', target=target)}"
    )


async def _show_messages_menu(message_or_query, chat_id: int) -> None:
    user = get_user_for_chat(chat_id)
    if not is_active_user_or_admin(chat_id, user):
        text = tr_chat(chat_id, "not_registered")
        if hasattr(message_or_query, "edit_message_text"):
            await message_or_query.edit_message_text(text)
        else:
            await message_or_query.reply_text(text)
        return

    menu_role = "sender" if is_admin(chat_id) else (user.role if user else "sender")
    markup = build_template_keyboard(menu_role, chat_id)
    if not markup:
        text = tr_chat(chat_id, "no_presets")
        back = InlineKeyboardMarkup([[InlineKeyboardButton(tr_chat(chat_id, "btn_back"), callback_data="nav:home")]])
        if hasattr(message_or_query, "edit_message_text"):
            await message_or_query.edit_message_text(text, reply_markup=back)
        else:
            await message_or_query.reply_text(text, reply_markup=back)
        return

    rows = list(markup.inline_keyboard)
    rows.append([InlineKeyboardButton(tr_chat(chat_id, "btn_back"), callback_data="nav:home")])
    markup = InlineKeyboardMarkup(rows)
    if hasattr(message_or_query, "edit_message_text"):
        await message_or_query.edit_message_text(_messages_menu_text(user, chat_id), reply_markup=markup)
    else:
        await message_or_query.reply_text(_messages_menu_text(user, chat_id), reply_markup=markup)


async def messages_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    observe_telegram_profile(update.effective_user)
    if not update.message or not update.effective_chat:
        return
    if update.effective_chat.type != ChatType.PRIVATE:
        await update.message.reply_text(tr_chat(update.effective_chat.id, "preset_private_only"))
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
                await query.answer(tr_chat(chat_id, "preset_menu_wrong_user"), show_alert=True)
                return
        except ValueError:
            await query.answer(tr_chat(chat_id, "invalid_preset_button"), show_alert=True)
            return
    elif len(parts) == 2:
        _prefix, template_raw = parts
    else:
        await query.answer(tr_chat(chat_id, "invalid_preset_button"), show_alert=True)
        return

    user = get_user_for_chat(chat_id)
    if not is_active_user_or_admin(chat_id, user):
        await query.answer(tr_chat(chat_id, "not_registered"), show_alert=True)
        return

    try:
        template_id = int(template_raw)
    except ValueError:
        await query.answer(tr_chat(chat_id, "invalid_preset_button"), show_alert=True)
        return

    template = get_message_template(template_id)
    if not template or not int(template["active"]):
        await query.answer(tr_chat(chat_id, "preset_not_active"), show_alert=True)
        return
    initiator_role = "sender" if is_admin(chat_id) else (user.role if user else "sender")
    if not _audience_allows(str(template["audience"]), "admin" if is_admin(chat_id) else initiator_role):
        await query.answer(tr_chat(chat_id, "preset_not_for_role"), show_alert=True)
        return

    recipient_role = _opposite_role(initiator_role)
    recipients = [r for r in _preset_recipients_for_role(initiator_role) if int(r["chat_id"]) != chat_id]
    if not recipients:
        await query.answer(tr_chat(chat_id, "no_active_recipients", role=tr_chat(chat_id, "target_" + recipient_role + "s")), show_alert=True)
        return

    broadcast_id = f"msg_{int(time.time())}_{chat_id}_{template_id}_{secrets.token_hex(6)}"
    sent = 0
    failed = 0
    for recipient in recipients:
        recipient_chat_id = int(recipient["chat_id"])
        sender_chat_id, receiver_chat_id, direction = _message_event_route(chat_id, initiator_role, recipient_chat_id)
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
        await query.answer(tr_chat(chat_id, "could_not_send_any", role=tr_chat(chat_id, "target_" + recipient_role + "s")), show_alert=True)
        return
    if failed:
        await query.answer(tr_chat(chat_id, "sent_failed", sent=sent, failed=failed), show_alert=False)
    else:
        await query.answer(tr_chat(chat_id, "sent_ok"), show_alert=False)


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
            text=tr_chat(chat_id, "already_answered_closed"),
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
        await query.answer(tr_chat(chat_id, "invalid_reply_button"), show_alert=True)
        return

    user = get_user_for_chat(chat_id)
    if not is_active_user_or_admin(chat_id, user):
        await query.answer(tr_chat(chat_id, "not_registered"), show_alert=True)
        return

    event = get_message_event(event_id)
    reply = get_message_reply(reply_id)
    if not event or not reply or not int(reply["active"]):
        await query.answer(tr_chat(chat_id, "reply_no_longer_available"), show_alert=True)
        return
    if int(event["recipient_chat_id"]) != chat_id:
        await query.answer(tr_chat(chat_id, "reply_not_for_account"), show_alert=True)
        return
    if int(reply["template_id"]) != int(event["template_id"]):
        await query.answer(tr_chat(chat_id, "reply_mismatch"), show_alert=True)
        return
    recipient_role_for_check = "admin" if is_admin(chat_id) else (user.role if user else "")
    if not _audience_allows(str(reply["audience"]), recipient_role_for_check):
        await query.answer(tr_chat(chat_id, "reply_not_for_role"), show_alert=True)
        return

    claimed, reason, claimed_event, other_events = claim_message_broadcast_reply(event_id, reply_id)
    if not claimed:
        try:
            await query.edit_message_reply_markup(reply_markup=None)
        except TelegramError:
            pass
        if reason in {"already_answered", "closed"}:
            await query.answer(tr_chat(chat_id, "already_answered_other"), show_alert=True)
        else:
            await query.answer(tr_chat(chat_id, "marketplace_msg_unavailable"), show_alert=True)
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
        await query.answer(tr_chat(chat_id, "reply_saved_notify_failed"), show_alert=True)
        return

    try:
        await query.edit_message_reply_markup(reply_markup=None)
    except TelegramError:
        pass
    await _clear_other_marketplace_messages(context, other_events)
    await query.answer(tr_chat(chat_id, "reply_sent"), show_alert=False)


# -----------------------------
# Sender / receiver flow
# -----------------------------


async def notify_active_senders(context: ContextTypes.DEFAULT_TYPE, text: str | None = None, *, key: str | None = None, **kwargs) -> tuple[int, int]:
    sent = 0
    failed = 0
    for sender in active_senders():
        sender_chat_id = int(sender["chat_id"])
        msg_text = tr_chat(sender_chat_id, key, **kwargs) if key else str(text or "")
        try:
            await context.bot.send_message(chat_id=sender_chat_id, text=msg_text, protect_content=PROTECT_CONTENT)
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
    user = get_user_for_chat(chat_id)
    if not can_use_receiver_features(chat_id, user):
        await update.message.reply_text(tr_chat(chat_id, "only_active_receivers_on"))
        return
    try:
        limit = int(context.args[0]) if context.args else 0
    except ValueError:
        limit = 0
    if limit <= 0:
        await update.message.reply_text(tr_chat(chat_id, "on_usage"))
        return
    set_receiver_online(chat_id, limit)
    await update.message.reply_text(tr_chat(chat_id, "receiver_online", limit=limit))
    sent, failed = await notify_active_senders(
        context,
        key="notify_receiver_online",
        capacity=total_marketplace_capacity(),
    )
    logger.info("Receiver %s online; notified senders sent=%s failed=%s", chat_id, sent, failed)


async def off_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    observe_telegram_profile(update.effective_user)
    if not update.message or not update.effective_chat:
        return
    chat_id = update.effective_chat.id
    user = get_user_for_chat(chat_id)
    if not can_use_receiver_features(chat_id, user):
        await update.message.reply_text(tr_chat(chat_id, "only_active_receivers_off"))
        return
    set_receiver_offline(chat_id)
    await update.message.reply_text(tr_chat(chat_id, "receiver_offline"))
    sent, failed = await notify_active_senders(
        context,
        key="notify_receiver_offline",
    )
    logger.info("Receiver %s offline; notified senders sent=%s failed=%s", chat_id, sent, failed)


async def limit_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    observe_telegram_profile(update.effective_user)
    if not update.message or not update.effective_chat:
        return
    chat_id = update.effective_chat.id
    user = get_user_for_chat(chat_id)
    if not can_use_receiver_features(chat_id, user):
        await update.message.reply_text(tr_chat(chat_id, "only_active_receivers_limit"))
        return
    raw = str(context.args[0]).strip() if context.args else ""
    if not raw or raw[0] not in "+-":
        await update.message.reply_text(tr_chat(chat_id, "limit_usage"))
        return
    try:
        delta = int(raw)
    except ValueError:
        await update.message.reply_text(tr_chat(chat_id, "limit_usage"))
        return
    if delta == 0:
        await update.message.reply_text(tr_chat(chat_id, "limit_delta_zero"))
        return
    existing = receiver_presence_row(chat_id)
    if not existing and delta < 0:
        await update.message.reply_text(tr_chat(chat_id, "limit_no_current"))
        return
    remaining, total, online = adjust_receiver_limit(chat_id, delta)
    delta_text = f"{delta:+d}"
    if online:
        await update.message.reply_text(tr_chat(chat_id, "limit_adjusted", delta=delta_text, remaining=remaining, total=total))
    else:
        await update.message.reply_text(tr_chat(chat_id, "limit_adjusted_offline", delta=delta_text, remaining=remaining, total=total))

    # Notify senders when marketplace receiver capacity changes. Do not include
    # receiver names, usernames, or chat IDs; only publish the capacity change.
    notify_key = "notify_receiver_limit_added" if delta > 0 else "notify_receiver_limit_reduced"
    sent, failed = await notify_active_senders(
        context,
        key=notify_key,
        change=abs(delta),
        capacity=total_marketplace_capacity(),
    )
    logger.info(
        "Receiver %s adjusted limit by %+d; notified senders sent=%s failed=%s",
        chat_id,
        delta,
        sent,
        failed,
    )


async def marketplace_status_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    observe_telegram_profile(update.effective_user)
    if not update.message or not update.effective_chat:
        return
    chat_id = update.effective_chat.id
    user = get_user_for_chat(chat_id)
    if not is_active_user_or_admin(chat_id, user):
        await update.message.reply_text(tr_chat(chat_id, "not_registered"))
        return
    if not is_admin(chat_id) and user and user.role == "receiver":
        await update.message.reply_text(tr_chat(update.effective_chat.id, "sender_status_only"))
        return
    await update.message.reply_text(marketplace_status_text(chat_id))


# In-memory wallet top-up states. These are short flows only; deposits themselves are persisted.
WALLET_TOPUP_FLOW: dict[int, dict] = {}
MANUAL_TXHASH_FLOW: dict[int, dict] = {}
WITHDRAW_FLOW: dict[int, dict] = {}
DISPUTE_FLOW: dict[int, dict] = {}
DISPUTE_REPLY_FLOW: dict[int, dict] = {}
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


def _wallet_main_keyboard(user_role: str, chat_id: int | None = None) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    if user_role == "sender":
        rows.append([InlineKeyboardButton(tr_chat(chat_id, "btn_topup_wallet"), callback_data="nav:loadwallet")])
        rows.append([InlineKeyboardButton(tr_chat(chat_id, "btn_wallet_history"), callback_data="wallet_history:0")])
    elif user_role == "receiver":
        rows.append([InlineKeyboardButton(tr_chat(chat_id, "btn_withdraw"), callback_data="withdraw:start")])
    rows.append([InlineKeyboardButton(tr_chat(chat_id, "btn_back"), callback_data="nav:home")])
    return InlineKeyboardMarkup(rows)


def _receiver_earnings_text(chat_id: int) -> str:
    wallet, _due, requested, available, _paid = receiver_earnings_numbers(chat_id)
    return (
        f"{tr_chat(chat_id, 'receiver_earnings_title')}\n\n"
        f"{tr_chat(chat_id, 'total_earned')}: *${_money(wallet['earned_usdt'])} USDT*\n"
        f"{tr_chat(chat_id, 'paid')}: *${_money(wallet['paid_usdt'])} USDT*\n"
        f"{tr_chat(chat_id, 'requested')}: *${_money(requested)} USDT*\n"
        f"{tr_chat(chat_id, 'available_withdraw')}: *${_money(available)} USDT*"
    )


def _sender_wallet_text(chat_id: int) -> str:
    wallet = get_wallet(chat_id)
    available = _dec(wallet["balance_usdt"]) - _dec(wallet["reserved_usdt"])
    return (
        f"{tr_chat(chat_id, 'wallet_title')}\n\n"
        f"{tr_chat(chat_id, 'usdt_balance')}: *${_money(wallet['balance_usdt'])}*\n"
        f"{tr_chat(chat_id, 'reserved')}: *${_money(wallet['reserved_usdt'])}*\n"
        f"{tr_chat(chat_id, 'available')}: *${_money(available)}*"
    )


def _topup_methods_keyboard(settings: dict | None = None, chat_id: int | None = None) -> InlineKeyboardMarkup:
    settings = settings or get_marketplace_settings()
    rows: list[list[InlineKeyboardButton]] = []
    if payment_method_enabled("bep20", settings):
        rows.append([InlineKeyboardButton("🟡 USDT (BEP20)", callback_data="wallet_currency:bep20")])
    if payment_method_enabled("polygon", settings):
        rows.append([InlineKeyboardButton("🟣 USDT (POLYGON)", callback_data="wallet_currency:polygon")])
    if payment_method_enabled("binance", settings):
        rows.append([InlineKeyboardButton("🟡 Binance Pay", callback_data="wallet_currency:binance")])
    rows.append([InlineKeyboardButton(tr_chat(chat_id, "btn_back"), callback_data="nav:wallet")])
    return InlineKeyboardMarkup(rows)


def _payment_label(network: str) -> str:
    network = (network or "bep20").lower()
    if network == "polygon":
        return "USDT (POLYGON)"
    if network == "binance":
        return "Binance Pay"
    return "USDT (BEP20)"


def _payment_title(network: str, chat_id: int | None = None) -> str:
    network = (network or "bep20").lower()
    if network == "polygon":
        return tr_chat(chat_id, "payment_title_polygon")
    if network == "binance":
        return tr_chat(chat_id, "payment_title_binance")
    return tr_chat(chat_id, "payment_title_bep20")


def _network_line(network: str, confirmations: int | None = None, chat_id: int | None = None) -> str:
    network = (network or "bep20").lower()
    if network == "polygon":
        base = tr_chat(chat_id, "network_polygon")
    elif network == "binance":
        base = tr_chat(chat_id, "network_binance")
    else:
        base = tr_chat(chat_id, "network_bep20")
    if confirmations and network in {"bep20", "polygon"}:
        return base + "\n" + tr_chat(chat_id, "network_confirm_after", confirmations=confirmations)
    return base


def _deposit_payment_keyboard(dep: sqlite3.Row) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[
        InlineKeyboardButton(tr_chat(int(dep["chat_id"]), "btn_check_payment"), callback_data=f"checkpay:{dep['ref_id']}"),
        InlineKeyboardButton(tr_chat(int(dep["chat_id"]), "btn_manual_verify"), callback_data=f"manualpay:{dep['ref_id']}"),
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
        return True, tr_chat(int(dep.get("chat_id") or dep["chat_id"]), "manual_verify_unlocked") if isinstance(dep, dict) else tr_chat(int(dep["chat_id"]), "manual_verify_unlocked")
    minutes = max(1, (remaining + 59) // 60)
    return False, tr_chat(int(dep.get("chat_id") or dep["chat_id"]), "manual_verify_unlocks", minutes=minutes) if isinstance(dep, dict) else tr_chat(int(dep["chat_id"]), "manual_verify_unlocks", minutes=minutes)


def _deposit_expired_text(dep: sqlite3.Row) -> str:
    settings = get_marketplace_settings()
    timeout_minutes = max(1, int(settings.get("payment_timeout_minutes") or PAYMENT_TIMEOUT_MINUTES))
    return tr_chat(int(dep["chat_id"]), "wallet_topup_expired", ref_id=dep["ref_id"], minutes=timeout_minutes)


def _deposit_pending_reminder_text(dep: sqlite3.Row) -> str:
    remaining_minutes = max(1, (_deposit_seconds_left(dep) + 59) // 60)
    return tr_chat(int(dep["chat_id"]), "wallet_topup_still_pending", ref_id=dep["ref_id"], minutes=remaining_minutes)


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
        text=tr_chat(chat_id, "wallet_topup_completed", amount=_money(amount_usdt), balance=_money(balance_usdt)),
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
        text=tr_chat(chat_id, "wallet_topup_rejected"),
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



def _payment_status_label(status: str, credited_at: str | None = None, chat_id: int | None = None) -> str:
    status = str(status or "").lower()
    if credited_at or status == "credited":
        return tr_chat(chat_id, "payment_status_completed")
    if status == "expired":
        return tr_chat(chat_id, "payment_status_expired")
    if status == "rejected":
        return tr_chat(chat_id, "payment_status_rejected")
    if status == "manual_pending":
        return tr_chat(chat_id, "payment_status_review")
    if status == "waiting":
        return tr_chat(chat_id, "payment_status_pending")
    return status.replace("_", " ").title() or tr_chat(chat_id, "payment_status_pending")


def _payment_method_label(method: str | None, network: str | None = None) -> str:
    key = normalize_payment_network(network or method)
    if key == "polygon":
        return "USDT (POLYGON)"
    if key == "binance":
        return "Binance Pay"
    return "USDT (BEP20)"


def _wallet_ledger_label(row: sqlite3.Row, chat_id: int | None = None) -> str:
    kind = str(row["kind"] or "").lower()
    amount = _dec(row["amount_usdt"])
    if kind in {"manual_sender_adjust", "manual_receiver_adjust"}:
        return tr_chat(chat_id, "wallet_label_admin_add") if amount >= 0 else tr_chat(chat_id, "wallet_label_admin_remove")
    return kind.replace("_", " ").title() or "Wallet Update"


def _wallet_ledger_payment_method_label(row: sqlite3.Row, chat_id: int | None = None) -> str:
    amount = _dec(row["amount_usdt"])
    return tr_chat(chat_id, "wallet_method_admin_add") if amount >= 0 else tr_chat(chat_id, "wallet_method_admin_remove")


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
            "status": _payment_status_label(dep["status"], dep["credited_at"], chat_id),
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
            "label": _wallet_ledger_label(row, chat_id),
            "method": _wallet_ledger_payment_method_label(row, chat_id),
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
    lines = [f"<b>{esc(tr_chat(chat_id, 'wallet_history_title', page=page + 1, total_pages=total_pages))}</b>", tr_chat(chat_id, "wallet_history_showing"), ""]
    if not shown:
        lines.append(tr_chat(chat_id, "wallet_history_empty"))
    else:
        for idx, item in enumerate(shown, start=1):
            if idx > 1:
                lines.append("")
            if item["type"] == "deposit":
                lines.extend([
                    f"<b>{esc(tr_chat(chat_id, 'wallet_topup_id'))}</b> <code>{esc(item['ref_id'])}</code>",
                    f"<b>{esc(tr_chat(chat_id, 'date_time'))}:</b> {esc(_history_datetime(item['created_at']))}",
                    f"<b>{esc(tr_chat(chat_id, 'payment_method_label'))}:</b> {esc(item['method'])}",
                    f"<b>{esc(tr_chat(chat_id, 'amount_label'))}:</b> ${_money(item['amount'])} USDT",
                    f"<b>{esc(tr_chat(chat_id, 'status'))}:</b> {esc(item['status'])}",
                ])
            else:
                amount = _dec(item["amount"])
                sign = "+" if amount >= 0 else "-"
                lines.extend([
                    f"<b>{esc(item['label'])}</b>",
                    f"<b>{esc(tr_chat(chat_id, 'date_time'))}:</b> {esc(_history_datetime(item['created_at']))}",
                    f"<b>{esc(tr_chat(chat_id, 'payment_method_label'))}:</b> {esc(item['method'])}",
                    f"<b>{esc(tr_chat(chat_id, 'amount_label'))}:</b> {sign}${_money(abs(amount))} USDT",
                    f"<b>{esc(tr_chat(chat_id, 'status'))}:</b> {esc(tr_chat(chat_id, 'payment_status_completed'))}",
                ])
                if item.get("related_id"):
                    lines.append(f"<b>{esc(tr_chat(chat_id, 'related_id_label'))}:</b> <code>{esc(item['related_id'])}</code>")
    buttons: list[list[InlineKeyboardButton]] = []
    nav: list[InlineKeyboardButton] = []
    if page > 0:
        nav.append(InlineKeyboardButton(tr_chat(chat_id, "btn_prev"), callback_data=f"wallet_history:{page-1}"))
    if page + 1 < total_pages:
        nav.append(InlineKeyboardButton(tr_chat(chat_id, "btn_next"), callback_data=f"wallet_history:{page+1}"))
    if nav:
        buttons.append(nav)
    buttons.append([InlineKeyboardButton(tr_chat(chat_id, "btn_topup_again"), callback_data="nav:loadwallet")])
    buttons.append([InlineKeyboardButton(tr_chat(chat_id, "btn_back"), callback_data="nav:wallet")])
    return "\n".join(lines), InlineKeyboardMarkup(buttons)


async def _send_wallet_home(message, chat_id: int) -> None:
    user = get_user_for_chat(chat_id)
    if not is_active_user_or_admin(chat_id, user):
        await message.reply_text(tr_chat(chat_id, "not_registered"))
        return
    if is_admin(chat_id) or (user and user.role == "sender"):
        await message.reply_text(
            _sender_wallet_text(chat_id),
            parse_mode="Markdown",
            reply_markup=_wallet_main_keyboard("sender", chat_id),
        )
    else:
        await message.reply_text(
            _receiver_earnings_text(chat_id),
            parse_mode="Markdown",
            reply_markup=_wallet_main_keyboard("receiver", chat_id),
        )


async def _send_load_wallet_options(message, chat_id: int) -> None:
    settings = get_marketplace_settings()
    if not available_payment_methods(settings):
        await message.reply_text(
            tr_chat(chat_id, "topup_no_methods"),
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(tr_chat(chat_id, "btn_back"), callback_data="nav:wallet")]]),
        )
        return
    await message.reply_text(
        tr_chat(chat_id, "topup_choose"),
        parse_mode="Markdown",
        reply_markup=_topup_methods_keyboard(settings, chat_id),
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
    chat_id = int(dep["chat_id"])
    network = str(dep["network"] or "bep20").lower()
    expected = _money3(dep["expected_usdt"])
    amount = _money(dep["amount_usdt"])
    pay_to = str(dep["pay_to"] or "").strip()
    pay_to_name = str(dep["pay_to_name"] or "").strip()
    settings = get_marketplace_settings()
    confirmations = int(settings.get("polygon_required_confirmations") if network == "polygon" else settings.get("bep20_required_confirmations") or 0)
    if network == "binance":
        details = tr_chat(chat_id, "payment_binance_details", pay_to=pay_to, name=esc(pay_to_name or "Binance Pay"))
    else:
        details = tr_chat(
            chat_id,
            "payment_wallet_details",
            pay_to=pay_to,
            network_line=_network_line(network, confirmations, chat_id),
        )
    interval_seconds = int(get_marketplace_settings().get("payment_watch_interval_seconds") or PAYMENT_WATCH_INTERVAL_SECONDS)
    template = tr_chat(
        chat_id,
        "payment_template",
        title=_payment_title(network, chat_id),
        ref_id=dep["ref_id"],
        amount=amount,
        expected=expected,
        details=details,
        interval_seconds=interval_seconds,
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
    user = get_user_for_chat(chat_id)
    if not is_active_user_or_admin(chat_id, user):
        await update.message.reply_text(tr_chat(chat_id, "not_registered"))
        return
    if not can_use_sender_features(chat_id, user):
        await update.message.reply_text(tr_chat(chat_id, "only_active_senders_wallet"))
        return
    await update.message.reply_text(
        _sender_wallet_text(chat_id),
        parse_mode="Markdown",
        reply_markup=_wallet_main_keyboard("sender", chat_id),
    )


async def loadwallet_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    observe_telegram_profile(update.effective_user)
    if not update.message or not update.effective_chat:
        return
    chat_id = update.effective_chat.id
    user = get_user_for_chat(chat_id)
    if not can_use_sender_features(chat_id, user):
        await update.message.reply_text(tr_chat(chat_id, "only_active_senders_load"))
        return
    if not context.args:
        await _send_load_wallet_options(update.message, chat_id)
        return
    # Compatibility: /loadwallet 25 bep20 still works, but the bot no longer presents that as the main flow.
    if len(context.args) < 2:
        await update.message.reply_text(tr_chat(chat_id, "loadwallet_hint"))
        return
    amount = _dec(context.args[0])
    method = context.args[1].strip().lower()
    if amount <= 0:
        await update.message.reply_text(tr_chat(chat_id, "amount_gt_zero"))
        return
    try:
        dep = create_deposit(chat_id, amount, method)
    except Exception as exc:
        await update.message.reply_text(tr_chat(chat_id, "could_not_create_deposit", error=str(exc)))
        return
    await _send_deposit_payment_message(update.message, dep, context)


async def wallet_nav_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.message:
        return
    await query.answer()
    chat_id = query.message.chat.id
    data = query.data or ""
    user = get_user_for_chat(chat_id)

    if data == "nav:commands":
        await query.edit_message_text(
            commands_help_text(user, chat_id),
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(tr_chat(chat_id, "btn_back"), callback_data="nav:home")]]),
        )
        return
    if data == "nav:support":
        await query.edit_message_text(
            tr_chat(chat_id, "support_text", support=support_display_text(chat_id)),
            reply_markup=support_keyboard(include_back=True, chat_id=chat_id),
        )
        return
    if data == "nav:language":
        await query.edit_message_text(
            language_selection_text(chat_id),
            reply_markup=language_selection_keyboard(chat_id, include_back=True),
        )
        return
    if data == "nav:home":
        WALLET_TOPUP_FLOW.pop(chat_id, None)
        MANUAL_TXHASH_FLOW.pop(chat_id, None)
        WITHDRAW_FLOW.pop(chat_id, None)
        DISPUTE_FLOW.pop(chat_id, None)
        DISPUTE_REPLY_FLOW.pop(chat_id, None)
        FAIL_REASON_FLOW.pop(chat_id, None)
        await query.edit_message_text(
            main_menu_text(user, chat_id),
            parse_mode="HTML",
            reply_markup=main_menu_keyboard(user, chat_id),
        )
        return

    if not is_active_user_or_admin(chat_id, user):
        await query.edit_message_text(
            tr_chat(chat_id, "not_registered_support"),
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton(tr_chat(chat_id, "btn_support"), callback_data="nav:support")],
                [InlineKeyboardButton(tr_chat(chat_id, "btn_back"), callback_data="nav:home")],
            ]),
        )
        return

    if data == "nav:messages":
        await _show_messages_menu(query, chat_id)
        return

    if data == "nav:wallet":
        await query.edit_message_text(
            _sender_wallet_text(chat_id) if is_admin(chat_id) or (user and user.role == "sender") else _receiver_earnings_text(chat_id),
            parse_mode="Markdown",
            reply_markup=_wallet_main_keyboard("sender" if is_admin(chat_id) or (user and user.role == "sender") else "receiver", chat_id),
        )
        return
    if data == "nav:earnings":
        await query.edit_message_text(
            _receiver_earnings_text(chat_id),
            parse_mode="Markdown",
            reply_markup=_wallet_main_keyboard("receiver", chat_id),
        )
        return
    if data == "nav:loadwallet":
        if not can_use_sender_features(chat_id, user):
            await query.edit_message_text(tr_chat(chat_id, "only_senders_load"))
            return
        settings = get_marketplace_settings()
        if not available_payment_methods(settings):
            await query.edit_message_text(
                tr_chat(chat_id, "topup_no_methods"),
                parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(tr_chat(chat_id, "btn_back"), callback_data="nav:wallet")]]),
            )
            return
        await query.edit_message_text(
            tr_chat(chat_id, "topup_choose"),
            parse_mode="Markdown",
            reply_markup=_topup_methods_keyboard(settings, chat_id),
        )
        return
    if data == "nav:status":
        if not can_use_sender_features(chat_id, user):
            await query.edit_message_text(
                tr_chat(chat_id, "sender_status_only_menu"),
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(tr_chat(chat_id, "btn_back"), callback_data="nav:home")]]),
            )
            return
        await query.edit_message_text(
            marketplace_status_text(chat_id),
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(tr_chat(chat_id, "btn_back"), callback_data="nav:home")]]),
        )
        return
    if data == "nav:pending":
        if not can_use_receiver_features(chat_id, user):
            await query.edit_message_text(tr_chat(chat_id, "only_receivers_pending"), reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(tr_chat(chat_id, "btn_back"), callback_data="nav:home")]]))
            return
        text, markup = _receiver_pending_text_keyboard(chat_id)
        if markup:
            rows = list(markup.inline_keyboard)
            rows.append([InlineKeyboardButton(tr_chat(chat_id, "btn_back"), callback_data="nav:home")])
            markup = InlineKeyboardMarkup(rows)
        else:
            markup = InlineKeyboardMarkup([[InlineKeyboardButton(tr_chat(chat_id, "btn_back"), callback_data="nav:home")]])
        await query.edit_message_text(text, reply_markup=markup)
        return
    if data == "nav:history":
        text, markup = _qr_history_text_keyboard(chat_id, user, 0)
        await query.edit_message_text(text, parse_mode="HTML", reply_markup=markup)
        return
    if data == "nav:dispute":
        DISPUTE_FLOW[chat_id] = {"public_id": None, "step": "reason"}
        await query.edit_message_text(
            tr_chat(chat_id, "dispute_open", qr_line=""),
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(tr_chat(chat_id, "btn_cancel"), callback_data="nav:home")]]),
        )
        return
    if data == "nav:stats":
        if is_admin(chat_id):
            text = stats_summary_text("Your sender stats", sender_chat_id=chat_id, chat_id=chat_id) + "\n\n" + stats_summary_text("Your receiver stats", receiver_chat_id=chat_id, chat_id=chat_id)
        elif user and user.role == "sender":
            text = stats_summary_text("Your sender stats", sender_chat_id=chat_id, chat_id=chat_id)
        else:
            text = stats_summary_text("Your receiver stats", receiver_chat_id=chat_id, chat_id=chat_id)
        await query.edit_message_text(
            text,
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(tr_chat(chat_id, "btn_back"), callback_data="nav:home")]]),
        )
        return


async def wallet_currency_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.message:
        return
    chat_id = query.message.chat.id
    user = get_user_for_chat(chat_id)
    if not can_use_sender_features(chat_id, user):
        await query.answer(tr_chat(chat_id, "only_active_senders_load"), show_alert=True)
        return
    network = (query.data or "").split(":", 1)[1].strip().lower()
    if not payment_method_enabled(network):
        await query.answer(tr_chat(chat_id, "topup_processed_or_expired"), show_alert=True)
        return
    await query.answer()
    await _send_topup_amount_prompt(query, chat_id, network)


async def qr_history_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.message:
        return
    chat_id = query.message.chat.id
    user = get_user_for_chat(chat_id)
    if not is_active_user_or_admin(chat_id, user):
        await query.answer(tr_chat(chat_id, "not_registered"), show_alert=True)
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
    user = get_user_for_chat(chat_id)
    if not is_active_user_or_admin(chat_id, user):
        await query.answer(tr_chat(chat_id, "not_registered"), show_alert=True)
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
        await _safe_callback_answer(query, tr_chat(query.from_user.id, "payment_not_found"), show_alert=True)
        return
    if int(dep["chat_id"]) != int(query.from_user.id):
        await _safe_callback_answer(query, tr_chat(query.from_user.id, "payment_not_yours"), show_alert=True)
        return
    if dep["credited_at"] or dep["status"] in {"credited", "confirmed"}:
        await _safe_callback_answer(query, tr_chat(query.from_user.id, "topup_already_completed"), show_alert=True)
        try:
            await send_deposit_completed_message(context.bot, dep)
        except TelegramError:
            pass
        return
    if dep["status"] not in ACTIVE_PAYMENT_CHECK_STATUSES:
        await _safe_callback_answer(query, tr_chat(query.from_user.id, "topup_processed_or_expired"), show_alert=True)
        await delete_deposit_payment_message(context.bot, dep)
        return

    # Answer immediately before the chain scan. If the Polygon RPC fallback takes
    # more than Telegram's callback-query window, the handler can still finish and
    # send the same completion message as BEP20.
    answered = await _safe_callback_answer(query, tr_chat(query.from_user.id, "checking_payment"), show_alert=False)
    tx_hash = str(dep["tx_hash"] or "").strip() or None
    use_hash = tx_hash
    ok, reason = await verify_and_credit_deposit_async(ref_id, use_hash, False, "check_button")
    if ok:
        await _safe_callback_answer(query, tr_chat(query.from_user.id, "payment_detected_processing"), show_alert=False)
        try:
            dep_after = get_deposit(ref_id) or dep
            await send_deposit_completed_message(context.bot, dep_after)
        except TelegramError:
            pass
    else:
        _unlocked, unlock_text = _manual_unlock_text(dep)
        not_found_text = tr_chat(query.from_user.id, "payment_not_found_yet_running", unlock_text=unlock_text)
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
        await query.answer(tr_chat(query.from_user.id, "payment_not_found"), show_alert=True)
        return
    if int(dep["chat_id"]) != int(query.from_user.id):
        await query.answer(tr_chat(query.from_user.id, "payment_not_yours"), show_alert=True)
        return
    active_manual = MANUAL_TXHASH_FLOW.get(int(query.from_user.id)) or {}
    if active_manual.get("ref_id") == ref_id and active_manual.get("step") == "screenshot":
        await query.answer(tr_chat(query.from_user.id, "payment_screenshot_first"), show_alert=True)
        return
    if dep["credited_at"] or dep["status"] in {"credited", "confirmed"}:
        await query.answer(tr_chat(query.from_user.id, "topup_already_completed"), show_alert=True)
        try:
            await send_deposit_completed_message(context.bot, dep)
        except TelegramError:
            pass
        return
    if dep["status"] != "waiting":
        await query.answer(tr_chat(query.from_user.id, "topup_processed_or_expired"), show_alert=True)
        await delete_deposit_payment_message(context.bot, dep)
        return

    unlocked, unlock_text = _manual_unlock_text(dep)
    if not unlocked:
        await query.answer(tr_chat(query.from_user.id, "payment_check_running") + "\n" + unlock_text, show_alert=True)
        return

    network = str(dep["network"] or dep["method"] or "").lower()
    if network == "binance":
        await query.answer(tr_chat(query.from_user.id, "checking_binance_history"), show_alert=False)
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
            await query.message.reply_text(tr_chat(query.from_user.id, "manual_verification_submitted", ref_id=ref_id))
        return

    MANUAL_TXHASH_FLOW[int(query.from_user.id)] = {"step": "txn_hash", "ref_id": ref_id}
    await query.answer()
    await query.message.reply_text(
        tr_chat(query.from_user.id, "manual_hash_prompt") + "\n\n" + tr_chat(query.from_user.id, "txid_hint"),
        parse_mode="Markdown",
    )


async def wallet_text_flow(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message or not update.effective_chat or not update.message.text:
        return
    chat_id = update.effective_chat.id
    user = get_user_for_chat(chat_id)
    if not is_active_user_or_admin(chat_id, user):
        return
    text = update.message.text.strip()
    if chat_id in FAIL_REASON_FLOW:
        await update.message.reply_text(tr_chat(chat_id, "select_failure_buttons_only"))
        return
    if chat_id in DISPUTE_REPLY_FLOW:
        await submit_dispute_chat_reply(update.message, chat_id, text)
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
            await update.message.reply_text(tr_chat(chat_id, "send_screenshot_not_text"))
            return
        ref_id = str(state.get("ref_id") or "").upper()
        tx_hash = text.strip()
        dep = get_deposit(ref_id)
        if not dep or int(dep["chat_id"]) != chat_id:
            MANUAL_TXHASH_FLOW.pop(chat_id, None)
            await update.message.reply_text(tr_chat(chat_id, "payment_session_gone"))
            return
        if dep["credited_at"] or dep["status"] != "waiting":
            MANUAL_TXHASH_FLOW.pop(chat_id, None)
            await update.message.reply_text(tr_chat(chat_id, "topup_processed_or_expired"))
            return
        if not re.fullmatch(r"0x[a-fA-F0-9]{64}", tx_hash):
            await update.message.reply_text(tr_chat(chat_id, "invalid_tx_hash"), parse_mode="Markdown")
            return
        checking_msg = await update.message.reply_text(tr_chat(chat_id, "checking_tx_hash"))
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
                    tr_chat(chat_id, "txhash_admin_review"),
                    parse_mode="Markdown",
                )
                return
            if _manual_failure_is_user_fixable(reason):
                MANUAL_TXHASH_FLOW[chat_id] = {"step": "txn_hash", "ref_id": ref_id}
                if "already been used" in public_reason.lower() or "already linked" in public_reason.lower() or "duplicate" in public_reason.lower():
                    await update.message.reply_text(
                        tr_chat(chat_id, "txhash_already_used")
                    )
                else:
                    await update.message.reply_text(
                        tr_chat(chat_id, "txhash_incorrect")
                    )
                return
            MANUAL_TXHASH_FLOW[chat_id] = {"step": "screenshot", "ref_id": ref_id, "tx_hash": tx_hash, "reason": public_reason}
            await update.message.reply_text(
                tr_chat(chat_id, "screenshot_proof_next"),
                parse_mode="Markdown",
            )
        return
    state = WALLET_TOPUP_FLOW.get(chat_id)
    if not state or state.get("step") != "amount":
        return
    try:
        amount = _dec(text)
    except Exception:
        await update.message.reply_text(tr_chat(chat_id, "enter_valid_number"))
        return
    if amount <= 0:
        await update.message.reply_text(tr_chat(chat_id, "amount_gt_zero"))
        return
    network = str(state.get("network") or "bep20")
    settings = get_marketplace_settings()
    min_topup = _dec(settings.get("wallet_min_usdt"), DEFAULT_MIN_WALLET_TOPUP_USDT)
    if amount < min_topup:
        await update.message.reply_text(tr_chat(chat_id, "minimum_topup_amount", amount=_money(min_topup)))
        return
    WALLET_TOPUP_FLOW.pop(chat_id, None)
    try:
        dep = create_deposit(chat_id, amount, network)
    except Exception as exc:
        await update.message.reply_text(tr_chat(chat_id, "could_not_create_deposit", error=str(exc)))
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
        await update.message.reply_text(tr_chat(chat_id, "send_screenshot_proof"))
        return True
    ref_id = str(state.get("ref_id") or "").upper()
    tx_hash = str(state.get("tx_hash") or "").strip()
    dep = get_deposit(ref_id)
    MANUAL_TXHASH_FLOW.pop(chat_id, None)
    if not dep or int(dep["chat_id"]) != chat_id:
        await update.message.reply_text(tr_chat(chat_id, "payment_session_gone"))
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
            await update.message.reply_text(tr_chat(chat_id, "txhash_used_other"))
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
        tr_chat(chat_id, "manual_verification_submitted", ref_id=ref_id),
    )
    return True


async def earnings_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    observe_telegram_profile(update.effective_user)
    if not update.message or not update.effective_chat:
        return
    chat_id = update.effective_chat.id
    user = get_user_for_chat(chat_id)
    if not is_active_user_or_admin(chat_id, user):
        await update.message.reply_text(tr_chat(chat_id, "not_registered"))
        return
    if not can_use_receiver_features(chat_id, user):
        await update.message.reply_text(tr_chat(chat_id, "only_active_receivers_earnings"))
        return
    await update.message.reply_text(
        _receiver_earnings_text(chat_id),
        parse_mode="Markdown",
        reply_markup=_wallet_main_keyboard("receiver", chat_id),
    )


async def _send_withdraw_amount_prompt(message_or_query, chat_id: int) -> None:
    settings = get_marketplace_settings()
    min_payout = _dec(settings["min_payout_usdt"])
    _wallet, due, requested, available, _paid = receiver_earnings_numbers(chat_id)
    WITHDRAW_FLOW[chat_id] = {"step": "amount"}
    text = tr_chat(chat_id, "withdraw_prompt", available=_money(available), minimum=_money(min_payout))
    # Receivers must type the withdrawal amount manually. Keep only navigation buttons here.
    markup = InlineKeyboardMarkup([[InlineKeyboardButton(tr_chat(chat_id, "btn_back"), callback_data="nav:wallet")]])
    if hasattr(message_or_query, "edit_message_text"):
        await message_or_query.edit_message_text(text, reply_markup=markup)
    else:
        await message_or_query.reply_text(text, reply_markup=markup)


async def _send_withdraw_details_prompt(message_or_query, chat_id: int, amount: Decimal | None = None) -> None:
    state: dict[str, Any] = {"step": "details"}
    if amount is not None:
        state["amount"] = str(amount)
    WITHDRAW_FLOW[chat_id] = state
    text = tr_chat(chat_id, "send_payment_details")
    markup = InlineKeyboardMarkup([[InlineKeyboardButton(tr_chat(chat_id, "btn_cancel"), callback_data="nav:wallet")]])
    if hasattr(message_or_query, "edit_message_text"):
        await message_or_query.edit_message_text(text, reply_markup=markup)
    else:
        await message_or_query.reply_text(text, reply_markup=markup)


async def _send_withdraw_payment_choice_prompt(message_or_query, chat_id: int, amount: Decimal, saved_details: str) -> None:
    WITHDRAW_FLOW[chat_id] = {"step": "payment_choice", "amount": str(amount)}
    text = tr_chat(chat_id, "payment_details_question", amount=_money(amount))
    markup = InlineKeyboardMarkup([
        [InlineKeyboardButton(payment_method_button_label(saved_details), callback_data="withdraw:use_saved")],
        [InlineKeyboardButton(tr_chat(chat_id, "btn_enter_new_payment_details"), callback_data="withdraw:new_details")],
        [InlineKeyboardButton(tr_chat(chat_id, "btn_cancel"), callback_data="nav:wallet")],
    ])
    if hasattr(message_or_query, "edit_message_text"):
        await message_or_query.edit_message_text(text, reply_markup=markup)
    else:
        await message_or_query.reply_text(text, reply_markup=markup)


async def _send_withdraw_prompt(message_or_query, chat_id: int) -> None:
    user = get_user_for_chat(chat_id)
    if not can_use_receiver_features(chat_id, user):
        text = tr_chat(chat_id, "only_active_receivers_payout")
        if hasattr(message_or_query, "edit_message_text"):
            await message_or_query.edit_message_text(text)
        else:
            await message_or_query.reply_text(text)
        return
    settings = get_marketplace_settings()
    min_payout = _dec(settings["min_payout_usdt"])
    _wallet, _due, _requested, available, _paid = receiver_earnings_numbers(chat_id)
    back_markup = InlineKeyboardMarkup([[InlineKeyboardButton(tr_chat(chat_id, "btn_back"), callback_data="nav:wallet")]])
    if _usdt_lt(available, min_payout):
        WITHDRAW_FLOW.pop(chat_id, None)
        text = tr_chat(chat_id, "withdraw_no_available", available=_money(available), minimum=_money(min_payout))
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
    chat_id = update.effective_chat.id
    user = get_user_for_chat(chat_id)
    if not can_use_receiver_features(chat_id, user):
        await update.message.reply_text(tr_chat(chat_id, "only_active_receivers_payout"))
        return
    if context.args:
        amount = _dec(context.args[0])
        await submit_withdraw_amount(update.message, chat_id, amount)
        return
    await _send_withdraw_prompt(update.message, chat_id)


async def withdraw_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.message:
        return
    chat_id = query.message.chat.id
    data = query.data or "withdraw:start"
    user = get_user_for_chat(chat_id)
    if not can_use_receiver_features(chat_id, user):
        await query.answer(tr_chat(chat_id, "only_active_receivers_payout"), show_alert=True)
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
    user = get_user_for_chat(chat_id)
    if not can_use_receiver_features(chat_id, user):
        await message.reply_text(tr_chat(chat_id, "only_active_receivers_payout"))
        return
    details = clean_payout_details_text(details_text)
    if len(details) < 4:
        await message.reply_text(tr_chat(chat_id, "send_payment_details"))
        return
    save_receiver_payout_details(chat_id, details)
    state = WITHDRAW_FLOW.get(chat_id) or {}
    pending_amount = state.get("amount")
    if pending_amount is not None:
        amount = _dec(str(pending_amount), "-1")
        await submit_withdraw_request(message, chat_id, amount, details)
        return
    await message.reply_text(tr_chat(chat_id, "payment_details_saved"))
    await _send_withdraw_amount_prompt(message, chat_id)


async def submit_withdraw_amount(message, chat_id: int, amount: Decimal) -> None:
    user = get_user_for_chat(chat_id)
    if not can_use_receiver_features(chat_id, user):
        await message.reply_text(tr_chat(chat_id, "only_active_receivers_payout"))
        return
    settings = get_marketplace_settings()
    min_payout = _dec(settings["min_payout_usdt"])
    _wallet, due, requested, available, _paid = receiver_earnings_numbers(chat_id)
    if amount <= 0:
        await message.reply_text(tr_chat(chat_id, "send_valid_quantity"))
        return
    if _usdt_lt(amount, min_payout):
        await message.reply_text(tr_chat(chat_id, "minimum_payout", amount=_money(min_payout)))
        return
    if _usdt_gt(amount, available):
        await message.reply_text(tr_chat(chat_id, "withdraw_available_due", available=_money(available), due=_money(due), requested=_money(requested)))
        return

    saved_details = get_receiver_payout_details(chat_id)
    if saved_details:
        await _send_withdraw_payment_choice_prompt(message, chat_id, amount, saved_details)
        return
    await _send_withdraw_details_prompt(message, chat_id, amount)


async def submit_withdraw_request(message_or_query, chat_id: int, amount: Decimal, payout_details: str) -> None:
    user = get_user_for_chat(chat_id)
    if not can_use_receiver_features(chat_id, user):
        text = tr_chat(chat_id, "only_active_receivers_payout")
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
    elif _usdt_lt(amount, min_payout):
        text = tr_chat(chat_id, "minimum_payout", amount=_money(min_payout))
    elif _usdt_gt(amount, available):
        text = f"Available: ${_money(available)} USDT\nDue: ${_money(due)} USDT · Requested: ${_money(requested)} USDT"
    else:
        text = ""
    if text:
        if hasattr(message_or_query, "edit_message_text"):
            await message_or_query.edit_message_text(text, reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(tr_chat(chat_id, "btn_back"), callback_data="nav:wallet")]]))
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
    text = tr_chat(chat_id, "withdraw_submitted", payout_id=payout_id, amount=_money(amount))
    if hasattr(message_or_query, "edit_message_text"):
        await message_or_query.edit_message_text(text)
    else:
        await message_or_query.reply_text(text)

def _dispute_public_id_from_reply(chat_id: int, user: UserRow, reply_message_id: int | None) -> str | None:
    if not reply_message_id:
        return None
    if is_admin(chat_id):
        photo = find_photo_by_receiver_message_id(chat_id, reply_message_id) or find_photo_by_sender_message_id(chat_id, reply_message_id)
    elif user.role == "receiver":
        photo = find_photo_by_receiver_message_id(chat_id, reply_message_id)
    else:
        photo = find_photo_by_sender_message_id(chat_id, reply_message_id)
    return photo.public_id if photo else None


def _validate_dispute_public_id(chat_id: int, user: UserRow, public_id: str | None) -> tuple[bool, str | None]:
    if not public_id:
        return True, None
    row = get_photo_record(public_id)
    if not row:
        return False, tr_chat(chat_id, "qr_id_not_found")
    if not is_admin(chat_id):
        if user.role == "sender" and int(row["sender_chat_id"]) != chat_id:
            return False, tr_chat(chat_id, "qr_not_linked_sender")
        if user.role == "receiver" and int(row["receiver_chat_id"] or 0) != chat_id:
            return False, tr_chat(chat_id, "qr_not_linked_receiver")
    order_status = str(row["status"] or "").lower()
    if order_status not in {"done", "failed"}:
        return False, tr_chat(chat_id, "dispute_only_after_finished")
    return True, None


async def dispute_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    observe_telegram_profile(update.effective_user)
    if not update.message or not update.effective_chat:
        return
    chat_id = update.effective_chat.id
    user = get_user_for_chat(chat_id)
    if not is_active_user_or_admin(chat_id, user):
        await update.message.reply_text(tr_chat(chat_id, "not_registered"))
        return

    public_id = None
    if context.args and re.fullmatch(r"\d{4}-\d{2}-\d{2}-\d{4}", context.args[0].strip()):
        public_id = context.args[0].strip()
    if not public_id and update.message.reply_to_message:
        public_id = _dispute_public_id_from_reply(chat_id, user, update.message.reply_to_message.message_id)

    ok, error = _validate_dispute_public_id(chat_id, user, public_id)
    if not ok:
        await update.message.reply_text(error or tr_chat(chat_id, "could_not_start_dispute"))
        return

    DISPUTE_FLOW[chat_id] = {"public_id": public_id, "step": "reason"}
    qr_line = f"QR ID: `{public_id}`" if public_id else ""
    await update.message.reply_text(
        tr_chat(chat_id, "dispute_open", qr_line=qr_line),
        parse_mode="Markdown",
    )


async def dispute_qr_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.message:
        return
    await query.answer()
    chat_id = query.message.chat.id
    user = get_user_for_chat(chat_id)
    if not is_active_user_or_admin(chat_id, user):
        await query.message.reply_text(tr_chat(chat_id, "not_registered"))
        return
    public_id = (query.data or "").split(":", 1)[1].strip()
    ok, error = _validate_dispute_public_id(chat_id, user, public_id)
    if not ok:
        await query.message.reply_text(error or tr_chat(chat_id, "could_not_start_dispute"))
        return
    DISPUTE_FLOW[chat_id] = {"public_id": public_id, "step": "reason"}
    await query.message.reply_text(
        tr_chat(chat_id, "dispute_open", qr_line=f"QR ID: `{public_id}`"),
        parse_mode="Markdown",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(tr_chat(chat_id, "btn_cancel"), callback_data="nav:home")]]),
    )


async def submit_dispute_reason(message, chat_id: int, reason: str) -> None:
    user = get_user_for_chat(chat_id)
    if not is_active_user_or_admin(chat_id, user):
        await message.reply_text(tr_chat(chat_id, "not_registered"))
        DISPUTE_FLOW.pop(chat_id, None)
        return
    reason = reason.strip()
    if reason.lower() in {"cancel", "/cancel"}:
        DISPUTE_FLOW.pop(chat_id, None)
        await message.reply_text(tr_chat(chat_id, "dispute_cancelled"))
        return
    if len(reason) < 3:
        await message.reply_text(tr_chat(chat_id, "dispute_reason_clear"))
        return
    state = DISPUTE_FLOW.pop(chat_id, {})
    public_id = state.get("public_id")
    ref_id = create_dispute(chat_id, public_id, reason)
    await message.reply_text(tr_chat(chat_id, "dispute_submitted", ref_id=ref_id))
    await notify_admins_new_dispute(ref_id, chat_id, public_id, reason)


async def notify_admins_new_dispute(ref_id: str, chat_id: int, public_id: str | None, message_text: str) -> None:
    if telegram_application is None or not ADMIN_IDS:
        return
    qr_line = f"\nQR ID: {public_id}" if public_id else ""
    text = f"⚠️ New dispute #{ref_id}{qr_line}\nFrom: {chat_id}\n\n{message_text}"
    for admin_id in sorted(ADMIN_IDS):
        try:
            await telegram_application.bot.send_message(chat_id=admin_id, text=text, protect_content=PROTECT_CONTENT)
        except TelegramError:
            pass


async def notify_admins_dispute_reply(row: sqlite3.Row, reply_text: str) -> None:
    if telegram_application is None or not ADMIN_IDS:
        return
    ref = str(row['ref_id'] or f"DSP{int(row['id']):06d}")
    qr_line = f"\nQR ID: {row['public_id']}" if row['public_id'] else ""
    text = f"💬 New dispute reply #{ref}{qr_line}\nFrom: {row['chat_id']}\n\n{reply_text}"
    markup = None
    if WEBHOOK_URL:
        markup = InlineKeyboardMarkup([[InlineKeyboardButton("⚠️ Open disputes", url=f"{WEBHOOK_URL}/admin/disputes?status=attention")]])
    for admin_id in sorted(ADMIN_IDS):
        try:
            await telegram_application.bot.send_message(chat_id=admin_id, text=text, reply_markup=markup, protect_content=PROTECT_CONTENT)
        except TelegramError:
            pass


async def dispute_reply_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.message:
        return
    data = query.data or ""
    raw_id = data.split(":", 1)[1].strip() if ":" in data else ""
    try:
        dispute_id = int(raw_id)
    except ValueError:
        await query.answer(tr_chat(chat_id if "chat_id" in locals() else query.from_user.id, "dispute_not_found"), show_alert=True)
        return
    row = get_dispute_by_id(dispute_id)
    chat_id = int(query.from_user.id)
    if not row or int(row['chat_id']) != chat_id:
        await query.answer(tr_chat(chat_id, "dispute_not_yours"), show_alert=True)
        return
    if str(row['status'] or '').lower() not in {'open', 'under_review'}:
        await query.answer(tr_chat(chat_id, "dispute_closed"), show_alert=True)
        return
    ref = str(row['ref_id'] or f"DSP{int(row['id']):06d}")
    DISPUTE_REPLY_FLOW[chat_id] = {"dispute_id": int(row['id']), "ref": ref}
    await query.answer()
    await query.message.reply_text(
        tr_chat(chat_id, "dispute_reply_prompt", ref=ref),
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(tr_chat(chat_id, "btn_cancel"), callback_data="nav:home")]]),
    )


async def submit_dispute_chat_reply(message, chat_id: int, reply_text: str) -> None:
    reply_text = str(reply_text or "").strip()
    if reply_text.lower() in {"cancel", "/cancel"}:
        DISPUTE_REPLY_FLOW.pop(chat_id, None)
        await message.reply_text(tr_chat(chat_id, "dispute_reply_cancelled"))
        return
    if len(reply_text) < 2:
        await message.reply_text(tr_chat(chat_id, "dispute_reply_clear"))
        return
    state = DISPUTE_REPLY_FLOW.pop(chat_id, {})
    dispute_id = int(state.get("dispute_id") or 0)
    row = get_dispute_by_id(dispute_id)
    if not row or int(row['chat_id']) != int(chat_id):
        await message.reply_text(tr_chat(chat_id, "dispute_not_found"))
        return
    if str(row['status'] or '').lower() not in {'open', 'under_review'}:
        await message.reply_text(tr_chat(chat_id, "dispute_closed"))
        return
    add_dispute_chat_message(dispute_id, "user", chat_id, reply_text)
    ref = str(row['ref_id'] or f"DSP{int(row['id']):06d}")
    await message.reply_text(tr_chat(chat_id, "dispute_reply_added", ref=ref))
    await notify_admins_dispute_reply(row, reply_text)


async def dispute_reply_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message or not update.effective_chat:
        return
    chat_id = update.effective_chat.id
    if not context.args:
        await update.message.reply_text(tr_chat(chat_id, "dispute_reply_usage"))
        return
    row = get_dispute_by_ref(context.args[0])
    if not row or int(row['chat_id']) != int(chat_id):
        await update.message.reply_text(tr_chat(chat_id, "dispute_not_found"))
        return
    if str(row['status'] or '').lower() not in {'open', 'under_review'}:
        await update.message.reply_text(tr_chat(chat_id, "dispute_closed"))
        return
    if len(context.args) == 1:
        DISPUTE_REPLY_FLOW[chat_id] = {"dispute_id": int(row['id']), "ref": str(row['ref_id'] or '')}
        await update.message.reply_text(tr_chat(chat_id, "dispute_reply_send_now", ref=row['ref_id']))
        return
    reply_text = " ".join(context.args[1:]).strip()
    DISPUTE_REPLY_FLOW[chat_id] = {"dispute_id": int(row['id']), "ref": str(row['ref_id'] or '')}
    await submit_dispute_chat_reply(update.message, chat_id, reply_text)


async def enforce_qr_expiry_after_delay(application: Application, public_id: str, expires_at: str | datetime | None) -> None:
    """Expire a single QR as soon as its configured expiry time passes.

    This is an extra runtime guard on top of marketplace_watcher().  The watcher
    still handles restarts and missed tasks; this task makes live orders expire
    close to the configured QR_EXPIRE_MINUTES value even after a receiver claims
    the QR.
    """
    try:
        delay = seconds_until_iso(expires_at)
        if delay > 0:
            await asyncio.sleep(delay + 1)
        row = get_photo_record(public_id)
        if not row:
            return
        if str(row["status"] or "").lower() != "pending":
            return
        if str(row["offer_state"] or "").lower() not in {"open", "claimed"}:
            return
        if not iso_is_due(row["offer_expires_at"]):
            return
        ok, _msg, expired_row = expire_pending_qr_in_db(public_id)
        if ok and expired_row is not None:
            await notify_qr_expired_by_timeout(application.bot, public_id, expired_row)
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.exception("QR expiry task failed for %s", public_id)


def schedule_qr_expiry_task(application: Application | None, public_id: str, expires_at: str | datetime | None) -> None:
    if application is None:
        return
    try:
        application.create_task(
            enforce_qr_expiry_after_delay(application, public_id, expires_at),
            name=f"qr_expiry_{public_id}",
        )
    except TypeError:
        # Older python-telegram-bot versions may not accept name=.
        application.create_task(enforce_qr_expiry_after_delay(application, public_id, expires_at))
    except Exception:
        logger.exception("Could not schedule QR expiry task for %s", public_id)


async def send_receiver_expiry_warning(bot, row: sqlite3.Row) -> bool:
    public_id = str(row["public_id"])
    receiver_chat_id = int(row["receiver_chat_id"] or 0)
    if receiver_chat_id <= 0:
        return False
    current = get_photo_record(public_id)
    if not current:
        return False
    if str(current["status"] or "").lower() != "pending" or str(current["offer_state"] or "").lower() != "claimed":
        return False
    if current["receiver_warning_sent_at"]:
        return False
    if iso_is_due(current["offer_expires_at"]):
        return False
    if not mark_receiver_expiry_warning_sent(public_id):
        return False
    try:
        await bot.send_message(
            chat_id=receiver_chat_id,
            text=tr_chat(
                receiver_chat_id,
                "receiver_expiry_warning",
                time_left=format_time_left_for_chat(receiver_chat_id, current["offer_expires_at"]),
            ),
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(tr_chat(receiver_chat_id, "btn_open_pending_qr"), callback_data=f"pendingqr:{public_id}")]]),
            protect_content=PROTECT_CONTENT,
        )
        return True
    except TelegramError as exc:
        logger.warning("Could not send expiry warning for QR %s to receiver %s: %s", public_id, receiver_chat_id, exc)
        return False


async def warn_receiver_before_expiry_after_delay(application: Application, public_id: str, expires_at: str | datetime | None) -> None:
    try:
        delay = max(0, seconds_until_iso(expires_at) - 60)
        if delay > 0:
            await asyncio.sleep(delay)
        row = get_photo_record(public_id)
        if row is not None:
            await send_receiver_expiry_warning(application.bot, row)
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.exception("QR expiry warning task failed for %s", public_id)


def schedule_qr_expiry_warning_task(application: Application | None, public_id: str, expires_at: str | datetime | None) -> None:
    if application is None:
        return
    try:
        application.create_task(
            warn_receiver_before_expiry_after_delay(application, public_id, expires_at),
            name=f"qr_expiry_warning_{public_id}",
        )
    except TypeError:
        application.create_task(warn_receiver_before_expiry_after_delay(application, public_id, expires_at))
    except Exception:
        logger.exception("Could not schedule QR expiry warning task for %s", public_id)


async def send_offer_to_receivers_by_bot(bot, public_id: str) -> tuple[int, int]:
    row = get_photo_record(public_id)
    if not row:
        return 0, 0
    receivers = online_receivers()
    if not receivers:
        return 0, 0

    # Send offers concurrently. Sequential sends can waste several seconds when many
    # receivers are online, and mandate QRs are time-limited.
    semaphore = asyncio.Semaphore(25)

    async def send_one(receiver) -> tuple[int, int | None]:
        receiver_chat_id = int(receiver["chat_id"])
        async with semaphore:
            try:
                msg = await bot.send_message(
                    chat_id=receiver_chat_id,
                    text=build_offer_text(public_id, int(row["daily_no"]), effective_sender_charge_amount(row, use_current_setting_if_missing=True), _dec(row["receiver_rate_usdt"]), str(row["offer_expires_at"]), receiver_chat_id),
                    reply_markup=build_offer_keyboard(public_id, receiver_chat_id),
                    protect_content=PROTECT_CONTENT,
                )
                return receiver_chat_id, msg.message_id
            except TelegramError as exc:
                logger.warning("Could not send offer %s to receiver %s: %s", public_id, receiver_chat_id, exc)
                return receiver_chat_id, None

    results = await asyncio.gather(*(send_one(receiver) for receiver in receivers))
    sent = failed = 0
    for receiver_chat_id, message_id in results:
        if message_id is None:
            failed += 1
            continue
        record_offer_notification(public_id, receiver_chat_id, message_id)
        sent += 1
    return sent, failed


async def send_offer_to_receivers(context: ContextTypes.DEFAULT_TYPE, public_id: str) -> tuple[int, int]:
    return await send_offer_to_receivers_by_bot(context.bot, public_id)

def reopen_failed_qr_in_db(public_id: str, expires_at: str) -> tuple[bool, str, sqlite3.Row | None]:
    row = get_photo_record(public_id)
    if not row:
        return False, "QR order not found.", None
    status = str(row["status"] or "").lower()
    if status == "pending":
        return False, "This QR is already pending/open.", row
    if status == "done":
        return False, "Done QR orders cannot be retried. Change it to Failed first if you need to reopen it.", row
    if not row["generated_file_id"]:
        return False, "This QR has no stored generated image, so it cannot be retried.", row
    sender_chat_id = int(row["sender_chat_id"])
    sender_rate = effective_sender_charge_amount(row, use_current_setting_if_missing=True)
    if available_sender_balance(sender_chat_id) < sender_rate:
        return False, f"Sender available balance is too low to retry. Required: ${_money(sender_rate)} USDT.", row
    ok, reserve_msg = reserve_sender_funds(sender_chat_id, sender_rate, public_id)
    if not ok:
        return False, reserve_msg, row
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        current = conn.execute("SELECT * FROM photos WHERE public_id = ?", (public_id,)).fetchone()
        if not current or str(current["status"] or "").lower() != "failed":
            conn.rollback()
            release_sender_reserve(sender_chat_id, sender_rate, public_id, "Retry aborted")
            return False, "QR was changed before retry could start.", current or row
        conn.execute("DELETE FROM offer_notifications WHERE public_id = ?", (public_id,))
        conn.execute(
            """
            UPDATE photos
            SET status = 'pending', offer_state = 'open', receiver_chat_id = 0, receiver_message_id = NULL,
                claimed_at = NULL, status_by = NULL, status_at = NULL, failure_reason = NULL,
                offer_expires_at = ?, charged_usdt = 0, earned_usdt = 0, reserved_usdt = ?,
                settled_at = NULL, receiver_warning_sent_at = NULL
            WHERE public_id = ?
            """,
            (expires_at, float(sender_rate), public_id),
        )
        new_row = conn.execute("SELECT * FROM photos WHERE public_id = ?", (public_id,)).fetchone()
        conn.commit()
    return True, "QR reopened as a new marketplace offer.", new_row


async def admin_retry_qr_order(bot, public_id: str) -> tuple[bool, str]:
    if not online_receivers():
        return False, "No online receivers right now. Ask a receiver to use /on LIMIT first, then retry."
    settings = get_marketplace_settings()
    expires_at = datetime.fromtimestamp(now_dt().timestamp() + max(1, int(settings["qr_expire_minutes"])) * 60, ZoneInfo(BOT_TZ)).isoformat(timespec="seconds")
    ok, msg, row = reopen_failed_qr_in_db(public_id, expires_at)
    if not ok or row is None:
        return False, msg
    sent, failed = await send_offer_to_receivers_by_bot(bot, public_id)
    sender_chat_id = int(row["sender_chat_id"])
    if sent <= 0:
        expire_offer_in_db(public_id, "expired")
        release_sender_reserve(sender_chat_id, effective_sender_charge_amount(row, use_current_setting_if_missing=True), public_id, "Retry failed: no receiver could be notified")
        await edit_sender_offer_caption(
            bot,
            sender_chat_id,
            int(row["sender_message_id"] or 0),
            build_sender_offer_caption(
                str(row["date"]),
                int(row["daily_no"]),
                public_id,
                tr_chat(sender_chat_id, "offer_failed_no_receiver"),
                chat_id=sender_chat_id,
            ),
            reply_markup=None,
        )
        return False, "Retry failed: no receiver could be notified. Sender reserve was released."
    await edit_sender_offer_caption(
        bot,
        sender_chat_id,
        int(row["sender_message_id"] or 0),
        build_sender_offer_caption(
            str(row["date"]),
            int(row["daily_no"]),
            public_id,
            tr_chat(sender_chat_id, "sender_offer_sent"),
            expires_at=expires_at,
            sender_rate=effective_sender_reserved_display(row),
            order_row=row,
            chat_id=sender_chat_id,
        ),
        reply_markup=sender_open_offer_keyboard(public_id, sender_chat_id),
    )
    if telegram_application is not None:
        schedule_qr_expiry_task(telegram_application, public_id, expires_at)
    return True, f"QR retried and sent to {sent} receiver(s). {failed} failed."

async def handle_photo(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    observe_telegram_profile(update.effective_user)
    if not update.effective_chat or not update.message:
        return
    if await wallet_manual_screenshot_flow(update, context):
        return

    chat = update.effective_chat
    if chat.type != ChatType.PRIVATE:
        return

    user = get_user_for_chat(chat.id)
    if not can_use_sender_features(chat.id, user):
        await update.message.reply_text(tr_chat(chat.id, "only_active_sender_photos"))
        return

    settings = get_marketplace_settings()
    if settings["maintenance_mode"]:
        await update.message.reply_text(tr_chat(chat.id, "maintenance_paused"))
        return

    receivers = online_receivers()
    if not receivers:
        await update.message.reply_text(tr_chat(chat.id, "no_receiver_online"))
        return

    sender_rate = _dec(settings["sender_rate_usdt"])
    receiver_rate = _dec(settings["receiver_rate_usdt"])
    if sender_rate > 0 and available_sender_balance(chat.id) < sender_rate:
        await update.message.reply_text(
            tr_chat(chat.id, "insufficient_wallet", required=_money(sender_rate), available=_money(available_sender_balance(chat.id)))
        )
        return

    started_at = time.perf_counter()
    try:
        clean_qr_file, qr_data, qr_hash = await extract_and_rebuild_clean_qr(update.message)
    except ValueError as exc:
        await update.message.reply_text(
            tr_chat(chat.id, "photo_rejected_clear_qr", error=str(exc))
        )
        await delete_original_sender_message_safely(context, chat.id, update.message.message_id, rejected=True)
        return
    except Exception:
        logger.exception("Unexpected QR processing error")
        await update.message.reply_text(tr_chat(chat.id, "photo_rejected_process"))
        await delete_original_sender_message_safely(context, chat.id, update.message.message_id, rejected=True)
        return

    date_str = today_str()
    daily_no = reserve_daily_number(date_str)
    public_id = f"{date_str}-{daily_no:04d}"
    qr_expire_minutes = int(settings["qr_expire_minutes"])
    expires_at = datetime.fromtimestamp(now_dt().timestamp() + max(1, qr_expire_minutes) * 60, ZoneInfo(BOT_TZ)).isoformat(timespec="seconds")

    ok, reserve_msg = reserve_sender_funds(chat.id, sender_rate, public_id)
    if not ok:
        await update.message.reply_text(
            tr_chat(chat.id, "insufficient_wallet", required=_money(sender_rate), available=_money(available_sender_balance(chat.id)))
        )
        return

    processing_ms = int((time.perf_counter() - started_at) * 1000)
    caption = build_sender_offer_caption(
        date_str,
        daily_no,
        public_id,
        tr_chat(chat.id, "sender_offer_created"),
        expires_at=expires_at,
        sender_rate=sender_rate,
        chat_id=chat.id,
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
        await update.message.reply_text(tr_chat(chat.id, "clean_qr_send_failed"))
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
    schedule_qr_expiry_task(context.application, public_id, expires_at)

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
                tr_chat(chat.id, "offer_failed_no_receiver"),
                chat_id=chat.id,
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
                tr_chat(chat.id, "sender_offer_sent"),
                expires_at=expires_at,
                sender_rate=sender_rate,
                chat_id=chat.id,
            ),
            reply_markup=sender_open_offer_keyboard(public_id, chat.id),
        )

    await delete_original_sender_message_safely(context, chat.id, update.message.message_id)


async def reject_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message:
        await update.message.reply_text(
            tr_chat(update.effective_chat.id if update.effective_chat else None, "send_photo_not_document")
        )


async def resolve_pending_photo_for_status(
    *,
    bot,
    actor_chat_id: int,
    public_id: str | None = None,
    reply_to_message_id: int | None = None,
) -> tuple[PhotoRow | None, str | None]:
    actor = get_user_for_chat(actor_chat_id)

    if not can_use_receiver_features(actor_chat_id, actor):
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

    if iso_is_due(record["offer_expires_at"]):
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
        return False, tr_chat(actor_chat_id, "status_invalid")

    if status == "failed":
        failure_reason = clean_failure_reason_text(failure_reason)
        if not failure_reason:
            return False, tr_chat(actor_chat_id, "select_failure_first")

    photo, error = await resolve_pending_photo_for_status(
        bot=bot,
        actor_chat_id=actor_chat_id,
        public_id=public_id,
        reply_to_message_id=reply_to_message_id,
    )
    if error or not photo:
        return False, error or tr_chat(actor_chat_id, "qr_photo_not_found")

    ok = update_photo_status(photo.public_id, status, actor_chat_id, failure_reason=failure_reason)
    if not ok:
        return False, tr_chat(actor_chat_id, "status_update_failed")

    settle_photo_wallets(photo.public_id, status)

    status_text = tr_chat(actor_chat_id, "stats_done") if status == "done" else tr_chat(actor_chat_id, "stats_failed")
    receiver_caption = build_status_caption(photo, status, failure_reason=failure_reason, chat_id=photo.receiver_chat_id or actor_chat_id)
    sender_caption = build_status_caption(photo, status, failure_reason=failure_reason, chat_id=photo.sender_chat_id)
    if status == "failed":
        receiver_caption += f"\n💳 {tr_chat(photo.receiver_chat_id or actor_chat_id, 'caption_sender_reserve_released')}"
        sender_caption += f"\n💳 {tr_chat(photo.sender_chat_id, 'caption_sender_reserve_released')}"

    # Update the existing QR photo captions on both sides. This avoids extra status messages.
    edit_errors: list[str] = []

    if photo.receiver_message_id:
        try:
            await bot.edit_message_caption(
                chat_id=photo.receiver_chat_id,
                message_id=photo.receiver_message_id,
                caption=receiver_caption,
                reply_markup=qr_dispute_keyboard(photo.public_id, photo.receiver_chat_id or actor_chat_id),
            )
        except TelegramError as exc:
            logger.warning("Could not edit receiver QR caption %s/%s: %s", photo.receiver_chat_id, photo.receiver_message_id, exc)
            edit_errors.append("receiver")

    if photo.sender_message_id:
        try:
            await bot.edit_message_caption(
                chat_id=photo.sender_chat_id,
                message_id=photo.sender_message_id,
                caption=sender_caption,
                reply_markup=qr_dispute_keyboard(photo.public_id, photo.sender_chat_id),
            )
        except TelegramError as exc:
            logger.warning("Could not edit sender QR caption %s/%s: %s", photo.sender_chat_id, photo.sender_message_id, exc)
            edit_errors.append("sender")

    emoji = "✅" if status == "done" else "❌"

    # The database status and wallet settlement are already saved above. Status updates
    # are shown by editing the original QR messages only; do not send a separate
    # "Done" confirmation message to the sender. If Telegram refuses to edit an old
    # message, log it for admin/debugging but keep the saved wallet/order status intact.
    if edit_errors:
        logger.warning("QR %s marked %s but caption edit failed for: %s", photo.public_id, status, ', '.join(edit_errors))

    if status == "failed" and failure_reason:
        try:
            await bot.send_message(
                chat_id=photo.sender_chat_id,
                text=tr_chat(photo.sender_chat_id, "qr_failed_notice", public_id=photo.public_id, reason=failure_reason),
                protect_content=PROTECT_CONTENT,
            )
        except TelegramError as exc:
            logger.warning("Could not notify sender about failed QR %s: %s", photo.public_id, exc)

    if status == "failed":
        return True, tr_chat(actor_chat_id, "qr_marked_failed_sender_notice")
    return True, tr_chat(actor_chat_id, "qr_status_updated_caption", emoji=emoji, status=status_text)


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
        await message.reply_text(error or tr_chat(chat_id, "qr_not_found_generic"))
        return
    FAIL_REASON_FLOW.pop(chat_id, None)
    await message.reply_text(
        tr_chat(chat_id, "select_failure_reason", public_id=photo.public_id),
        reply_markup=failure_reason_keyboard(photo.public_id, chat_id),
    )


async def submit_failure_reason(message, context: ContextTypes.DEFAULT_TYPE, chat_id: int, reason: str) -> None:
    # Custom typed failure reasons are intentionally not accepted.
    # Receivers must use the fixed failure reason buttons so sender/admin messages stay clean and predictable.
    await message.reply_text(tr_chat(chat_id, "select_failure_reason_alert"))


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
        await query.answer(tr_chat(query.message.chat.id if query.message else query.from_user.id, "invalid_failure_reason"), show_alert=True)
        return

    reason = FAIL_REASON_CHOICES.get(reason_key)
    if not reason:
        await query.answer(tr_chat(query.message.chat.id if query.message else query.from_user.id, "invalid_failure_reason"), show_alert=True)
        return

    chat_id = query.message.chat.id
    reason_label_keys = {
        "qr_not_working": "fail_reason_qr_not_working",
        "qr_expired": "fail_reason_qr_expired",
        "limit_over": "fail_reason_limit_over",
    }
    localized_reason = tr_chat(chat_id, reason_label_keys.get(reason_key, reason_key))
    ok, result = await complete_photo(
        bot=context.bot,
        actor_chat_id=chat_id,
        status="failed",
        public_id=public_id,
        failure_reason=reason,
    )
    if ok:
        FAIL_REASON_FLOW.pop(chat_id, None)
        await query.answer(tr_chat(chat_id, "marked_failed_alert"), show_alert=False)
        try:
            await query.edit_message_text(
                f"{tr_chat(chat_id, 'qr_marked_failed')}\n"
                f"🆔 {tr_chat(chat_id, 'caption_id')}: {public_id}\n"
                f"📝 {tr_chat(chat_id, 'caption_reason')}: {localized_reason}"
            )
        except TelegramError:
            pass
        return

    await query.answer(result, show_alert=True)



def localized_claim_offer_result(chat_id: int, result: str, public_id: str | None = None) -> str:
    mapping = {
        "Only active receivers can accept offers.": "claim_only_active_receivers",
        "Admin account is not active in the bot. Send /start first.": "claim_admin_not_active",
        "You are offline or your limit is 0. Use /on LIMIT first.": "claim_offline_or_limit_zero",
        "Offer not found.": "claim_offer_not_found",
        "Offer expired.": "claim_offer_expired",
        "Offer expired. Another receiver already accepted this QR.": "claim_offer_taken",
        "Claimed.": "claim_success",
        "claim_offer_canceled": "claim_offer_canceled",
    }
    key = mapping.get(str(result or ""))
    if not key:
        return str(result or "")
    return tr_chat(chat_id, key)


async def claim_offer_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.message:
        return
    try:
        _action, public_id = query.data.split(":", 1)
    except Exception:
        await query.answer(tr_chat(query.message.chat.id if query.message else query.from_user.id, "invalid_offer_button"), show_alert=True)
        return
    receiver_chat_id = query.message.chat.id
    ok, result, row, auto_off = claim_offer_in_db(public_id, receiver_chat_id)
    if not ok:
        if result == "Offer expired.":
            expired_ok, _expired_msg, expired_row = expire_pending_qr_in_db(public_id)
            if expired_ok and expired_row is not None:
                await notify_qr_expired_by_timeout(context.bot, public_id, expired_row)
        result_text = localized_claim_offer_result(receiver_chat_id, result, public_id)
        await query.answer(result_text, show_alert=True)
        try:
            state = "canceled" if result == "claim_offer_canceled" else "expired"
            await query.edit_message_text(f"⛔ {result_text}\n🆔 {tr_chat(receiver_chat_id, 'offer_id')}: {public_id}")
            set_offer_notification_state(public_id, receiver_chat_id, state)
        except TelegramError:
            pass
        return
    assert row is not None
    receiver_message_id: int | None = None
    accepted_caption = build_receiver_qr_caption(
        str(row["date"]),
        int(row["daily_no"]),
        public_id,
        str(row["offer_expires_at"] or ""),
        receiver_chat_id,
    )

    await query.answer(tr_chat(receiver_chat_id, "offer_claimed"), show_alert=False)
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
                    reply_markup=receiver_status_keyboard(public_id, receiver_chat_id),
                )
                receiver_message_id = note_message_id
                set_receiver_message_for_offer(public_id, note_message_id)
                set_offer_notification_state(public_id, receiver_chat_id, "claimed")
            else:
                await context.bot.edit_message_text(
                    chat_id=note_chat_id,
                    message_id=note_message_id,
                    text=tr_chat(note_chat_id, "offer_taken_text", offer_id_label=tr_chat(note_chat_id, "offer_id"), public_id=public_id),
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
                reply_markup=receiver_status_keyboard(public_id, receiver_chat_id),
                protect_content=PROTECT_CONTENT,
            )
            set_receiver_message_for_offer(public_id, receiver_msg.message_id)
            receiver_message_id = receiver_msg.message_id
        except TelegramError as exc:
            logger.warning("Could not deliver claimed QR %s to receiver %s: %s", public_id, receiver_chat_id, exc)
            await query.answer(tr_chat(receiver_chat_id, "claim_saved_delivery_failed"), show_alert=True)
            return

    await edit_sender_offer_caption(
        context.bot,
        int(row["sender_chat_id"]),
        int(row["sender_message_id"] or 0),
        build_sender_offer_caption(
            str(row["date"]),
            int(row["daily_no"]),
            public_id,
            tr_chat(int(row["sender_chat_id"]), "sender_offer_accepted"),
            expires_at=str(row["offer_expires_at"] or ""),
            sender_rate=effective_sender_reserved_display(row),
            order_row=row,
            chat_id=int(row["sender_chat_id"]),
        ),
        reply_markup=sender_notify_keyboard(public_id, int(row["sender_chat_id"])),
    )
    schedule_qr_expiry_warning_task(context.application, public_id, str(row["offer_expires_at"] or ""))

    if auto_off:
        await context.bot.send_message(
            chat_id=receiver_chat_id,
            text=tr_chat(receiver_chat_id, "auto_off_limit_zero"),
        )
        await notify_active_senders(context, tr_chat(None, "sender_notify_limit_zero"))


async def cancel_order_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.message:
        return
    try:
        _action, public_id = (query.data or "").split(":", 1)
    except Exception:
        await query.answer(tr_chat(query.message.chat.id if query.message else query.from_user.id, "invalid_button"), show_alert=True)
        return

    sender_chat_id = query.message.chat.id
    ok, message_key, row, seconds_left = cancel_open_order_in_db(public_id, sender_chat_id)
    if not ok:
        if message_key == "cancel_order_expired":
            expired_ok, _expired_msg, expired_row = expire_pending_qr_in_db(public_id)
            if expired_ok and expired_row is not None:
                await notify_qr_expired_by_timeout(context.bot, public_id, expired_row)
        kwargs = {"seconds": seconds_left}
        if row is not None:
            kwargs["status"] = str(row["status"] or "").upper()
        await query.answer(tr_chat(sender_chat_id, message_key, **kwargs), show_alert=True)
        return

    assert row is not None
    canceled_caption = build_sender_offer_caption(
        str(row["date"]),
        int(row["daily_no"]),
        public_id,
        tr_chat(sender_chat_id, "cancel_order_status_line"),
        chat_id=sender_chat_id,
    )
    try:
        await context.bot.edit_message_caption(
            chat_id=sender_chat_id,
            message_id=int(row["sender_message_id"] or query.message.message_id),
            caption=canceled_caption,
            reply_markup=None,
        )
    except TelegramError as exc:
        logger.warning("Could not edit canceled sender QR %s/%s: %s", sender_chat_id, public_id, exc)

    # Remove receiver-side accept buttons so late receivers cannot try to claim it.
    for note in offer_notifications(public_id):
        receiver_chat_id = int(note["receiver_chat_id"])
        try:
            await context.bot.edit_message_text(
                chat_id=receiver_chat_id,
                message_id=int(note["message_id"]),
                text=tr_chat(receiver_chat_id, "offer_canceled_receiver_text", public_id=public_id),
            )
            set_offer_notification_state(public_id, receiver_chat_id, "canceled")
            await asyncio.sleep(0.02)
        except TelegramError as exc:
            logger.debug("Could not edit canceled offer notification %s/%s: %s", receiver_chat_id, public_id, exc)

    await query.answer(tr_chat(sender_chat_id, "cancel_order_done"), show_alert=False)


async def notify_receiver_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.message:
        return
    try:
        _action, public_id = (query.data or "").split(":", 1)
    except Exception:
        await query.answer(tr_chat(query.message.chat.id if query.message else query.from_user.id, "invalid_notify_button"), show_alert=True)
        return

    sender_chat_id = query.message.chat.id
    row = get_photo_record(public_id)
    if not row:
        await query.answer(tr_chat(sender_chat_id if "sender_chat_id" in locals() else query.message.chat.id, "qr_not_found"), show_alert=True)
        return
    if int(row["sender_chat_id"] or 0) != sender_chat_id:
        await query.answer(tr_chat(sender_chat_id, "only_sender_notify_receiver"), show_alert=True)
        return

    status = str(row["status"] or "").lower()
    offer_state = str(row["offer_state"] or "").lower()
    receiver_chat_id = int(row["receiver_chat_id"] or 0)

    if status != "pending":
        await query.answer(tr_chat(sender_chat_id, "qr_already_marked", status=status.upper()), show_alert=True)
        return
    if offer_state != "claimed" or receiver_chat_id <= 0:
        await query.answer(tr_chat(sender_chat_id, "no_receiver_accepted"), show_alert=True)
        return
    if iso_is_due(row["offer_expires_at"]):
        expired_ok, _expired_msg, expired_row = expire_pending_qr_in_db(public_id)
        if expired_ok and expired_row is not None:
            await notify_qr_expired_by_timeout(context.bot, public_id, expired_row)
        await query.answer(tr_chat(sender_chat_id, "qr_expired_alert"), show_alert=True)
        return

    try:
        await context.bot.send_message(
            chat_id=receiver_chat_id,
            text=tr_chat(
                receiver_chat_id,
                "sender_reminder",
                public_id=public_id,
                expires=display_datetime(str(row['offer_expires_at'] or '')),
                time_left=format_time_left_for_chat(receiver_chat_id, row["offer_expires_at"]),
            ),
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(tr_chat(receiver_chat_id, "btn_open_pending_qr"), callback_data=f"pendingqr:{public_id}")]]),
            protect_content=PROTECT_CONTENT,
        )
        await query.answer(tr_chat(sender_chat_id, "receiver_notified"), show_alert=False)
    except TelegramError as exc:
        logger.warning("Could not notify receiver %s for QR %s: %s", receiver_chat_id, public_id, exc)
        await query.answer(tr_chat(sender_chat_id, "notify_receiver_failed"), show_alert=True)


async def pending_qr_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.message:
        return
    try:
        _action, public_id = (query.data or "").split(":", 1)
    except Exception:
        await query.answer(tr_chat(query.message.chat.id if query.message else query.from_user.id, "invalid_qr_button"), show_alert=True)
        return
    chat_id = query.message.chat.id
    user = get_user_for_chat(chat_id)
    if not can_use_receiver_features(chat_id, user):
        await query.answer(tr_chat(chat_id, "only_receivers_open_pending"), show_alert=True)
        return
    row = get_photo_record(public_id)
    if not row or int(row["receiver_chat_id"] or 0) != chat_id:
        await query.answer(tr_chat(chat_id, "qr_not_found_for_account"), show_alert=True)
        return
    if str(row["status"]) != "pending" or str(row["offer_state"]) != "claimed":
        await query.answer(tr_chat(chat_id, "qr_no_longer_pending"), show_alert=True)
        return
    if iso_is_due(row["offer_expires_at"]):
        expired_ok, _expired_msg, expired_row = expire_pending_qr_in_db(public_id)
        if expired_ok and expired_row is not None:
            await notify_qr_expired_by_timeout(context.bot, public_id, expired_row)
        await query.answer(tr_chat(chat_id, "qr_expired_alert"), show_alert=True)
        return
    try:
        msg = await context.bot.send_photo(
            chat_id=chat_id,
            photo=row["generated_file_id"],
            caption=build_receiver_qr_caption(
                str(row["date"]),
                int(row["daily_no"]),
                public_id,
                str(row["offer_expires_at"] or ""),
                chat_id,
            ),
            reply_markup=receiver_status_keyboard(public_id, chat_id),
            protect_content=PROTECT_CONTENT,
        )
        set_receiver_message_for_offer(public_id, msg.message_id)
        await query.answer(tr_chat(chat_id, "qr_opened_below"))
    except TelegramError as exc:
        logger.warning("Could not reopen pending QR %s for %s: %s", public_id, chat_id, exc)
        await query.answer(tr_chat(chat_id, "qr_open_failed"), show_alert=True)


async def button_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.message:
        return

    try:
        raw_action, public_id = query.data.split(":", 1)
    except Exception:
        await query.answer(tr_chat(query.message.chat.id if query.message else query.from_user.id, "invalid_button"), show_alert=True)
        return

    action = normalize_status_callback_action(raw_action)
    if action not in {"done", "failed"}:
        await query.answer(tr_chat(query.message.chat.id if query.message else query.from_user.id, "invalid_action"), show_alert=True)
        return

    chat_id = query.message.chat.id
    if action == "failed":
        photo, error = await resolve_pending_photo_for_status(
            bot=context.bot,
            actor_chat_id=chat_id,
            public_id=public_id,
        )
        if error or not photo:
            await query.answer(error or tr_chat(chat_id, "qr_not_found_generic"), show_alert=True)
            return
        FAIL_REASON_FLOW.pop(chat_id, None)
        await query.answer(tr_chat(chat_id, "select_failure_reason_alert"), show_alert=False)
        await query.message.reply_text(
            tr_chat(chat_id, "select_failure_reason", public_id=photo.public_id),
            reply_markup=failure_reason_keyboard(photo.public_id, chat_id),
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
    expired_at = qr_expiry_status_at(row)

    def expired_caption_for(chat_id: int | None) -> str:
        return (
            f"{build_caption(str(row['date']), int(row['daily_no']), public_id, chat_id)}\n\n"
            f"{tr_chat(chat_id, 'expired_caption_status_line')}\n"
            f"🕒 {tr_chat(chat_id, 'caption_updated')}: {display_datetime(expired_at)}\n"
            f"💳 {tr_chat(chat_id, 'caption_sender_reserve_released')}"
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
                    caption=expired_caption_for(note_chat_id),
                    reply_markup=qr_dispute_keyboard(public_id, note_chat_id),
                )
            else:
                await bot.edit_message_text(
                    chat_id=note_chat_id,
                    message_id=note_message_id,
                    text=tr_chat(note_chat_id, "expired_offer_text", public_id=public_id),
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
                caption=expired_caption_for(claimed_receiver_id),
                reply_markup=qr_dispute_keyboard(public_id, claimed_receiver_id),
            )
        except TelegramError:
            pass

    try:
        if row["sender_message_id"]:
            sender_chat_id = int(row["sender_chat_id"])
            await bot.edit_message_caption(
                chat_id=sender_chat_id,
                message_id=int(row["sender_message_id"]),
                caption=expired_caption_for(sender_chat_id),
                reply_markup=qr_dispute_keyboard(public_id, sender_chat_id),
            )
    except TelegramError:
        pass


async def expire_offer_runtime(bot, public_id: str, row: sqlite3.Row, reason_text: str = "Offer expired. No receiver accepted in time.") -> None:
    release_sender_reserve(int(row["sender_chat_id"]), effective_sender_charge_amount(row, use_current_setting_if_missing=True), public_id, reason_text)
    await notify_qr_expired_by_timeout(bot, public_id, row)



def expire_pending_qr_in_db(public_id: str) -> tuple[bool, str, sqlite3.Row | None]:
    """Expire any pending QR, whether still open or already claimed.

    The expiry timestamp is the configured offer_expires_at value, not the time
    this cleanup function happened to run.  This keeps admin duration correct and
    enforces QR_EXPIRE_MINUTES across both open and claimed orders.
    """
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
        expires_at = qr_expiry_status_at(row)
        cur = conn.execute(
            """
            UPDATE photos
            SET status = 'failed', offer_state = 'expired', status_by = NULL, status_at = ?, failure_reason = COALESCE(NULLIF(failure_reason, ''), 'QR expired')
            WHERE public_id = ? AND status = 'pending'
            """,
            (expires_at, public_id),
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

    def expired_admin_caption_for(chat_id: int | None) -> str:
        return (
            f"{build_caption(str(row['date']), int(row['daily_no']), public_id, chat_id)}\n\n"
            f"⏱ {tr_chat(chat_id, 'caption_status')}: {tr_chat(chat_id, 'status_expired_by_admin_caps')}\n"
            f"🕒 {tr_chat(chat_id, 'caption_updated')}: {display_datetime()}\n"
            f"💳 {tr_chat(chat_id, 'caption_sender_reserve_released')}"
        )

    for note in offer_notifications(public_id):
        note_chat_id = int(note["receiver_chat_id"])
        try:
            await bot.edit_message_text(
                chat_id=note_chat_id,
                message_id=int(note["message_id"]),
                text=tr_chat(note_chat_id, "expired_offer_text", public_id=public_id),
            )
            set_offer_notification_state(public_id, note_chat_id, "expired")
            await asyncio.sleep(0.02)
        except TelegramError:
            pass

    try:
        if row["sender_message_id"]:
            sender_id = int(row["sender_chat_id"])
            await bot.edit_message_caption(
                chat_id=sender_id,
                message_id=int(row["sender_message_id"]),
                caption=expired_admin_caption_for(sender_id),
                reply_markup=qr_dispute_keyboard(public_id, sender_id),
            )
    except TelegramError:
        pass

    receiver_id = int(row["receiver_chat_id"] or 0)
    try:
        if receiver_id and row["receiver_message_id"]:
            await bot.edit_message_caption(
                chat_id=receiver_id,
                message_id=int(row["receiver_message_id"]),
                caption=expired_admin_caption_for(receiver_id),
                reply_markup=qr_dispute_keyboard(public_id, receiver_id),
            )
    except TelegramError:
        pass

    try:
        sender_id = int(row["sender_chat_id"])
        await bot.send_message(
            chat_id=sender_id,
            text=f"⏱ {tr_chat(sender_id, 'status_expired_by_admin_caps')}\n🆔 {tr_chat(sender_id, 'caption_id')}: {public_id}\n💳 {tr_chat(sender_id, 'caption_sender_reserve_released')}",
            protect_content=PROTECT_CONTENT,
        )
    except TelegramError:
        pass

    if receiver_id:
        try:
            await bot.send_message(
                chat_id=receiver_id,
                text=f"⏱ {tr_chat(receiver_id, 'status_expired_by_admin_caps')}\n🆔 {tr_chat(receiver_id, 'caption_id')}: {public_id}",
                protect_content=PROTECT_CONTENT,
            )
        except TelegramError:
            pass


async def notify_admin_order_status_change(bot, result: dict) -> tuple[int, int]:
    """Notify sender/receiver and update Telegram QR captions after an admin status override."""
    row = result.get("row_after")
    if row is None:
        return 0, 0
    public_id = str(result.get("public_id") or row["public_id"])
    new_status = str(result.get("new_status") or row["status"]).lower()
    old_status = str(result.get("old_status") or "").lower()
    failure_reason = result.get("failure_reason")
    sender_chat_id = int(result.get("sender_chat_id") or row["sender_chat_id"])
    receiver_chat_id = int(result.get("receiver_chat_id") or row["receiver_chat_id"] or 0)
    sender_amount = _dec(result.get("sender_amount"))
    receiver_amount = _dec(result.get("receiver_amount"))
    sender_effect = str(result.get("sender_effect") or "none")
    receiver_effect = str(result.get("receiver_effect") or "none")

    photo = row_to_photo(row)
    caption = build_status_caption(photo, new_status, failure_reason=failure_reason) if photo else f"Order {public_id}: {new_status.upper()}"
    caption += "\n🛠 Changed by admin."
    if sender_effect == "refunded":
        caption += f"\n💳 Sender refunded: ${_money(abs(sender_amount))} USDT."
    elif sender_effect == "reserve_released":
        caption += f"\n💳 Sender reserve released: ${_money(abs(sender_amount))} USDT."
    elif sender_effect == "charged":
        caption += f"\n💳 Sender charged: ${_money(abs(sender_amount))} USDT."
    if receiver_effect == "deducted":
        caption += f"\n💰 Receiver earnings deducted: ${_money(abs(receiver_amount))} USDT."
    elif receiver_effect == "credited":
        caption += f"\n💰 Receiver credited: ${_money(abs(receiver_amount))} USDT."

    # Open offer messages are text messages, not photo captions. Disable/replace them on failed overrides.
    if new_status == "failed":
        offer_text = (
            "❌ QR order marked FAILED by admin.\n"
            f"🆔 Order ID: {public_id}\n"
            "This QR can no longer be accepted or completed."
        )
        for note in offer_notifications(public_id):
            try:
                await bot.edit_message_text(
                    chat_id=int(note["receiver_chat_id"]),
                    message_id=int(note["message_id"]),
                    text=offer_text,
                )
                set_offer_notification_state(public_id, int(note["receiver_chat_id"]), "expired")
                await asyncio.sleep(0.02)
            except TelegramError:
                pass

    for chat_id, message_id, label in (
        (sender_chat_id, int(row["sender_message_id"] or 0), "sender"),
        (receiver_chat_id, int(row["receiver_message_id"] or 0), "receiver"),
    ):
        if not chat_id or not message_id:
            continue
        try:
            await bot.edit_message_caption(
                chat_id=chat_id,
                message_id=message_id,
                caption=caption,
                reply_markup=qr_dispute_keyboard(public_id, chat_id),
            )
        except TelegramError as exc:
            logger.warning("Could not edit %s caption after admin status change for %s: %s", label, public_id, exc)

    sent = failed = 0
    status_line = "✅ DONE" if new_status == "done" else "❌ FAILED"
    sender_lines = [
        tr_chat(sender_chat_id, "admin_order_status_changed"),
        f"🆔 {tr_chat(sender_chat_id, 'order_id_label')}: {public_id}",
        tr_chat(sender_chat_id, "status_change_line", old_status=old_status.upper(), new_status=status_line),
    ]
    if sender_effect == "refunded":
        sender_lines.append(tr_chat(sender_chat_id, "sender_wallet_refunded", amount=_money(abs(sender_amount))))
    elif sender_effect == "reserve_released":
        sender_lines.append(tr_chat(sender_chat_id, "sender_reserve_released", amount=_money(abs(sender_amount))))
    elif sender_effect == "charged":
        sender_lines.append(tr_chat(sender_chat_id, "sender_wallet_charged", amount=_money(abs(sender_amount))))
    sender_lines.append(tr_chat(sender_chat_id, "use_wallet_balance"))
    try:
        await bot.send_message(chat_id=sender_chat_id, text="\n".join(sender_lines), protect_content=PROTECT_CONTENT)
        sent += 1
    except TelegramError as exc:
        logger.warning("Could not notify sender %s after admin status change for %s: %s", sender_chat_id, public_id, exc)
        failed += 1

    if receiver_chat_id:
        receiver_lines = [
            tr_chat(receiver_chat_id, "admin_order_status_changed"),
            f"🆔 {tr_chat(receiver_chat_id, 'order_id_label')}: {public_id}",
            tr_chat(receiver_chat_id, "status_change_line", old_status=old_status.upper(), new_status=status_line),
        ]
        if receiver_effect == "deducted":
            receiver_lines.append(tr_chat(receiver_chat_id, "receiver_earnings_deducted", amount=_money(abs(receiver_amount))))
        elif receiver_effect == "credited":
            receiver_lines.append(tr_chat(receiver_chat_id, "receiver_earnings_credited", amount=_money(abs(receiver_amount))))
        else:
            receiver_lines.append(tr_chat(receiver_chat_id, "receiver_earnings_no_change"))
        receiver_lines.append(tr_chat(receiver_chat_id, "use_earnings_balance"))
        try:
            await bot.send_message(chat_id=receiver_chat_id, text="\n".join(receiver_lines), protect_content=PROTECT_CONTENT)
            sent += 1
        except TelegramError as exc:
            logger.warning("Could not notify receiver %s after admin status change for %s: %s", receiver_chat_id, public_id, exc)
            failed += 1

    return sent, failed


async def marketplace_watcher(application: Application) -> None:
    while True:
        try:
            for row in list_claimed_qrs_needing_expiry_warning(limit=100):
                await send_receiver_expiry_warning(application.bot, row)
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
            await update.callback_query.answer(tr_chat(update.callback_query.message.chat.id if update.callback_query.message else update.callback_query.from_user.id, "maintenance_on_alert"), show_alert=True)
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



def admin_qr_status_override_form(public_id: str, current_status: str | None) -> str:
    current = str(current_status or "pending").strip().lower()
    options = []
    for value, label in (("done", "✅ Done"), ("failed", "❌ Failed")):
        selected = " selected" if value == current else ""
        options.append(f'<option value="{esc(value)}"{selected}>{esc(label)}</option>')
    return f'''
    <div class="admin-status-override">
      <h3>🛠 Change order status</h3>
      <p class="muted small">Admin can change this order to Done or Failed. Wallet balances are adjusted automatically and both parties are notified.</p>
      <form method="post" action="/admin/qrs/{esc(public_id)}/status"
            data-confirm-title="Change order status?" data-confirm-button="Update status" data-confirm-class="danger"
            data-confirm-message="This will adjust sender/receiver balances for this order and notify both parties.">
        <div class="row">
          <div><label>New status</label><select name="status">{''.join(options)}</select></div>
          <div><label>Failure/admin note</label><input name="failure_reason" placeholder="optional, used when marking failed"></div>
        </div>
        <button type="submit">Update order status</button>
      </form>
    </div>
    '''


def admin_qr_force_retry_forms(public_id: str, row: sqlite3.Row) -> str:
    status = str(row["status"] or "pending").strip().lower()
    parts: list[str] = []
    if status != "failed":
        parts.append(
            f'''<form class="inline" method="post" action="/admin/qrs/{esc(public_id)}/force-release"
                 data-confirm-title="Force release this order?" data-confirm-button="Force release" data-confirm-class="danger"
                 data-confirm-message="This marks the QR as Failed, releases/refunds the sender as needed, deducts receiver earnings if this was Done, and notifies both parties.">
                 <button class="danger" type="submit">Force release / mark Failed</button></form>'''
        )
    if status == "failed" and row["generated_file_id"]:
        parts.append(
            f'''<form class="inline" method="post" action="/admin/qrs/{esc(public_id)}/retry"
                 data-confirm-title="Retry this QR?" data-confirm-button="Retry QR" data-confirm-class="danger"
                 data-confirm-message="This reopens the same QR as a new marketplace offer, reserves sender balance again, and sends it to online receivers.">
                 <button type="submit">🔁 Retry QR offer</button></form>'''
        )
    if not parts:
        return ""
    return '''
    <div class="admin-status-override">
      <h3>⚡ Force actions</h3>
      <p class="muted small">Use these only when an order is stuck or needs manual correction.</p>
      <div class="action-row">''' + "".join(parts) + "</div></div>"


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

def effective_qr_status_at(row: sqlite3.Row) -> str | None:
    status_at = row["status_at"] if "status_at" in row.keys() else None
    if str(row["status"] or "").lower() == "failed" and str(row["offer_state"] or "").lower() == "expired":
        expires_at = row["offer_expires_at"] if "offer_expires_at" in row.keys() else None
        if expires_at:
            return str(expires_at)
    return str(status_at) if status_at else None


def completed_value(row: sqlite3.Row) -> str:
    status = str(row["status"] or "pending").lower()
    final_at = effective_qr_status_at(row)
    if status in {"done", "failed"} and final_at:
        return display_datetime(final_at)
    return "—"


def _parse_iso_dt(value: str | datetime | None) -> datetime | None:
    return parse_bot_datetime(value)


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
    final_at = effective_qr_status_at(row)
    if status in {"done", "failed"} and final_at:
        return duration_between(row["created_at"], final_at)
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
          <a href="/admin/broadcast">📣 Broadcast</a>
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
            <div id="generic-confirm-fields"></div>
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
      const genericFields = document.getElementById('generic-confirm-fields');
      function clearGenericConfirmFields() {{
        if (genericFields) genericFields.innerHTML = '';
      }}
      function copyFormFieldsToGenericConfirm(form) {{
        clearGenericConfirmFields();
        if (!genericFields || !form) return;
        const data = new FormData(form);
        data.forEach(function(value, key) {{
          if (typeof File !== 'undefined' && value instanceof File) return;
          const input = document.createElement('input');
          input.type = 'hidden';
          input.name = key;
          input.value = value;
          genericFields.appendChild(input);
        }});
      }}
      function closeGenericConfirm() {{
        if (genericShell) genericShell.hidden = true;
        if (genericForm) genericForm.action = '';
        clearGenericConfirmFields();
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
          copyFormFieldsToGenericConfirm(form);
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
    status_override_form = admin_qr_status_override_form(public_id, row["status"])
    force_retry_forms = admin_qr_force_retry_forms(public_id, row)
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
          {status_override_form}
          {force_retry_forms}
        </div>
        <div>
          <p><strong>Sender:</strong><br>{sender_html}</p>
          <p><strong>Receiver:</strong><br>{receiver_html}</p>
          <p><strong>Sender rate:</strong> ${_money(row["sender_rate_usdt"])} USDT</p>
          <p><strong>Order charge / reserved snapshot:</strong> ${_money(effective_sender_charge_amount(row, use_current_setting_if_missing=True))} USDT</p>
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


@web_app.post("/admin/qrs/{public_id}/status")
async def admin_qr_status_override(request: Request, public_id: str):
    guard = admin_guard(request)
    if guard:
        return guard
    form = await request.form()
    # Prefer the canonical select field, but accept alternate button/JS field names too.
    submitted_status = (
        form.get("status")
        or form.get("new_status")
        or form.get("target_status")
        or form.get("order_status")
        or form.get("action")
        or form.get("submit")
        or ""
    )
    new_status = normalize_admin_order_status(submitted_status)
    failure_reason = str(form.get("failure_reason", "")).strip() or None
    ok, msg, result = admin_override_photo_status(public_id, new_status, failure_reason=failure_reason, status_by=0)
    if ok and result is not None and telegram_application is not None:
        sent, failed = await notify_admin_order_status_change(telegram_application.bot, result)
        msg += f" Notifications sent: {sent}, failed: {failed}."
    elif ok:
        msg += " Telegram bot is not ready, so notifications were not sent."
    return redirect_with_msg(admin_safe_return_path(request, f"/admin/qrs/{quote(public_id)}"), msg)


@web_app.post("/admin/qrs/{public_id}/force-release")
async def admin_qr_force_release(request: Request, public_id: str):
    guard = admin_guard(request)
    if guard:
        return guard
    ok, msg, result = admin_override_photo_status(public_id, "failed", failure_reason="Forced release by admin", status_by=0)
    if ok and result is not None and telegram_application is not None:
        sent, failed = await notify_admin_order_status_change(telegram_application.bot, result)
        msg += f" Notifications sent: {sent}, failed: {failed}."
    elif ok:
        msg += " Telegram bot is not ready, so notifications were not sent."
    return redirect_with_msg(admin_safe_return_path(request, f"/admin/qrs/{quote(public_id)}"), msg)


@web_app.post("/admin/qrs/{public_id}/retry")
async def admin_qr_retry(request: Request, public_id: str):
    guard = admin_guard(request)
    if guard:
        return guard
    if telegram_application is None:
        return redirect_with_msg(admin_safe_return_path(request, f"/admin/qrs/{quote(public_id)}"), "Telegram bot is not ready; cannot retry QR right now.")
    ok, msg = await admin_retry_qr_order(telegram_application.bot, public_id)
    return redirect_with_msg(admin_safe_return_path(request, f"/admin/qrs/{quote(public_id)}"), msg)


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
    sender_users = [u for u in users if str(u["role"] or "").lower() == "sender"]
    receiver_users = [u for u in users if str(u["role"] or "").lower() == "receiver"]

    def selected(value: str, current: str) -> str:
        return " selected" if value == current else ""

    def user_full_name(u: sqlite3.Row) -> str:
        return " ".join([str(u["first_name"] or "").strip(), str(u["last_name"] or "").strip()]).strip()

    def sender_wallet_html(u: sqlite3.Row) -> str:
        total = _dec(u["wallet_balance_usdt"] if "wallet_balance_usdt" in u.keys() else 0)
        reserved = _dec(u["wallet_reserved_usdt"] if "wallet_reserved_usdt" in u.keys() else 0)
        available = max(Decimal("0"), total - reserved)
        html = f'<strong>${esc(_money(available))} USDT</strong>'
        if reserved > 0:
            html += f'<br><span class="muted small">Reserved: ${esc(_money(reserved))}</span>'
        return html

    def receiver_earnings_html(u: sqlite3.Row) -> str:
        earned = _dec(u["wallet_earned_usdt"] if "wallet_earned_usdt" in u.keys() else 0)
        paid = _dec(u["wallet_paid_usdt"] if "wallet_paid_usdt" in u.keys() else 0)
        pending = _dec(u["wallet_pending_payout_usdt"] if "wallet_pending_payout_usdt" in u.keys() else 0)
        due = max(Decimal("0"), earned - paid)
        available = max(Decimal("0"), due - pending)
        html = f'<strong>${esc(_money(available))} USDT</strong>'
        if pending > 0:
            html += f'<br><span class="muted small">Pending payout: ${esc(_money(pending))}</span>'
        return html

    def user_actions_html(u: sqlite3.Row) -> str:
        next_state = "off" if u["active"] else "on"
        action_label = "Disable" if u["active"] else "Enable"
        btn_class = "danger" if u["active"] else "secondary"
        return (
            f'<form class="inline" method="post" action="/admin/users/active">'
            f'<input type="hidden" name="chat_id" value="{esc(u["chat_id"])}">'
            f'<input type="hidden" name="state" value="{next_state}">'
            f'<button class="{btn_class}" type="submit">{action_label}</button>'
            f'</form>'
        )

    def render_user_section(title: str, rows: list[sqlite3.Row], balance_header: str, balance_renderer, page_key: str) -> str:
        if not rows:
            return f'<div class="card"><h3>{esc(title)} <span class="muted small">(0)</span></h3><p>No users found in this section.</p></div>'
        paged_rows, pager_html = paginate_items(rows, request, key=page_key)
        html = f'<div class="card"><h3>{esc(title)} <span class="muted small">({esc(len(rows))})</span></h3>'
        html += '<div class="table-wrap"><table><tr><th>ID/Username</th><th>Alias</th><th>Name</th>'
        html += f'<th>{esc(balance_header)}</th><th class="cell-center">Status</th><th class="cell-center">Actions</th></tr>'
        for u in paged_rows:
            full_name = user_full_name(u)
            html += f"""
            <tr>
              <td>{user_link(u)}</td>
              <td>{esc(u['alias'] or '')}</td>
              <td>{esc(full_name or '—')}</td>
              <td>{balance_renderer(u)}</td>
              <td class="cell-center">{badge(bool(u['active']))}</td>
              <td class="cell-center">{user_actions_html(u)}</td>
            </tr>"""
        html += '</table></div>' + pager_html + '</div>'
        return html

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

    if q or role is not None or active is not None:
        body += f'<div class="card"><p class="muted small">Showing {esc(len(users))} matching user(s): {esc(len(sender_users))} sender(s), {esc(len(receiver_users))} receiver(s).</p></div>'

    if not users:
        if q or role is not None or active is not None:
            body += '<div class="card"><p>No users matched your search/filter.</p></div>'
        else:
            body += '<div class="card"><p>No users yet. Ask users to send <code>/myid</code> to the bot, then add their ID/Username here.</p></div>'
    else:
        if role_filter in {"all", "sender"}:
            body += render_user_section("📤 Senders", sender_users, "Wallet balance", sender_wallet_html, "sender_page")
        if role_filter in {"all", "receiver"}:
            body += render_user_section("📥 Receivers", receiver_users, "Earnings balance", receiver_earnings_html, "receiver_page")

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
        lifetime_used = sender_lifetime_balance_used(chat_id)
        balance_cards = f'''
          <div><b>${_money(balance)}</b><span>Total balance</span></div>
          <div><b>${_money(reserved)}</b><span>Reserved</span></div>
          <div><b>${_money(available)}</b><span>Available</span></div>
          <div><b>${_money(lifetime_used)}</b><span>Lifetime balance used</span></div>
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
            rates = f"Sender ${_money(effective_sender_charge_amount(r, use_current_setting_if_missing=True))}<br>Receiver ${_money(r['receiver_rate_usdt'])}"
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
        notify_key = "notify_receiver_online"
        notify_kwargs = {"capacity": total_marketplace_capacity()}
        notify_text = "receiver online"
    else:
        set_receiver_offline(receiver_chat_id)
        notify_key = "notify_receiver_offline"
        notify_kwargs = {}
        notify_text = "receiver offline"
    note = "Receiver status updated."
    if maintenance_mode_enabled():
        note += " Maintenance mode is ON, so sender notifications were not sent."
    elif telegram_application is not None and notify_text:
        sent = failed = 0
        for sender in active_senders():
            try:
                sender_chat_id = int(sender["chat_id"])
                await telegram_application.bot.send_message(chat_id=sender_chat_id, text=tr_chat(sender_chat_id, notify_key, **notify_kwargs), protect_content=PROTECT_CONTENT)
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
                    text=tr_chat(int(row['receiver_chat_id']), "payout_done", amount=_money(row['amount_usdt'])),
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
                text=tr_chat(int(row['receiver_chat_id']), "payout_rejected", amount=_money(row['amount_usdt'])),
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
        where = "WHERE d.status IN ('open','under_review')"
    elif status_filter != "all":
        where = "WHERE d.status = ?"
        params = (status_filter,)
    with get_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT
                d.*,
                COUNT(m.id) AS message_count,
                COALESCE(SUM(CASE
                    WHEN m.sender_type = 'user' AND m.id > COALESCE(d.admin_seen_message_id, 0) THEN 1
                    ELSE 0
                END), 0) AS admin_unread_count,
                COALESCE(MAX(m.id), 0) AS latest_message_id,
                MAX(m.created_at) AS latest_message_at,
                (
                    SELECT m2.sender_type
                    FROM dispute_messages m2
                    WHERE m2.dispute_id = d.id
                    ORDER BY m2.id DESC
                    LIMIT 1
                ) AS latest_sender_type
            FROM disputes d
            LEFT JOIN dispute_messages m ON m.dispute_id = d.id
            {where}
            GROUP BY d.id
            ORDER BY d.created_at DESC
            LIMIT 500
            """,
            params,
        ).fetchall()
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
        body += '''<style>
        .dispute-chat-log{display:flex;flex-direction:column;gap:8px;min-width:0;max-width:none}
        .dispute-chat-bubble{padding:9px 11px;border-radius:12px;border:1px solid rgba(148,163,184,.25);background:rgba(15,23,42,.35)}
        .dispute-chat-bubble.admin{background:rgba(37,99,235,.16);border-color:rgba(96,165,250,.35)}
        .dispute-chat-bubble.user{background:rgba(22,163,74,.12);border-color:rgba(74,222,128,.28)}
        .dispute-chat-bubble div{white-space:pre-wrap;margin-top:4px;overflow-wrap:anywhere}
        .small{font-size:12px}.dispute-actions{display:flex;gap:6px;flex-wrap:wrap}
        .dispute-chat-cell{display:flex;align-items:flex-start;gap:8px;flex-wrap:wrap;min-width:190px}
        .dispute-chat-meta{flex:0 0 100%;margin-top:2px}.dispute-unread-badge{vertical-align:middle}
        #dispute-chat-modal.confirm-modal-shell{position:fixed;inset:0;z-index:10000;display:flex;align-items:center;justify-content:center;padding:22px;max-width:none;margin:0}
        #dispute-chat-modal.confirm-modal-shell[hidden]{display:none!important}
        #dispute-chat-modal .confirm-modal-backdrop{position:absolute;inset:0;z-index:0;background:rgba(0,0,0,.76);backdrop-filter:blur(3px)}
        #dispute-chat-modal .dispute-chat-panel{position:relative;z-index:1;width:min(820px,calc(100vw - 44px));max-height:calc(100dvh - 44px);overflow:auto;margin:0;background:var(--panel);border:1px solid var(--line);border-radius:20px;padding:28px;box-shadow:0 26px 90px var(--shadow)}
        .dispute-chat-popup-log{max-height:46vh;overflow:auto;background:#0b1220;border:1px solid var(--line);border-radius:16px;padding:12px;margin-bottom:16px}
        .dispute-chat-readonly-note{background:rgba(148,163,184,.12);border:1px solid rgba(148,163,184,.25);border-radius:12px;padding:10px 12px;margin-top:10px;color:var(--muted)}
        @media (max-width:820px){#dispute-chat-modal.confirm-modal-shell{padding:10px}#dispute-chat-modal .dispute-chat-panel{width:calc(100vw - 20px);max-height:calc(100dvh - 20px);padding:18px}.dispute-chat-popup-log{max-height:42dvh}}
        </style>'''
        body += '<div class="table-wrap"><table><tr><th>ID</th><th>QR</th><th>User</th><th>Replies</th><th>Status</th><th>Created</th><th>Action</th></tr>'
        for r in paged:
            user = get_admin_user_row(int(r['chat_id']))
            qr_public_id = str(r['public_id'] or '')
            qr = qr_id_link(qr_public_id) if qr_public_id else '<span class="muted">General</span>'
            ref = str(r['ref_id'] or f"DSP{int(r['id']):06d}")
            status = str(r['status'] or 'open').lower()
            active_status = status in {'open', 'under_review'}
            dispute_id = int(r['id'])
            user_label = strip_tags(user_link(user)) if user else str(r['chat_id'])
            chat_html_attr = esc(dispute_chat_html(dispute_id, limit=100))
            unread_count = int(r['admin_unread_count'] or 0)
            message_count = int(r['message_count'] or 0)
            latest_sender = 'Admin' if str(r['latest_sender_type'] or '') == 'admin' else ('User' if r['latest_sender_type'] else '—')
            latest_at = display_datetime(r['latest_message_at']) if r['latest_message_at'] else display_datetime(r['created_at'])
            unread_badge = f'<span class="badge bad dispute-unread-badge">{unread_count} new</span>' if active_status and unread_count else ''
            chat_action = f'/admin/disputes/{dispute_id}/message' if active_status else ''
            chat_button_label = '💬 Reply' if active_status else '💬 View chat'
            qr_label = qr_public_id or "General"
            chat_cell = (
                f'<div class="dispute-chat-cell">'
                f'<button type="button" class="secondary dispute-chat-open" '
                f'data-dispute-id="{dispute_id}" data-action="{esc(chat_action)}" data-seen-action="/admin/disputes/{dispute_id}/seen" '
                f'data-mode="message" data-ref="{esc(ref)}" data-user="{esc(user_label)}" data-qr="{esc(qr_label)}" '
                f'data-status="{esc(status)}" data-chat-html="{chat_html_attr}">{chat_button_label}</button>'
                f'{unread_badge}'
                f'<div class="muted small dispute-chat-meta">{message_count} message{"s" if message_count != 1 else ""} · Last: {esc(latest_sender)} · {esc(latest_at)}</div>'
                f'</div>'
            )
            action_parts: list[str] = []
            if status == 'open':
                action_parts.append(
                    f'<form class="inline" method="post" action="/admin/disputes/{dispute_id}/review" '
                    'data-confirm-title="Mark under review?" data-confirm-button="Mark under review" data-confirm-class="secondary" '
                    'data-confirm-message="The user will be notified that the dispute is under review.">'
                    '<button class="secondary" type="submit">Under review</button></form>'
                )
            if active_status:
                action_parts.append(
                    f'<form class="inline dispute-chat-form" method="post" action="/admin/disputes/{dispute_id}/resolve" '
                    f'data-mode="resolve" data-ref="{esc(ref)}" data-user="{esc(user_label)}" data-qr="{esc(qr_label)}" '
                    f'data-dispute-id="{dispute_id}" data-seen-action="/admin/disputes/{dispute_id}/seen" data-chat-html="{chat_html_attr}">'
                    '<button class="success" type="submit">Resolve</button></form>'
                )
                action_parts.append(
                    f'<form class="inline dispute-chat-form" method="post" action="/admin/disputes/{dispute_id}/reject" '
                    f'data-mode="reject" data-ref="{esc(ref)}" data-user="{esc(user_label)}" data-qr="{esc(qr_label)}" '
                    f'data-dispute-id="{dispute_id}" data-seen-action="/admin/disputes/{dispute_id}/seen" data-chat-html="{chat_html_attr}">'
                    '<button class="danger" type="submit">Reject</button></form>'
                )
            action = '<div class="dispute-actions">' + ' '.join(action_parts) + '</div>' if action_parts else '<span class="muted">No action</span>'
            body += (
                f'<tr><td>#{esc(ref)}</td><td>{qr}</td><td>{user_link(user) if user else esc(r["chat_id"])}</td>'
                f'<td>{chat_cell}</td><td>{dispute_status_pill(status)}</td><td>{esc(display_datetime(r["created_at"]))}</td><td>{action}</td></tr>'
            )
        body += '</table></div>' + pager
    body += '</div>'
    body += """
    <div id="dispute-chat-modal" class="confirm-modal-shell" hidden>
      <div class="confirm-modal-backdrop" data-close-dispute-chat></div>
      <div class="confirm-modal-panel dispute-chat-panel" role="dialog" aria-modal="true" aria-labelledby="dispute-chat-title">
        <button class="modal-close" type="button" data-close-dispute-chat aria-label="Close dispute chat">×</button>
        <h2 id="dispute-chat-title">Dispute chat</h2>
        <p id="dispute-chat-desc" class="confirm-modal-desc">Previous replies are shown below.</p>
        <div id="dispute-chat-content" class="dispute-chat-popup-log"></div>
        <form id="dispute-chat-submit-form" method="post" action="">
          <label id="dispute-chat-label">Reply to disputer</label>
          <textarea name="admin_note" required placeholder="Type your reply."></textarea>
          <div class="confirm-actions">
            <button type="button" class="secondary" data-close-dispute-chat>Cancel</button>
            <button type="submit" id="dispute-chat-submit-button" class="success">Send Reply</button>
          </div>
        </form>
        <div id="dispute-chat-readonly" class="dispute-chat-readonly-note" hidden>This dispute is closed, so the chat is read-only.</div>
      </div>
    </div>
    <script>
    document.addEventListener('DOMContentLoaded', function() {
      const shell = document.getElementById('dispute-chat-modal');
      const submitForm = document.getElementById('dispute-chat-submit-form');
      const title = document.getElementById('dispute-chat-title');
      const desc = document.getElementById('dispute-chat-desc');
      const button = document.getElementById('dispute-chat-submit-button');
      const label = document.getElementById('dispute-chat-label');
      const chatContent = document.getElementById('dispute-chat-content');
      const readonlyNote = document.getElementById('dispute-chat-readonly');
      if (!shell || !submitForm || !chatContent) return;
      // Keep the dispute popup outside the admin layout/sidebar stacking context.
      if (shell.parentElement !== document.body) {
        document.body.appendChild(shell);
      }

      function closeModal() {
        shell.hidden = true;
        submitForm.action = '';
        chatContent.innerHTML = '';
      }
      function markSeen(source) {
        const seenAction = source.getAttribute('data-seen-action') || '';
        if (!seenAction) return;
        fetch(seenAction, {method: 'POST', credentials: 'same-origin'}).catch(function() {});
        const row = source.closest('tr');
        if (row) {
          row.querySelectorAll('.dispute-unread-badge').forEach(function(el) { el.remove(); });
        }
      }
      function openModal(source, action, mode) {
        const ref = source.getAttribute('data-ref') || '';
        const user = source.getAttribute('data-user') || '';
        const qr = source.getAttribute('data-qr') || '';
        const status = source.getAttribute('data-status') || '';
        const chatHtml = source.getAttribute('data-chat-html') || '<div class="muted">No previous replies.</div>';
        const isReadOnly = !action;
        chatContent.innerHTML = chatHtml;
        submitForm.action = action || '';
        submitForm.hidden = isReadOnly;
        if (readonlyNote) readonlyNote.hidden = !isReadOnly;
        if (title) title.textContent = mode === 'reject' ? 'Reject dispute?' : (mode === 'resolve' ? 'Resolve dispute?' : 'Dispute chat / reply');
        if (desc) desc.textContent = 'Dispute #' + ref + ' · ' + user + ' · QR: ' + qr + (status ? ' · Status: ' + status.replace('_', ' ') : '');
        if (button) {
          button.textContent = mode === 'reject' ? 'Reject & Send' : (mode === 'resolve' ? 'Resolve & Send' : 'Send Reply');
          button.className = mode === 'reject' ? 'danger' : (mode === 'resolve' ? 'success' : 'success');
        }
        if (label) label.textContent = mode === 'reject' ? 'Final rejection message' : (mode === 'resolve' ? 'Final resolved message' : 'Reply to disputer');
        const textarea = submitForm.querySelector('textarea[name="admin_note"]');
        if (textarea) {
          textarea.value = '';
          textarea.placeholder = mode === 'reject' ? 'Final rejection message.' : (mode === 'resolve' ? 'Final resolved message.' : 'Type your reply.');
        }
        document.body.classList.remove('sidebar-open');
        shell.hidden = false;
        chatContent.scrollTop = chatContent.scrollHeight;
        if (textarea && !isReadOnly) textarea.focus();
        markSeen(source);
      }

      document.querySelectorAll('[data-close-dispute-chat]').forEach(function(el) { el.addEventListener('click', closeModal); });
      document.querySelectorAll('.dispute-chat-open').forEach(function(buttonEl) {
        buttonEl.addEventListener('click', function() {
          openModal(buttonEl, buttonEl.getAttribute('data-action') || '', buttonEl.getAttribute('data-mode') || 'message');
        });
      });
      document.querySelectorAll('.dispute-chat-form').forEach(function(form) {
        form.addEventListener('submit', function(event) {
          event.preventDefault();
          openModal(form, form.action, form.getAttribute('data-mode') || 'message');
        });
      });
      document.addEventListener('keydown', function(event) { if (event.key === 'Escape' && !shell.hidden) closeModal(); });
    });
    </script>
    """
    return render_page("Disputes", body, request)

async def _notify_dispute_user(row: sqlite3.Row, text: str, reply_button: bool = False) -> bool:
    if telegram_application is None:
        return False
    markup = None
    if reply_button and str(row['status'] or '').lower() in {'open', 'under_review'}:
        markup = InlineKeyboardMarkup([[InlineKeyboardButton("💬 Reply to admin", callback_data=f"disputereply:{int(row['id'])}")]])
    try:
        await telegram_application.bot.send_message(chat_id=int(row['chat_id']), text=text, reply_markup=markup, protect_content=PROTECT_CONTENT)
        return True
    except TelegramError:
        return False


@web_app.post("/admin/disputes/{dispute_id}/seen")
async def admin_dispute_seen(request: Request, dispute_id: int):
    guard = admin_guard(request)
    if guard:
        return guard
    row = get_dispute_by_id(dispute_id)
    if not row:
        raise HTTPException(status_code=404, detail="Dispute not found")
    mark_dispute_admin_seen(dispute_id)
    return Response(status_code=204)


@web_app.post("/admin/disputes/{dispute_id}/message")
async def admin_dispute_message(request: Request, dispute_id: int):
    guard = admin_guard(request)
    if guard:
        return guard
    form = await request.form()
    admin_note = str(form.get("admin_note", "")).strip()
    if not admin_note:
        return redirect_with_msg("/admin/disputes", "Message cannot be empty.")
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM disputes WHERE id = ?", (dispute_id,)).fetchone()
        if not row or str(row['status'] or '').lower() not in {'open', 'under_review'}:
            return redirect_with_msg("/admin/disputes", "Dispute is already closed or not found.")
        conn.execute(
            "INSERT INTO dispute_messages(dispute_id, sender_type, sender_chat_id, message, created_at) VALUES (?, 'admin', NULL, ?, ?)",
            (dispute_id, admin_note, now_iso()),
        )
        conn.execute("UPDATE disputes SET status = 'under_review', admin_note = ? WHERE id = ? AND status IN ('open','under_review')", (admin_note, dispute_id))
        latest_id = conn.execute("SELECT COALESCE(MAX(id), 0) AS latest_id FROM dispute_messages WHERE dispute_id = ?", (dispute_id,)).fetchone()["latest_id"]
        conn.execute("UPDATE disputes SET admin_seen_message_id = ? WHERE id = ?", (int(latest_id or 0), dispute_id))
        row = conn.execute("SELECT * FROM disputes WHERE id = ?", (dispute_id,)).fetchone()
    ref = str(row['ref_id'] or f"DSP{int(row['id']):06d}")
    qr_line = f"\nQR ID: {row['public_id']}" if row['public_id'] else ""
    notified = await _notify_dispute_user(row, f"💬 Admin message for dispute #{ref}{qr_line}\n\n{admin_note}\n\nTap the button below to reply.", reply_button=True)
    return redirect_with_msg("/admin/disputes", "Message sent to disputer." if notified else "Message saved, but Telegram notification failed.")


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
        if cur.rowcount:
            conn.execute(
                "INSERT INTO dispute_messages(dispute_id, sender_type, sender_chat_id, message, created_at) VALUES (?, 'admin', NULL, ?, ?)",
                (dispute_id, admin_note, now_iso()),
            )
            latest_id = conn.execute("SELECT COALESCE(MAX(id), 0) AS latest_id FROM dispute_messages WHERE dispute_id = ?", (dispute_id,)).fetchone()["latest_id"]
            conn.execute("UPDATE disputes SET admin_seen_message_id = ? WHERE id = ?", (int(latest_id or 0), dispute_id))
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
        if cur.rowcount:
            conn.execute(
                "INSERT INTO dispute_messages(dispute_id, sender_type, sender_chat_id, message, created_at) VALUES (?, 'admin', NULL, ?, ?)",
                (dispute_id, admin_note, now_iso()),
            )
            latest_id = conn.execute("SELECT COALESCE(MAX(id), 0) AS latest_id FROM dispute_messages WHERE dispute_id = ?", (dispute_id,)).fetchone()["latest_id"]
            conn.execute("UPDATE disputes SET admin_seen_message_id = ? WHERE id = ?", (int(latest_id or 0), dispute_id))
    if row and cur.rowcount:
        ref = str(row['ref_id'] or f"DSP{int(row['id']):06d}")
        qr_line = f"\nQR ID: {row['public_id']}" if row['public_id'] else ""
        notified = await _notify_dispute_user(row, f"❌ Your dispute #{ref} has been rejected.{qr_line}\n\nAdmin message:\n{admin_note}")
        return redirect_with_msg("/admin/disputes", "Dispute rejected and message sent." if notified else "Dispute rejected, but Telegram notification failed.")
    return redirect_with_msg("/admin/disputes", "Dispute was already updated or not found.")



def admin_broadcast_form_html(action: str = "/admin/broadcast") -> str:
    language_options = [
        ("all", "All languages"),
        ("en", "English"),
        ("id", "Indonesian / Bahasa Indonesia"),
        ("vi", "Vietnamese / Tiếng Việt"),
        ("zh", "Chinese / 中文"),
        ("es", "Spanish / Español"),
    ]
    role_options = [
        ("all", "All active users"),
        ("sender", "Senders only"),
        ("receiver", "Receivers only"),
        ("admin", "Admins only"),
    ]
    lang_html = "".join(f'<option value="{esc(code)}">{esc(label)}</option>' for code, label in language_options)
    role_html = "".join(f'<option value="{esc(code)}">{esc(label)}</option>' for code, label in role_options)
    return f'''
    <div class="card"><h2>📣 Broadcast</h2>
      <p class="muted">Send an admin-written Telegram message to users by selected bot language. The message is sent exactly as typed and is not auto-translated.</p>
      <form method="post" action="{esc(action)}">
        <div class="row">
          <div><label>Send to language</label><select name="language">{lang_html}</select></div>
          <div><label>Target users</label><select name="role">{role_html}</select></div>
        </div>
        <label>Broadcast message</label><textarea name="message_text" required placeholder="Write the exact message to send. It will only go to the selected language group."></textarea>
        <button type="submit">📣 Send broadcast</button>
      </form>
      <p class="muted small">Users who never selected a language are treated as English. Admin panel text and admin-written messages remain English/unchanged.</p>
    </div>
    '''


def admin_broadcast_counts_html() -> str:
    languages = [("all", "All languages")] + [(code, meta["name"]) for code, meta in SUPPORTED_LANGUAGES.items()]
    roles = [("all", "All"), ("sender", "Senders"), ("receiver", "Receivers"), ("admin", "Admins")]
    rows_html = ""
    for code, label in languages:
        cells = []
        for role, _role_label in roles:
            try:
                count = len(users_for_language_broadcast(code, role, limit=10000))
            except Exception:
                count = 0
            cells.append(f"<td>{count}</td>")
        rows_html += f"<tr><td>{esc(label)}</td>{''.join(cells)}</tr>"
    return f'''
    <div class="card"><h3>Audience counts</h3>
      <div class="table-wrap"><table class="compact-table">
        <tr><th>Language</th><th>All</th><th>Senders</th><th>Receivers</th><th>Admins</th></tr>
        {rows_html}
      </table></div>
      <p class="muted small">Counts include active users only. Admin IDs are not excluded; sender/receiver targets include matching users plus configured admin IDs, and Admins targets only configured admin IDs.</p>
    </div>
    '''


async def send_admin_language_broadcast_from_form(form, redirect_path: str) -> RedirectResponse:
    language_raw = str(form.get("language", "all")).strip().lower() or "all"
    role = str(form.get("role", "all")).strip().lower() or "all"
    if role not in {"all", "sender", "receiver", "admin"}:
        role = "all"
    language = "all" if language_raw == "all" else normalize_language_code(language_raw)
    message_text = str(form.get("message_text", "")).strip()
    if not message_text:
        return redirect_with_msg(redirect_path, "Broadcast message is required.")
    if len(message_text) > 3900:
        return redirect_with_msg(redirect_path, "Broadcast message is too long. Keep it under 3900 characters.")
    rows = users_for_language_broadcast(language, role)
    if not rows:
        lang_label = "all languages" if language == "all" else SUPPORTED_LANGUAGES[language]["name"]
        return redirect_with_msg(redirect_path, f"No active {role} users found for {lang_label}.")
    if telegram_application is None:
        return redirect_with_msg(redirect_path, "Bot is not ready; could not send broadcast.")
    sent = failed = 0
    for row in rows:
        try:
            await telegram_application.bot.send_message(chat_id=int(row["chat_id"]), text=message_text, protect_content=PROTECT_CONTENT)
            sent += 1
            await asyncio.sleep(0.03)
        except TelegramError:
            failed += 1
    lang_label = "all languages" if language == "all" else SUPPORTED_LANGUAGES[language]["name"]
    return redirect_with_msg(redirect_path, f"Broadcast sent to {sent} {role} users for {lang_label}. Failed: {failed}.")


@web_app.get("/admin/broadcast", response_class=HTMLResponse)
async def admin_broadcast_page(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    body = admin_broadcast_form_html("/admin/broadcast") + admin_broadcast_counts_html()
    return render_page("Broadcast", body, request)


@web_app.post("/admin/broadcast")
async def admin_broadcast_send(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    form = await request.form()
    return await send_admin_language_broadcast_from_form(form, "/admin/broadcast")


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
    <div class="card"><h3>📣 Broadcast</h3>
      <p class="muted">Broadcast now has its own sidebar panel.</p>
      <a class="btn" href="/admin/broadcast">Open Broadcast panel</a>
    </div>
    '''

    body += '<div class="card"><h3>Existing messages</h3>'
    if not templates:
        body += '<p>No preset messages yet.</p>'
    else:
        body += '<div class="message-list">'
        for t in paged_templates:
            edit_msg_link = f'<a class="btn secondary" href="/admin/messages/{esc(t["id"])}/edit">✏️ Edit</a>'
            delete_msg_form = f'<form class="inline" method="post" action="/admin/messages/delmsg"><input type="hidden" name="message_id" value="{esc(t["id"])}"><button class="danger" type="submit">Delete</button></form>'
            body += f'''
            <div class="message-card">
              <div class="message-head">
                <div><span class="muted small">ID</span><div class="message-id">#{esc(t["id"])}</div></div>
                <div><span class="muted small">Audience</span><div>{esc(t["audience"])}</div></div>
                <div><span class="muted small">Button</span><div class="message-button">{esc(t["button_text"])}</div></div>
                <div><span class="muted small">Message</span><div class="message-text">{esc(t["message_text"])}</div><div class="muted small">Created: {esc(display_datetime(t["created_at"]))}</div></div>
                <div class="button-row">{edit_msg_link}{delete_msg_form}</div>
              </div>
            '''
            replies = replies_by_template.get(int(t["id"]), [])
            if replies:
                body += '<div class="reply-list">'
                for r in replies:
                    edit_reply_link = f'<a class="btn secondary" href="/admin/messages/replies/{esc(r["id"])}/edit">✏️ Edit</a>'
                    delete_reply_form = f'<form class="inline" method="post" action="/admin/messages/delreply"><input type="hidden" name="reply_id" value="{esc(r["id"])}"><button class="danger" type="submit">Delete</button></form>'
                    body += f'''
                    <div class="reply-card">
                      <div><span class="muted small">Reply ID</span><div class="message-id">#{esc(r["id"])}</div></div>
                      <div><span class="muted small">Audience</span><div>{esc(r["audience"])}</div></div>
                      <div><span class="muted small">Button</span><div class="message-button">{esc(r["button_text"])}</div></div>
                      <div><span class="muted small">Reply text</span><div class="message-text">{esc(r["reply_text"])}</div><div class="muted small">Created: {esc(display_datetime(r["created_at"]))}</div></div>
                      <div class="button-row">{edit_reply_link}{delete_reply_form}</div>
                    </div>
                    '''
                body += '</div>'
            else:
                body += '<div class="reply-list"><p class="muted">No replies added yet.</p></div>'
            body += '</div>'
        body += '</div>' + templates_pager
    body += '</div>'
    return render_page("Preset Messages", body, request)


@web_app.get("/admin/messages/{message_id}/edit", response_class=HTMLResponse)
async def admin_messages_edit_page(request: Request, message_id: int):
    guard = admin_guard(request)
    if guard:
        return guard
    template = get_message_template(message_id)
    if not template:
        return render_page("Edit Preset Message", '<div class="card"><p>Message not found.</p><a class="btn" href="/admin/messages">← Back</a></div>', request)
    body = f'''
    <div class="card"><h2>✏️ Edit preset message #{esc(template["id"])}</h2>
      <form method="post" action="/admin/messages/{esc(template["id"])}/edit">
        <div class="row">
          <div><label>Who can send it?</label><select name="audience">{_audience_options_html(str(template["audience"] or ""))}</select></div>
          <div><label>Button text</label><input name="button_text" required value="{esc(template["button_text"])}"></div>
        </div>
        <label>Message text delivered</label><textarea name="message_text" required>{esc(template["message_text"])}</textarea>
        <div class="button-row">
          <button type="submit">💾 Save message</button>
          <a class="btn secondary" href="/admin/messages">Cancel</a>
        </div>
      </form>
    </div>
    <div class="card"><p class="muted small">Editing this preset only changes future broadcasts. Already-sent marketplace messages are not changed.</p></div>
    '''
    return render_page("Edit Preset Message", body, request)


@web_app.post("/admin/messages/{message_id}/edit")
async def admin_messages_edit_save(request: Request, message_id: int):
    guard = admin_guard(request)
    if guard:
        return guard
    form = await request.form()
    try:
        ok = update_message_template(
            message_id,
            str(form.get("audience", "")),
            str(form.get("button_text", "")),
            str(form.get("message_text", "")),
        )
    except Exception as exc:
        return redirect_with_msg(f"/admin/messages/{message_id}/edit", f"Could not save message: {exc}")
    return redirect_with_msg("/admin/messages", "Message updated." if ok else "Message not found.")


@web_app.get("/admin/messages/replies/{reply_id}/edit", response_class=HTMLResponse)
async def admin_message_reply_edit_page(request: Request, reply_id: int):
    guard = admin_guard(request)
    if guard:
        return guard
    reply = get_message_reply(reply_id)
    if not reply:
        return render_page("Edit Preset Reply", '<div class="card"><p>Reply not found.</p><a class="btn" href="/admin/messages">← Back</a></div>', request)
    template = get_message_template(int(reply["template_id"]))
    parent_label = f'#{esc(reply["template_id"])}'
    if template:
        parent_label += f' — {esc(template["button_text"])}'
    body = f'''
    <div class="card"><h2>✏️ Edit reply button #{esc(reply["id"])}</h2>
      <p class="muted">Parent message: {parent_label}</p>
      <form method="post" action="/admin/messages/replies/{esc(reply["id"])}/edit">
        <div class="row">
          <div><label>Who can reply?</label><select name="audience">{_audience_options_html(str(reply["audience"] or ""))}</select></div>
          <div><label>Reply button</label><input name="button_text" required value="{esc(reply["button_text"])}"></div>
        </div>
        <label>Reply text delivered back</label><textarea name="reply_text" required>{esc(reply["reply_text"])}</textarea>
        <div class="button-row">
          <button type="submit">💾 Save reply</button>
          <a class="btn secondary" href="/admin/messages">Cancel</a>
        </div>
      </form>
    </div>
    <div class="card"><p class="muted small">Editing this reply button only affects future broadcasts and future button menus.</p></div>
    '''
    return render_page("Edit Preset Reply", body, request)


@web_app.post("/admin/messages/replies/{reply_id}/edit")
async def admin_message_reply_edit_save(request: Request, reply_id: int):
    guard = admin_guard(request)
    if guard:
        return guard
    form = await request.form()
    try:
        ok = update_message_reply(
            reply_id,
            str(form.get("audience", "")),
            str(form.get("button_text", "")),
            str(form.get("reply_text", "")),
        )
    except Exception as exc:
        return redirect_with_msg(f"/admin/messages/replies/{reply_id}/edit", f"Could not save reply: {exc}")
    return redirect_with_msg("/admin/messages", "Reply updated." if ok else "Reply not found.")


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


@web_app.post("/admin/messages/broadcast")
async def admin_messages_language_broadcast(request: Request):
    guard = admin_guard(request)
    if guard:
        return guard
    form = await request.form()
    return await send_admin_language_broadcast_from_form(form, "/admin/broadcast")


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
        ("language", "Change language"),
        ("messages", "Preset marketplace messages"),
        ("myid", "Show your chat ID"),
        ("history", "Show QR history"),
        ("stats", "Show your stats"),
        ("dispute", "Open a dispute"),
        ("disputereply", "Reply to a dispute"),
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
            ("limit", "Add or reduce current limit"),
            ("off", "Go offline"),
            ("pending", "Show pending QRs"),
            ("done", "Mark replied QR done"),
            ("failed", "Mark replied QR failed"),
            ("earnings", "Show earnings"),
            ("withdraw", "Request payout"),
        ]
    if role == "admin":
        return common + [
            ("status", "Show marketplace capacity"),
            ("wallet", "Show wallet balance"),
            ("loadwallet", "Top-up your wallet"),
            ("on", "Go online with limit"),
            ("limit", "Add or reduce current limit"),
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
        if is_admin(chat_id):
            await bot.set_my_commands(bot_commands_for_role("admin"), scope=scope)
        elif user and user.active:
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
    app.add_handler(CommandHandler("language", language_cmd))
    app.add_handler(CommandHandler("messages", messages_cmd))
    app.add_handler(CommandHandler("myid", myid))
    app.add_handler(CommandHandler("status", marketplace_status_cmd))
    app.add_handler(CommandHandler("wallet", wallet_cmd))
    app.add_handler(CommandHandler("loadwallet", loadwallet_cmd))
    app.add_handler(CommandHandler("on", on_cmd))
    app.add_handler(CommandHandler("limit", limit_cmd))
    app.add_handler(CommandHandler("off", off_cmd))
    app.add_handler(CommandHandler("earnings", earnings_cmd))
    app.add_handler(CommandHandler("withdraw", withdraw_cmd))
    app.add_handler(CommandHandler("dispute", dispute_cmd))
    app.add_handler(CommandHandler("disputereply", dispute_reply_cmd))
    app.add_handler(CommandHandler("history", history_cmd))
    app.add_handler(CommandHandler("stats", stats_cmd))
    app.add_handler(CommandHandler("pending", pending_cmd))
    app.add_handler(CommandHandler("done", done_cmd))
    app.add_handler(CommandHandler("failed", failed_cmd))
    app.add_handler(CallbackQueryHandler(wallet_nav_button, pattern=r"^nav:(wallet|earnings|loadwallet|status|pending|history|dispute|stats|messages|commands|support|language|home)$"))
    app.add_handler(CallbackQueryHandler(language_button, pattern=r"^language:set:"))
    app.add_handler(CallbackQueryHandler(wallet_currency_button, pattern=r"^wallet_currency:"))
    app.add_handler(CallbackQueryHandler(wallet_history_button, pattern=r"^wallet_history:"))
    app.add_handler(CallbackQueryHandler(qr_history_button, pattern=r"^qr_history:"))
    app.add_handler(CallbackQueryHandler(withdraw_button, pattern=r"^withdraw:"))
    app.add_handler(CallbackQueryHandler(preset_send_button, pattern=r"^msgsend:"))
    app.add_handler(CallbackQueryHandler(preset_reply_button, pattern=r"^msgreply:"))
    app.add_handler(CallbackQueryHandler(fail_reason_button, pattern=r"^failreason:"))
    app.add_handler(CallbackQueryHandler(dispute_qr_button, pattern=r"^disputeqr:"))
    app.add_handler(CallbackQueryHandler(dispute_reply_button, pattern=r"^disputereply:"))
    app.add_handler(CallbackQueryHandler(cancel_order_button, pattern=r"^cancelorder:"))
    app.add_handler(CallbackQueryHandler(notify_receiver_button, pattern=r"^notify:"))
    app.add_handler(CallbackQueryHandler(check_payment_button, pattern=r"^checkpay:"))
    app.add_handler(CallbackQueryHandler(manual_payment_button, pattern=r"^manualpay:"))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, wallet_text_flow))
    app.add_handler(CallbackQueryHandler(claim_offer_button, pattern=r"^claim:"))
    app.add_handler(CallbackQueryHandler(pending_qr_button, pattern=r"^pendingqr:"))
    app.add_handler(CallbackQueryHandler(button_status, pattern=r"^(done|failed|✅\s*(Done|Selesai|Hoàn tất|完成|Completado|Hecho)|❌\s*(Failed|Gagal|Thất bại|失败|Fallido)|Selesai|Gagal|Hoàn tất|Thất bại|完成|失败|Completado|Fallido|Hecho):"))
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
