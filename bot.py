# -*- coding: utf-8 -*-
"""
SR King Bot Hosting Platform — full refactor with Private Access Control.
Python 3.10+ required.
"""

from __future__ import annotations

import ast
import atexit
import hashlib
import html
import importlib.util
import io
import json
import logging
import mimetypes
import os
import re
import shutil
import signal
import sqlite3
import stat
import string
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

os.environ.setdefault("PYTHONIOENCODING", "utf-8")
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

import psutil
import requests
import telebot
from telebot import types

# ─────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────
TOKEN = os.environ.get("BOT_TOKEN", "").strip()
if not TOKEN:
    raise RuntimeError("BOT_TOKEN environment variable set nahi hai.")

OWNER_ID = 7892255798
ADMIN_ID = 7892255798
YOUR_USERNAME = '@srking5306'
UPDATE_CHANNEL = '@srk_era'
FORCE_JOIN_CHANNELS = {
    "@srk_era": "🟢 JOIN",
}
BACKUP_CHANNEL_ID = -1003972335264
LOG_LEVEL = "INFO"

# ─────────────────────────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────────────────────────
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_BOTS_DIR = os.path.join(BASE_DIR, "upload_bots")
DATA_DIR = os.path.join(BASE_DIR, "inf")
DATABASE_PATH = os.path.join(DATA_DIR, "bot_data.db")
AUTOSTART_PATH = os.path.join(DATA_DIR, "autostart.json")

os.makedirs(UPLOAD_BOTS_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

# ─────────────────────────────────────────────────────────────────
# LIMITS & CONSTANTS
# ─────────────────────────────────────────────────────────────────
FREE_USER_LIMIT = 5
SUBSCRIBED_USER_LIMIT = 20
ADMIN_LIMIT = 500
OWNER_LIMIT = float("inf")

ZIP_MAX_UNCOMPRESSED_BYTES = 200 * 1024 * 1024
TG_MAX_UPLOAD_BYTES = 20 * 1024 * 1024

LOG_MAX_BYTES = 2 * 1024 * 1024
LOG_KEEP_BYTES = 512 * 1024

BACKUP_PART_SIZE = 15 * 1024 * 1024
BACKUP_MAX_PARTS = 40
BACKUP_MAX_FILE_BYTES = 300 * 1024 * 1024
BACKUP_ZIP_NAME = "srk_bot_backup.zip"
BACKUP_DEBOUNCE_SECONDS = 8
BACKUP_MANIFEST_TAG = "SRKBACKUP1"

_BACKUP_SKIP_DIRS = {"node_modules", "__pycache__", ".git", "venv", ".venv",
                     "site-packages", ".cache", ".npm", "_sandbox"}
_BACKUP_SKIP_EXT = (".pyc", ".log")

MSG_RATE_WINDOW = 3.0
MAX_MSG_PER_WINDOW = 5

# ─────────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("srk-bot")
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("werkzeug").setLevel(logging.WARNING)

# ─────────────────────────────────────────────────────────────────
# NETWORK SANDBOX (user scripts only — pip/npm never touched)
# ─────────────────────────────────────────────────────────────────
SANDBOX_DIR = os.path.join(BASE_DIR, "_sandbox")
SANDBOX_MODE = "block"
SANDBOX_ALLOW_HOSTS = (
    "api.telegram.org,core.telegram.org,telegram.org,t.me,"
    "pypi.org,files.pythonhosted.org,pypi.python.org,"
    "registry.npmjs.org,nodejs.org,"
    "localhost,127.0.0.1,::1"
)

_SANDBOX_SOURCE = r'''# SRK Bot Hosting — sandbox network policy (auto-imported by Python)
import os
import sys
import threading as _threading
import socket as _socket

_MODE = os.environ.get("SRK_SANDBOX_MODE", "block").lower()
_ALLOWED = [
    h.strip().lower()
    for h in os.environ.get(
        "SRK_SANDBOX_ALLOW_HOSTS",
        "api.telegram.org,core.telegram.org,telegram.org,t.me,pypi.org,files.pythonhosted.org,pypi.python.org,registry.npmjs.org,nodejs.org,localhost,127.0.0.1,::1",
    ).split(",")
    if h.strip()
]

def _is_allowed_host(host):
    if not isinstance(host, str):
        return True
    hl = host.lower()
    for a in _ALLOWED:
        if hl == a or hl.endswith("." + a):
            return True
    return False

if _MODE != "off":
    try:
        _orig_getaddrinfo = _socket.getaddrinfo
        _orig_connect = _socket.socket.connect
        _orig_connect_ex = _socket.socket.connect_ex

        _allowed_ips = set()
        _ip_lock = _threading.Lock()

        def _getaddrinfo(host, *args, **kwargs):
            if _is_allowed_host(host):
                res = _orig_getaddrinfo(host, *args, **kwargs)
                try:
                    with _ip_lock:
                        for entry in res:
                            sa = entry[4] if len(entry) >= 5 else None
                            if isinstance(sa, tuple) and sa:
                                _allowed_ips.add(sa[0])
                except Exception:
                    pass
                return res
            msg = "[sandbox] DNS lookup blocked: %r" % (host,)
            print(msg, file=sys.stderr)
            if _MODE == "block":
                raise PermissionError(msg)
            return _orig_getaddrinfo(host, *args, **kwargs)

        def _connect(self, address):
            ip = address[0] if isinstance(address, tuple) and address else None
            if ip and ip not in ("127.0.0.1", "::1"):
                with _ip_lock:
                    allowed_now = ip in _allowed_ips
                if not allowed_now:
                    msg = "[sandbox] connect blocked: %r" % (address,)
                    print(msg, file=sys.stderr)
                    if _MODE == "block":
                        raise PermissionError(msg)
            return _orig_connect(self, address)

        def _connect_ex(self, address):
            ip = address[0] if isinstance(address, tuple) and address else None
            if ip and ip not in ("127.0.0.1", "::1"):
                with _ip_lock:
                    allowed_now = ip in _allowed_ips
                if not allowed_now:
                    msg = "[sandbox] connect_ex blocked: %r" % (address,)
                    print(msg, file=sys.stderr)
                    if _MODE == "block":
                        raise PermissionError(msg)
            return _orig_connect_ex(self, address)

        _socket.getaddrinfo = _getaddrinfo
        _socket.socket.connect = _connect
        _socket.socket.connect_ex = _connect_ex
    except Exception as _e:
        print("[sandbox] init error: %r" % (_e,), file=sys.stderr)
'''

try:
    os.makedirs(SANDBOX_DIR, exist_ok=True)
    with open(os.path.join(SANDBOX_DIR, "sitecustomize.py"), "w", encoding="utf-8") as _sf:
        _sf.write(_SANDBOX_SOURCE)
    logger.info("Network sandbox initialised (mode=%s).", SANDBOX_MODE)
except Exception as _e:
    logger.warning("Could not initialise network sandbox: %s", _e)

# ─────────────────────────────────────────────────────────────────
# BOT INIT
# ─────────────────────────────────────────────────────────────────
# [ADDED: speed — pyTelegramBotAPI defaults to only 2 worker threads, so any
# slow handler (starting/stopping a hosted script, building a backup zip,
# etc.) blocks every other user behind it. More workers = the bot keeps
# answering everyone else while one of those runs.]
bot = telebot.TeleBot(TOKEN, parse_mode=None, num_threads=24)

# ─────────────────────────────────────────────────────────────────
# GLOBAL STATE + LOCKS
# ─────────────────────────────────────────────────────────────────
bot_scripts: dict[str, dict] = {}
user_subscriptions: dict[int, dict] = {}
user_files: dict[int, list[tuple[str, str]]] = {}
active_users: set[int] = set()
admin_ids: set[int] = {ADMIN_ID, OWNER_ID}
allowed_users_ids: set[int] = set()
banned_users: set[int] = set()
banned_usernames: set[str] = set()

bot_locked = False
_lock_state = threading.RLock()
_lock_files = threading.RLock()
_lock_scripts = threading.RLock()

_launch_stamp: dict[str, float] = {}
_bot_username_cache: dict[tuple[int, str], str] = {}

_rate_map: dict[int, list[float]] = {}
_lock_rate = threading.Lock()

# ─────────────────────────────────────────────────────────────────
# SAFE HTML HELPERS
# ─────────────────────────────────────────────────────────────────
def esc(s: Any) -> str:
    if s is None:
        return ""
    return html.escape(str(s), quote=False)

def md_code(s: Any) -> str:
    return f"<code>{esc(s)}</code>"

def md_bold(s: Any) -> str:
    return f"<b>{esc(s)}</b>"

def md_italic(s: Any) -> str:
    return f"<i>{esc(s)}</i>"

def safe_reply(message, text: str, **kwargs):
    kwargs.setdefault("parse_mode", "HTML")
    try:
        return bot.reply_to(message, text, **kwargs)
    except telebot.apihelper.ApiTelegramException as e:
        if "parse" in str(e).lower() or "entities" in str(e).lower():
            kwargs.pop("parse_mode", None)
            return bot.reply_to(message, re.sub(r"<[^>]+>", "", text), **kwargs)
        raise

def safe_send(chat_id: int, text: str, **kwargs):
    kwargs.setdefault("parse_mode", "HTML")
    try:
        return bot.send_message(chat_id, text, **kwargs)
    except telebot.apihelper.ApiTelegramException as e:
        if "parse" in str(e).lower() or "entities" in str(e).lower():
            kwargs.pop("parse_mode", None)
            return bot.send_message(chat_id, re.sub(r"<[^>]+>", "", text), **kwargs)
        raise

def _rate_ok(user_id: int) -> bool:
    now = time.monotonic()
    with _lock_rate:
        bucket = _rate_map.setdefault(user_id, [])
        bucket[:] = [t for t in bucket if now - t < MSG_RATE_WINDOW]
        if len(bucket) >= MAX_MSG_PER_WINDOW:
            return False
        bucket.append(now)
        return True

# ─────────────────────────────────────────────────────────────────
# FLASK KEEP-ALIVE
# ─────────────────────────────────────────────────────────────────
from flask import Flask  # noqa: E402

_flask_app = Flask("srk-keepalive")

@_flask_app.route("/")
def _flask_home():
    return "bot is running...."

@_flask_app.route("/health")
def _flask_health():
    return "ok", 200

def _run_flask():
    port = int(os.environ.get("PORT", 10000))
    _flask_app.run(host="0.0.0.0", port=port, threaded=True, use_reloader=False)

def _self_ping_loop():
    import urllib.request
    time.sleep(30)
    while True:
        url = (os.environ.get("RENDER_EXTERNAL_URL")
               or os.environ.get("KEEP_ALIVE_URL") or "").rstrip("/")
        try:
            if url:
                urllib.request.urlopen(url + "/health", timeout=20).read()
            else:
                port = os.environ.get("PORT", "10000")
                urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=10).read()
        except Exception as e:
            logger.debug("Self-ping failed: %s", e)
        time.sleep(50)

def keep_alive():
    threading.Thread(target=_run_flask, daemon=True).start()
    threading.Thread(target=_self_ping_loop, daemon=True).start()
    logger.info("Flask keep-alive started.")

# ─────────────────────────────────────────────────────────────────
# COLORED BUTTONS
# ─────────────────────────────────────────────────────────────────
def _apply_style(btn, style):
    if not style:
        return btn
    try:
        btn.style = style
    except Exception:
        pass
    original_to_dict = btn.to_dict
    def _to_dict_with_style():
        d = original_to_dict()
        d["style"] = style
        return d
    try:
        btn.to_dict = _to_dict_with_style
    except Exception:
        pass
    return btn

def cbtn(text: str, style: Optional[str] = None, **kwargs):
    return _apply_style(types.InlineKeyboardButton(text, **kwargs), style)

def kbtn(text: str, style: Optional[str] = None):
    return _apply_style(types.KeyboardButton(text), style)

# ─────────────────────────────────────────────────────────────────
# BAN / LOCK / ACCESS HELPERS
# ─────────────────────────────────────────────────────────────────
def is_banned_user(user_id: int, username: Optional[str] = None) -> bool:
    if user_id == OWNER_ID:
        return False
    with _lock_state:
        if user_id in banned_users:
            return True
        if username:
            uname = str(username).lstrip("@").lower()
            return any(str(b).lstrip("@").lower() == uname for b in banned_usernames)
    return False

def _block_banned(message, user=None) -> bool:
    try:
        u = user or message.from_user
        if is_banned_user(u.id, getattr(u, "username", None)):
            try:
                safe_send(message.chat.id, "🚫 You are banned from using this bot.")
            except Exception:
                pass
            return True
    except Exception as e:
        logger.warning("Ban check error: %s", e)
    return False

def is_admin(user_id: int) -> bool:
    with _lock_state:
        return user_id in admin_ids

def has_access(user_id: int) -> bool:
    if user_id == OWNER_ID:
        return True
    with _lock_state:
        if user_id in admin_ids:
            return True
        return user_id in allowed_users_ids

def _block_no_access(message, user=None) -> bool:
    try:
        u = user or message.from_user
        if not has_access(u.id):
            try:
                safe_send(
                    message.chat.id,
                    "🚫 <b>This is a private bot.</b>\n\n"
                    "You do not have access to use it.\n"
                    f"Contact Owner: {esc(YOUR_USERNAME)}"
                )
            except Exception:
                pass
            return True
    except Exception as e:
        logger.warning("Access check error: %s", e)
    return False

def _answer_no_access(call) -> None:
    try:
        bot.answer_callback_query(
            call.id,
            "🚫 Private bot. You don't have access.",
            show_alert=True,
        )
    except Exception:
        pass

def _block_locked(message, user_id: int, text: str = "⚠️ Bot locked by admin. Try later.") -> bool:
    with _lock_state:
        locked = bot_locked
    if locked and not is_admin(user_id):
        try:
            bot.reply_to(message, text)
        except Exception:
            pass
        return True
    return False

def _guard(message) -> bool:
    if _block_banned(message):
        return True
    if _block_no_access(message):
        return True
    if _block_locked(message, message.from_user.id):
        return True
    return False

# ─────────────────────────────────────────────────────────────────
# FORCE JOIN
# ─────────────────────────────────────────────────────────────────
_fj_cache: dict[int, tuple[bool, float]] = {}
_fj_lock = threading.Lock()

def is_user_joined_all(user_id: int, ttl: float = 60.0) -> bool:
    now = time.monotonic()
    with _fj_lock:
        cached = _fj_cache.get(user_id)
        if cached and cached[1] > now:
            return cached[0]
    ok = True
    for ch in FORCE_JOIN_CHANNELS.keys():
        try:
            member = bot.get_chat_member(ch, user_id)
            if member.status not in ("member", "administrator", "creator"):
                ok = False
                break
        except Exception as e:
            logger.warning("Force join check failed for %s on %s: %s", user_id, ch, e)
            ok = False
            break
    with _fj_lock:
        _fj_cache[user_id] = (ok, now + ttl)
    return ok

def send_force_join_msg(chat_id: int):
    markup = types.InlineKeyboardMarkup(row_width=1)
    for ch, label in FORCE_JOIN_CHANNELS.items():
        markup.add(cbtn(label, style="primary", url=f"https://t.me/{ch.replace('@', '')}"))
    markup.add(cbtn("✅ Joined All", style="success", callback_data="force_join_check"))
    safe_send(chat_id, "𝐉𝐎𝐈𝐍 𝐀𝐋𝐋 𝐂𝐇𝐀𝐍𝐍𝐄𝐋 𝐓𝐎 𝐔𝐒𝐄 𝐌𝐄 🤍🌙:", reply_markup=markup)

# ─────────────────────────────────────────────────────────────────
# ATOMIC JSON WRITE
# ─────────────────────────────────────────────────────────────────
def atomic_write_json(path: str, payload: Any) -> None:
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=parent, prefix=".tmp_", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

# ─────────────────────────────────────────────────────────────────
# BACKUP / RESTORE
# ─────────────────────────────────────────────────────────────────
_backup_dirty = threading.Event()
_backup_lock = threading.Lock()
_last_backup_ids: list[int] = []
_backup_push_blocked = False

def _tg_retry(func, *args, tries: int = 4, **kwargs):
    last = None
    for attempt in range(tries):
        try:
            return func(*args, **kwargs)
        except telebot.apihelper.ApiTelegramException as e:
            last = e
            wait = 3 * (attempt + 1)
            try:
                wait = int(e.result_json.get("parameters", {}).get("retry_after", wait))
            except Exception:
                pass
            if e.error_code in (400, 401, 403, 404):
                raise
            time.sleep(min(wait, 60))
        except Exception as e:
            last = e
            time.sleep(3 * (attempt + 1))
    raise last

def _build_backup_zip() -> str:
    tmp_path = os.path.join(tempfile.gettempdir(), BACKUP_ZIP_NAME)
    if os.path.exists(tmp_path):
        os.remove(tmp_path)
    db_snapshot = os.path.join(tempfile.gettempdir(), "db_snapshot.sqlite")
    have_snapshot = False
    try:
        src = sqlite3.connect(DATABASE_PATH, timeout=30)
        dst = sqlite3.connect(db_snapshot)
        src.backup(dst)
        dst.close(); src.close()
        have_snapshot = True
    except Exception as e:
        logger.warning("Backup: DB snapshot failed: %s", e)
    with zipfile.ZipFile(tmp_path, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
        if have_snapshot:
            try:
                zf.write(db_snapshot, os.path.relpath(DATABASE_PATH, BASE_DIR))
            except Exception as e:
                logger.warning("Backup: could not add DB snapshot: %s", e)
                have_snapshot = False
        for folder in (DATA_DIR, UPLOAD_BOTS_DIR):
            if not os.path.isdir(folder):
                continue
            for root, dirs, files in os.walk(folder):
                dirs[:] = [d for d in dirs if d not in _BACKUP_SKIP_DIRS]
                for fname in files:
                    full_path = os.path.join(root, fname)
                    if fname.lower().endswith(_BACKUP_SKIP_EXT):
                        continue
                    if have_snapshot and os.path.abspath(full_path) in (
                        os.path.abspath(DATABASE_PATH),
                        os.path.abspath(DATABASE_PATH) + "-wal",
                        os.path.abspath(DATABASE_PATH) + "-shm",
                    ):
                        continue
                    try:
                        if os.path.getsize(full_path) > BACKUP_MAX_FILE_BYTES:
                            continue
                        zf.write(full_path, os.path.relpath(full_path, BASE_DIR))
                    except Exception as e:
                        logger.warning("Backup: could not add %s: %s", full_path, e)
    try:
        os.remove(db_snapshot)
    except Exception:
        pass
    return tmp_path

def push_backup_to_channel():
    global _last_backup_ids
    if not BACKUP_CHANNEL_ID:
        return
    if _backup_push_blocked:
        logger.error("Backup push skipped: existing backup could not be restored.")
        return
    with _backup_lock:
        sent_ids: list[int] = []
        try:
            zip_path = _build_backup_zip()
            total = os.path.getsize(zip_path)
            n_parts = max(1, -(-total // BACKUP_PART_SIZE))
            if n_parts > BACKUP_MAX_PARTS:
                raise RuntimeError(f"Backup too large ({total/1024/1024:.0f} MB)")
            stamp = f"{datetime.now():%Y-%m-%d %H:%M:%S}"
            parts: list[str] = []
            with open(zip_path, "rb") as f:
                for i in range(n_parts):
                    chunk = f.read(BACKUP_PART_SIZE)
                    name = f"{BACKUP_ZIP_NAME}.part{i+1:03d}"
                    def _send_part(chunk=chunk, name=name, i=i):
                        buf = io.BytesIO(chunk)
                        buf.name = name
                        return bot.send_document(
                            BACKUP_CHANNEL_ID, buf,
                            caption=f"🗄️ SRK backup {stamp} - part {i+1}/{n_parts}",
                            timeout=180,
                        )
                    sent = _tg_retry(_send_part)
                    sent_ids.append(sent.message_id)
                    parts.append(sent.document.file_id)
            manifest = BACKUP_MANIFEST_TAG + "\n" + json.dumps({
                "time": stamp, "size": total, "parts": parts, "msg_ids": list(sent_ids),
            })
            m = _tg_retry(bot.send_message, BACKUP_CHANNEL_ID, manifest)
            sent_ids.append(m.message_id)
            _tg_retry(bot.pin_chat_message, BACKUP_CHANNEL_ID, m.message_id,
                      disable_notification=True)
            if _last_backup_ids:
                try:
                    bot.unpin_chat_message(BACKUP_CHANNEL_ID, _last_backup_ids[-1])
                except Exception as e:
                    logger.warning("Backup: could not unpin previous: %s", e)
            _last_backup_ids = list(sent_ids)
            logger.info("✅ Backup pushed (%.1f MB, %d part(s)).",
                        total/1024/1024, n_parts)
        except Exception as e:
            logger.error("❌ Backup push failed: %s", e, exc_info=True)
            for mid in sent_ids:
                try:
                    bot.delete_message(BACKUP_CHANNEL_ID, mid)
                except Exception:
                    pass
            _backup_dirty.set()
        finally:
            try:
                os.remove(os.path.join(tempfile.gettempdir(), BACKUP_ZIP_NAME))
            except Exception:
                pass

def mark_data_dirty():
    if BACKUP_CHANNEL_ID:
        _backup_dirty.set()

def _backup_worker_loop():
    while True:
        try:
            _backup_dirty.wait()
            time.sleep(BACKUP_DEBOUNCE_SECONDS)
            _backup_dirty.clear()
            push_backup_to_channel()
            time.sleep(5)
        except Exception as e:
            logger.error("Backup worker error: %s", e, exc_info=True)
            time.sleep(30)

def _safe_extract(zf: zipfile.ZipFile, dest: str) -> None:
    dest_real = os.path.realpath(dest)
    for member in zf.infolist():
        target = os.path.realpath(os.path.join(dest_real, member.filename))
        if target != dest_real and not target.startswith(dest_real + os.sep):
            logger.warning("Restore: skipping unsafe path %s", member.filename)
            continue
        zf.extract(member, dest_real)

def restore_backup_from_channel() -> bool:
    global _last_backup_ids, _backup_push_blocked
    if not BACKUP_CHANNEL_ID:
        logger.info("BACKUP_CHANNEL_ID not set - starting fresh.")
        return False
    tmp_path = os.path.join(tempfile.gettempdir(), BACKUP_ZIP_NAME + ".restore")
    try:
        chat = _tg_retry(bot.get_chat, BACKUP_CHANNEL_ID)
        pinned = getattr(chat, "pinned_message", None)
        if not pinned:
            logger.info("No pinned backup found.")
            return False
        text = getattr(pinned, "text", None) or ""
        _backup_push_blocked = True
        with open(tmp_path, "wb") as out:
            if text.startswith(BACKUP_MANIFEST_TAG):
                info = json.loads(text.split("\n", 1)[1])
                for file_id in info["parts"]:
                    fi = _tg_retry(bot.get_file, file_id)
                    out.write(_tg_retry(bot.download_file, fi.file_path))
                _last_backup_ids = list(info.get("msg_ids", [])) + [pinned.message_id]
            elif getattr(pinned, "document", None):
                fi = _tg_retry(bot.get_file, pinned.document.file_id)
                out.write(_tg_retry(bot.download_file, fi.file_path))
                _last_backup_ids = [pinned.message_id]
            else:
                logger.info("Pinned message is not a backup.")
                _backup_push_blocked = False
                return False
        with zipfile.ZipFile(tmp_path, "r") as zf:
            bad = zf.testzip()
            if bad:
                raise zipfile.BadZipFile(f"corrupt entry: {bad}")
            _safe_extract(zf, BASE_DIR)
        _backup_push_blocked = False
        logger.info("✅ Restored data from backup channel.")
        return True
    except Exception as e:
        logger.error("❌ Restore failed: %s", e, exc_info=True)
        return False
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass

# ─────────────────────────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────────────────────────
DB_LOCK = threading.Lock()
_db_local = threading.local()
_all_db_conns: list[sqlite3.Connection] = []
_all_db_conns_lock = threading.Lock()

def _db_conn() -> sqlite3.Connection:
    conn = getattr(_db_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False, timeout=30)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=30000")
            conn.execute("PRAGMA foreign_keys=ON")
        except Exception as e:
            logger.warning("Could not apply SQLite PRAGMAs: %s", e)
        _db_local.conn = conn
        with _all_db_conns_lock:
            _all_db_conns.append(conn)
    return conn

def _close_all_db_conns() -> None:
    with _all_db_conns_lock:
        for c in _all_db_conns:
            try:
                c.close()
            except Exception:
                pass
        _all_db_conns.clear()

def init_db():
    logger.info("Initializing DB at %s", DATABASE_PATH)
    try:
        conn = _db_conn()
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS subscriptions (user_id INTEGER PRIMARY KEY, expiry TEXT)")
        c.execute("""CREATE TABLE IF NOT EXISTS user_files
                     (user_id INTEGER, file_name TEXT, file_type TEXT,
                      PRIMARY KEY (user_id, file_name))""")
        c.execute("CREATE TABLE IF NOT EXISTS active_users (user_id INTEGER PRIMARY KEY)")
        c.execute("CREATE TABLE IF NOT EXISTS admins (user_id INTEGER PRIMARY KEY)")
        c.execute("CREATE TABLE IF NOT EXISTS allowed_users (user_id INTEGER PRIMARY KEY)")
        c.execute("INSERT OR IGNORE INTO admins (user_id) VALUES (?)", (OWNER_ID,))
        if ADMIN_ID != OWNER_ID:
            c.execute("INSERT OR IGNORE INTO admins (user_id) VALUES (?)", (ADMIN_ID,))
        conn.commit()
        logger.info("DB initialized.")
    except Exception as e:
        logger.error("DB init error: %s", e, exc_info=True)

def load_data():
    logger.info("Loading data from DB...")
    try:
        conn = _db_conn()
        c = conn.cursor()
        c.execute("SELECT user_id, expiry FROM subscriptions")
        for user_id, expiry in c.fetchall():
            try:
                user_subscriptions[user_id] = {"expiry": datetime.fromisoformat(expiry)}
            except ValueError:
                logger.warning("Invalid expiry for %s: %s", user_id, expiry)
        c.execute("SELECT user_id, file_name, file_type FROM user_files")
        with _lock_files:
            user_files.clear()
            for user_id, file_name, file_type in c.fetchall():
                user_files.setdefault(user_id, []).append((file_name, file_type))
        c.execute("SELECT user_id FROM active_users")
        active_users.update(uid for (uid,) in c.fetchall())
        c.execute("SELECT user_id FROM admins")
        with _lock_state:
            admin_ids.update(uid for (uid,) in c.fetchall())
        c.execute("SELECT user_id FROM allowed_users")
        with _lock_state:
            allowed_users_ids.update(uid for (uid,) in c.fetchall())
        logger.info("Loaded: %d users, %d subs, %d admins, %d allowed.",
                    len(active_users), len(user_subscriptions),
                    len(admin_ids), len(allowed_users_ids))
    except Exception as e:
        logger.error("Load error: %s", e, exc_info=True)

_RESTORED_FROM_BACKUP = restore_backup_from_channel()
init_db()
load_data()

# ─────────────────────────────────────────────────────────────────
# MALWARE SCAN
# ─────────────────────────────────────────────────────────────────
_EXECUTABLE_SIGNATURES = [b"MZ", b"\x7fELF", b"\xfe\xed\xfa", b"\xce\xfa\xed\xfe"]
_ARCHIVE_SIGNATURES = {b"PK": "zip", b"Rar!": "rar", b"7z\xbc\xaf\x27\x1c": "7z"}
_SUSPICIOUS_EXT = {
    ".exe", ".dll", ".bat", ".cmd", ".scr", ".com", ".pif", ".application",
    ".gadget", ".msi", ".msp", ".hta", ".cpl", ".msc", ".jar", ".bin",
    ".deb", ".rpm", ".apk", ".app", ".dmg", ".iso", ".img",
}
_ENCRYPTED_INDICATORS = [b"openssl", b"encrypted", b"cipher", b"gpg", b"pgp"]
_SUSPICIOUS_KEYWORDS = [b"ransomware", b"trojan", b"virus", b"malware",
                        b"backdoor", b"keylogger", b"rootkit", b"botnet"]

def get_file_type(sample: bytes) -> str:
    if sample.startswith(b"\x7fELF"): return "application/x-executable"
    if sample.startswith(b"MZ"): return "application/x-dosexec"
    if sample.startswith((b"\xfe\xed\xfa", b"\xce\xfa\xed\xfe")): return "application/x-mach-binary"
    if sample.startswith(b"PK"): return "application/zip"
    if sample.startswith(b"Rar!"): return "application/x-rar"
    return "application/octet-stream"

def is_suspicious_file(file_content: bytes, file_name: str) -> tuple[bool, str]:
    name_lower = file_name.lower()
    ext = os.path.splitext(name_lower)[1]

    if ext in _SUSPICIOUS_EXT:
        return True, f"Suspicious file extension: {file_name}"

    sample = file_content[:4096]

    for sig in _EXECUTABLE_SIGNATURES:
        if sample.startswith(sig):
            return True, f"Executable signature detected: {sig!r}"

    for sig, kind in _ARCHIVE_SIGNATURES.items():
        if sample.startswith(sig) and not (ext == "." + kind or ext == ".zip"):
            return True, f"Archive content ({kind}) with unexpected extension: {file_name}"

    for ind in _ENCRYPTED_INDICATORS:
        if ind in sample:
            return True, f"Encrypted-file indicator: {ind.decode('utf-8', 'ignore')}"

    try:
        text = sample.decode("utf-8", "ignore").lower()
    except Exception:
        text = ""
    for kw in _SUSPICIOUS_KEYWORDS:
        if kw.decode() in text:
            return True, f"Suspicious keyword: {kw.decode()}"

    if ext in (".py", ".js", ".zip"):
        ftype = get_file_type(sample)
        if ftype in ("application/x-dosexec", "application/x-executable", "application/x-mach-binary"):
            return True, f"Declared as {ext} but is {ftype}"

    return False, "File appears safe"

def scan_file_for_malware(file_content: bytes, file_name: str, user_id: int) -> tuple[bool, str]:
    if user_id == OWNER_ID:
        return True, "Owner bypass"
    is_sus, reason = is_suspicious_file(file_content, file_name)
    if is_sus:
        logger.warning("🚨 Malware detected in %s from %s: %s", file_name, user_id, reason)
        return False, f"Security violation: {reason}"
    return True, "Passed security check"

# ─────────────────────────────────────────────────────────────────
# FILE NAMING / LIMITS / FOLDERS
# ─────────────────────────────────────────────────────────────────
MAX_STORED_FILENAME_LEN = 30
_BOT_TOKEN_RE = re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")

def _cap_file_name(name: str) -> str:
    base, ext = os.path.splitext(name)
    ext = ext[:10]
    max_base = max(4, MAX_STORED_FILENAME_LEN - len(ext))
    if len(base) <= max_base:
        return base + ext
    h = hashlib.sha1(base.encode("utf-8", "ignore")).hexdigest()[:6]
    keep = max(1, max_base - len(h) - 1)
    return f"{base[:keep]}_{h}{ext}"

def _extract_bot_token(text: str) -> Optional[str]:
    if not text:
        return None
    m = _BOT_TOKEN_RE.search(text)
    return m.group(0) if m else None

def _bot_username_from_token(token: str) -> Optional[str]:
    try:
        resp = requests.get(f"https://api.telegram.org/bot{token}/getMe", timeout=5)
        data = resp.json()
        if data.get("ok") and data.get("result", {}).get("username"):
            uname = re.sub(r"[^A-Za-z0-9_]", "", data["result"]["username"])
            return uname or None
    except Exception as e:
        logger.warning("getMe failed: %s", e)
    return None

def _unique_file_name(user_id: int, name: str) -> str:
    name = _cap_file_name(name)
    with _lock_files:
        existing = {fn for fn, _ in user_files.get(user_id, [])}
    if name not in existing:
        return name
    base, ext = os.path.splitext(name)
    i = 2
    while f"{base}_{i}{ext}" in existing:
        i += 1
    return _cap_file_name(f"{base}_{i}{ext}")

def _friendly_file_name(user_id: int, file_name: str, file_ext: str, source_bytes: bytes):
    try:
        src = source_bytes.decode("utf-8", "ignore")
    except Exception:
        src = ""
    token = _extract_bot_token(src)
    if token:
        uname = _bot_username_from_token(token)
        if uname:
            return _unique_file_name(user_id, f"{uname}{file_ext}"), True
    return _unique_file_name(user_id, file_name), False

def get_cached_bot_username(user_id: int, file_name: str) -> Optional[str]:
    key = (user_id, file_name)
    if key in _bot_username_cache:
        return _bot_username_cache[key] or None
    username = None
    try:
        if os.path.splitext(file_name)[1].lower() in (".py", ".js"):
            fp = os.path.join(get_user_folder(user_id), file_name)
            if os.path.exists(fp):
                with open(fp, "rb") as f:
                    src = f.read()
                tok = _extract_bot_token(src.decode("utf-8", "ignore"))
                if tok:
                    username = _bot_username_from_token(tok)
    except Exception as e:
        logger.warning("Username lookup failed: %s", e)
    _bot_username_cache[key] = username or ""
    return username

def invalidate_cached_bot_username(user_id: int, file_name: str) -> None:
    _bot_username_cache.pop((user_id, file_name), None)

def display_name_for_file(user_id: int, file_name: str) -> str:
    u = get_cached_bot_username(user_id, file_name)
    return f"@{u} ({file_name})" if u else file_name

def get_user_folder(user_id: int) -> str:
    folder = os.path.join(UPLOAD_BOTS_DIR, str(user_id))
    os.makedirs(folder, exist_ok=True)
    return folder

def get_user_file_limit(user_id: int) -> float:
    if user_id == OWNER_ID: return OWNER_LIMIT
    if is_admin(user_id): return ADMIN_LIMIT
    sub = user_subscriptions.get(user_id)
    if sub and sub.get("expiry") and sub["expiry"] > datetime.now():
        return SUBSCRIBED_USER_LIMIT
    return FREE_USER_LIMIT

def get_user_file_count(user_id: int) -> int:
    with _lock_files:
        return len(user_files.get(user_id, []))

def _log_path_for(user_folder: str, file_name: str) -> str:
    base, ext = os.path.splitext(file_name)
    ext_tag = ext.lstrip(".") or "out"
    return os.path.join(user_folder, f"{base}__{ext_tag}.log")

# ─────────────────────────────────────────────────────────────────
# ENVIRONMENT BUILDERS
# ─────────────────────────────────────────────────────────────────
_SAFE_ENV_KEYS = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "HOME", "TMPDIR",
                  "USER", "SHELL", "SYSTEMROOT", "WINDIR")

def _child_env(extra: Optional[dict] = None) -> dict:
    env: dict[str, str] = {}
    for k in _SAFE_ENV_KEYS:
        v = os.environ.get(k)
        if v is not None:
            env[k] = v
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = SANDBOX_DIR
    env["SRK_SANDBOX_MODE"] = SANDBOX_MODE
    env["SRK_SANDBOX_ALLOW_HOSTS"] = SANDBOX_ALLOW_HOSTS
    if extra:
        env.update(extra)
    return env

def _pkg_env(extra: Optional[dict] = None) -> dict:
    env: dict[str, str] = {}
    for k in _SAFE_ENV_KEYS:
        v = os.environ.get(k)
        if v is not None:
            env[k] = v
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if extra:
        env.update(extra)
    return env

# ─────────────────────────────────────────────────────────────────
# RESOURCE LIMITS
# ─────────────────────────────────────────────────────────────────
# [FIXED: RLIMIT_NPROC — Python 3.14 + asyncio + aiohttp needs many threads]
def _preexec_limits():
    try:
        import resource
        # 2 GB address space — Python 3.14 + aiohttp + aiogram needs headroom
        resource.setrlimit(resource.RLIMIT_AS,
                           (2 * 1024 * 1024 * 1024, 2 * 1024 * 1024 * 1024))
        # 200 MB file writes
        resource.setrlimit(resource.RLIMIT_FSIZE,
                           (200 * 1024 * 1024, 200 * 1024 * 1024))
        # IMPORTANT: RLIMIT_NPROC is per-USER, shared with parent + all
        # hosted bots. 64 was way too low — asyncio/aiohttp easily spawn
        # 100+ threads. 2048 allows normal workloads while still stopping
        # extreme fork-bombs.
        try:
            resource.setrlimit(resource.RLIMIT_NPROC, (2048, 2048))
        except Exception:
            pass
        # No core dumps
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except Exception:
            pass
        # [ADDED: speed — mild niceness on hosted scripts so the main
        # hosting bot process always keeps CPU priority and stays
        # responsive, even if many hosted bots are busy at once. This only
        # matters when the CPU is actually contended; with spare CPU
        # (the normal case) hosted bots run at full speed either way.]
        try:
            os.nice(3)
        except Exception:
            pass
    except Exception:
        pass

# ─────────────────────────────────────────────────────────────────
# PACKAGE INSTALL
# ─────────────────────────────────────────────────────────────────
try:
    _STDLIB_MODULES = set(sys.stdlib_module_names)
except AttributeError:
    _STDLIB_MODULES = {
        "os","sys","re","time","math","random","json","logging","threading",
        "subprocess","zipfile","tempfile","shutil","sqlite3","atexit","io",
        "datetime","collections","itertools","functools","asyncio","socket",
        "struct","hashlib","hmac","base64","traceback","signal","csv","uuid",
        "typing","enum","copy","queue","string","textwrap","unittest","abc",
        "urllib","http","email","html","xml","pathlib","glob","argparse",
        "configparser","pickle","inspect","contextlib","warnings","ssl",
        "select","ctypes","platform","multiprocessing","concurrent",
    }

TELEGRAM_MODULES: dict[str, Optional[str]] = {
    "telebot": "pyTelegramBotAPI",
    "telegram": "python-telegram-bot",
    "python_telegram_bot": "python-telegram-bot",
    "aiogram": "aiogram",
    "pyrogram": "pyrogram",
    "telethon": "telethon",
    "telethon.sync": "telethon",
    "telepot": "telepot",
    "tgcrypto": "tgcrypto",
    "bs4": "beautifulsoup4",
    "requests": "requests",
    "pil": "Pillow",
    "pillow": "Pillow",
    "cv2": "opencv-python",
    "yaml": "PyYAML",
    "dotenv": "python-dotenv",
    "dateutil": "python-dateutil",
    "pandas": "pandas",
    "numpy": "numpy",
    "flask": "Flask",
    "django": "Django",
    "sqlalchemy": "SQLAlchemy",
    "psutil": "psutil",
    "aiohttp": "aiohttp",
    "httpx": "httpx",
    "openai": "openai",
    "google.generativeai": "google-generativeai",
    "asyncio": None, "json": None, "datetime": None, "os": None, "sys": None,
    "re": None, "time": None, "math": None, "random": None, "logging": None,
    "threading": None, "subprocess": None, "zipfile": None, "tempfile": None,
    "shutil": None, "sqlite3": None, "atexit": None, "io": None,
}

def _extract_imported_modules(script_path: str) -> set[str]:
    mods: set[str] = set()
    try:
        with open(script_path, "r", encoding="utf-8", errors="ignore") as f:
            src = f.read()
        tree = ast.parse(src, filename=script_path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mods.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module and node.level == 0:
                    mods.add(node.module.split(".")[0])
    except SyntaxError as e:
        logger.warning("Import scan syntax error %s: %s", script_path, e)
    except Exception as e:
        logger.warning("Import scan failed %s: %s", script_path, e)
    return mods

def _module_installed(mod: str) -> bool:
    try:
        return importlib.util.find_spec(mod) is not None
    except Exception:
        return False

def _pip_package_for(module: str) -> Optional[str]:
    low = module.lower()
    if low == "pil":
        return "Pillow"
    return TELEGRAM_MODULES.get(low, module)

def preinstall_missing_packages(script_path: str, message) -> bool:
    try:
        modules = _extract_imported_modules(script_path)
    except Exception as e:
        logger.warning("preinstall scan error: %s", e)
        return True

    to_install: list[str] = []
    for mod in sorted(modules):
        low = mod.lower()
        if low in _STDLIB_MODULES or mod in _STDLIB_MODULES:
            continue
        if low in TELEGRAM_MODULES and TELEGRAM_MODULES[low] is None:
            continue
        if _module_installed(mod):
            continue
        pkg = _pip_package_for(mod)
        if pkg:
            to_install.append(pkg)

    if not to_install:
        return True

    try:
        safe_reply(message,
            f"🔄 Found {len(to_install)} missing package(s): "
            + ", ".join(md_code(p) for p in to_install)
            + "\nInstalling all now...")
    except Exception:
        pass

    ok = True
    for pkg in to_install:
        if not attempt_install_pip(pkg, message):
            ok = False
    return ok

def attempt_install_pip(package_name: str, message) -> bool:
    if not package_name:
        return False
    try:
        safe_reply(message, f"🐍 Installing {md_code(package_name)} ...")
        cmd = [sys.executable, "-m", "pip", "install",
               "--only-binary=:all:", "--no-cache-dir",
               "--disable-pip-version-check", package_name]
        logger.info("pip install: %s", " ".join(cmd))
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=False,
            encoding="utf-8", errors="replace",
            env=_pkg_env(),
        )
        if result.returncode == 0:
            safe_reply(message, f"✅ Installed {md_code(package_name)}")
            return True
        err = (result.stderr or result.stdout or "unknown error")[:3500]
        safe_reply(message,
            f"❌ Failed to install {md_code(package_name)}.\n<pre>{esc(err)}</pre>")
        return False
    except Exception as e:
        logger.error("pip install error: %s", e, exc_info=True)
        safe_reply(message, f"❌ Error installing {md_code(package_name)}: {esc(e)}")
        return False

def attempt_install_npm(module_name: str, user_folder: str, message) -> bool:
    try:
        safe_reply(message, f"🟠 Installing Node package {md_code(module_name)} ...")
        cmd = ["npm", "install", "--no-audit", "--no-fund", module_name]
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=False,
            cwd=user_folder, encoding="utf-8", errors="replace",
            env=_pkg_env(),
        )
        if result.returncode == 0:
            safe_reply(message, f"✅ Installed {md_code(module_name)}")
            return True
        err = (result.stderr or result.stdout or "unknown")[:3500]
        safe_reply(message, f"❌ npm install failed:\n<pre>{esc(err)}</pre>")
        return False
    except FileNotFoundError:
        safe_reply(message, "❌ 'npm' not found.")
        return False
    except Exception as e:
        logger.error("npm install error: %s", e, exc_info=True)
        safe_reply(message, f"❌ Error: {esc(e)}")
        return False

# ─────────────────────────────────────────────────────────────────
# PROCESS MANAGEMENT
# ─────────────────────────────────────────────────────────────────
def _script_key(owner: int, file_name: str) -> str:
    return f"{owner}_{file_name}"

def is_bot_running(owner: int, file_name: str) -> bool:
    key = _script_key(owner, file_name)
    with _lock_scripts:
        info = bot_scripts.get(key)
    if not info or not info.get("process"):
        return False
    try:
        popen_obj = info["process"]
        proc = psutil.Process(popen_obj.pid)
        running = proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE
        if not running:
            _cleanup_dead(key, info)
        return running
    except psutil.NoSuchProcess:
        _cleanup_dead(key, info)
        return False
    except Exception as e:
        logger.error("Process status check failed %s: %s", key, e)
        return False

def _cleanup_dead(key: str, info: dict) -> None:
    proc = info.get("process")
    if proc:
        try: proc.kill()
        except Exception: pass
        try: proc.wait(timeout=1)
        except Exception: pass
    lf = info.get("log_file")
    if lf and hasattr(lf, "close") and not lf.closed:
        try: lf.close()
        except Exception: pass
    with _lock_scripts:
        bot_scripts.pop(key, None)

def kill_process_tree(info: dict) -> None:
    key = info.get("script_key", "?")
    lf = info.get("log_file")
    if lf and hasattr(lf, "close") and not lf.closed:
        try: lf.close()
        except Exception: pass
    proc = info.get("process")
    if not proc or not getattr(proc, "pid", None):
        return
    try:
        parent = psutil.Process(proc.pid)
        children = parent.children(recursive=True)
        for c in children:
            try: c.terminate()
            except Exception: pass
        _, alive = psutil.wait_procs(children, timeout=1)
        for p in alive:
            try: p.kill()
            except Exception: pass
        try:
            parent.terminate()
            try: parent.wait(timeout=1)
            except psutil.TimeoutExpired:
                parent.kill()
        except psutil.NoSuchProcess:
            pass
        except Exception:
            try: parent.kill()
            except Exception: pass
    except psutil.NoSuchProcess:
        pass
    except Exception as e:
        logger.error("kill_process_tree %s: %s", key, e, exc_info=True)

def _log_trimmer_loop():
    while True:
        try:
            time.sleep(180)
        except Exception:
            pass

# ─────────────────────────────────────────────────────────────────
# SCRIPT RUNNER
# ─────────────────────────────────────────────────────────────────
def _read_log_tail(log_path: str, n: int) -> str:
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
        return data[-n:]
    except Exception:
        return ""

# [FIXED: background watcher — if a hosted bot dies later, clean up + notify]
def _watch_process(key: str, log_path: str) -> None:
    """Poll the process every 15s; if it dies, remove from bot_scripts and
    notify the owner so the panel doesn't keep showing 'Running'."""
    time.sleep(15)
    while True:
        time.sleep(15)
        with _lock_scripts:
            info = bot_scripts.get(key)
        if not info:
            return
        proc = info.get("process")
        if proc is None:
            return
        try:
            code = proc.poll()
        except Exception:
            return
        if code is None:
            continue  # still alive
        # Died — clean up
        owner = info.get("script_owner_id")
        fname = info.get("file_name")
        lf = info.get("log_file")
        if lf and hasattr(lf, "close") and not lf.closed:
            try: lf.close()
            except Exception: pass
        with _lock_scripts:
            bot_scripts.pop(key, None)
        try:
            set_autostart(owner, fname, False)
        except Exception:
            pass
        tail = _read_log_tail(log_path, 800)
        try:
            safe_send(owner,
                f"⚠️ Hosted bot {md_code(fname)} stopped (exit {code}).\n"
                f"<pre>{esc(tail or '(no output)')}</pre>")
        except Exception:
            pass
        return

def _run_subprocess_and_track(kind: str, script_path: str, owner: int,
                              user_folder: str, file_name: str, message):
    key = _script_key(owner, file_name)
    _launch_stamp[key] = time.time()
    log_path = _log_path_for(user_folder, file_name)

    with _lock_scripts:
        old = bot_scripts.get(key)
    if old and is_bot_running(owner, file_name):
        logger.warning("%s already running - stopping old copy.", key)
        kill_process_tree(old)
        with _lock_scripts:
            bot_scripts.pop(key, None)
        time.sleep(1)

    try:
        log_file = open(log_path, "a", encoding="utf-8", errors="replace")
    except Exception as e:
        safe_reply(message, f"❌ Failed to open log file: {esc(e)}")
        return

    startupinfo = None
    creationflags = 0
    if os.name == "nt":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE

    cmd = [sys.executable, script_path] if kind == "py" else ["node", script_path]

    try:
        process = subprocess.Popen(
            cmd, cwd=user_folder,
            stdout=log_file, stderr=log_file, stdin=subprocess.PIPE,
            startupinfo=startupinfo, creationflags=creationflags,
            text=True, encoding="utf-8", errors="replace",
            env=_child_env(),
            preexec_fn=_preexec_limits if os.name != "nt" else None,
        )
    except FileNotFoundError:
        safe_reply(message, f"❌ Interpreter not found for {kind}.")
        try: log_file.close()
        except Exception: pass
        return
    except Exception as e:
        safe_reply(message, f"❌ Failed to start: {esc(e)}")
        try: log_file.close()
        except Exception: pass
        return

    with _lock_scripts:
        bot_scripts[key] = {
            "process": process, "log_file": log_file, "file_name": file_name,
            "chat_id": message.chat.id, "script_owner_id": owner,
            "start_time": datetime.now(), "user_folder": user_folder,
            "type": kind, "script_key": key,
        }
    set_autostart(owner, file_name, True)

    # [FIXED: spawn watcher so later deaths clean up + notify]
    threading.Thread(target=_watch_process, args=(key, log_path), daemon=True).start()

    # [FIXED: longer health check window — 8s instead of 4s]
    time.sleep(8)
    exited = process.poll() is not None
    log_tail_check = _read_log_tail(log_path, 3000) if not exited else ""
    fatal_marker = (
        "can't start new thread" in log_tail_check
        or "RLIMIT_NPROC" in log_tail_check
    )
    if exited or fatal_marker:
        code = process.poll() if exited else "(killed)"
        if not exited:
            try:
                kill_process_tree({
                    "process": process, "log_file": log_file, "script_key": key,
                })
            except Exception:
                pass
        try: log_file.close()
        except Exception: pass
        with _lock_scripts:
            bot_scripts.pop(key, None)
        set_autostart(owner, file_name, False)
        tail = _read_log_tail(log_path, 1500)
        safe_reply(message,
            f"❌ {md_code(file_name)} failed to start (code {code}).\n"
            f"<pre>{esc(tail or '(empty)')}</pre>")
        return

    safe_reply(message, f"✅ {kind.upper()} script {md_code(file_name)} started!\n🆔 PID: {process.pid}")

def run_script(script_path: str, owner: int, user_folder: str, file_name: str, message, attempt: int = 1):
    if attempt > 4:
        safe_reply(message, f"❌ Failed to run {md_code(file_name)} after 4 attempts.")
        return
    if not os.path.exists(script_path):
        safe_reply(message, f"❌ Script {md_code(file_name)} not found.")
        remove_user_file_db(owner, file_name)
        return

    if attempt == 1:
        preinstall_missing_packages(script_path, message)

        try:
            check_proc = subprocess.Popen(
                [sys.executable, script_path],
                cwd=user_folder,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace",
                env=_child_env(),
                preexec_fn=_preexec_limits if os.name != "nt" else None,
            )
            try:
                _, stderr = check_proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                check_proc.kill()
                check_proc.communicate()
                stderr = ""
                check_proc.returncode = 0
            rc = check_proc.returncode
            if rc != 0 and stderr:
                m = re.search(r"ModuleNotFoundError: No module named '([^']+)'", stderr)
                if m:
                    mod = m.group(1).strip()
                    pkg = _pip_package_for(mod) or mod
                    if attempt_install_pip(pkg, message):
                        safe_reply(message, f"🔄 Retrying {md_code(file_name)}...")
                        time.sleep(2)
                        threading.Thread(
                            target=run_script,
                            args=(script_path, owner, user_folder, file_name, message, attempt + 1),
                            daemon=True,
                        ).start()
                        return
                    safe_reply(message, f"❌ Install failed for {md_code(mod)}")
                    return
                safe_reply(message, f"❌ Pre-check error:\n<pre>{esc(stderr[:500])}</pre>")
                return
        except Exception as e:
            logger.warning("Pre-check error: %s", e)

    _run_subprocess_and_track("py", script_path, owner, user_folder, file_name, message)

def run_js_script(script_path: str, owner: int, user_folder: str, file_name: str, message, attempt: int = 1):
    if attempt > 3:
        safe_reply(message, f"❌ Failed to run {md_code(file_name)} after 3 attempts.")
        return
    if not os.path.exists(script_path):
        safe_reply(message, f"❌ Script {md_code(file_name)} not found.")
        remove_user_file_db(owner, file_name)
        return

    if attempt == 1:
        try:
            check_proc = subprocess.Popen(
                ["node", script_path], cwd=user_folder,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace",
                env=_child_env(),
                preexec_fn=_preexec_limits if os.name != "nt" else None,
            )
            try:
                _, stderr = check_proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                check_proc.kill()
                check_proc.communicate()
                stderr = ""
                check_proc.returncode = 0
            rc = check_proc.returncode
            if rc != 0 and stderr:
                m = re.search(r"Cannot find module '([^']+)'", stderr)
                if m:
                    mod = m.group(1).strip()
                    if not mod.startswith((".", "/")):
                        if attempt_install_npm(mod, user_folder, message):
                            safe_reply(message, f"🔄 Retrying {md_code(file_name)}...")
                            time.sleep(2)
                            threading.Thread(
                                target=run_js_script,
                                args=(script_path, owner, user_folder, file_name, message, attempt + 1),
                                daemon=True,
                            ).start()
                            return
                        safe_reply(message, f"❌ Failed to install {md_code(mod)}")
                        return
                safe_reply(message, f"❌ JS error:\n<pre>{esc(stderr[:500])}</pre>")
                return
        except FileNotFoundError:
            safe_reply(message, "❌ Node.js not installed.")
            return
        except Exception as e:
            logger.warning("JS pre-check error: %s", e)

    _run_subprocess_and_track("js", script_path, owner, user_folder, file_name, message)

# ─────────────────────────────────────────────────────────────────
# DATABASE OPS
# ─────────────────────────────────────────────────────────────────
def save_user_file(user_id: int, file_name: str, file_type: str = "py") -> None:
    with DB_LOCK:
        conn = _db_conn()
        try:
            c = conn.cursor()
            c.execute("INSERT OR REPLACE INTO user_files (user_id, file_name, file_type) VALUES (?,?,?)",
                      (user_id, file_name, file_type))
            conn.commit()
            with _lock_files:
                bucket = user_files.setdefault(user_id, [])
                bucket[:] = [(fn, ft) for fn, ft in bucket if fn != file_name]
                bucket.append((file_name, file_type))
            mark_data_dirty()
        except Exception as e:
            logger.error("save_user_file error: %s", e, exc_info=True)

def remove_user_file_db(user_id: int, file_name: str) -> None:
    set_autostart(user_id, file_name, False)
    with DB_LOCK:
        conn = _db_conn()
        try:
            c = conn.cursor()
            c.execute("DELETE FROM user_files WHERE user_id=? AND file_name=?", (user_id, file_name))
            conn.commit()
            with _lock_files:
                if user_id in user_files:
                    user_files[user_id] = [f for f in user_files[user_id] if f[0] != file_name]
                    if not user_files[user_id]:
                        del user_files[user_id]
            mark_data_dirty()
        except Exception as e:
            logger.error("remove_user_file_db error: %s", e, exc_info=True)

def add_active_user(user_id: int) -> None:
    active_users.add(user_id)
    with DB_LOCK:
        conn = _db_conn()
        try:
            c = conn.cursor()
            c.execute("INSERT OR IGNORE INTO active_users (user_id) VALUES (?)", (user_id,))
            conn.commit()
            mark_data_dirty()
        except Exception as e:
            logger.error("add_active_user: %s", e)

def save_subscription(user_id: int, expiry: datetime) -> None:
    with DB_LOCK:
        conn = _db_conn()
        try:
            c = conn.cursor()
            c.execute("INSERT OR REPLACE INTO subscriptions (user_id, expiry) VALUES (?,?)",
                      (user_id, expiry.isoformat()))
            conn.commit()
            user_subscriptions[user_id] = {"expiry": expiry}
            mark_data_dirty()
        except Exception as e:
            logger.error("save_subscription: %s", e)

def remove_subscription_db(user_id: int) -> None:
    with DB_LOCK:
        conn = _db_conn()
        try:
            c = conn.cursor()
            c.execute("DELETE FROM subscriptions WHERE user_id=?", (user_id,))
            conn.commit()
            user_subscriptions.pop(user_id, None)
            mark_data_dirty()
        except Exception as e:
            logger.error("remove_subscription_db: %s", e)

def add_admin_db(admin_id: int) -> None:
    with DB_LOCK:
        conn = _db_conn()
        try:
            c = conn.cursor()
            c.execute("INSERT OR IGNORE INTO admins (user_id) VALUES (?)", (admin_id,))
            conn.commit()
            with _lock_state:
                admin_ids.add(admin_id)
            mark_data_dirty()
        except Exception as e:
            logger.error("add_admin_db: %s", e)

def remove_admin_db(admin_id: int) -> bool:
    if admin_id == OWNER_ID:
        return False
    with DB_LOCK:
        conn = _db_conn()
        try:
            c = conn.cursor()
            c.execute("DELETE FROM admins WHERE user_id=?", (admin_id,))
            conn.commit()
            removed = c.rowcount > 0
            with _lock_state:
                admin_ids.discard(admin_id)
            if removed:
                mark_data_dirty()
            return removed
        except Exception as e:
            logger.error("remove_admin_db: %s", e)
            return False

def add_allowed_user_db(user_id: int) -> None:
    with DB_LOCK:
        conn = _db_conn()
        try:
            c = conn.cursor()
            c.execute("INSERT OR IGNORE INTO allowed_users (user_id) VALUES (?)", (user_id,))
            conn.commit()
            with _lock_state:
                allowed_users_ids.add(user_id)
            mark_data_dirty()
        except Exception as e:
            logger.error("add_allowed_user_db: %s", e)

def remove_allowed_user_db(user_id: int) -> bool:
    if user_id == OWNER_ID or is_admin(user_id):
        return False
    with DB_LOCK:
        conn = _db_conn()
        try:
            c = conn.cursor()
            c.execute("DELETE FROM allowed_users WHERE user_id=?", (user_id,))
            conn.commit()
            removed = c.rowcount > 0
            with _lock_state:
                allowed_users_ids.discard(user_id)
            if removed:
                mark_data_dirty()
            return removed
        except Exception as e:
            logger.error("remove_allowed_user_db: %s", e)
            return False

def _rename_file_db(user_id: int, old_fn: str, new_fn: str, file_type: str) -> bool:
    if old_fn == new_fn:
        return True
    with DB_LOCK:
        conn = _db_conn()
        try:
            c = conn.cursor()
            c.execute("DELETE FROM user_files WHERE user_id=? AND file_name=?",
                      (user_id, new_fn))
            c.execute(
                "UPDATE user_files SET file_name=? WHERE user_id=? AND file_name=?",
                (new_fn, user_id, old_fn),
            )
            conn.commit()
            updated = c.rowcount > 0
            with _lock_files:
                if user_id in user_files:
                    user_files[user_id] = [
                        (new_fn, ft) if fn == old_fn else (fn, ft)
                        for fn, ft in user_files[user_id]
                    ]
            if updated:
                mark_data_dirty()
            return updated
        except Exception as e:
            logger.error("_rename_file_db: %s", e, exc_info=True)
            return False

def _rename_autostart(user_id: int, old_fn: str, new_fn: str) -> None:
    if old_fn == new_fn:
        return
    try:
        with _autostart_lock:
            items = _read_autostart()
            changed = False
            new_items: list[tuple[int, str]] = []
            for u, fn in items:
                if u == user_id and fn == old_fn:
                    new_items.append((u, new_fn))
                    changed = True
                else:
                    new_items.append((u, fn))
            if changed:
                atomic_write_json(AUTOSTART_PATH, new_items)
                mark_data_dirty()
    except Exception as e:
        logger.error("_rename_autostart: %s", e)

# ─────────────────────────────────────────────────────────────────
# AUTOSTART
# ─────────────────────────────────────────────────────────────────
_autostart_lock = threading.RLock()

def _read_autostart() -> list[tuple[int, str]]:
    try:
        with open(AUTOSTART_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        out: list[tuple[int, str]] = []
        for item in data:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                try:
                    out.append((int(item[0]), str(item[1])))
                except Exception:
                    continue
        return out
    except FileNotFoundError:
        return []
    except Exception as e:
        logger.error("autostart read error: %s", e)
        return []

def set_autostart(user_id: int, file_name: str, on: bool) -> None:
    try:
        with _autostart_lock:
            items = [x for x in _read_autostart() if not (x[0] == user_id and x[1] == file_name)]
            if on:
                items.append((user_id, file_name))
            atomic_write_json(AUTOSTART_PATH, items)
        mark_data_dirty()
    except Exception as e:
        logger.error("set_autostart: %s", e)

def autostart_all_scripts():
    time.sleep(8)
    items = _read_autostart()
    logger.info("♻️ Autostart: %d script(s)", len(items))
    for user_id, file_name in items:
        try:
            with _lock_files:
                fi = next((f for f in user_files.get(user_id, []) if f[0] == file_name), None)
            file_path = os.path.join(get_user_folder(user_id), file_name)
            if not fi or not os.path.exists(file_path):
                logger.warning("Autostart skip (missing): %s/%s", user_id, file_name)
                continue
            if is_bot_running(user_id, file_name):
                continue
            try:
                msg = safe_send(user_id, f"♻️ Server restarted - auto-starting {md_code(file_name)}...")
            except Exception:
                msg = safe_send(ADMIN_ID, f"♻️ Autostart {md_code(file_name)} (user {user_id})")
            runner = run_js_script if fi[1] == "js" else run_script
            threading.Thread(
                target=runner,
                args=(file_path, user_id, get_user_folder(user_id), file_name, msg),
                daemon=True,
            ).start()
            time.sleep(3)
        except Exception as e:
            logger.error("Autostart failed %s/%s: %s", user_id, file_name, e, exc_info=True)

# ─────────────────────────────────────────────────────────────────
# MENUS
# ─────────────────────────────────────────────────────────────────
COMMAND_LAYOUT_USER = [
    [("📢 Updates Channel", "primary")],
    [("📤 Upload File", "success"), ("📂 Check Files", "primary")],
    [("⚡ Bot Speed", "primary"), ("📊 Statistics", "primary")],
    [("📤 Send Command", "primary"), ("📞 Contact Owner", "primary")],
]
COMMAND_LAYOUT_ADMIN = [
    [("📢 Updates Channel", "primary")],
    [("📤 Upload File", "success"), ("📂 Check Files", "primary")],
    [("⚡ Bot Speed", "primary"), ("📊 Statistics", "primary")],
    [("💳 Subscriptions", "primary"), ("📢 Broadcast", "primary")],
    [("🔒 Lock Bot", "danger"), ("🟢 Running All Code", "success")],
    [("📤 Send Command", "primary"), ("👑 Admin Panel", "primary")],
    [("📞 Contact Owner", "primary")],
]

def create_reply_keyboard_main_menu(user_id: int):
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    layout = COMMAND_LAYOUT_ADMIN if is_admin(user_id) else COMMAND_LAYOUT_USER
    for row in layout:
        markup.add(*[kbtn(t, s) for t, s in row])
    return markup

def create_main_menu_inline(user_id: int):
    with _lock_state:
        locked = bot_locked
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(cbtn("📢 Updates Channel", style="primary", url=UPDATE_CHANNEL))
    markup.add(cbtn("📤 Upload File", style="success", callback_data="upload"),
               cbtn("📂 Check Files", style="primary", callback_data="check_files"))
    markup.add(cbtn("⚡ Bot Speed", style="primary", callback_data="speed"),
               cbtn("📊 Statistics", style="primary", callback_data="stats"))
    markup.add(cbtn("📤 Send Command", style="primary", callback_data="send_command"))
    if is_admin(user_id):
        markup.add(cbtn("💳 Subscriptions", style="primary", callback_data="subscription"),
                   cbtn("📢 Broadcast", style="primary", callback_data="broadcast"))
        markup.add(cbtn("🔓 Unlock Bot" if locked else "🔒 Lock Bot",
                        style="success" if locked else "danger",
                        callback_data="unlock_bot" if locked else "lock_bot"),
                   cbtn("🟢 Run All User Scripts", style="success", callback_data="run_all_scripts"))
        markup.add(cbtn("👑 Admin Panel", style="primary", callback_data="admin_panel"))
    markup.add(cbtn("📞 Contact Owner", style="primary",
                    url=f"https://t.me/{YOUR_USERNAME.replace('@', '')}"))
    return markup

def create_control_buttons(owner_id: int, file_name: str, running: bool):
    markup = types.InlineKeyboardMarkup(row_width=2)
    uname = get_cached_bot_username(owner_id, file_name)
    if uname:
        markup.row(cbtn(f"🔗 Open @{uname}", style="primary", url=f"https://t.me/{uname}"))
    if running:
        markup.row(
            cbtn("🔴 Stop", style="danger", callback_data=f"stop_{owner_id}_{file_name}"),
            cbtn("🔄 Restart", style="primary", callback_data=f"restart_{owner_id}_{file_name}"),
        )
        markup.row(
            cbtn("🗑️ Delete", style="danger", callback_data=f"delete_{owner_id}_{file_name}"),
            cbtn("📜 Logs", style="primary", callback_data=f"logs_{owner_id}_{file_name}"),
        )
        markup.row(
            cbtn("📤 Send Command", style="primary",
                 callback_data=f"cmdsend_{owner_id}_{file_name}"),
            cbtn("🔄 Change File", style="primary",
                 callback_data=f"cf_{owner_id}_{file_name}"),
        )
    else:
        markup.row(
            cbtn("🟢 Start", style="success", callback_data=f"start_{owner_id}_{file_name}"),
            cbtn("🗑️ Delete", style="danger", callback_data=f"delete_{owner_id}_{file_name}"),
        )
        markup.row(
            cbtn("📜 View Logs", style="primary",
                 callback_data=f"logs_{owner_id}_{file_name}"),
            cbtn("🔄 Change File", style="primary",
                 callback_data=f"cf_{owner_id}_{file_name}"),
        )
    markup.add(cbtn("🔙 Back to Files", style="primary", callback_data="check_files"))
    return markup

def create_admin_panel():
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.row(cbtn("➕ Add Admin", style="success", callback_data="add_admin"),
               cbtn("➖ Remove Admin", style="danger", callback_data="remove_admin"))
    markup.row(cbtn("📋 List Admins", style="primary", callback_data="list_admins"))
    markup.row(cbtn("🔙 Back to Main", style="primary", callback_data="back_to_main"))
    return markup

def create_subscription_menu():
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.row(cbtn("➕ Add Subscription", style="success", callback_data="add_subscription"),
               cbtn("➖ Remove Subscription", style="danger", callback_data="remove_subscription"))
    markup.row(cbtn("🔍 Check Subscription", style="primary", callback_data="check_subscription"))
    markup.row(cbtn("🔙 Back to Main", style="primary", callback_data="back_to_main"))
    return markup

def create_send_command_menu():
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.row(cbtn("📝 Send to Process", style="success", callback_data="send_to_process"),
               cbtn("🔍 View All Logs", style="primary", callback_data="view_all_logs"))
    markup.row(cbtn("🔙 Back to Main", style="primary", callback_data="back_to_main"))
    return markup

# ─────────────────────────────────────────────────────────────────
# ZIP HANDLING
# ─────────────────────────────────────────────────────────────────
def handle_zip_file(content: bytes, zip_name: str, message) -> None:
    user_id = message.from_user.id
    user_folder = get_user_folder(user_id)
    temp_dir = None

    if user_id != OWNER_ID:
        ok, reason = scan_file_for_malware(content, zip_name, user_id)
        if not ok:
            safe_reply(message, f"🚨 Security Alert: {esc(reason)}")
            return

    try:
        temp_dir = tempfile.mkdtemp(prefix=f"user_{user_id}_zip_")
        zip_path = os.path.join(temp_dir, zip_name)
        with open(zip_path, "wb") as f:
            f.write(content)

        with zipfile.ZipFile(zip_path, "r") as zf:
            if user_id != OWNER_ID:
                total_uncompressed = 0
                for member in zf.infolist():
                    ml = member.filename.lower()
                    if any(ml.endswith(ext) for ext in _SUSPICIOUS_EXT):
                        safe_reply(message,
                            f"🚨 ZIP contains suspicious file: {esc(member.filename)}")
                        return
                    member_path = os.path.abspath(os.path.join(temp_dir, member.filename))
                    if not member_path.startswith(os.path.abspath(temp_dir)):
                        raise zipfile.BadZipFile(f"unsafe path: {member.filename}")
                    is_symlink = stat.S_ISLNK((member.external_attr >> 16) & 0xFFFF)
                    if is_symlink:
                        safe_reply(message,
                            f"🚨 ZIP contains symlink ({esc(member.filename)}). Not allowed.")
                        return
                    total_uncompressed += member.file_size
                    if total_uncompressed > ZIP_MAX_UNCOMPRESSED_BYTES:
                        safe_reply(message,
                            f"🚨 ZIP too large uncompressed "
                            f"(> {ZIP_MAX_UNCOMPRESSED_BYTES // (1024*1024)} MB).")
                        return
            zf.extractall(temp_dir)

        target_dir = temp_dir
        if not any(f.endswith((".py", ".js")) for f in os.listdir(target_dir)):
            for root, dirs, files in os.walk(temp_dir):
                dirs[:] = [d for d in dirs if not d.startswith((".", "__"))]
                if any(f.endswith((".py", ".js")) for f in files):
                    target_dir = root
                    break
        if target_dir != temp_dir:
            for item in os.listdir(target_dir):
                s = os.path.join(target_dir, item)
                d = os.path.join(temp_dir, item)
                if os.path.exists(d):
                    if os.path.isdir(d):
                        shutil.rmtree(d, ignore_errors=True)
                    else:
                        os.remove(d)
                shutil.move(s, d)

        items = os.listdir(temp_dir)
        py_files = [f for f in items if f.endswith(".py")]
        js_files = [f for f in items if f.endswith(".js")]
        req_file = "requirements.txt" if "requirements.txt" in items else None
        pkg_json = "package.json" if "package.json" in items else None

        if req_file:
            safe_reply(message, "🔄 Installing Python deps from requirements.txt...")
            try:
                r = subprocess.run(
                    [sys.executable, "-m", "pip", "install",
                     "--only-binary=:all:", "--no-cache-dir",
                     "-r", os.path.join(temp_dir, req_file)],
                    capture_output=True, text=True, check=True,
                    encoding="utf-8", errors="ignore",
                    env=_pkg_env(),
                )
                safe_reply(message, "✅ Python deps installed.")
            except subprocess.CalledProcessError as e:
                safe_reply(message,
                    f"❌ Failed to install requirements:\n<pre>{esc((e.stderr or e.stdout or '')[:3500])}</pre>")
                return

        if pkg_json:
            safe_reply(message, "🔄 Installing Node deps...")
            try:
                r = subprocess.run(
                    ["npm", "install", "--no-audit", "--no-fund"],
                    capture_output=True, text=True, check=True,
                    cwd=temp_dir, encoding="utf-8", errors="ignore",
                    env=_pkg_env(),
                )
                safe_reply(message, "✅ Node deps installed.")
            except FileNotFoundError:
                safe_reply(message, "❌ 'npm' not found.")
                return
            except subprocess.CalledProcessError as e:
                safe_reply(message,
                    f"❌ npm install failed:\n<pre>{esc((e.stderr or e.stdout or '')[:3500])}</pre>")
                return

        main_script = None
        ftype = None
        for p in ("main.py", "bot.py", "app.py"):
            if p in py_files:
                main_script, ftype = p, "py"
                break
        if not main_script:
            for p in ("index.js", "main.js", "bot.js", "app.js"):
                if p in js_files:
                    main_script, ftype = p, "js"
                    break
        if not main_script:
            if py_files:
                main_script, ftype = py_files[0], "py"
            elif js_files:
                main_script, ftype = js_files[0], "js"
        if not main_script:
            safe_reply(message, "❌ No .py or .js script found in archive.")
            return

        main_ext = os.path.splitext(main_script)[1]
        try:
            with open(os.path.join(temp_dir, main_script), "rb") as f:
                src = f.read()
        except Exception:
            src = b""
        friendly, renamed = _friendly_file_name(user_id, main_script, main_ext, src)
        if friendly != main_script:
            try:
                os.rename(os.path.join(temp_dir, main_script),
                          os.path.join(temp_dir, friendly))
                main_script = friendly
                if renamed:
                    safe_reply(message,
                        f"ℹ️ Token se bot username mila — file ko {md_code(main_script)} "
                        f"naam se save kar rahe hain.")
                else:
                    safe_reply(message,
                        f"ℹ️ Naam already exist karta tha — naya upload "
                        f"{md_code(main_script)} ke naam se save ho raha hai.")
            except Exception as e:
                logger.error("Rename failed: %s", e)

        for name in os.listdir(temp_dir):
            if name == zip_name:
                continue
            s = os.path.join(temp_dir, name)
            d = os.path.join(user_folder, name)
            if os.path.isdir(d):
                shutil.rmtree(d, ignore_errors=True)
            elif os.path.exists(d):
                os.remove(d)
            shutil.move(s, d)

        save_user_file(user_id, main_script, ftype)
        path = os.path.join(user_folder, main_script)
        safe_reply(message, f"✅ Extracted. Starting {md_code(main_script)} ...")
        runner = run_script if ftype == "py" else run_js_script
        threading.Thread(target=runner,
                         args=(path, user_id, user_folder, main_script, message),
                         daemon=True).start()
    except zipfile.BadZipFile as e:
        safe_reply(message, f"❌ Invalid ZIP: {esc(e)}")
    except Exception as e:
        logger.error("zip handling error: %s", e, exc_info=True)
        safe_reply(message, f"❌ Error processing zip: {esc(e)}")
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)

# ─────────────────────────────────────────────────────────────────
# LOGIC FUNCTIONS
# ─────────────────────────────────────────────────────────────────
BUTTON_TEXT_TO_LOGIC: dict[str, Callable] = {}

def _logic_send_welcome(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    uname = message.from_user.first_name or "User"
    uhandle = getattr(message.from_user, "username", None)

    if not has_access(user_id):
        try:
            safe_send(
                chat_id,
                "🚫 <b>This is a private bot.</b>\n\n"
                "You do not have access to use it.\n"
                f"Contact Owner: {esc(YOUR_USERNAME)}"
            )
        except Exception:
            pass
        return

    if _block_banned(message):
        return
    if not is_admin(user_id) and not is_user_joined_all(user_id):
        send_force_join_msg(chat_id)
        return
    with _lock_state:
        locked = bot_locked
    if locked and not is_admin(user_id):
        safe_send(chat_id, "⚠️ Bot locked by admin. Try later.")
        return

    user_bio = "Could not fetch bio"
    photo_id = None
    try:
        user_bio = bot.get_chat(user_id).bio or "No bio"
    except Exception:
        pass
    try:
        p = bot.get_user_profile_photos(user_id, limit=1)
        if p.photos:
            photo_id = p.photos[0][-1].file_id
    except Exception:
        pass

    if user_id not in active_users:
        add_active_user(user_id)
        try:
            note = (
                f"New user joined!\n"
                f"Name: {esc(uname)}\n"
                f"User: @{esc(uhandle) if uhandle else 'N/A'}\n"
                f"User ID: {md_code(user_id)}\n"
                f"Bio: {esc(user_bio)}"
            )
            safe_send(OWNER_ID, note)
            if photo_id:
                try:
                    bot.send_photo(OWNER_ID, photo_id,
                                   caption=f"New user photo — ID {user_id}")
                except Exception:
                    pass
        except Exception as e:
            logger.error("Notify owner failed: %s", e)

    fl = get_user_file_limit(user_id)
    cf = get_user_file_count(user_id)
    limit_str = "Unlimited" if fl == float("inf") else str(fl)
    expiry_info = ""
    if user_id == OWNER_ID:
        status = "Owner"
    elif is_admin(user_id):
        status = "Admin"
    elif user_id in user_subscriptions:
        exp = user_subscriptions[user_id].get("expiry")
        if exp and exp > datetime.now():
            status = "Premium"
            expiry_info = f"\nExpires in: {(exp - datetime.now()).days} days"
        else:
            status = "Free (expired)"
            remove_subscription_db(user_id)
    else:
        status = "Free User"

    txt = (
        f"Welcome, {esc(uname)}!\n\n"
        f"Your User ID: {md_code(user_id)}\n"
        f"Username: {md_code('@' + uhandle if uhandle else 'Not set')}\n"
        f"Status: {status}{expiry_info}\n"
        f"Files: {cf} / {limit_str}\n\n"
        f"Host & run .py or .js scripts (single file or .zip).\n"
        f"Use buttons or type commands below."
    )
    kb = create_reply_keyboard_main_menu(user_id)
    try:
        if photo_id:
            bot.send_photo(chat_id, photo_id)
        safe_send(chat_id, txt, reply_markup=kb)
    except Exception as e:
        logger.error("welcome send error: %s", e)
        safe_send(chat_id, txt, reply_markup=kb)

def _logic_updates_channel(message):
    if _guard(message):
        return
    m = types.InlineKeyboardMarkup()
    m.add(cbtn("📢 Updates Channel", style="primary", url=UPDATE_CHANNEL))
    safe_reply(message, "Visit our Updates Channel:", reply_markup=m)

def _logic_upload_file(message):
    user_id = message.from_user.id
    if _guard(message):
        return
    fl = get_user_file_limit(user_id)
    cf = get_user_file_count(user_id)
    if cf >= fl:
        ls = "Unlimited" if fl == float("inf") else str(fl)
        safe_reply(message, f"⚠️ File limit ({cf}/{ls}) reached.")
        return
    safe_reply(message, "📤 Send your .py, .js, or .zip file.")

def _logic_check_files(message):
    user_id = message.from_user.id
    if _guard(message):
        return
    with _lock_files:
        files = list(user_files.get(user_id, []))
    if not files:
        safe_reply(message, "📂 Your files:\n\n(No files uploaded yet)")
        return
    m = types.InlineKeyboardMarkup(row_width=1)
    for fn, ft in sorted(files):
        run = is_bot_running(user_id, fn)
        icon = "🟢 Running" if run else "🔴 Stopped"
        m.add(cbtn(f"{fn} ({ft}) - {icon}", style="primary",
                   callback_data=f"file_{user_id}_{fn}"))
    safe_reply(message, "📂 Your files:\nClick to manage.", reply_markup=m)

def _logic_bot_speed(message):
    if _guard(message):
        return
    t0 = time.time()
    wait = bot.reply_to(message, "🏃 Testing speed...")
    try:
        bot.send_chat_action(message.chat.id, "typing")
        rt = round((time.time() - t0) * 1000, 2)
        with _lock_state:
            locked = bot_locked
        st = "🔓 Unlocked" if not locked else "🔒 Locked"
        if message.from_user.id == OWNER_ID:
            lvl = "Owner"
        elif is_admin(message.from_user.id):
            lvl = "Admin"
        else:
            lvl = "Free User"
        bot.edit_message_text(
            f"Bot Speed & Status:\n\n"
            f"API Response Time: {rt} ms\n"
            f"Bot Status: {st}\n"
            f"Your Level: {lvl}",
            message.chat.id, wait.message_id,
        )
    except Exception as e:
        logger.error("speed test error: %s", e)
        try:
            bot.edit_message_text("❌ Error during speed test.",
                                  message.chat.id, wait.message_id)
        except Exception:
            pass

def _logic_contact_owner(message):
    if _guard(message):
        return
    m = types.InlineKeyboardMarkup()
    m.add(cbtn("📞 Contact Owner", style="primary",
               url=f"https://t.me/{YOUR_USERNAME.replace('@', '')}"))
    safe_reply(message, "Click to contact Owner:", reply_markup=m)

def _logic_statistics(message):
    if _guard(message):
        return
    total_users = len(active_users)
    total_files = sum(len(v) for v in user_files.values())
    with _lock_scripts:
        keys = list(bot_scripts.keys())
    running = 0
    mine = 0
    for k in keys:
        try:
            owner_str, _ = k.split("_", 1)
            owner_id = int(owner_str)
        except Exception:
            continue
        with _lock_scripts:
            info = bot_scripts.get(k)
        if info and is_bot_running(owner_id, info["file_name"]):
            running += 1
            if owner_id == message.from_user.id:
                mine += 1
    with _lock_state:
        locked = bot_locked
    base = (
        f"Bot Statistics:\n\n"
        f"Total Users: {total_users}\n"
        f"Total File Records: {total_files}\n"
        f"Active Bots: {running}\n"
    )
    if is_admin(message.from_user.id):
        base += f"Bot: {'Locked' if locked else 'Unlocked'}\n"
    base += f"Your Running Bots: {mine}"
    safe_reply(message, base)

def _logic_send_command(message):
    if _guard(message):
        return
    safe_reply(message, "📤 Send Command Options:", reply_markup=create_send_command_menu())

def _logic_subscriptions_panel(message):
    if not is_admin(message.from_user.id):
        safe_reply(message, "⚠️ Admin only.")
        return
    safe_reply(message, "💳 Subscription Management:",
               reply_markup=create_subscription_menu())

def _logic_broadcast_init(message):
    if not is_admin(message.from_user.id):
        safe_reply(message, "⚠️ Admin only.")
        return
    msg = bot.reply_to(message, "📢 Send message to broadcast.\n/cancel to abort.")
    bot.register_next_step_handler(msg, process_broadcast_message)

def _logic_toggle_lock_bot(message):
    if not is_admin(message.from_user.id):
        safe_reply(message, "⚠️ Admin only.")
        return
    global bot_locked
    with _lock_state:
        bot_locked = not bot_locked
        locked = bot_locked
    logger.warning("Bot %s by %s", "locked" if locked else "unlocked",
                   message.from_user.id)
    safe_reply(message, f"🔒 Bot {'locked' if locked else 'unlocked'}.")

def _logic_admin_panel(message):
    if not is_admin(message.from_user.id):
        safe_reply(message, "⚠️ Admin only.")
        return
    safe_reply(message, "👑 Admin Panel:", reply_markup=create_admin_panel())

def _logic_run_all_scripts(target):
    if isinstance(target, types.Message):
        admin_id = target.from_user.id
        chat_id = target.chat.id
        reply = lambda t, **kw: bot.reply_to(target, t, **kw)
        ctx = target
    elif isinstance(target, types.CallbackQuery):
        admin_id = target.from_user.id
        chat_id = target.message.chat.id
        bot.answer_callback_query(target.id)
        reply = lambda t, **kw: bot.send_message(chat_id, t, **kw)
        ctx = target.message
    else:
        return
    if not is_admin(admin_id):
        reply("⚠️ Admin only.")
        return
    reply("⏳ Starting all user scripts...")
    logger.info("Admin %s triggered run-all", admin_id)
    started = 0
    errors: list[str] = []
    with _lock_files:
        snapshot = {u: list(fs) for u, fs in user_files.items()}
    for owner, files in snapshot.items():
        folder = get_user_folder(owner)
        for fn, ft in files:
            if is_bot_running(owner, fn):
                continue
            path = os.path.join(folder, fn)
            if not os.path.exists(path):
                errors.append(f"{fn} (User {owner}): missing")
                continue
            try:
                runner = run_script if ft == "py" else run_js_script
                threading.Thread(target=runner,
                                 args=(path, owner, folder, fn, ctx),
                                 daemon=True).start()
                started += 1
                time.sleep(0.5)
            except Exception as e:
                errors.append(f"{fn} (User {owner}): {e}")
    msg = f"✅ Queued {started} script(s)."
    if errors:
        msg += f"\n⚠️ {len(errors)} skipped:\n" + "\n".join(errors[:5])
    reply(msg)

BUTTON_TEXT_TO_LOGIC.update({
    "📢 Updates Channel": _logic_updates_channel,
    "📤 Upload File": _logic_upload_file,
    "📂 Check Files": _logic_check_files,
    "⚡ Bot Speed": _logic_bot_speed,
    "📤 Send Command": _logic_send_command,
    "📞 Contact Owner": _logic_contact_owner,
    "📊 Statistics": _logic_statistics,
    "💳 Subscriptions": _logic_subscriptions_panel,
    "📢 Broadcast": _logic_broadcast_init,
    "🔒 Lock Bot": _logic_toggle_lock_bot,
    "🟢 Running All Code": _logic_run_all_scripts,
    "👑 Admin Panel": _logic_admin_panel,
})

# ─────────────────────────────────────────────────────────────────
# SEND COMMAND / LOGS
# ─────────────────────────────────────────────────────────────────
def send_to_process_init(message):
    user_id = message.from_user.id
    with _lock_scripts:
        items = list(bot_scripts.items())
    mine = []
    for key, info in items:
        owner = info["script_owner_id"]
        if (user_id == owner or is_admin(user_id)) and is_bot_running(owner, info["file_name"]):
            mine.append((key, info))
    if not mine:
        safe_reply(message, "❌ No running scripts found.")
        return
    m = types.InlineKeyboardMarkup(row_width=1)
    for key, info in mine:
        label = display_name_for_file(info["script_owner_id"], info["file_name"])
        if is_admin(user_id):
            label = f"{label} (User {info['script_owner_id']})"
        m.add(cbtn(label, style="primary", callback_data=f"sendcmd_select_{key}"))
    m.add(cbtn("🔙 Back", style="primary", callback_data="send_command"))
    safe_reply(message, "📝 Select a running script:", reply_markup=m)

def process_send_command(message, script_key: str):
    user_id = message.from_user.id
    with _lock_scripts:
        info = bot_scripts.get(script_key)
    if not info:
        safe_reply(message, "❌ Script not running.")
        return
    owner = info.get("script_owner_id")
    if not (user_id == owner or is_admin(user_id)):
        safe_reply(message, "⚠️ Permission denied.")
        return
    proc = info["process"]
    label = display_name_for_file(owner, info["file_name"])
    if not proc or proc.poll() is not None:
        safe_reply(message, f"❌ {md_code(label)} not running.")
        return
    text = message.text or ""
    try:
        if proc.stdin and not proc.stdin.closed:
            def _writer():
                try:
                    proc.stdin.write(text + "\n")
                    proc.stdin.flush()
                except Exception as e:
                    logger.warning("stdin write failed: %s", e)
            threading.Thread(target=_writer, daemon=True).start()
            safe_reply(message, f"✅ Sent to {md_code(label)}:\n<pre>{esc(text)}</pre>")
        else:
            safe_reply(message, f"❌ {md_code(label)} stdin closed.")
    except Exception as e:
        logger.error("send command error: %s", e)
        safe_reply(message, f"❌ Error: {esc(e)}")

def view_all_logs(message):
    user_id = message.from_user.id
    folder = get_user_folder(user_id)
    logs: list[tuple[str, int]] = []
    try:
        for fn in os.listdir(folder):
            if fn.endswith(".log"):
                p = os.path.join(folder, fn)
                logs.append((fn, os.path.getsize(p)))
    except Exception:
        pass
    if not logs:
        safe_reply(message, "📜 No log files found.")
        return
    m = types.InlineKeyboardMarkup(row_width=1)
    for fn, size in sorted(logs):
        m.add(cbtn(f"{fn} ({size/1024:.1f} KB)", style="primary",
                   callback_data=f"viewlog_{user_id}_{fn}"))
    m.add(cbtn("🔙 Back", style="primary", callback_data="send_command"))
    safe_reply(message, "📜 Available Log Files:", reply_markup=m)

def send_log_file(message, log_path: str, log_filename: str):
    try:
        size = os.path.getsize(log_path)
        if size > 50 * 1024 * 1024:
            safe_reply(message, f"❌ Log too large ({size/1024/1024:.1f} MB).")
            return
        with open(log_path, "rb") as f:
            bot.send_document(message.chat.id, f, caption=f"📜 {log_filename}")
    except Exception as e:
        logger.error("send_log_file: %s", e)
        safe_reply(message, f"❌ Error: {esc(e)}")

# ─────────────────────────────────────────────────────────────────
# COMMAND HANDLERS
# ─────────────────────────────────────────────────────────────────
@bot.message_handler(commands=["start", "help"])
def cmd_start(message):
    if not _rate_ok(message.from_user.id):
        return
    _logic_send_welcome(message)

@bot.message_handler(commands=["status"])
def cmd_status(message):
    _logic_statistics(message)

@bot.message_handler(commands=["ping"])
def cmd_ping(message):
    t0 = time.time()
    msg = bot.reply_to(message, "Pong!")
    lat = round((time.time() - t0) * 1000, 2)
    bot.edit_message_text(f"Pong! Latency: {lat} ms", message.chat.id, msg.message_id)

@bot.message_handler(commands=["cancel"])
def cmd_cancel(message):
    try:
        bot.clear_step_handler_by_chat_id(message.chat.id)
    except Exception:
        pass
    safe_reply(message, "❌ Cancelled.")

@bot.message_handler(commands=["ac"])
def cmd_ac(message):
    if not is_admin(message.from_user.id):
        safe_reply(message, "⚠️ Admin only.")
        return
    parts = (message.text or "").split()
    if len(parts) != 2:
        safe_reply(message, "Usage: <code>/ac &lt;user_id&gt;</code>")
        return
    try:
        uid = int(parts[1].strip())
    except ValueError:
        safe_reply(message, "⚠️ Invalid user ID.")
        return
    if uid <= 0:
        safe_reply(message, "⚠️ Invalid user ID.")
        return
    if uid == OWNER_ID or is_admin(uid):
        safe_reply(message, f"ℹ️ {md_code(uid)} already has access (Owner/Admin).")
        return
    with _lock_state:
        already = uid in allowed_users_ids
    if already:
        safe_reply(message, f"ℹ️ {md_code(uid)} already has access.")
        return
    add_allowed_user_db(uid)
    safe_reply(message,
        f"✅ Access granted to user {md_code(uid)}.\n"
        f"They can now use the bot as a Free User.")
    try:
        safe_send(uid,
            "✅ Access granted!\n\n"
            "You can now use this bot as a Free User.")
    except Exception:
        pass

@bot.message_handler(commands=["rc"])
def cmd_rc(message):
    if not is_admin(message.from_user.id):
        safe_reply(message, "⚠️ Admin only.")
        return
    parts = (message.text or "").split()
    if len(parts) != 2:
        safe_reply(message, "Usage: <code>/rc &lt;user_id&gt;</code>")
        return
    try:
        uid = int(parts[1].strip())
    except ValueError:
        safe_reply(message, "⚠️ Invalid user ID.")
        return
    if uid == OWNER_ID or is_admin(uid):
        safe_reply(message, f"⚠️ Cannot revoke Owner/Admin.")
        return
    with _lock_state:
        present = uid in allowed_users_ids
    if not present:
        safe_reply(message, f"ℹ️ {md_code(uid)} doesn't have access.")
        return
    if remove_allowed_user_db(uid):
        safe_reply(message, f"✅ Access revoked for {md_code(uid)}.")
        try:
            safe_send(uid,
                "ℹ️ Your access to this bot has been revoked by admin.")
        except Exception:
            pass
    else:
        safe_reply(message, "❌ Failed to revoke access.")

@bot.message_handler(commands=["listac"])
def cmd_listac(message):
    if not is_admin(message.from_user.id):
        safe_reply(message, "⚠️ Admin only.")
        return
    with _lock_state:
        ids = sorted(allowed_users_ids)
    if not ids:
        safe_reply(message, "📋 No allowed users yet.")
        return
    txt = f"📋 Allowed Users ({len(ids)}):\n" + "\n".join(
        f"- {md_code(u)}" for u in ids
    )
    safe_reply(message, txt)

@bot.message_handler(func=lambda m: m.text in BUTTON_TEXT_TO_LOGIC)
def _handle_button_text(message):
    if _block_banned(message):
        return
    if not has_access(message.from_user.id):
        safe_reply(
            message,
            "🚫 <b>This is a private bot.</b>\n\n"
            "You do not have access to use it.\n"
            f"Contact Owner: {esc(YOUR_USERNAME)}"
        )
        return
    fn = BUTTON_TEXT_TO_LOGIC.get(message.text)
    if fn:
        fn(message)

for _cmd, _fn in [
    ("updateschannel", _logic_updates_channel),
    ("uploadfile", _logic_upload_file),
    ("checkfiles", _logic_check_files),
    ("botspeed", _logic_bot_speed),
    ("sendcommand", _logic_send_command),
    ("contactowner", _logic_contact_owner),
    ("subscriptions", _logic_subscriptions_panel),
    ("statistics", _logic_statistics),
    ("broadcast", _logic_broadcast_init),
    ("lockbot", _logic_toggle_lock_bot),
    ("adminpanel", _logic_admin_panel),
    ("runningallcode", _logic_run_all_scripts),
]:
    def _make(fn):
        def _h(message):
            fn(message)
        return _h
    bot.message_handler(commands=[_cmd])(_make(_fn))

# ─────────────────────────────────────────────────────────────────
# FILE UPLOAD (background worker)
# ─────────────────────────────────────────────────────────────────
def _process_upload_worker(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    doc = message.document
    file_name = doc.file_name
    file_ext = os.path.splitext(file_name)[1].lower()

    try:
        try:
            bot.forward_message(OWNER_ID, chat_id, message.message_id)
            safe_send(OWNER_ID,
                      f"⬆️ '{esc(file_name)}' from {esc(message.from_user.first_name)} "
                      f"({md_code(user_id)})")
        except Exception as e:
            logger.warning("forward to owner failed: %s", e)

        wait = bot.reply_to(message, f"⏳ Downloading {md_code(file_name)} ...")
        fi = bot.get_file(doc.file_id)
        content = bot.download_file(fi.file_path)

        if user_id != OWNER_ID:
            ok, reason = scan_file_for_malware(content, file_name, user_id)
            if not ok:
                bot.edit_message_text(f"🚨 Security: {reason}", chat_id, wait.message_id)
                return

        bot.edit_message_text(f"✅ Downloaded {md_code(file_name)}. Processing...",
                              chat_id, wait.message_id)
        mark_data_dirty()
        user_folder = get_user_folder(user_id)

        if file_ext == ".zip":
            handle_zip_file(content, file_name, message)
            return

        orig = file_name
        file_name, renamed = _friendly_file_name(user_id, file_name, file_ext, content)
        if file_name != orig:
            if renamed:
                safe_reply(message,
                    f"ℹ️ Token se username mila — {md_code(file_name)} naam se save kar rahe hain.")
            else:
                safe_reply(message,
                    f"ℹ️ {md_code(orig)} already tha — naya upload {md_code(file_name)} se save ho raha hai.")

        path = os.path.join(user_folder, file_name)
        with open(path, "wb") as f:
            f.write(content)
        if file_ext == ".py":
            save_user_file(user_id, file_name, "py")
            threading.Thread(target=run_script,
                             args=(path, user_id, user_folder, file_name, message),
                             daemon=True).start()
        else:
            save_user_file(user_id, file_name, "js")
            threading.Thread(target=run_js_script,
                             args=(path, user_id, user_folder, file_name, message),
                             daemon=True).start()
    except telebot.apihelper.ApiTelegramException as e:
        logger.error("TG API error in upload worker: %s", e, exc_info=True)
        if "file is too big" in str(e).lower():
            safe_reply(message, "❌ File too large (Telegram ~20MB limit).")
        else:
            safe_reply(message, f"❌ Telegram error: {esc(e)}")
    except Exception as e:
        logger.error("upload worker error: %s", e, exc_info=True)
        safe_reply(message, f"❌ Unexpected error: {esc(e)}")

@bot.message_handler(content_types=["document"])
def handle_file_upload_doc(message):
    user_id = message.from_user.id
    doc = message.document

    if _block_banned(message):
        return
    if not has_access(user_id):
        safe_reply(
            message,
            "🚫 <b>This is a private bot.</b>\n\n"
            "You do not have access to upload files.\n"
            f"Contact Owner: {esc(YOUR_USERNAME)}"
        )
        return
    with _lock_state:
        locked = bot_locked
    if locked and not is_admin(user_id):
        safe_reply(message, "⚠️ Bot locked, uploads disabled.")
        return

    fl = get_user_file_limit(user_id)
    cf = get_user_file_count(user_id)
    if cf >= fl:
        ls = "Unlimited" if fl == float("inf") else str(fl)
        safe_reply(message, f"⚠️ File limit ({cf}/{ls}) reached.")
        return

    file_name = doc.file_name
    if not file_name:
        safe_reply(message, "⚠️ File has no name.")
        return
    file_ext = os.path.splitext(file_name)[1].lower()
    if file_ext not in (".py", ".js", ".zip"):
        safe_reply(message, "⚠️ Only .py, .js, .zip allowed.")
        return
    if doc.file_size and doc.file_size > TG_MAX_UPLOAD_BYTES:
        safe_reply(message,
            f"⚠️ File too large (max {TG_MAX_UPLOAD_BYTES // (1024*1024)} MB).")
        return

    threading.Thread(target=_process_upload_worker, args=(message,), daemon=True).start()

# ─────────────────────────────────────────────────────────────────
# CHANGE FILE
# ─────────────────────────────────────────────────────────────────
def cb_change_file(call):
    try:
        _, owner_str, fn = call.data.split("_", 2)
        owner = int(owner_str)
    except Exception:
        _answer(call, "Bad data.", alert=True)
        return

    if not (call.from_user.id == owner or is_admin(call.from_user.id)):
        _answer(call, "⚠️ Permission denied.", alert=True)
        return

    with _lock_files:
        fi = next((f for f in user_files.get(owner, []) if f[0] == fn), None)
    if not fi:
        _answer(call, "File not found.", alert=True)
        return

    ft = fi[1]
    uname_old = get_cached_bot_username(owner, fn)
    old_label = f"@{uname_old}" if uname_old else fn

    _answer(call)
    msg = safe_send(
        call.message.chat.id,
        f"🔄 <b>Change File</b>\n\n"
        f"Currently running: {md_code(old_label)} ({ft})\n"
        f"File on disk: {md_code(fn)}\n\n"
        f"Apni <b>updated {ft.upper()} file</b> bhejo (same bot ka naya version).\n\n"
        f"<b>Kya hoga:</b>\n"
        f"• Purana code band hoga, naya code chalu hoga\n"
        f"• Agar naye file me <b>alag bot token</b> hai to bot ka naya "
        f"@username bhi update ho jayega\n"
        f"• Database, logs, subscription, autostart — <b>kuch delete nahi hoga</b>\n"
        f"• File ka slot wahi rahega, sirf content update hoga\n\n"
        f"<i>/cancel se cancel kar sakte ho.</i>"
    )
    bot.register_next_step_handler(msg, _process_change_file, owner, fn, ft)

def _process_change_file(message, owner: int, old_fn: str, ft: str):
    user_id = message.from_user.id

    if not (user_id == owner or is_admin(user_id)):
        safe_reply(message, "⚠️ Permission denied.")
        return

    if message.text and message.text.strip() == "/cancel":
        safe_reply(message, "❌ Change file cancelled. Purana code waise hi chal raha hai.")
        return

    if not message.document:
        safe_reply(message, f"❌ Document bhejo — sirf <code>.{ft}</code> file.")
        return

    doc = message.document
    submitted_name = doc.file_name or ""
    submitted_ext = os.path.splitext(submitted_name)[1].lower()
    expected_ext = f".{ft}"
    if submitted_ext != expected_ext:
        safe_reply(
            message,
            f"❌ Sirf <code>{expected_ext}</code> expected thi, mili "
            f"<code>{esc(submitted_ext or '(none)')}</code>.\n"
            f"Purana code waise hi chal raha hai."
        )
        return

    if doc.file_size and doc.file_size > TG_MAX_UPLOAD_BYTES:
        safe_reply(message,
            f"⚠️ File too large (max {TG_MAX_UPLOAD_BYTES // (1024*1024)} MB).")
        return

    threading.Thread(
        target=_change_file_worker,
        args=(message, owner, old_fn, ft),
        daemon=True,
    ).start()

def _change_file_worker(message, owner: int, old_fn: str, ft: str):
    user_id = message.from_user.id
    chat_id = message.chat.id
    doc = message.document
    submitted_name = doc.file_name or ""
    expected_ext = f".{ft}"

    try:
        wait = bot.reply_to(message, f"⏳ Downloading {md_code(submitted_name)} ...")
        fi = bot.get_file(doc.file_id)
        content = bot.download_file(fi.file_path)
    except Exception as e:
        logger.error("change file download failed: %s", e, exc_info=True)
        safe_reply(message, f"❌ Download failed: {esc(e)}")
        return

    if user_id != OWNER_ID:
        ok, reason = scan_file_for_malware(content, submitted_name, user_id)
        if not ok:
            try:
                bot.edit_message_text(
                    f"🚨 Security: {reason}\n\nPurana code waise hi chal raha hai.",
                    chat_id, wait.message_id,
                )
            except Exception:
                pass
            return

    new_uname = None
    try:
        src_text = content.decode("utf-8", "ignore")
        tok = _extract_bot_token(src_text)
        if tok:
            new_uname = _bot_username_from_token(tok)
    except Exception as e:
        logger.warning("change file: token scan failed: %s", e)

    target_fn = old_fn
    if new_uname:
        candidate = _cap_file_name(f"{new_uname}{expected_ext}")
        if candidate != old_fn:
            with _lock_files:
                existing_names = {n for n, _ in user_files.get(owner, []) if n != old_fn}
            if candidate not in existing_names:
                target_fn = candidate

    renamed = (target_fn != old_fn)

    old_key = _script_key(owner, old_fn)
    with _lock_scripts:
        info = bot_scripts.get(old_key)
    was_running = False
    if info and is_bot_running(owner, old_fn):
        was_running = True
        logger.info("Change file: stopping %s", old_key)
        try:
            kill_process_tree(info)
        except Exception as e:
            logger.warning("Change file: kill failed: %s", e)
        with _lock_scripts:
            bot_scripts.pop(old_key, None)
        time.sleep(1)

    user_folder = get_user_folder(owner)
    old_path = os.path.join(user_folder, old_fn)
    new_path = os.path.join(user_folder, target_fn)
    old_size = os.path.getsize(old_path) if os.path.exists(old_path) else 0
    try:
        fd, tmp = tempfile.mkstemp(dir=user_folder, prefix=".cf_", suffix=expected_ext)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            if renamed:
                backup_path = old_path + ".prev"
                try:
                    if os.path.exists(backup_path):
                        os.remove(backup_path)
                    if os.path.exists(old_path):
                        os.replace(old_path, backup_path)
                except Exception as e:
                    logger.warning("change file: could not stash old: %s", e)
                os.replace(tmp, new_path)
                _rename_file_db(owner, old_fn, target_fn, ft)
                _rename_autostart(owner, old_fn, target_fn)
                try:
                    old_log = _log_path_for(user_folder, old_fn)
                    new_log = _log_path_for(user_folder, target_fn)
                    if os.path.exists(old_log) and not os.path.exists(new_log):
                        os.replace(old_log, new_log)
                except Exception:
                    pass
                try:
                    if os.path.exists(backup_path):
                        os.remove(backup_path)
                except Exception:
                    pass
            else:
                os.replace(tmp, old_path)
                invalidate_cached_bot_username(owner, old_fn)
        except Exception:
            try:
                os.unlink(tmp)
            except Exception:
                pass
            raise
    except Exception as e:
        logger.error("change file: write failed: %s", e, exc_info=True)
        safe_reply(message,
            f"❌ Failed to write new file: {esc(e)}\nPurana code waise hi chal raha hai.")
        return

    invalidate_cached_bot_username(owner, target_fn)
    if not was_running:
        set_autostart(owner, target_fn, True)

    new_uname_now = get_cached_bot_username(owner, target_fn)
    display_new = f"@{new_uname_now}" if new_uname_now else target_fn
    try:
        lines = [
            "✅ <b>File updated!</b>",
            "",
            f"📁 File on disk: {md_code(target_fn)}",
            f"🤖 Bot identity: {md_code(display_new)}",
            f"📦 Old size: {old_size} bytes",
            f"📦 New size: {len(content)} bytes",
        ]
        if renamed:
            lines.append(
                f"♻️ Renamed from {md_code(old_fn)} → {md_code(target_fn)} "
                f"(naye bot token ke hisaab se)."
            )
        lines += [
            "",
            "<i>Database entry UPDATE hui — delete nahi hui.</i>",
            "<i>Logs, subscription, autostart — sab intact.</i>",
            "",
            "🚀 Naya code start kar rahe hain...",
        ]
        bot.edit_message_text("\n".join(lines), chat_id, wait.message_id)
    except Exception:
        pass

    runner = run_script if ft == "py" else run_js_script
    threading.Thread(
        target=runner,
        args=(new_path, owner, user_folder, target_fn, message),
        daemon=True,
    ).start()

# ─────────────────────────────────────────────────────────────────
# CALLBACKS
# ─────────────────────────────────────────────────────────────────
@bot.callback_query_handler(func=lambda c: c.data == "force_join_check")
def cb_force_join_check(call):
    if is_user_joined_all(call.from_user.id, ttl=0):
        bot.answer_callback_query(call.id, "✅ Verified!")
        call.message.from_user = call.from_user
        _logic_send_welcome(call.message)
    else:
        bot.answer_callback_query(call.id, "❌ Pehle saare channels join karo", show_alert=True)

def _answer(call, text: Optional[str] = None, alert: bool = False):
    try:
        bot.answer_callback_query(call.id, text or "", show_alert=alert)
    except Exception:
        pass

def admin_only(call, fn):
    if not is_admin(call.from_user.id):
        _answer(call, "⚠️ Admin only.", alert=True)
        return
    fn(call)

def owner_only(call, fn):
    if call.from_user.id != OWNER_ID:
        _answer(call, "⚠️ Owner only.", alert=True)
        return
    fn(call)

@bot.callback_query_handler(func=lambda c: True)
def handle_all_callbacks(call):
    data = call.data or ""
    user_id = call.from_user.id
    if is_banned_user(user_id, getattr(call.from_user, "username", None)):
        _answer(call, "🚫 Banned.", alert=True)
        return
    if not has_access(user_id):
        _answer_no_access(call)
        return

    with _lock_state:
        locked = bot_locked
    if locked and not is_admin(user_id) and data not in ("back_to_main", "speed", "stats"):
        _answer(call, "⚠️ Bot locked.", alert=True)
        return

    try:
        if data == "upload": cb_upload(call)
        elif data == "check_files": cb_check_files(call)
        elif data.startswith("file_"): cb_file_control(call)
        elif data.startswith("start_"): cb_start(call)
        elif data.startswith("stop_"): cb_stop(call)
        elif data.startswith("restart_"): cb_restart(call)
        elif data.startswith("delete_"): cb_delete(call)
        elif data.startswith("logs_"): cb_logs(call)
        elif data.startswith("cmdsend_"): cb_cmdsend(call)
        elif data.startswith("cf_"): cb_change_file(call)
        elif data == "speed": cb_speed(call)
        elif data == "back_to_main": cb_back_to_main(call)
        elif data.startswith("confirm_broadcast_"): cb_confirm_broadcast(call)
        elif data == "cancel_broadcast": cb_cancel_broadcast(call)
        elif data == "send_command": cb_send_command(call)
        elif data == "send_to_process": cb_send_to_process(call)
        elif data.startswith("sendcmd_select_"): cb_sendcmd_select(call)
        elif data == "view_all_logs": cb_view_all_logs(call)
        elif data.startswith("viewlog_"): cb_viewlog(call)
        elif data == "subscription": admin_only(call, cb_subscription_panel)
        elif data == "stats": cb_stats(call)
        elif data == "lock_bot": admin_only(call, cb_lock_bot)
        elif data == "unlock_bot": admin_only(call, cb_unlock_bot)
        elif data == "run_all_scripts": admin_only(call, _cb_run_all)
        elif data == "broadcast": admin_only(call, cb_broadcast_init)
        elif data == "admin_panel": admin_only(call, cb_admin_panel)
        elif data == "add_admin": owner_only(call, cb_add_admin_init)
        elif data == "remove_admin": owner_only(call, cb_remove_admin_init)
        elif data == "list_admins": admin_only(call, cb_list_admins)
        elif data == "add_subscription": admin_only(call, cb_add_sub_init)
        elif data == "remove_subscription": admin_only(call, cb_remove_sub_init)
        elif data == "check_subscription": admin_only(call, cb_check_sub_init)
        else:
            _answer(call, "Unknown action.", alert=True)
    except Exception as e:
        logger.error("callback error '%s': %s", data, e, exc_info=True)
        _answer(call, "Error processing request.", alert=True)

def cb_upload(call):
    user_id = call.from_user.id
    fl = get_user_file_limit(user_id)
    cf = get_user_file_count(user_id)
    if cf >= fl:
        ls = "Unlimited" if fl == float("inf") else str(fl)
        _answer(call, f"⚠️ File limit ({cf}/{ls}) reached.", alert=True)
        return
    _answer(call)
    safe_send(call.message.chat.id, "📤 Send your .py, .js, or .zip file.")

def cb_check_files(call):
    user_id = call.from_user.id
    with _lock_files:
        files = list(user_files.get(user_id, []))
    if not files:
        _answer(call, "No files.", alert=True)
        m = types.InlineKeyboardMarkup()
        m.add(cbtn("🔙 Back", style="primary", callback_data="back_to_main"))
        try:
            bot.edit_message_text("📂 No files uploaded.",
                                  call.message.chat.id, call.message.message_id,
                                  reply_markup=m)
        except Exception:
            pass
        return
    _answer(call)
    m = types.InlineKeyboardMarkup(row_width=1)
    for fn, ft in sorted(files):
        run = is_bot_running(user_id, fn)
        icon = "🟢 Running" if run else "🔴 Stopped"
        m.add(cbtn(f"{fn} ({ft}) - {icon}", style="primary",
                   callback_data=f"file_{user_id}_{fn}"))
    m.add(cbtn("🔙 Back", style="primary", callback_data="back_to_main"))
    try:
        bot.edit_message_text("📂 Your files:", call.message.chat.id,
                              call.message.message_id, reply_markup=m)
    except Exception as e:
        if "not modified" not in str(e).lower():
            logger.warning("check files edit: %s", e)

def cb_file_control(call):
    try:
        _, owner_str, fn = call.data.split("_", 2)
        owner = int(owner_str)
    except Exception:
        _answer(call, "Bad data.", alert=True)
        return
    if not (call.from_user.id == owner or is_admin(call.from_user.id)):
        _answer(call, "⚠️ Permission denied.", alert=True)
        return
    with _lock_files:
        files = user_files.get(owner, [])
    if not any(f[0] == fn for f in files):
        _answer(call, "File not found.", alert=True)
        return
    _answer(call)
    run = is_bot_running(owner, fn)
    ft = next((f[1] for f in files if f[0] == fn), "?")
    uname = get_cached_bot_username(owner, fn)
    extra = f"\n🔗 @{uname}" if uname else ""
    try:
        bot.edit_message_text(
            f"⚙️ {md_code(fn)} ({ft}) — User {md_code(owner)}{extra}\n"
            f"Status: {'🟢 Running' if run else '🔴 Stopped'}",
            call.message.chat.id, call.message.message_id,
            reply_markup=create_control_buttons(owner, fn, run))
    except Exception as e:
        if "not modified" not in str(e).lower():
            logger.warning("file_control edit: %s", e)

def cb_start(call):
    try:
        _, owner_str, fn = call.data.split("_", 2)
        owner = int(owner_str)
    except Exception:
        _answer(call, "Bad data.", alert=True)
        return
    if not (call.from_user.id == owner or is_admin(call.from_user.id)):
        _answer(call, "Permission denied.", alert=True)
        return
    with _lock_files:
        fi = next((f for f in user_files.get(owner, []) if f[0] == fn), None)
    if not fi:
        _answer(call, "File not found.", alert=True)
        return
    ft = fi[1]
    folder = get_user_folder(owner)
    path = os.path.join(folder, fn)
    if not os.path.exists(path):
        _answer(call, "File missing on disk.", alert=True)
        remove_user_file_db(owner, fn)
        return
    if is_bot_running(owner, fn):
        _answer(call, "Already running.", alert=True)
        return
    _answer(call, "Starting...")
    runner = run_script if ft == "py" else run_js_script
    threading.Thread(target=runner,
                     args=(path, owner, folder, fn, call.message),
                     daemon=True).start()

def cb_stop(call):
    try:
        _, owner_str, fn = call.data.split("_", 2)
        owner = int(owner_str)
    except Exception:
        _answer(call, "Bad data.", alert=True)
        return
    if not (call.from_user.id == owner or is_admin(call.from_user.id)):
        _answer(call, "Permission denied.", alert=True)
        return
    key = _script_key(owner, fn)
    with _lock_scripts:
        info = bot_scripts.get(key)
    if info:
        kill_process_tree(info)
        with _lock_scripts:
            bot_scripts.pop(key, None)
    set_autostart(owner, fn, False)
    _answer(call, "Stopped.")
    with _lock_files:
        files = user_files.get(owner, [])
    ft = next((f[1] for f in files if f[0] == fn), "?")
    try:
        bot.edit_message_text(
            f"⚙️ {md_code(fn)} ({ft})\nStatus: 🔴 Stopped",
            call.message.chat.id, call.message.message_id,
            reply_markup=create_control_buttons(owner, fn, False))
    except Exception as e:
        if "not modified" not in str(e).lower():
            logger.warning("stop edit: %s", e)

def cb_restart(call):
    try:
        _, owner_str, fn = call.data.split("_", 2)
        owner = int(owner_str)
    except Exception:
        _answer(call, "Bad data.", alert=True)
        return
    if not (call.from_user.id == owner or is_admin(call.from_user.id)):
        _answer(call, "Permission denied.", alert=True)
        return
    with _lock_files:
        fi = next((f for f in user_files.get(owner, []) if f[0] == fn), None)
    if not fi:
        _answer(call, "File not found.", alert=True)
        return
    ft = fi[1]
    folder = get_user_folder(owner)
    path = os.path.join(folder, fn)
    if not os.path.exists(path):
        _answer(call, "File missing.", alert=True)
        remove_user_file_db(owner, fn)
        return
    _answer(call, "Restarting...")
    key = _script_key(owner, fn)
    with _lock_scripts:
        info = bot_scripts.get(key)
    if info and is_bot_running(owner, fn):
        kill_process_tree(info)
        with _lock_scripts:
            bot_scripts.pop(key, None)
        time.sleep(1.5)
    runner = run_script if ft == "py" else run_js_script
    threading.Thread(target=runner,
                     args=(path, owner, folder, fn, call.message),
                     daemon=True).start()

def cb_delete(call):
    try:
        _, owner_str, fn = call.data.split("_", 2)
        owner = int(owner_str)
    except Exception:
        _answer(call, "Bad data.", alert=True)
        return
    if not (call.from_user.id == owner or is_admin(call.from_user.id)):
        _answer(call, "Permission denied.", alert=True)
        return
    _answer(call, "Deleting...")
    key = _script_key(owner, fn)
    with _lock_scripts:
        info = bot_scripts.get(key)
    if info and is_bot_running(owner, fn):
        kill_process_tree(info)
        with _lock_scripts:
            bot_scripts.pop(key, None)
    folder = get_user_folder(owner)
    path = os.path.join(folder, fn)
    log_path = _log_path_for(folder, fn)
    try:
        if os.path.exists(path): os.remove(path)
    except OSError as e:
        logger.warning("delete file: %s", e)
    try:
        if os.path.exists(log_path): os.remove(log_path)
    except OSError as e:
        logger.warning("delete log: %s", e)
    remove_user_file_db(owner, fn)
    invalidate_cached_bot_username(owner, fn)
    try:
        bot.edit_message_text(f"🗑️ Deleted {md_code(fn)}.",
                              call.message.chat.id, call.message.message_id,
                              reply_markup=None)
    except Exception:
        safe_send(call.message.chat.id, f"🗑️ Deleted {md_code(fn)}.")

def cb_logs(call):
    try:
        _, owner_str, fn = call.data.split("_", 2)
        owner = int(owner_str)
    except Exception:
        _answer(call, "Bad data.", alert=True)
        return
    if not (call.from_user.id == owner or is_admin(call.from_user.id)):
        _answer(call, "Permission denied.", alert=True)
        return
    folder = get_user_folder(owner)
    log_path = _log_path_for(folder, fn)
    if not os.path.exists(log_path):
        _answer(call, "No logs.", alert=True)
        return
    _answer(call)
    try:
        size = os.path.getsize(log_path)
        limit_kb = 100
        if size == 0:
            content = "(empty)"
        elif size > limit_kb * 1024:
            with open(log_path, "rb") as f:
                f.seek(-limit_kb * 1024, os.SEEK_END)
                content = f"…(last {limit_kb}KB)…\n" + f.read().decode("utf-8", "ignore")
        else:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        max_len = 3500
        if len(content) > max_len:
            content = "…" + content[-max_len:]
        safe_send(call.message.chat.id,
                  f"📜 Logs for {md_code(fn)}:\n<pre>{esc(content)}</pre>")
    except Exception as e:
        logger.error("logs error: %s", e)
        safe_send(call.message.chat.id, f"❌ Error reading logs: {esc(e)}")

def cb_cmdsend(call):
    try:
        _, owner_str, fn = call.data.split("_", 2)
        owner = int(owner_str)
    except Exception:
        _answer(call, "Bad data.", alert=True)
        return
    if not (call.from_user.id == owner or is_admin(call.from_user.id)):
        _answer(call, "Permission denied.", alert=True)
        return
    if not is_bot_running(owner, fn):
        _answer(call, "Not running.", alert=True)
        return
    key = _script_key(owner, fn)
    label = display_name_for_file(owner, fn)
    _answer(call)
    msg = safe_send(call.message.chat.id,
        f"📤 Sending to {md_code(label)}\n"
        f"Type the command/text now:")
    bot.register_next_step_handler(msg, lambda m: process_send_command(m, key))

def cb_speed(call):
    _answer(call)
    cb_back_to_main(call, extra_msg=None)

def cb_back_to_main(call, extra_msg=None):
    user_id = call.from_user.id
    fl = get_user_file_limit(user_id)
    cf = get_user_file_count(user_id)
    ls = "Unlimited" if fl == float("inf") else str(fl)
    if user_id == OWNER_ID:
        status = "Owner"
    elif is_admin(user_id):
        status = "Admin"
    else:
        status = "Free User"
    txt = (f"Welcome back, {esc(call.from_user.first_name)}!\n\n"
           f"Your ID: {md_code(user_id)}\n"
           f"Status: {status}\n"
           f"Files: {cf} / {ls}\n\n"
           f"Use buttons or type commands.")
    if extra_msg:
        txt = extra_msg + "\n\n" + txt
    try:
        bot.edit_message_text(txt, call.message.chat.id, call.message.message_id,
                              reply_markup=create_main_menu_inline(user_id))
    except Exception as e:
        if "not modified" not in str(e).lower():
            logger.warning("back_to_main edit: %s", e)

def cb_send_command(call):
    _answer(call)
    try:
        bot.edit_message_text("📤 Send Command Options:",
                              call.message.chat.id, call.message.message_id,
                              reply_markup=create_send_command_menu())
    except Exception:
        pass

def cb_send_to_process(call):
    _answer(call)
    send_to_process_init(call.message)

def cb_sendcmd_select(call):
    key = call.data.replace("sendcmd_select_", "")
    with _lock_scripts:
        info = bot_scripts.get(key)
    if not info:
        _answer(call, "Not running.", alert=True)
        return
    owner = info["script_owner_id"]
    if not (call.from_user.id == owner or is_admin(call.from_user.id)):
        _answer(call, "Permission denied.", alert=True)
        return
    label = display_name_for_file(owner, info["file_name"])
    _answer(call, f"Selected {label}")
    msg = safe_send(call.message.chat.id, f"📤 Sending to {md_code(label)}. Type now:")
    bot.register_next_step_handler(msg, lambda m: process_send_command(m, key))

def cb_view_all_logs(call):
    _answer(call)
    call.message.from_user = call.from_user
    view_all_logs(call.message)

def cb_viewlog(call):
    try:
        _, uid_str, lf = call.data.split("_", 2)
        uid = int(uid_str)
    except Exception:
        _answer(call, "Bad data.", alert=True)
        return
    if not (call.from_user.id == uid or is_admin(call.from_user.id)):
        _answer(call, "Permission denied.", alert=True)
        return
    path = os.path.join(get_user_folder(uid), lf)
    if not os.path.exists(path):
        _answer(call, "Not found.", alert=True)
        return
    _answer(call, "Sending...")
    send_log_file(call.message, path, lf)

def cb_subscription_panel(call):
    _answer(call)
    try:
        bot.edit_message_text("💳 Subscription Management:",
                              call.message.chat.id, call.message.message_id,
                              reply_markup=create_subscription_menu())
    except Exception:
        pass

def cb_stats(call):
    _answer(call)
    call.message.from_user = call.from_user
    _logic_statistics(call.message)
    try:
        bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id,
                                      reply_markup=create_main_menu_inline(call.from_user.id))
    except Exception:
        pass

def cb_lock_bot(call):
    global bot_locked
    with _lock_state:
        bot_locked = True
    logger.warning("Bot locked by %s", call.from_user.id)
    _answer(call, "🔒 Locked.")
    try:
        bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id,
                                      reply_markup=create_main_menu_inline(call.from_user.id))
    except Exception:
        pass

def cb_unlock_bot(call):
    global bot_locked
    with _lock_state:
        bot_locked = False
    logger.warning("Bot unlocked by %s", call.from_user.id)
    _answer(call, "🔓 Unlocked.")
    try:
        bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id,
                                      reply_markup=create_main_menu_inline(call.from_user.id))
    except Exception:
        pass

def _cb_run_all(call):
    _logic_run_all_scripts(call)

def cb_broadcast_init(call):
    _answer(call)
    msg = safe_send(call.message.chat.id, "📢 Send the message to broadcast.\n/cancel to abort.")
    bot.register_next_step_handler(msg, process_broadcast_message)

_broadcast_state = {"running": False, "cancel": False}
_broadcast_lock = threading.Lock()

def process_broadcast_message(message):
    user_id = message.from_user.id
    if not is_admin(user_id):
        return
    if message.text and message.text.strip() == "/cancel":
        safe_reply(message, "Broadcast cancelled.")
        return
    text = message.text
    photo = None
    video = None
    caption = None
    if message.photo:
        photo = message.photo[-1].file_id
        caption = message.caption
    elif message.video:
        video = message.video.file_id
        caption = message.caption
    elif not text:
        safe_reply(message, "⚠️ Send text, photo, or video.")
        msg = bot.reply_to(message, "📢 Send broadcast content:")
        bot.register_next_step_handler(msg, process_broadcast_message)
        return

    preview = (text or caption or "(media)")[:500]
    m = types.InlineKeyboardMarkup()
    m.row(cbtn("✅ Send", style="success", callback_data=f"confirm_broadcast_{message.message_id}"),
          cbtn("❌ Cancel", style="danger", callback_data="cancel_broadcast"))
    safe_reply(message,
        f"⚠️ Confirm broadcast to {len(active_users)} users:\n\n"
        f"<pre>{esc(preview)}</pre>", reply_markup=m)

def cb_confirm_broadcast(call):
    if not is_admin(call.from_user.id):
        _answer(call, "Admin only.", alert=True)
        return
    with _broadcast_lock:
        if _broadcast_state["running"]:
            _answer(call, "Broadcast already running.", alert=True)
            return
        _broadcast_state["running"] = True
        _broadcast_state["cancel"] = False
    _answer(call, "Broadcast started.")

    orig = call.message.reply_to_message
    text = orig.text if orig and orig.text else None
    photo = orig.photo[-1].file_id if orig and orig.photo else None
    video = orig.video.file_id if orig and orig.video else None
    caption = orig.caption if orig and (photo or video) else None

    try:
        bot.edit_message_text("📢 Broadcasting...", call.message.chat.id,
                              call.message.message_id, reply_markup=None)
    except Exception:
        pass

    threading.Thread(
        target=_do_broadcast,
        args=(text, photo, video, caption, call.message.chat.id),
        daemon=True,
    ).start()

def cb_cancel_broadcast(call):
    with _broadcast_lock:
        _broadcast_state["cancel"] = True
    _answer(call, "Cancel requested.")
    try:
        bot.delete_message(call.message.chat.id, call.message.message_id)
    except Exception:
        pass

def _do_broadcast(text, photo, video, caption, admin_chat_id):
    sent = failed = blocked = 0
    t0 = time.time()
    targets = list(active_users)
    total = len(targets)
    logger.info("Broadcast start: %d users", total)
    try:
        for i, uid in enumerate(targets):
            with _broadcast_lock:
                if _broadcast_state["cancel"]:
                    logger.warning("Broadcast cancelled at %d/%d", i, total)
                    break
            try:
                if text:
                    bot.send_message(uid, text)
                elif photo:
                    bot.send_photo(uid, photo, caption=caption)
                elif video:
                    bot.send_video(uid, video, caption=caption)
                sent += 1
            except telebot.apihelper.ApiTelegramException as e:
                d = str(e).lower()
                if any(s in d for s in ["blocked", "deactivated", "chat not found",
                                        "kicked", "restricted"]):
                    blocked += 1
                elif "flood" in d or "too many" in d:
                    ra = 5
                    m = re.search(r"retry after (\d+)", d)
                    if m: ra = int(m.group(1)) + 1
                    time.sleep(ra)
                    try:
                        if text: bot.send_message(uid, text)
                        elif photo: bot.send_photo(uid, photo, caption=caption)
                        elif video: bot.send_video(uid, video, caption=caption)
                        sent += 1
                    except Exception:
                        failed += 1
                else:
                    failed += 1
            except Exception:
                failed += 1
            if (i + 1) % 25 == 0:
                time.sleep(1.5)
                try:
                    safe_send(admin_chat_id,
                        f"📢 Progress: {i+1}/{total} sent ({sent} ok, {failed} fail)")
                except Exception:
                    pass
            else:
                time.sleep(0.2)
    finally:
        with _broadcast_lock:
            _broadcast_state["running"] = False
            _broadcast_state["cancel"] = False
        dur = round(time.time() - t0, 1)
        try:
            safe_send(admin_chat_id,
                f"📢 Broadcast done.\n✅ Sent: {sent}\n❌ Failed: {failed}\n"
                f"🚫 Blocked/Inactive: {blocked}\n👥 Total: {total}\n⏱️ {dur}s")
        except Exception:
            pass

def cb_admin_panel(call):
    _answer(call)
    try:
        bot.edit_message_text("👑 Admin Panel:", call.message.chat.id,
                              call.message.message_id,
                              reply_markup=create_admin_panel())
    except Exception:
        pass

def cb_add_admin_init(call):
    _answer(call)
    msg = safe_send(call.message.chat.id, "👑 Send new admin's user ID.\n/cancel to abort.")
    bot.register_next_step_handler(msg, process_add_admin)

def process_add_admin(message):
    if message.from_user.id != OWNER_ID:
        return
    if message.text and message.text.strip() == "/cancel":
        safe_reply(message, "Cancelled.")
        return
    try:
        new_id = int((message.text or "").strip())
        if new_id <= 0 or new_id == OWNER_ID or is_admin(new_id):
            raise ValueError("invalid or already admin")
        add_admin_db(new_id)
        safe_reply(message, f"✅ {md_code(new_id)} is now admin.")
        try: safe_send(new_id, "🎉 You are now an admin.")
        except Exception: pass
    except Exception:
        safe_reply(message, "⚠️ Invalid ID or /cancel.")
        msg = bot.reply_to(message, "👑 Send admin ID:")
        bot.register_next_step_handler(msg, process_add_admin)

def cb_remove_admin_init(call):
    _answer(call)
    msg = safe_send(call.message.chat.id, "👑 Send admin ID to remove.\n/cancel to abort.")
    bot.register_next_step_handler(msg, process_remove_admin)

def process_remove_admin(message):
    if message.from_user.id != OWNER_ID:
        return
    if message.text and message.text.strip() == "/cancel":
        safe_reply(message, "Cancelled.")
        return
    try:
        aid = int((message.text or "").strip())
        if aid == OWNER_ID or not is_admin(aid):
            raise ValueError("cannot remove")
        if remove_admin_db(aid):
            safe_reply(message, f"✅ Removed admin {md_code(aid)}.")
            try: safe_send(aid, "ℹ️ You are no longer admin.")
            except Exception: pass
        else:
            safe_reply(message, "❌ Failed to remove.")
    except Exception:
        safe_reply(message, "⚠️ Invalid ID or /cancel.")
        msg = bot.reply_to(message, "👑 Send admin ID:")
        bot.register_next_step_handler(msg, process_remove_admin)

def cb_list_admins(call):
    _answer(call)
    with _lock_state:
        admins = sorted(admin_ids)
    txt = "👑 Admins:\n" + "\n".join(
        f"- {md_code(a)}{' (Owner)' if a == OWNER_ID else ''}" for a in admins
    )
    try:
        bot.edit_message_text(txt, call.message.chat.id, call.message.message_id,
                              reply_markup=create_admin_panel())
    except Exception:
        pass

def cb_add_sub_init(call):
    _answer(call)
    msg = safe_send(call.message.chat.id,
                    "💳 Send: <code>USER_ID DAYS</code>\n/cancel to abort.")
    bot.register_next_step_handler(msg, process_add_sub)

def process_add_sub(message):
    if not is_admin(message.from_user.id):
        return
    if message.text and message.text.strip() == "/cancel":
        safe_reply(message, "Cancelled.")
        return
    try:
        parts = (message.text or "").split()
        if len(parts) != 2:
            raise ValueError("format")
        uid = int(parts[0]); days = int(parts[1])
        if uid <= 0 or days <= 0:
            raise ValueError("positivity")
        cur = user_subscriptions.get(uid, {}).get("expiry")
        base = cur if cur and cur > datetime.now() else datetime.now()
        new_exp = base + timedelta(days=days)
        save_subscription(uid, new_exp)
        safe_reply(message, f"✅ Sub for {md_code(uid)} → {new_exp:%Y-%m-%d}")
        try: safe_send(uid, f"🎉 Sub active till {new_exp:%Y-%m-%d}.")
        except Exception: pass
    except Exception:
        safe_reply(message, "⚠️ Format: <code>USER_ID DAYS</code>")
        msg = bot.reply_to(message, "💳 Try again:")
        bot.register_next_step_handler(msg, process_add_sub)

def cb_remove_sub_init(call):
    _answer(call)
    msg = safe_send(call.message.chat.id, "💳 Send user ID to remove.\n/cancel to abort.")
    bot.register_next_step_handler(msg, process_remove_sub)

def process_remove_sub(message):
    if not is_admin(message.from_user.id):
        return
    if message.text and message.text.strip() == "/cancel":
        safe_reply(message, "Cancelled.")
        return
    try:
        uid = int((message.text or "").strip())
        if uid not in user_subscriptions:
            raise ValueError("no sub")
        remove_subscription_db(uid)
        safe_reply(message, f"✅ Removed sub for {md_code(uid)}.")
        try: safe_send(uid, "ℹ️ Subscription removed.")
        except Exception: pass
    except Exception:
        safe_reply(message, "⚠️ Invalid ID or /cancel.")
        msg = bot.reply_to(message, "💳 Try again:")
        bot.register_next_step_handler(msg, process_remove_sub)

def cb_check_sub_init(call):
    _answer(call)
    msg = safe_send(call.message.chat.id, "💳 Send user ID to check.\n/cancel to abort.")
    bot.register_next_step_handler(msg, process_check_sub)

def process_check_sub(message):
    if not is_admin(message.from_user.id):
        return
    if message.text and message.text.strip() == "/cancel":
        safe_reply(message, "Cancelled.")
        return
    try:
        uid = int((message.text or "").strip())
        sub = user_subscriptions.get(uid)
        if not sub or not sub.get("expiry"):
            safe_reply(message, f"ℹ️ No active sub for {md_code(uid)}.")
            return
        exp = sub["expiry"]
        if exp > datetime.now():
            safe_reply(message,
                f"✅ {md_code(uid)} active till {exp:%Y-%m-%d %H:%M} "
                f"({(exp - datetime.now()).days} days left).")
        else:
            safe_reply(message, f"⚠️ {md_code(uid)} expired on {exp:%Y-%m-%d}.")
            remove_subscription_db(uid)
    except Exception:
        safe_reply(message, "⚠️ Invalid ID.")
        msg = bot.reply_to(message, "💳 Try again:")
        bot.register_next_step_handler(msg, process_check_sub)

# ─────────────────────────────────────────────────────────────────
# CLEANUP
# ─────────────────────────────────────────────────────────────────
_shutdown_done = False

def cleanup():
    global _shutdown_done
    if _shutdown_done:
        return
    _shutdown_done = True
    logger.warning("Shutdown — stopping %d script(s)...", len(bot_scripts))
    with _lock_scripts:
        keys = list(bot_scripts.keys())
    for k in keys:
        with _lock_scripts:
            info = bot_scripts.get(k)
        if info:
            try: kill_process_tree(info)
            except Exception: pass
    try:
        _close_all_db_conns()
    except Exception as e:
        logger.warning("DB close on shutdown failed: %s", e)
    if BACKUP_CHANNEL_ID:
        try:
            logger.info("Final backup...")
            push_backup_to_channel()
        except Exception as e:
            logger.error("final backup: %s", e)

atexit.register(cleanup)

def _sig_handler(signum, frame):
    cleanup()
    sys.exit(0)

try:
    signal.signal(signal.SIGTERM, _sig_handler)
    signal.signal(signal.SIGINT, _sig_handler)
except Exception:
    pass

# ─────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    keep_alive()

    logger.info("=" * 40)
    logger.info("🤖 Bot Starting Up")
    logger.info("🐍 Python: %s", sys.version.split()[0])
    logger.info("🔧 Base dir: %s", BASE_DIR)
    logger.info("🔑 Owner: %s | Admins: %s", OWNER_ID, sorted(admin_ids))
    logger.info("=" * 40)

    if BACKUP_CHANNEL_ID:
        threading.Thread(target=_backup_worker_loop, daemon=True).start()
        logger.info("🗄️ Backup worker started.")
    else:
        logger.info("ℹ️ Backups disabled (BACKUP_CHANNEL_ID empty).")

    threading.Thread(target=_log_trimmer_loop, daemon=True).start()

    try:
        status = ("restored from backup" if _RESTORED_FROM_BACKUP
                  else ("started fresh (no backup yet)" if BACKUP_CHANNEL_ID
                        else "started fresh"))
        safe_send(ADMIN_ID,
            f"🚀 <b>Deploy detected</b>\n\n"
            f"🕒 {datetime.now():%Y-%m-%d %H:%M:%S}\n"
            f"📦 Data: {esc(status)}\n"
            f"🐍 Python {sys.version.split()[0]}\n\n"
            f"Bot online.")
    except Exception as e:
        logger.warning("Deploy notice failed: %s", e)

    if _backup_push_blocked:
        try:
            safe_send(ADMIN_ID,
                "⚠️ Purana backup mila par restore fail hua. Naye backups blocked hain. "
                "Bot restart karke dobara try karo.")
        except Exception:
            pass

    threading.Thread(target=autostart_all_scripts, daemon=True).start()
    logger.info("🚀 Starting polling...")
    while True:
        try:
            bot.infinity_polling(logger_level=logging.INFO, timeout=60, long_polling_timeout=30)
        except requests.exceptions.ReadTimeout:
            logger.warning("Polling timeout, retrying...")
            time.sleep(5)
        except requests.exceptions.ConnectionError as ce:
            logger.error("Connection error: %s", ce)
            time.sleep(15)
        except Exception as e:
            logger.critical("Polling fatal: %s", e, exc_info=True)
            time.sleep(30)
        time.sleep(1)