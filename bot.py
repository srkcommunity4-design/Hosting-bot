"""
Telegram Channel Moderation Bot -- Signature Check + Blocklist + Rate Limit
------------------------------------------------------------------------------
Library : aiogram 3.x   |   Python : 3.10+

SETUP (Render.com):
  Environment Variable: BOT_TOKEN = <BotFather se mila token>
  pip install aiogram --upgrade
  python bot.py

Bot ko channel me ADMIN banao + "Delete Messages" + "Sign Messages" ON karo.
Phir bot ko PRIVATE me /start bhejo.
"""

import asyncio
import json
import logging
import os
import time
import unicodedata
from pathlib import Path

import aiohttp
from aiogram import Bot, Dispatcher, F
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import (
    CallbackQuery,
    ChatMemberUpdated,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)

# ============================================================
# CONFIG — sirf BOT_TOKEN environment variable me daalo
# ============================================================
BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
SUPER_ADMIN_IDS = {7892255798}             # apni User ID daalo (/myid se milegi)

CACHE_TTL_SECONDS      = 15 * 60          # admin list 15 min cache
ADMIN_REFRESH_INTERVAL = 10 * 60          # background admin refresh: 10 min
RATE_LIMIT_SECONDS     = 60 * 60          # 1 admin, 1 channel, 1 post/hour (default)

KEEPALIVE_INTERVAL     = 50               # Render.com sleep se bachne ke liye, har 50 sec

DATA_FILE = Path(__file__).resolve().parent / "bot_data.json"

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
log = logging.getLogger("channel-moderation-bot")

bot = Bot(token=BOT_TOKEN)
dp  = Dispatcher(storage=MemoryStorage())

# ---------------------------------------------------------------------------
# Persistent storage
# ---------------------------------------------------------------------------
DATA: dict = {"channels": {}, "global_blocklist": []}
# custom_rate_limits: { (chat_id, user_id): max_posts_per_hour }
# e.g. {(-100123456, 987654321): 5}
CUSTOM_RATE_LIMITS: dict[tuple[int, int], int] = {}
# global user rate limits: { user_id: max_posts_per_hour }  -- SABHI channels pe apply
# e.g. {987654321: 5}  => ye user har channel me 5 posts/hour kar sakta hai
GLOBAL_USER_RATE_LIMITS: dict[int, int] = {}
# post count tracking for custom limits: { (chat_id, user_id): [timestamps] }
_post_timestamps: dict[tuple[int, int], list] = {}


def load_data() -> None:
    global DATA
    if DATA_FILE.exists():
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                DATA = json.load(f)
        except Exception as e:
            log.warning("bot_data.json read nahi ho payi, fresh start: %s", e)
            DATA = {"channels": {}, "global_blocklist": []}
    DATA.setdefault("channels", {})
    DATA.setdefault("global_blocklist", [])

    # custom (per-channel) rate limits load karo
    raw_crl = DATA.get("custom_rate_limits", {})
    for k, v in raw_crl.items():
        try:
            chat_id_str, uid_str = k.split(":")
            CUSTOM_RATE_LIMITS[(int(chat_id_str), int(uid_str))] = int(v)
        except Exception:
            pass

    # global (all-channels) rate limits load karo
    raw_grl = DATA.get("global_user_rate_limits", {})
    for k, v in raw_grl.items():
        try:
            GLOBAL_USER_RATE_LIMITS[int(k)] = int(v)
        except Exception:
            pass


def save_data() -> None:
    try:
        DATA["custom_rate_limits"] = {
            f"{c}:{u}": v for (c, u), v in CUSTOM_RATE_LIMITS.items()
        }
        DATA["global_user_rate_limits"] = {
            str(uid): v for uid, v in GLOBAL_USER_RATE_LIMITS.items()
        }
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(DATA, f, ensure_ascii=False, indent=2)
    except Exception as e:
        log.error("bot_data.json save nahi ho payi: %s", e)


def save_data_async() -> None:
    asyncio.create_task(asyncio.to_thread(save_data))


def get_channel_info(chat_id: int) -> dict:
    return DATA["channels"].setdefault(str(chat_id), {"blocklist": [], "title": str(chat_id)})


# ============================================================
# UNICODE / FANCY FONT NORMALIZATION
# ============================================================
_UNICODE_FONT_MAP: dict[str, str] = {}


def _build_font_map() -> None:
    ranges: list[tuple[int, str]] = [
        (0x1D400, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        (0x1D41A, "abcdefghijklmnopqrstuvwxyz"),
        (0x1D434, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        (0x1D44E, "abcdefghijklmnopqrstuvwxyz"),
        (0x1D468, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        (0x1D482, "abcdefghijklmnopqrstuvwxyz"),
        (0x1D49C, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        (0x1D4B6, "abcdefghijklmnopqrstuvwxyz"),
        (0x1D4D0, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        (0x1D4EA, "abcdefghijklmnopqrstuvwxyz"),
        (0x1D504, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        (0x1D51E, "abcdefghijklmnopqrstuvwxyz"),
        (0x1D538, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        (0x1D552, "abcdefghijklmnopqrstuvwxyz"),
        (0x1D56C, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        (0x1D586, "abcdefghijklmnopqrstuvwxyz"),
        (0x1D5A0, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        (0x1D5BA, "abcdefghijklmnopqrstuvwxyz"),
        (0x1D5D4, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        (0x1D5EE, "abcdefghijklmnopqrstuvwxyz"),
        (0x1D608, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        (0x1D622, "abcdefghijklmnopqrstuvwxyz"),
        (0x1D63C, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        (0x1D656, "abcdefghijklmnopqrstuvwxyz"),
        (0x1D670, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        (0x1D68A, "abcdefghijklmnopqrstuvwxyz"),
        (0x1D7CE, "0123456789"),
        (0x1D7D8, "0123456789"),
        (0x1D7E2, "0123456789"),
        (0x1D7EC, "0123456789"),
        (0x1D7F6, "0123456789"),
        (0x24B6, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        (0x24D0, "abcdefghijklmnopqrstuvwxyz"),
        (0x2460, "123456789"),
        (0xFF21, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        (0xFF41, "abcdefghijklmnopqrstuvwxyz"),
        (0xFF10, "0123456789"),
        (0x249C, "abcdefghijklmnopqrstuvwxyz"),
        (0x1F1E6, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
    ]

    individual: dict[str, str] = {
        "\u212C": "B", "\u2130": "E", "\u2131": "F", "\u210B": "H",
        "\u2110": "I", "\u2112": "L", "\u2133": "M", "\u2134": "o",
        "\u2118": "P", "\u211B": "R",
        "\u2102": "C", "\u210D": "H", "\u2115": "N", "\u2119": "P",
        "\u211A": "Q", "\u211D": "R", "\u2124": "Z",
        "\u212D": "C", "\u210C": "H", "\u2111": "I", "\u211C": "R",
        "\u2128": "Z",
        "\u2070": "0", "\u00B9": "1", "\u00B2": "2", "\u00B3": "3",
        "\u2074": "4", "\u2075": "5", "\u2076": "6", "\u2077": "7",
        "\u2078": "8", "\u2079": "9",
        "\u1D43": "a", "\u1D47": "b", "\u1D9C": "c", "\u1D48": "d",
        "\u1D49": "e", "\u1DA0": "f", "\u1D4D": "g", "\u02B0": "h",
        "\u2071": "i", "\u02B2": "j", "\u1D4F": "k", "\u02E1": "l",
        "\u1D50": "m", "\u207F": "n", "\u1D52": "o", "\u1D56": "p",
        "\u02B3": "r", "\u02E2": "s", "\u1D57": "t", "\u1D58": "u",
        "\u1D5B": "v", "\u02B7": "w", "\u02E3": "x", "\u02B8": "y",
        "\u1DBB": "z",
        "\u1D2C": "A", "\u1D2E": "B", "\u1D30": "D", "\u1D31": "E",
        "\u1D33": "G", "\u1D34": "H", "\u1D35": "I", "\u1D36": "J",
        "\u1D37": "K", "\u1D38": "L", "\u1D39": "M", "\u1D3A": "N",
        "\u1D3C": "O", "\u1D3E": "P", "\u1D3F": "R", "\u1D40": "T",
        "\u1D41": "U", "\u1D42": "W",
        "\u0410": "A", "\u0412": "B", "\u0421": "C", "\u0415": "E",
        "\u041C": "M", "\u041E": "O", "\u0420": "R", "\u0422": "T",
        "\u0425": "X", "\u0443": "y", "\u0441": "c", "\u0435": "e",
        "\u043E": "o", "\u0440": "p", "\u0445": "x",
        "\u03B1": "a", "\u03B2": "B", "\u03B5": "e", "\u03BD": "v",
        "\u03C7": "x", "\u03BF": "o", "\u03C1": "p",
        "\u0131": "i", "\u0237": "j", "\uFB00": "ff", "\uFB01": "fi",
        "\uFB02": "fl", "\uFB03": "ffi", "\uFB04": "ffl",
        "\u00E6": "ae", "\u0153": "oe",
        "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
        "7": "t", "$": "s", "@": "a", "!": "i",
    }
    _UNICODE_FONT_MAP.update(individual)

    for start, chars in ranges:
        for i, ch in enumerate(chars):
            _UNICODE_FONT_MAP[chr(start + i)] = ch


_build_font_map()


def normalize_text(text: str) -> str:
    text = unicodedata.normalize("NFKD", text)
    result = []
    for ch in text:
        result.append(_UNICODE_FONT_MAP.get(ch, ch))
    text = "".join(result)
    text = "".join(c for c in text if unicodedata.category(c) != "Mn")
    return text.lower()


def text_contains_blocked(text: str, combined_blocklist: set) -> str | None:
    text_lower = text.lower()
    text_norm  = normalize_text(text)
    for word in combined_blocklist:
        word_lower = word.lower()
        word_norm  = normalize_text(word)
        if word_lower in text_lower or word_norm in text_norm:
            return word
    return None


# ---------------------------------------------------------------------------
# Admin-signature cache
# ---------------------------------------------------------------------------
_admin_cache: dict[int, dict] = {}


async def get_valid_signatures(chat_id: int, force_refresh: bool = False) -> dict[str, int] | None:
    now = time.monotonic()
    cached = _admin_cache.get(chat_id)
    if not force_refresh and cached and cached["expires_at"] > now:
        return cached["map"]

    try:
        admins = await bot.get_chat_administrators(chat_id)
        sig_map: dict[str, int] = {}
        for admin in admins:
            user = admin.user
            uid  = user.id
            custom_title = getattr(admin, "custom_title", None)
            if custom_title:
                sig_map[custom_title.strip()] = uid
            if user.first_name:
                sig_map[user.first_name.strip()] = uid
            full_name = user.first_name or ""
            if user.last_name:
                full_name = f"{full_name} {user.last_name}"
            if full_name.strip():
                sig_map[full_name.strip()] = uid
            if user.username:
                sig_map[user.username.strip()] = uid

        _admin_cache[chat_id] = {"map": sig_map, "expires_at": now + CACHE_TTL_SECONDS}
        return sig_map

    except Exception as e:
        log.warning("Chat %s: get_chat_administrators fail: %s", chat_id, e)
        if cached:
            return cached["map"]
        return None


async def admin_cache_refresher() -> None:
    while True:
        await asyncio.sleep(ADMIN_REFRESH_INTERVAL)
        for chat_id_str in list(DATA["channels"].keys()):
            try:
                await get_valid_signatures(int(chat_id_str), force_refresh=True)
            except Exception as e:
                log.warning("Background admin refresh fail (%s): %s", chat_id_str, e)


async def is_owner(chat_id: int, user_id: int) -> bool:
    try:
        member = await bot.get_chat_member(chat_id, user_id)
        return member.status == "creator"
    except Exception as e:
        log.warning("Owner check fail (chat %s, user %s): %s", chat_id, user_id, e)
        return False


async def get_user_role(chat_id: int, user_id: int) -> str | None:
    try:
        member = await bot.get_chat_member(chat_id, user_id)
        if member.status in ("creator", "administrator"):
            return member.status
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Fast delete
# ---------------------------------------------------------------------------
async def safe_delete(message: Message, reason: str) -> None:
    try:
        await message.delete()
        log.info("Chat %s: post DELETE -- %s", message.chat.id, reason)
    except Exception as e:
        log.warning(
            "Chat %s: delete FAIL (%s): %s -- bot Admin + 'Delete Messages' permission check karo.",
            message.chat.id, reason, e,
        )


# ---------------------------------------------------------------------------
# Keep-alive for Render.com
# ---------------------------------------------------------------------------
async def keep_alive_task() -> None:
    await asyncio.sleep(10)
    url = os.environ.get("RENDER_EXTERNAL_URL", "")
    if not url:
        log.info("RENDER_EXTERNAL_URL set nahi -- keep-alive skip.")
        return
    if not url.startswith("http"):
        url = "https://" + url

    log.info("Keep-alive chalu: har %s sec me %s ping karega.", KEEPALIVE_INTERVAL, url)
    async with aiohttp.ClientSession() as session:
        while True:
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    log.debug("Keep-alive ping: %s", resp.status)
            except Exception as e:
                log.debug("Keep-alive ping fail (normal): %s", e)
            await asyncio.sleep(KEEPALIVE_INTERVAL)


# ---------------------------------------------------------------------------
# Channel post moderation
# ---------------------------------------------------------------------------
_last_post_time: dict[tuple[int, int], float] = {}


@dp.channel_post()
async def handle_channel_post(message: Message) -> None:
    try:
        chat_id  = message.chat.id
        signature = (message.author_signature or "").strip()

        # 1) Signature check
        if not signature:
            asyncio.create_task(safe_delete(message, "author_signature khaali/None hai"))
            return

        sig_map = await get_valid_signatures(chat_id)
        if sig_map is None:
            log.warning("Chat %s: admin list bharosemand nahi -- post skip.", chat_id)
            return
        if signature not in sig_map:
            asyncio.create_task(safe_delete(message, f"signature '{signature}' kisi admin se match nahi"))
            return

        poster_id = sig_map[signature]
        info = get_channel_info(chat_id)

        # 2) Blocklist check (normalized)
        raw_text = (message.text or message.caption or "")
        combined_blocklist = set(info.get("blocklist", [])) | set(DATA.get("global_blocklist", []))
        blocked_word = text_contains_blocked(raw_text, combined_blocklist)
        if blocked_word:
            asyncio.create_task(safe_delete(message, f"blocklist word '{blocked_word}' mila (normalized check)"))
            return

        # 3) Rate limit check
        #    Priority: per-channel override > global user limit > default 1/hour
        key = (chat_id, poster_id)
        now_ts = time.monotonic()

        max_posts = None
        if key in CUSTOM_RATE_LIMITS:
            max_posts = CUSTOM_RATE_LIMITS[key]
        elif poster_id in GLOBAL_USER_RATE_LIMITS:
            max_posts = GLOBAL_USER_RATE_LIMITS[poster_id]

        if max_posts is not None:
            # Custom / global limit — sliding 1-hour window per (channel, user)
            timestamps = _post_timestamps.setdefault(key, [])
            timestamps[:] = [t for t in timestamps if now_ts - t < RATE_LIMIT_SECONDS]
            if len(timestamps) >= max_posts:
                asyncio.create_task(safe_delete(
                    message,
                    f"rate limit -- {max_posts} posts/hour limit cross ho gayi"
                ))
                return
            timestamps.append(now_ts)
        else:
            # Default 1 post/hour per (channel, user)
            last_time = _last_post_time.get(key)
            if last_time is not None and (now_ts - last_time) < RATE_LIMIT_SECONDS:
                wait_left = int(RATE_LIMIT_SECONDS - (now_ts - last_time))
                asyncio.create_task(safe_delete(message, f"rate limit -- abhi {wait_left}s baaki hai"))
                return
            _last_post_time[key] = now_ts

        # Title bookkeeping
        if info.get("title") != message.chat.title:
            info["title"] = message.chat.title
            save_data_async()

        log.info("Chat %s: '%s' -> OK, post rakha gaya.", chat_id, signature)

    except Exception as e:
        log.error("handle_channel_post me unexpected error: %s", e)


@dp.my_chat_member()
async def on_bot_membership_change(update: ChatMemberUpdated) -> None:
    try:
        if update.chat.type != "channel":
            return
        if update.new_chat_member.status in ("administrator", "creator"):
            info = get_channel_info(update.chat.id)
            info["title"] = update.chat.title or info.get("title")
            save_data_async()
            log.info("Naya channel register hua: %s (%s)", update.chat.title, update.chat.id)
    except Exception as e:
        log.error("on_bot_membership_change error: %s", e)


# ---------------------------------------------------------------------------
# Rate limit helper — ek hi jagah logic
# ---------------------------------------------------------------------------
async def _resolve_user_id(target_arg: str) -> tuple[int | None, str | None]:
    """
    '@username' ya '123456789' se user ID nikaalo.
    Return: (uid, error_message). error hone par uid=None.
    """
    username_str = target_arg.lstrip("@")
    try:
        return int(username_str), None
    except ValueError:
        pass
    try:
        user_obj = await bot.get_chat(f"@{username_str}")
        return user_obj.id, None
    except Exception as e:
        return None, (
            f"❌ User '@{username_str}' nahi mila ya private hai.\n"
            f"User se pehle /myid bhijwao aur User ID use karo.\n"
            f"Error: {e}"
        )


async def _apply_global_limit(message: Message, uid: int, max_posts: int) -> None:
    """SABHI registered channels pe user ke liye N posts/hour set karo."""
    channel_keys = list(DATA["channels"].keys())
    if not channel_keys:
        await message.answer("❌ Koi channel registered nahi. Pehle bot ko channel me Admin banao.")
        return

    old_global = GLOBAL_USER_RATE_LIMITS.get(uid)
    GLOBAL_USER_RATE_LIMITS[uid] = max_posts

    # Per-channel overrides clear karo — kyunki ab global apply hona chahiye
    for cid_str in channel_keys:
        try:
            cid = int(cid_str)
        except ValueError:
            continue
        k = (cid, uid)
        CUSTOM_RATE_LIMITS.pop(k, None)
        _post_timestamps.pop(k, None)
        _last_post_time.pop(k, None)

    save_data_async()

    lines = []
    for cid_str in channel_keys:
        title = DATA["channels"][cid_str].get("title", cid_str)
        lines.append(f"• {title}")

    old_txt = f"\n<i>(pehle global: {old_global}/hour tha)</i>" if old_global is not None else ""
    await message.answer(
        f"✅ <b>GLOBAL limit set ho gayi!</b>{old_txt}\n\n"
        f"<b>User ID:</b> <code>{uid}</code>\n"
        f"<b>Limit:</b> {max_posts} posts/hour <b>har channel me</b>\n"
        f"<b>Applied on {len(channel_keys)} channels:</b>\n" + "\n".join(lines),
        parse_mode="HTML",
    )


async def _apply_single_limit(
    message: Message, uid: int, max_posts: int, channel_arg: str | None, target_arg: str
) -> None:
    """Ek specific channel pe custom limit set karo."""
    chat_id_to_use = None
    if channel_arg:
        try:
            chat_id_to_use = int(channel_arg)
        except ValueError:
            try:
                c_obj = await bot.get_chat(channel_arg)
                chat_id_to_use = c_obj.id
            except Exception:
                pass

    if chat_id_to_use is None:
        channel_list = list(DATA["channels"].keys())
        if len(channel_list) == 1:
            chat_id_to_use = int(channel_list[0])
        elif len(channel_list) == 0:
            await message.answer("❌ Koi channel registered nahi. Pehle bot ko channel me Admin banao.")
            return
        else:
            channel_lines = "\n".join(
                f"• <code>{cid}</code> — {DATA['channels'][cid].get('title', cid)}"
                for cid in channel_list
            )
            await message.answer(
                f"❌ Multiple channels hain. Ye 2 options use kar:\n\n"
                f"<b>SABHI channels me ek saath:</b>\n"
                f"<code>/d {target_arg} {max_posts} ALL</code>\n\n"
                f"<b>Sirf ek channel me:</b>\n"
                f"<code>/d {target_arg} {max_posts} CHANNEL_ID</code>\n\n"
                f"Tumhare channels:\n{channel_lines}",
                parse_mode="HTML",
            )
            return

    key = (chat_id_to_use, uid)
    old_val = CUSTOM_RATE_LIMITS.get(key)
    CUSTOM_RATE_LIMITS[key] = max_posts
    _post_timestamps.pop(key, None)
    _last_post_time.pop(key, None)
    save_data_async()

    channel_info = DATA["channels"].get(str(chat_id_to_use), {})
    channel_name = channel_info.get("title", str(chat_id_to_use))

    if old_val is not None:
        msg = (
            f"✅ Update ho gaya!\n\n"
            f"<b>User ID:</b> <code>{uid}</code>\n"
            f"<b>Channel:</b> {channel_name}\n"
            f"<b>Pehle:</b> {old_val} posts/hour\n"
            f"<b>Ab:</b> {max_posts} posts/hour"
        )
    else:
        msg = (
            f"✅ Custom limit set ho gayi!\n\n"
            f"<b>User ID:</b> <code>{uid}</code>\n"
            f"<b>Channel:</b> {channel_name}\n"
            f"<b>Limit:</b> {max_posts} posts/hour"
        )
    await message.answer(msg, parse_mode="HTML")


# ---------------------------------------------------------------------------
# /d command — custom rate limit set karna
# Usage:
#   /d @username 5              (single channel / auto-pick)
#   /d 123456789 5              (User ID se)
#   /d @username 5 ALL          (SABHI channels me globally)
#   /d @username 5 -100123...   (specific channel)
# ---------------------------------------------------------------------------
@dp.message(Command("d"), F.chat.type == "private")
async def cmd_d(message: Message) -> None:
    if message.from_user.id not in SUPER_ADMIN_IDS:
        await message.answer("❌ Ye command sirf Super Admin ke liye hai.")
        return

    parts = (message.text or "").split()
    if len(parts) < 3:
        await message.answer(
            "❌ Galat format.\n\n"
            "<b>Sahi formats:</b>\n"
            "• <code>/d @username 5</code> — ek channel me (auto)\n"
            "• <code>/d 123456789 5</code> — User ID se\n"
            "• <code>/d @username 5 ALL</code> — <b>SABHI channels me globally</b>\n"
            "• <code>/d @username 5 -1001234567890</code> — specific channel\n\n"
            "💡 Shortcut: <code>/dall @username 5</code>",
            parse_mode="HTML",
        )
        return

    target_arg  = parts[1]
    count_arg   = parts[2]
    channel_arg = parts[3] if len(parts) >= 4 else None

    try:
        max_posts = int(count_arg)
        if max_posts < 1 or max_posts > 100000:
            raise ValueError
    except ValueError:
        await message.answer("❌ Number galat hai. 1 se 100000 ke beech hona chahiye.")
        return

    uid, err = await _resolve_user_id(target_arg)
    if err:
        await message.answer(err)
        return

    if channel_arg and channel_arg.upper() == "ALL":
        await _apply_global_limit(message, uid, max_posts)
    else:
        await _apply_single_limit(message, uid, max_posts, channel_arg, target_arg)


# ---------------------------------------------------------------------------
# /dall — shortcut for global (all channels) limit
# ---------------------------------------------------------------------------
@dp.message(Command("dall"), F.chat.type == "private")
async def cmd_dall(message: Message) -> None:
    if message.from_user.id not in SUPER_ADMIN_IDS:
        await message.answer("❌ Ye command sirf Super Admin ke liye hai.")
        return

    parts = (message.text or "").split()
    if len(parts) < 3:
        await message.answer(
            "❌ Format: <code>/dall @username 5</code>\n"
            "Ya: <code>/dall 123456789 5</code>\n\n"
            "Ye <b>SABHI registered channels</b> me us user ko N posts/hour dega.",
            parse_mode="HTML",
        )
        return

    target_arg = parts[1]
    count_arg  = parts[2]

    try:
        max_posts = int(count_arg)
        if max_posts < 1 or max_posts > 100000:
            raise ValueError
    except ValueError:
        await message.answer("❌ Number galat hai. 1 se 100000 ke beech hona chahiye.")
        return

    uid, err = await _resolve_user_id(target_arg)
    if err:
        await message.answer(err)
        return

    await _apply_global_limit(message, uid, max_posts)


# ---------------------------------------------------------------------------
# /dlist — saari active rate limits ek jagah
# ---------------------------------------------------------------------------
@dp.message(Command("dlist"), F.chat.type == "private")
async def cmd_dlist(message: Message) -> None:
    if message.from_user.id not in SUPER_ADMIN_IDS:
        await message.answer("❌ Ye command sirf Super Admin ke liye hai.")
        return

    lines = ["<b>📋 Active Rate Limits</b>\n"]

    if GLOBAL_USER_RATE_LIMITS:
        lines.append("<b>🌐 Global (sabhi channels):</b>")
        for uid, n in GLOBAL_USER_RATE_LIMITS.items():
            lines.append(f"• <code>{uid}</code> → {n}/hour (each channel)")
    else:
        lines.append("<b>🌐 Global:</b> koi nahi")

    lines.append("")

    if CUSTOM_RATE_LIMITS:
        lines.append("<b>📌 Per-channel overrides:</b>")
        for (cid, uid), n in CUSTOM_RATE_LIMITS.items():
            title = DATA["channels"].get(str(cid), {}).get("title", str(cid))
            lines.append(f"• {title} / <code>{uid}</code> → {n}/hour")
    else:
        lines.append("<b>📌 Per-channel:</b> koi nahi")

    lines.append("\n<i>Default: 1 post/hour per admin per channel.</i>")
    await message.answer("\n".join(lines), parse_mode="HTML")


# ---------------------------------------------------------------------------
# /dlimit_remove — custom + global dono clear karo
# ---------------------------------------------------------------------------
@dp.message(Command("dlimit_remove"), F.chat.type == "private")
async def cmd_dlimit_remove(message: Message) -> None:
    if message.from_user.id not in SUPER_ADMIN_IDS:
        await message.answer("❌ Ye command sirf Super Admin ke liye hai.")
        return

    parts = (message.text or "").split()
    if len(parts) < 2:
        await message.answer("Format: <code>/dlimit_remove USER_ID</code>", parse_mode="HTML")
        return

    try:
        uid = int(parts[1])
    except ValueError:
        await message.answer("❌ Sahi User ID do (number).")
        return

    removed_channels = []
    for key in list(CUSTOM_RATE_LIMITS.keys()):
        if key[1] == uid:
            CUSTOM_RATE_LIMITS.pop(key)
            _post_timestamps.pop(key, None)
            _last_post_time.pop(key, None)
            removed_channels.append(key[0])

    removed_global = uid in GLOBAL_USER_RATE_LIMITS
    if removed_global:
        GLOBAL_USER_RATE_LIMITS.pop(uid, None)

    # timestamp tracking cleanup (global-only mode bhi clear kar do)
    for key in list(_post_timestamps.keys()):
        if key[1] == uid:
            _post_timestamps.pop(key, None)
    for key in list(_last_post_time.keys()):
        if key[1] == uid:
            _last_post_time.pop(key, None)

    if removed_channels or removed_global:
        save_data_async()
        parts_txt = []
        if removed_global:
            parts_txt.append("global limit")
        if removed_channels:
            parts_txt.append(f"{len(removed_channels)} channel-specific limit")
        await message.answer(
            f"✅ User <code>{uid}</code> ki " + " + ".join(parts_txt) +
            " hata di. Ab default (1/hour) lagega.",
            parse_mode="HTML",
        )
    else:
        await message.answer(
            f"⚠️ User <code>{uid}</code> ki koi custom/global limit nahi thi.",
            parse_mode="HTML",
        )


# ---------------------------------------------------------------------------
# PRIVATE CHAT control panel
# ---------------------------------------------------------------------------
class BlocklistStates(StatesGroup):
    waiting_for_word = State()


def build_channel_menu(chat_id: int) -> tuple[str, InlineKeyboardMarkup]:
    info = get_channel_info(chat_id)
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="➕ Blocklist word add karo", callback_data=f"bl_add:{chat_id}")],
        [InlineKeyboardButton(text=f"📃 Blocklist dekho ({len(info.get('blocklist', []))})", callback_data=f"bl_view:{chat_id}")],
        [InlineKeyboardButton(text="➖ Word hatao", callback_data=f"bl_remove:{chat_id}")],
        [InlineKeyboardButton(text="⬅️ Wapas channel list", callback_data="back_to_list")],
    ])
    text = f"Channel: {info.get('title')}\n\nKya karna hai?"
    return text, kb


def build_super_menu() -> tuple[str, InlineKeyboardMarkup]:
    blocklist = DATA.get("global_blocklist", [])
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="➕ Global word add karo", callback_data="gbl_add")],
        [InlineKeyboardButton(text=f"📃 Global blocklist dekho ({len(blocklist)})", callback_data="gbl_view")],
        [InlineKeyboardButton(text="➖ Global word hatao", callback_data="gbl_remove")],
        [InlineKeyboardButton(text="⬅️ Wapas channel list", callback_data="back_to_list")],
    ])
    text = "🌐 Super Admin Panel -- Global Blocklist\n(Ye SABHI channels pe apply hota hai)"
    return text, kb


async def render_channel_list(target, user_id: int) -> None:
    buttons = []
    if user_id in SUPER_ADMIN_IDS:
        buttons.append([InlineKeyboardButton(text="🌐 Super Admin Panel (Global Blocklist)", callback_data="super_menu")])

    for chat_id_str, info in DATA["channels"].items():
        chat_id = int(chat_id_str)
        role = await get_user_role(chat_id, user_id)
        if role:
            tag = "👑" if role == "creator" else "🛡️"
            title = info.get("title", chat_id_str)
            buttons.append([InlineKeyboardButton(text=f"{tag} {title}", callback_data=f"menu:{chat_id}")])

    if not buttons:
        text = "Aapko kisi jaane-pehchane channel me Admin/Owner nahi mila.\nPehle bot ko us channel me Admin banao."
        kb = None
    else:
        text = "Apna channel chuno:"
        kb = InlineKeyboardMarkup(inline_keyboard=buttons)

    if isinstance(target, Message):
        await target.answer(text, reply_markup=kb)
    else:
        await target.message.edit_text(text, reply_markup=kb)


@dp.message(CommandStart(), F.chat.type == "private")
async def cmd_start(message: Message) -> None:
    await render_channel_list(message, message.from_user.id)


@dp.message(Command("myid"), F.chat.type == "private")
async def cmd_myid(message: Message) -> None:
    await message.answer(f"Aapki Telegram User ID: <code>{message.from_user.id}</code>", parse_mode="HTML")


@dp.callback_query(F.data == "back_to_list")
async def cb_back_to_list(callback: CallbackQuery) -> None:
    await render_channel_list(callback, callback.from_user.id)
    await callback.answer()


@dp.callback_query(F.data.startswith("menu:"))
async def cb_channel_menu(callback: CallbackQuery) -> None:
    chat_id = int(callback.data.split(":")[1])
    text, kb = build_channel_menu(chat_id)
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()


@dp.callback_query(F.data.startswith("bl_view:"))
async def cb_bl_view(callback: CallbackQuery) -> None:
    chat_id = int(callback.data.split(":")[1])
    blocklist = get_channel_info(chat_id).get("blocklist", [])
    text = ("Blocklist:\n" + "\n".join(f"• {w}" for w in blocklist)) if blocklist else "Blocklist khaali hai."
    kb = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="⬅️ Wapas", callback_data=f"menu:{chat_id}")]])
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()


@dp.callback_query(F.data.startswith("bl_add:"))
async def cb_bl_add(callback: CallbackQuery, state: FSMContext) -> None:
    chat_id = int(callback.data.split(":")[1])
    if not await is_owner(chat_id, callback.from_user.id):
        await callback.answer("Sirf channel ka OWNER hi blocklist word add kar sakta hai. Admin bhi nahi.", show_alert=True)
        return
    await state.update_data(target=chat_id)
    await state.set_state(BlocklistStates.waiting_for_word)
    done_kb = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="✅ Done -- menu par wapas", callback_data=f"bl_done:{chat_id}")]])
    await callback.message.edit_text(
        "Jitne words block karne hain bhej do -- ek-ek karke, ya comma/line se kai ek saath.\n\n"
        "Khatam par 'Done' dabao (ya /done bhejo).",
        reply_markup=done_kb,
    )
    await callback.answer()


@dp.callback_query(F.data.startswith("bl_done:"))
async def cb_bl_done(callback: CallbackQuery, state: FSMContext) -> None:
    chat_id = int(callback.data.split(":")[1])
    await state.clear()
    text, kb = build_channel_menu(chat_id)
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer("Done!")


async def render_remove_menu(callback: CallbackQuery, chat_id: int) -> None:
    blocklist = get_channel_info(chat_id).get("blocklist", [])
    if not blocklist:
        kb = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="⬅️ Wapas", callback_data=f"menu:{chat_id}")]])
        await callback.message.edit_text("Blocklist ab khaali hai.", reply_markup=kb)
        return
    buttons = [[InlineKeyboardButton(text=f"❌ {w}", callback_data=f"bl_rm:{chat_id}:{i}")] for i, w in enumerate(blocklist)]
    buttons.append([InlineKeyboardButton(text="⬅️ Wapas", callback_data=f"menu:{chat_id}")])
    await callback.message.edit_text("Hataane ke liye word chuno:", reply_markup=InlineKeyboardMarkup(inline_keyboard=buttons))


@dp.callback_query(F.data.startswith("bl_remove:"))
async def cb_bl_remove_menu(callback: CallbackQuery) -> None:
    chat_id = int(callback.data.split(":")[1])
    if not await is_owner(chat_id, callback.from_user.id):
        await callback.answer("Sirf OWNER hi word hata sakta hai.", show_alert=True)
        return
    await render_remove_menu(callback, chat_id)
    await callback.answer()


@dp.callback_query(F.data.startswith("bl_rm:"))
async def cb_bl_remove_word(callback: CallbackQuery) -> None:
    _, chat_id_str, idx_str = callback.data.split(":")
    chat_id = int(chat_id_str)
    idx = int(idx_str)

    if not await is_owner(chat_id, callback.from_user.id):
        await callback.answer("Sirf OWNER hi word hata sakta hai.", show_alert=True)
        return

    blocklist = get_channel_info(chat_id).get("blocklist", [])
    if 0 <= idx < len(blocklist):
        removed = blocklist.pop(idx)
        save_data()
        await callback.answer(f"'{removed}' hata diya.")
    else:
        await callback.answer("List badal chuki hai, dobara dekho.")

    await render_remove_menu(callback, chat_id)


# ---------------- GLOBAL (Super Admin) blocklist ----------------
@dp.callback_query(F.data == "super_menu")
async def cb_super_menu(callback: CallbackQuery) -> None:
    if callback.from_user.id not in SUPER_ADMIN_IDS:
        await callback.answer("Sirf Super Admin ke liye.", show_alert=True)
        return
    text, kb = build_super_menu()
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()


@dp.callback_query(F.data == "gbl_view")
async def cb_gbl_view(callback: CallbackQuery) -> None:
    if callback.from_user.id not in SUPER_ADMIN_IDS:
        await callback.answer("Sirf Super Admin ke liye.", show_alert=True)
        return
    blocklist = DATA.get("global_blocklist", [])
    text = ("Global Blocklist:\n" + "\n".join(f"• {w}" for w in blocklist)) if blocklist else "Global blocklist khaali hai."
    kb = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="⬅️ Wapas", callback_data="super_menu")]])
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()


@dp.callback_query(F.data == "gbl_add")
async def cb_gbl_add(callback: CallbackQuery, state: FSMContext) -> None:
    if callback.from_user.id not in SUPER_ADMIN_IDS:
        await callback.answer("Sirf Super Admin ke liye.", show_alert=True)
        return
    await state.update_data(target="GLOBAL")
    await state.set_state(BlocklistStates.waiting_for_word)
    done_kb = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="✅ Done -- menu par wapas", callback_data="gbl_done")]])
    await callback.message.edit_text(
        "GLOBAL blocklist words bhejo (SABHI channels pe apply hoga) -- comma/line se kai ek saath bhi.\n\n"
        "Khatam par 'Done' dabao (ya /done bhejo).",
        reply_markup=done_kb,
    )
    await callback.answer()


@dp.callback_query(F.data == "gbl_done")
async def cb_gbl_done(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    text, kb = build_super_menu()
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer("Done!")


async def render_global_remove_menu(callback: CallbackQuery) -> None:
    blocklist = DATA.get("global_blocklist", [])
    if not blocklist:
        kb = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="⬅️ Wapas", callback_data="super_menu")]])
        await callback.message.edit_text("Global blocklist khaali hai.", reply_markup=kb)
        return
    buttons = [[InlineKeyboardButton(text=f"❌ {w}", callback_data=f"gbl_rm:{i}")] for i, w in enumerate(blocklist)]
    buttons.append([InlineKeyboardButton(text="⬅️ Wapas", callback_data="super_menu")])
    await callback.message.edit_text("Hataane ke liye word chuno:", reply_markup=InlineKeyboardMarkup(inline_keyboard=buttons))


@dp.callback_query(F.data == "gbl_remove")
async def cb_gbl_remove_menu(callback: CallbackQuery) -> None:
    if callback.from_user.id not in SUPER_ADMIN_IDS:
        await callback.answer("Sirf Super Admin ke liye.", show_alert=True)
        return
    await render_global_remove_menu(callback)
    await callback.answer()


@dp.callback_query(F.data.startswith("gbl_rm:"))
async def cb_gbl_remove_word(callback: CallbackQuery) -> None:
    if callback.from_user.id not in SUPER_ADMIN_IDS:
        await callback.answer("Sirf Super Admin ke liye.", show_alert=True)
        return
    idx = int(callback.data.split(":")[1])
    blocklist = DATA.get("global_blocklist", [])
    if 0 <= idx < len(blocklist):
        removed = blocklist.pop(idx)
        save_data()
        await callback.answer(f"'{removed}' hata diya.")
    else:
        await callback.answer("List badal chuki hai.")
    await render_global_remove_menu(callback)


# ---------------- Shared word-input handler ----------------
@dp.message(BlocklistStates.waiting_for_word, F.chat.type == "private")
async def process_new_word(message: Message, state: FSMContext) -> None:
    fsm_data = await state.get_data()
    target = fsm_data.get("target")

    if target is None:
        await state.clear()
        return

    is_global = target == "GLOBAL"

    if is_global:
        if message.from_user.id not in SUPER_ADMIN_IDS:
            await message.answer("Sirf Super Admin hi global blocklist manage kar sakta hai.")
            await state.clear()
            return
        blocklist = DATA.setdefault("global_blocklist", [])
        done_cb = "gbl_done"
    else:
        chat_id = target
        if not await is_owner(chat_id, message.from_user.id):
            await message.answer("Sirf channel ka OWNER hi blocklist word add kar sakta hai.")
            await state.clear()
            return
        info = get_channel_info(chat_id)
        blocklist = info.setdefault("blocklist", [])
        done_cb = f"bl_done:{chat_id}"

    raw_text = message.text or ""
    parts = [p.strip().lower() for line in raw_text.splitlines() for p in line.split(",")]
    words = [w for w in parts if w]

    done_kb = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="✅ Done -- menu par wapas", callback_data=done_cb)]])

    if not words:
        await message.answer("Khaali message hai, dobara try karo ya 'Done' dabao.", reply_markup=done_kb)
        return

    added, skipped = [], []
    for w in words:
        if w in blocklist:
            skipped.append(w)
        else:
            blocklist.append(w)
            added.append(w)

    if added:
        save_data_async()

    reply_lines = []
    if added:
        reply_lines.append("✅ Add ho gaya: " + ", ".join(added))
    if skipped:
        reply_lines.append("⏭ Pehle se tha: " + ", ".join(skipped))
    reply_lines.append("\nAur word bhejo, ya 'Done' dabao khatam karne ke liye.")

    await message.answer("\n".join(reply_lines), reply_markup=done_kb)


@dp.message(Command("done"), F.chat.type == "private")
async def cmd_done(message: Message, state: FSMContext) -> None:
    fsm_data = await state.get_data()
    target = fsm_data.get("target")
    await state.clear()
    if target == "GLOBAL":
        text, kb = build_super_menu()
        await message.answer(text, reply_markup=kb)
    elif target:
        text, kb = build_channel_menu(target)
        await message.answer(text, reply_markup=kb)
    else:
        await message.answer("Done! /start bhejo channel list ke liye.")


@dp.message(Command("cancel"), F.chat.type == "private")
async def cmd_cancel(message: Message, state: FSMContext) -> None:
    fsm_data = await state.get_data()
    target = fsm_data.get("target")
    await state.clear()
    if target == "GLOBAL":
        text, kb = build_super_menu()
        await message.answer(text, reply_markup=kb)
    elif target:
        text, kb = build_channel_menu(target)
        await message.answer(text, reply_markup=kb)
    else:
        await message.answer("Cancel kar diya.")


# ---------------------------------------------------------------------------
async def main() -> None:
    if not BOT_TOKEN:
        print("❌ BOT_TOKEN environment variable set nahi hai!")
        print("   Render.com Dashboard -> Environment -> BOT_TOKEN set karo.")
        return
    load_data()
    asyncio.create_task(admin_cache_refresher())
    asyncio.create_task(keep_alive_task())
    log.info("Bot chalu ho gaya. Naye channel posts + PM commands ka wait kar raha hai...")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())