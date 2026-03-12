from __future__ import annotations

from datetime import datetime, timezone, timedelta
import os
from pathlib import Path
from typing import Optional

LOG_DIR: Optional[str] = None
LOG_FILE: Optional[str] = None
LOG_NEEDS_SEPARATOR = False
PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOGIN_CHAT_DIR = PROJECT_ROOT / "logs" / "login_chat"


def _ensure_log() -> None:
    global LOG_DIR, LOG_FILE, LOG_NEEDS_SEPARATOR
    if LOG_DIR:
        return
    LOG_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "logs"))
    os.makedirs(LOG_DIR, exist_ok=True)
    LOG_FILE = os.path.join(LOG_DIR, "playwright_probe.log")
    LOG_NEEDS_SEPARATOR = True


_STDOUT_KEYWORDS = (
    "POST sample saved",
    "Socket sample saved",
    "saved cookies to",
    "socket capture proxy collected",
)


def _log(message: str) -> None:
    global LOG_NEEDS_SEPARATOR
    try:
        _ensure_log()
        tz = timezone(timedelta(hours=8))
        ts = datetime.now(tz).strftime("%Y-%m-%dT%H:%M:%S")
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            if LOG_NEEDS_SEPARATOR:
                fh.write("\n")
                LOG_NEEDS_SEPARATOR = False
            fh.write(f"[{ts}] {message}\n")
        if any(keyword in message for keyword in _STDOUT_KEYWORDS):
            print(message, flush=True)
    except Exception:
        pass


def _ensure_login_chat_dir() -> None:
    try:
        LOGIN_CHAT_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


def _create_login_chat_file(prefix: str = "login_chat") -> Optional[Path]:
    try:
        _ensure_login_chat_dir()
        tz = timezone(timedelta(hours=8))
        ts = datetime.now(tz).strftime("%Y%m%d_%H%M")
        base_name = f"{prefix}_{ts}"
        path = LOGIN_CHAT_DIR / f"{base_name}.log"
        counter = 1
        while path.exists():
            counter += 1
            path = LOGIN_CHAT_DIR / f"{base_name}_{counter}.log"
        path.touch()
        return path
    except Exception as exc:
        _log(f"login chat file create failed: {exc}")
        return None


def _append_login_chat(path: Optional[Path], role: str, content: str) -> None:
    if not path:
        return
    try:
        tz = timezone(timedelta(hours=8))
        ts = datetime.now(tz).strftime("%Y-%m-%d %H:%M")
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"[{ts}] {role.upper()}:\n{content}\n\n")
    except Exception as exc:
        _log(f"login chat write failed: {exc}")
