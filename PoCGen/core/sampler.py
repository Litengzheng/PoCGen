from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from playwright.sync_api import sync_playwright

from PoCGen.config.config import SETTINGS
from PoCGen.core.logger import _append_login_chat, _create_login_chat_file, _log
from PoCGen.core.login_flow import (
    LoginResult,
    normalize_url,
    perform_login_interaction,
    wait_for_page_idle,
    wait_for_url_change,
)
from PoCGen.core.target_profile import TargetSample
from PoCGen.core.proxy import SocketCaptureProxy


PROJECT_ROOT = Path(__file__).resolve().parent.parent
REQUEST_LOG_DIR = str(PROJECT_ROOT / "output" / "http_post_sample")
SOCKET_SAMPLE_DIR = str(PROJECT_ROOT / "output" / "socket_sample")
SOCKET_PACKAGE_DIR = str(PROJECT_ROOT / "output" / "socket_package")


def _ensure_dir(path: str) -> None:
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        pass


def _safe_str_body(payload: Any, limit: int = 8000) -> str:
    try:
        if payload is None:
            return ""
        if isinstance(payload, memoryview):
            payload = payload.tobytes()
        if isinstance(payload, (bytes, bytearray)):
            return payload.decode("latin-1", errors="replace")[:limit]
        return str(payload)[:limit]
    except Exception:
        return ""


def _setup_network_logging(
    context,
    tag: str = "login",
    post_collector: Optional[List[str]] = None,
    socket_collector: Optional[List[str]] = None,
    log_socket_requests: bool = False,
    request_log_dir: Optional[str] = None,
    socket_filter_dir: Optional[str] = None,
) -> None:
    """Attach Playwright hooks and dump raw HTTP traffic to disk."""

    log_dir = request_log_dir or REQUEST_LOG_DIR
    _ensure_dir(log_dir)
    if socket_filter_dir:
        _ensure_dir(socket_filter_dir)

    seq = {"n": 0}
    state = {"post_saved": False, "socket_sample_saved": False}

    def _on_request(request: Any) -> None:
        try:
            method = (request.method or "").upper()
            if not log_socket_requests and method != "POST":
                return

            seq["n"] += 1
            req_id = seq["n"]
            ts = time.strftime("%Y%m%d_%H%M%S", time.localtime())

            raw_headers = []
            headers_array = getattr(request, "headers_array", None)
            if headers_array:
                try:
                    raw_headers = list(headers_array or [])
                except Exception:
                    raw_headers = []
            if not raw_headers:
                headers_value = getattr(request, "headers", {}) or {}
                if callable(headers_value):
                    try:
                        headers_value = headers_value()
                    except Exception:
                        headers_value = {}
                if isinstance(headers_value, dict):
                    raw_headers = list(headers_value.items())

            parsed = urlparse(request.url or "")
            path_q = parsed.path or "/"
            if parsed.query:
                path_q += f"?{parsed.query}"

            is_websocket = any(
                name.lower() == "upgrade" and "websocket" in (value or "").lower()
                for name, value in raw_headers
            )
            request_line = f"{method} {path_q} HTTP/1.1"
            if is_websocket and parsed.scheme in {"http", "https"}:
                scheme = "ws" if parsed.scheme == "http" else "wss"
                host_mount = parsed.netloc or ""
                request_line = f"{method} {scheme}://{host_mount}{path_q} HTTP/1.1"

            has_host = any(name.lower() == "host" for name, _ in raw_headers)
            if not has_host and parsed.netloc:
                raw_headers.insert(0, ("Host", parsed.netloc))

            payload = getattr(request, "post_data_buffer", None)
            if payload is None:
                payload = getattr(request, "post_data", None)
            body = _safe_str_body(payload)

            lines: List[str] = [request_line]
            for name, value in raw_headers:
                if value is None:
                    continue
                lines.append(f"{name}: {value}")
            lines.append("")
            if body:
                lines.append(body)
            content = "\n".join(lines)

            write_reason: Optional[str] = None
            content_lower = content.lower()
            is_socket_match = is_websocket and "socket" in content_lower

            if log_socket_requests:
                if is_socket_match and not state["socket_sample_saved"]:
                    state["socket_sample_saved"] = True
                    write_reason = "socket"
            else:
                if method == "POST" and not state["post_saved"]:
                    state["post_saved"] = True
                    write_reason = "post"

            fname = None
            if write_reason:
                fname = os.path.join(log_dir, f"{tag}_{ts}_{req_id:04d}.http")
                with open(fname, "w", encoding="utf-8", errors="replace") as fh:
                    fh.write(content)

            if write_reason == "post" and post_collector is not None:
                post_collector.append(content)
            if write_reason == "socket":
                if socket_collector is not None:
                    socket_collector.append(content)
                if socket_filter_dir and fname:
                    try:
                        filtered = os.path.join(socket_filter_dir, os.path.basename(fname))
                        with open(filtered, "w", encoding="utf-8", errors="replace") as fh:
                            fh.write(content)
                    except Exception as exc:
                        _log(f"socket filter write failed: {exc}")

            if fname:
                if log_socket_requests:
                    _log(f"Socket sample saved {fname} url={request.url}")
                else:
                    _log(f"POST sample saved {fname} url={request.url}")
        except Exception as exc:
            _log(f"network log hook failed: {exc}")

    try:
        context.on("request", _on_request)
        _log(f"network logging attached tag={tag} dir={log_dir} sockets={log_socket_requests}")
    except Exception as exc:
        _log(f"attach network logging failed: {exc}")


def _save_cookies(context, tag: str) -> Optional[str]:
    try:
        cookies_dir = getattr(SETTINGS, "cookie_dir", None) or os.path.normpath(
            os.path.join(os.path.dirname(__file__), "..", "cookie")
        )
        _ensure_dir(cookies_dir)

        ck = context.cookies()
        payload = {"tag": tag, "cookies": ck}
        ts = time.strftime("%Y%m%d_%H%M%S", time.localtime())
        fname = os.path.join(cookies_dir, f"cookies_{tag}_{ts}.json")
        with open(fname, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        _log(f"saved cookies to {fname}")
        pairs = []
        for item in ck or []:
            name = item.get("name")
            value = item.get("value")
            if name is None or value is None:
                continue
            pairs.append(f"{name}={value}")
        return "; ".join(pairs) if pairs else None
    except Exception as exc:
        _log(f"save cookies failed: {exc}")
        return None


def sample_target_with_playwright(
    target: str,
    login_url: Optional[str] = None,
    login_username: Optional[str] = None,
    login_password: Optional[str] = None,
    login_user_field: str = "username",
    login_pass_field: str = "password",
    headless: Optional[bool] = None,
    preview_chars: Optional[int] = None,
    capture_posts: bool = True,
    capture_cookies: bool = True,
    capture_socket_messages: bool = True,
) -> TargetSample:
    """Use Playwright to optionally log in and capture the target page."""

    headless_flag = headless
    if headless_flag is None:
        headless_flag = str(getattr(SETTINGS, "browser_headless", "true")).lower() not in {"0", "false", "no", "off"}

    login_page = login_url or urljoin(target.rstrip("/") + "/", "login")
    preview_len = preview_chars or SETTINGS.sample_preview_chars
    _ = login_user_field
    _ = login_pass_field

    captured_posts: List[str] = []
    captured_cookie_header: Optional[str] = None
    captured_socket_messages: List[str] = []
    log_socket_requests = False
    proxy: Optional[SocketCaptureProxy] = None
    proxy_url: Optional[str] = None

    login_chat_path = _create_login_chat_file()
    if login_chat_path:
        password_state = "<provided>" if login_password else "<none>"
        username_state = login_username if login_username is not None else "<none>"
        _append_login_chat(
            login_chat_path,
            "system",
            f"Target: {target}\nLogin URL: {login_page}\nCredentials: username={username_state} password={password_state}",
        )

    with sync_playwright() as p:
        browser = None
        context = None
        page = None
        try:
            if capture_socket_messages:
                proxy = SocketCaptureProxy(output_dir=SOCKET_SAMPLE_DIR)
                proxy.start()
                proxy_url = proxy.server_url
                _log(f"socket capture proxy started at {proxy_url}")

            browser = p.chromium.launch(
                headless=headless_flag,
                proxy={"server": proxy_url} if proxy_url else None,
            )
            context = browser.new_context(ignore_https_errors=True)
            if capture_posts:
                post_collector = captured_posts if capture_posts else None
                _setup_network_logging(
                    context,
                    tag="login_flow",
                    post_collector=post_collector,
                    socket_collector=None,
                    log_socket_requests=False,
                    request_log_dir=REQUEST_LOG_DIR,
                    socket_filter_dir=None,
                )
            page = context.new_page()

            _log(f"open {login_page}")
            page.goto(login_page, wait_until="networkidle", timeout=5000)
            wait_for_page_idle(page, "login page load", total_timeout=20000)

            if login_username is None and login_password is None:
                login_result = LoginResult(None, None, "no-login", False, None)
            else:
                login_result = perform_login_interaction(page, login_username, login_password, login_chat_path)
                if login_result.clicked_login:
                    wait_for_url_change(
                        page,
                        login_result.pre_login_url,
                        "post-login url change",
                        total_timeout=35000,
                    )
                    wait_for_page_idle(page, "post-login transition", total_timeout=35000)

            resp = None
            cur_url = page.url
            _log(f"post-login current url: {cur_url}")
            try:
                page.wait_for_selector("form, button, input, body", timeout=8000)
            except Exception:
                _log("post-login wait_for_selector timeout; continuing")

            try:
                cur = urlparse(cur_url)
                tgt = urlparse(target)
                same_host = cur.netloc == tgt.netloc
                same_prefix = cur.geturl().rstrip("/").startswith(tgt.geturl().rstrip("/"))
            except Exception:
                same_host = False
                same_prefix = False

            normalized_login_url = normalize_url(login_page)
            normalized_post_url = normalize_url(cur_url)
            if normalized_login_url and normalized_post_url == normalized_login_url:
                _log("post-login url matches login page; login may have failed")

            if same_host and same_prefix:
                _log("already on target host/path after login; reuse current page")
                wait_for_page_idle(page, "post-login reuse", total_timeout=25000)
                try:
                    page.wait_for_selector("form, button, input, body", timeout=8000)
                except Exception:
                    _log("post-login reuse wait_for_selector timeout; continuing")
            else:
                _log(f"goto target {target}")
                resp = page.goto(target, wait_until="networkidle", timeout=25000)
                wait_for_page_idle(page, "target navigation", total_timeout=25000)

            if capture_socket_messages:
                linger_ms = getattr(SETTINGS, "socket_sample_linger_ms", 4000)
                if linger_ms and linger_ms > 0:
                    _log(f"socket sampling linger {linger_ms}ms before harvesting DOM")
                    try:
                        page.wait_for_timeout(linger_ms)
                    except Exception:
                        pass

            if capture_cookies:
                try:
                    captured_cookie_header = _save_cookies(context, "post_login")
                except Exception:
                    captured_cookie_header = None
            html = page.content()
            status_code = resp.status if resp else 0
            headers = resp.headers if resp else {}
            _log(f"target status={status_code} headers={list(headers.keys()) if headers else []}")
        finally:
            if browser:
                browser.close()
            if proxy:
                proxy.stop()
                captured_socket_messages = proxy.get_samples()
                _log(f"socket capture proxy collected {len(captured_socket_messages)} sample(s)")

    body = html
    if len(body) > preview_len:
        preview = body[:preview_len] + "\n... <truncated>"
    else:
        preview = body

    header_lines = []
    for name, value in headers.items():
        header_lines.append(f"{name}: {value}")
        if len("\n".join(header_lines)) > preview_len:
            break
    headers_str = "\n".join(header_lines)

    user_descriptor = login_result.user_entry["descriptor"] if login_result.user_entry else "<none>"
    pass_descriptor = login_result.pass_entry["descriptor"] if login_result.pass_entry else "<none>"
    strategy_label = login_result.login_scenario if (login_username or login_password) else "no-login"
    artifacts_line = (
        f"Captured artifacts -> POST:{len(captured_posts)} Cookie:{'yes' if captured_cookie_header else 'no'} Socket:{len(captured_socket_messages)}"
    )
    request_template = (
        "PLAYWRIGHT GET (rendered page)\n"
        f"Target: {target}\n"
        f"Login URL: {login_page}\n"
        f"Headless: {headless_flag}\n"
        f"Login strategy: {strategy_label}\n"
        f"Detected fields: user={user_descriptor} pass={pass_descriptor}\n"
        f"{artifacts_line}"
    )

    return TargetSample(
        url=target,
        status_code=status_code or 0,
        content_type=headers.get("content-type") if headers else None,
        encoding="utf-8",
        body_preview=preview,
        request_template=request_template,
        response_headers=headers_str,
        post_samples=captured_posts,
        cookies_header=captured_cookie_header if capture_cookies else None,
        socket_samples=captured_socket_messages,
    )
