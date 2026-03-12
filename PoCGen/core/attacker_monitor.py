from __future__ import annotations

import argparse
import json
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional, Tuple
from urllib.parse import urlparse, urlunparse, parse_qs
import errno

import httpx

from rich.console import Console

MONITOR_LISTEN_HOST = "0.0.0.0"
MONITOR_LOOPBACK_HOST = "127.0.0.1"
MONITOR_PORT = 6666


def get_monitor_base_url() -> str:
    return f"http://{MONITOR_LOOPBACK_HOST}:{MONITOR_PORT}"


console = Console()


class _MonitorHandler(BaseHTTPRequestHandler):
    server_version = "PoCGenAttackerMonitor/1.0"

    def do_GET(self):
        # Status probe endpoint for external processes to reuse the same monitor.
        if self.path.startswith("/_status"):
            self.server.parent.handle_status(self)
            return

        self.server.parent.record_hit(self)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        body = b"OK"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(length) if length > 0 else b""
        self.do_GET()

    def log_message(self, format: str, *args):
        # Suppress default logging to stderr; handled by monitor
        return


class AttackerMonitor:
    def __init__(self, url: Optional[str], timeout: float) -> None:
        parsed = urlparse(url) if url else None
        self.listen_host = MONITOR_LISTEN_HOST
        self.listen_port = MONITOR_PORT
        if parsed and parsed.hostname:
            # Allow overriding via explicit URL when running standalone CLI.
            self.listen_host = parsed.hostname
        if parsed and parsed.port:
            self.listen_port = parsed.port
        self.timeout = timeout
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._event = threading.Event()
        self.last_request_summary: Optional[str] = None
        self.last_hit_ts: Optional[float] = None
        self._reused_existing = False

    def start(self) -> None:
        try:
            self._server = ThreadingHTTPServer((self.listen_host, self.listen_port), _MonitorHandler)
        except OSError as exc:
            if exc.errno == errno.EADDRINUSE and monitor_available(get_monitor_base_url()):
                console.print(f"[cyan]Attacker monitor already running on {get_monitor_base_url()}, reusing existing instance")
                self._reused_existing = True
                self._server = None
                return
            console.print(f"[yellow]Warning: failed to start attacker monitor on {self.listen_host}:{self.listen_port}: {exc}")
            self._server = None
            return
        self._server.parent = self
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        console.print(f"[green]Attacker monitor listening on http://{self.listen_host}:{self.listen_port}")

    def is_running(self) -> bool:
        return self._server is not None or self._reused_existing

    def record_hit(self, handler: _MonitorHandler) -> None:
        remote_ip, remote_port = handler.client_address if handler.client_address else ("?", "?")
        self.last_hit_ts = time.time()
        ts_iso = datetime.fromtimestamp(self.last_hit_ts).isoformat()
        summary = (
            f"Time: {ts_iso}\n"
            f"{handler.command} {handler.path}\n"
            f"Remote: {remote_ip}:{remote_port}\n"
            + "\n".join(f"{k}: {v}" for k, v in handler.headers.items())
        )
        self.last_request_summary = summary
        self._event.set()
        console.print(f"[bold green]Attacker monitor received request:[/bold green]\n{summary}")

    def handle_status(self, handler: _MonitorHandler) -> None:
        # Expose hit state over HTTP so other processes can reuse an existing monitor.
        parsed = urlparse(handler.path)
        params = parse_qs(parsed.query)
        clear = params.get("clear", ["0"])[0] in {"1", "true", "yes"}
        hit = self._event.is_set()
        body = json.dumps(
            {
                "ok": True,
                "hit": hit,
                "hit_time": self.last_hit_ts or 0,
                "summary": self.last_request_summary or "",
            }
        ).encode("utf-8")
        if clear:
            self._event.clear()
            self.last_request_summary = None
            self.last_hit_ts = None

        handler.send_response(200)
        handler.send_header("Content-Type", "application/json; charset=utf-8")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)

    def wait_for_hit(self, timeout: Optional[float] = None) -> bool:
        if self._server:
            wait_timeout = self.timeout if timeout is None else timeout
            hit = self._event.wait(wait_timeout)
            if hit:
                self._event.clear()
            return hit
        if self._reused_existing:
            hit, summary = wait_for_external_monitor(get_monitor_base_url(), timeout or self.timeout)
            if hit:
                self.last_request_summary = summary
            return hit
        return False

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1)
        self._thread = None
        self._event.clear()
        self._reused_existing = False


def _status_url(base_url: Optional[str]) -> str:
    if not base_url:
        base_url = get_monitor_base_url()
    parsed = urlparse(base_url)
    scheme = parsed.scheme or "http"
    host = parsed.hostname or MONITOR_LOOPBACK_HOST
    port = parsed.port or (443 if scheme == "https" else MONITOR_PORT)
    return urlunparse((scheme, f"{host}:{port}", "/_status", "", "", ""))


def monitor_available(url: Optional[str] = None, timeout: float = 1.0) -> bool:
    """Check if a monitor is already running at the local monitor URL."""
    status_url = _status_url(url)
    try:
        resp = httpx.get(status_url, timeout=timeout, verify=False)
        return resp.status_code == 200 and resp.json().get("ok") is True
    except Exception:
        return False


def reset_external_monitor(url: Optional[str] = None, timeout: float = 1.0) -> bool:
    """Clear any prior hit state on an existing monitor."""
    status_url = _status_url(url)
    try:
        resp = httpx.get(status_url, params={"clear": "1"}, timeout=timeout, verify=False)
        return resp.status_code == 200
    except Exception:
        return False


def wait_for_external_monitor(
    url: Optional[str], timeout: float, poll_interval: float = 1.0, since_ts: Optional[float] = None
) -> Tuple[bool, Optional[str]]:
    """Poll an already-running monitor for a hit within timeout, optionally only after since_ts (epoch seconds)."""
    status_url = _status_url(url)
    deadline = time.time() + timeout
    last_summary: Optional[str] = None
    while time.time() < deadline:
        try:
            resp = httpx.get(status_url, params={"clear": "1"}, timeout=timeout, verify=False)
            if resp.status_code == 200:
                data = resp.json()
                last_summary = data.get("summary") or None
                hit_time = data.get("hit_time") or 0
                if data.get("hit") and (since_ts is None or hit_time >= since_ts):
                    return True, last_summary
        except Exception:
            pass
        time.sleep(poll_interval)
    return False, last_summary


__all__ = [
    "AttackerMonitor",
    "get_monitor_base_url",
    "monitor_available",
    "reset_external_monitor",
    "wait_for_external_monitor",
]


def _cli():
    parser = argparse.ArgumentParser(description="Run a standalone attacker monitor HTTP server")
    parser.add_argument("--url", default="http://0.0.0.0:6666", help="Listen URL, e.g., http://0.0.0.0:6666")
    parser.add_argument("--timeout", type=float, default=3600.0, help="Idle timeout used only for wait_for_hit (not shutdown)")
    args = parser.parse_args()

    monitor = AttackerMonitor(args.url, timeout=args.timeout)
    monitor.start()
    if not monitor.is_running():
        console.print("[red]Monitor failed to start. Check bind address/port permissions.[/red]")
        return

    try:
        console.print("[cyan]Press Ctrl+C to stop the monitor[/cyan]")
        # Keep the main thread alive while the HTTP server runs in background thread.
        while True:
            threading.Event().wait(3600)
    except KeyboardInterrupt:
        console.print("[yellow]Stopping monitor...[/yellow]")
    finally:
        monitor.stop()


if __name__ == "__main__":
    _cli()
