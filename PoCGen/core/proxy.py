from __future__ import annotations

import os
import socket
import socketserver
import threading
import time
import select
from dataclasses import dataclass
from typing import List, Optional, Tuple
from urllib.parse import urlparse


@dataclass
class CaptureRecord:
    raw_bytes: bytes
    saved_path: Optional[str]


class _CaptureBuffer:
    def __init__(self, keyword: bytes, max_bytes: int) -> None:
        self._keyword = keyword.lower()
        self._max_bytes = max_bytes
        self._chunks: List[bytes] = []
        self._size = 0
        self._matched = False

    def add(self, direction: str, data: bytes) -> None:
        if not data:
            return
        if self._keyword in data.lower():
            self._matched = True
        if self._size >= self._max_bytes:
            return
        prefix = f"\n--- {direction} ---\n".encode("utf-8")
        to_add = prefix + data
        remaining = self._max_bytes - self._size
        if len(to_add) > remaining:
            to_add = to_add[:remaining]
        self._chunks.append(to_add)
        self._size += len(to_add)

    @property
    def matched(self) -> bool:
        return self._matched

    def render(self) -> bytes:
        return b"".join(self._chunks)


class _ProxyServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


class _ProxyRequestHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        proxy = getattr(self.server, "capture_proxy", None)
        if proxy is None:
            return

        capture = _CaptureBuffer(proxy.keyword, proxy.max_capture_bytes)
        try:
            initial = self._recv_until_headers(self.request)
            if not initial:
                return
            capture.add("CLIENT->PROXY", initial)
            method, target, version = self._parse_request_line(initial)
            if not method or not target:
                return

            if method.upper() == "CONNECT":
                host, port = self._parse_connect_target(target)
                if not host:
                    return
                upstream = self._connect_upstream(host, port)
                if not upstream:
                    return
                try:
                    self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                except Exception:
                    upstream.close()
                    return
                self._relay(self.request, upstream, b"", capture)
            else:
                host, port, rewritten = self._rewrite_request(initial, target)
                if not host:
                    return
                upstream = self._connect_upstream(host, port)
                if not upstream:
                    return
                self._relay(self.request, upstream, rewritten, capture)
        finally:
            if capture.matched:
                proxy.record_capture(capture.render())

    def _recv_until_headers(self, sock: socket.socket, limit: int = 262144) -> bytes:
        data = b""
        while b"\r\n\r\n" not in data and len(data) < limit:
            chunk = sock.recv(8192)
            if not chunk:
                break
            data += chunk
        return data

    def _parse_request_line(self, data: bytes) -> Tuple[str, str, str]:
        try:
            line = data.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
            parts = line.split()
            if len(parts) < 3:
                return "", "", ""
            return parts[0], parts[1], parts[2]
        except Exception:
            return "", "", ""

    def _parse_connect_target(self, target: str) -> Tuple[str, int]:
        if ":" not in target:
            return "", 0
        host, port_str = target.rsplit(":", 1)
        try:
            port = int(port_str)
        except Exception:
            port = 443
        return host, port

    def _connect_upstream(self, host: str, port: int) -> Optional[socket.socket]:
        try:
            upstream = socket.create_connection((host, port), timeout=10)
            return upstream
        except Exception:
            return None

    def _rewrite_request(self, initial: bytes, target: str) -> Tuple[str, int, bytes]:
        headers_end = initial.find(b"\r\n\r\n")
        if headers_end == -1:
            headers_end = len(initial)
        header_block = initial[:headers_end].decode("latin-1", errors="replace")
        body = initial[headers_end + 4 :] if headers_end + 4 <= len(initial) else b""

        lines = header_block.split("\r\n")
        if not lines:
            return "", 0, initial

        request_line = lines[0]
        parts = request_line.split()
        if len(parts) < 3:
            return "", 0, initial
        method, raw_target, version = parts[0], parts[1], parts[2]

        parsed = (
            urlparse(raw_target)
            if raw_target.startswith(("http://", "https://", "ws://", "wss://"))
            else None
        )
        host = ""
        port = 80
        path = raw_target
        if parsed:
            host = parsed.hostname or ""
            port = parsed.port or (443 if parsed.scheme in {"https", "wss"} else 80)
            path = parsed.path or "/"
            if parsed.query:
                path += f"?{parsed.query}"
        else:
            host_header = ""
            for line in lines[1:]:
                if line.lower().startswith("host:"):
                    host_header = line.split(":", 1)[1].strip()
                    break
            if host_header:
                if ":" in host_header:
                    host, port_str = host_header.rsplit(":", 1)
                    try:
                        port = int(port_str)
                    except Exception:
                        port = 80
                else:
                    host = host_header
                    port = 80

        if not host:
            return "", 0, initial

        new_request_line = f"{method} {path} {version}"
        lines[0] = new_request_line
        rebuilt = ("\r\n".join(lines)).encode("latin-1") + b"\r\n\r\n" + body
        return host, port, rebuilt

    def _relay(self, client: socket.socket, upstream: socket.socket, initial_to_upstream: bytes, capture: _CaptureBuffer) -> None:
        try:
            if initial_to_upstream:
                upstream.sendall(initial_to_upstream)
        except Exception:
            upstream.close()
            return

        client.setblocking(False)
        upstream.setblocking(False)
        sockets = [client, upstream]
        try:
            while True:
                readable, _, _ = select.select(sockets, [], [], 10)
                if not readable:
                    continue
                for sock in readable:
                    try:
                        data = sock.recv(65535)
                    except Exception:
                        data = b""
                    if not data:
                        return
                    if sock is client:
                        capture.add("CLIENT->SERVER", data)
                        try:
                            upstream.sendall(data)
                        except Exception:
                            return
                    else:
                        capture.add("SERVER->CLIENT", data)
                        try:
                            client.sendall(data)
                        except Exception:
                            return
        finally:
            try:
                client.close()
            except Exception:
                pass
            try:
                upstream.close()
            except Exception:
                pass


class SocketCaptureProxy:
    def __init__(
        self,
        output_dir: str,
        keyword: str = "socket",
        listen_host: str = "127.0.0.1",
        listen_port: int = 0,
        max_capture_bytes: int = 200000,
        max_samples: int = 1,
    ) -> None:
        self.output_dir = output_dir
        self.keyword = keyword.encode("utf-8", errors="ignore")
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.max_capture_bytes = max_capture_bytes
        self.max_samples = max_samples

        self._server: Optional[_ProxyServer] = None
        self._thread: Optional[threading.Thread] = None
        self._samples: List[str] = []
        self._lock = threading.Lock()
        self._counter = 0

    @property
    def server_url(self) -> Optional[str]:
        if not self._server:
            return None
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> None:
        os.makedirs(self.output_dir, exist_ok=True)
        self._server = _ProxyServer((self.listen_host, self.listen_port), _ProxyRequestHandler)
        self._server.capture_proxy = self
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1)
        self._thread = None

    def record_capture(self, payload: bytes) -> Optional[CaptureRecord]:
        if not payload:
            return None
        with self._lock:
            if self._samples:
                return None
            if len(self._samples) >= self.max_samples:
                return None
            self._counter += 1
            ts = time.strftime("%Y%m%d_%H%M%S", time.localtime())
            fname = f"socket_proxy_{ts}_{self._counter:04d}.log"
            fpath = os.path.join(self.output_dir, fname)
            try:
                with open(fpath, "wb") as fh:
                    fh.write(payload)
                text = payload.decode("latin-1", errors="replace")
                self._samples.append(text)
                return CaptureRecord(raw_bytes=payload, saved_path=fpath)
            except Exception:
                return None

    def get_samples(self) -> List[str]:
        with self._lock:
            return list(self._samples)


__all__ = ["SocketCaptureProxy"]
