from __future__ import annotations

import json
import ssl
import time
from pathlib import Path
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

import websocket

PayloadType = Union[str, Dict[str, Any], List[Any]]


@dataclass
class SocketSendResult:
    """Structured response for a Socket.IO dispatch."""

    handshake: Optional[str]
    ready: Optional[str]
    responses: List[str]


class SocketIOSender:
    """Minimal Socket.IO client for dispatching crafted events."""

    def __init__(
        self,
        url: str,
        namespace: Optional[str] = None,
        timeout: float = 10.0,
        headers: Optional[Dict[str, str]] = None,
        verify_ssl: bool = False,
    ) -> None:
        self.url = url
        self.namespace = namespace or ""
        self.timeout = timeout
        self.headers = headers or {}
        self.verify_ssl = verify_ssl

    def _build_header_list(self, cookies: Optional[str]) -> List[str]:
        blocked = {
            "host",
            "connection",
            "upgrade",
            "sec-websocket-version",
            "sec-websocket-key",
            "sec-websocket-extensions",
            "sec-websocket-protocol",
            "cookie",
        }
        header_list = [
            f"{k}: {v}"
            for k, v in self.headers.items()
            if k and k.lower() not in blocked
        ]
        if cookies:
            header_list.append(f"Cookie: {cookies}")
        return header_list

    def _ssl_options(self) -> Optional[Dict[str, Any]]:
        scheme = urlparse(self.url).scheme.lower()
        if scheme != "wss":
            return None
        if self.verify_ssl:
            return {}
        return {"cert_reqs": ssl.CERT_NONE}

    def _log_raw_frame(self, label: str, frame_text: str) -> None:
        try:
            log_dir = Path(__file__).resolve().parents[3] / "logs"
            log_dir.mkdir(parents=True, exist_ok=True)
            log_path = log_dir / "socket_send_raw.log"
            ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())
            frame_bytes = frame_text.encode("utf-8", errors="replace")
            try:
                frame = websocket.ABNF.create_frame(frame_text, websocket.ABNF.OPCODE_TEXT)
                raw_bytes = frame.format()
                raw_hex = raw_bytes.hex()
            except Exception:
                raw_hex = ""
            with open(log_path, "a", encoding="utf-8") as fh:
                fh.write(f"[{ts}] {label} url={self.url}\n")
                fh.write(f"text={frame_text}\n")
                fh.write(f"text_bytes_len={len(frame_bytes)}\n")
                if raw_hex:
                    fh.write(f"frame_hex={raw_hex}\n")
                fh.write("\n")
        except Exception:
            pass

    def _build_handshake_frame(self) -> str:
        if self.namespace:
            return f"40/{self.namespace.lstrip('/') }"
        return "40"

    def _build_event_frame(self, event: str, payload: str) -> str:
        if self.namespace:
            return f"42/{self.namespace.lstrip('/') },[\"{event}\",{payload}]"
        return f"42[\"{event}\",{payload}]"

    @staticmethod
    def _serialize_payload(payload: PayloadType) -> str:
        if isinstance(payload, str):
            return payload
        return json.dumps(payload, separators=(",", ":"))

    def send_event(
        self,
        event: str,
        payload: PayloadType,
        cookies: Optional[str] = None,
        wait_for_response: bool = True,
        max_response_frames: int = 1,
    ) -> SocketSendResult:
        """Send a single Socket.IO event and optional response collection."""

        header_list = self._build_header_list(cookies)
        sslopt = self._ssl_options()
        ws = websocket.create_connection(
            self.url,
            timeout=self.timeout,
            header=header_list if header_list else None,
            sslopt=sslopt,
        )
        result = SocketSendResult(handshake=None, ready=None, responses=[])
        try:
            try:
                result.handshake = ws.recv()
            except websocket.WebSocketTimeoutException:
                result.handshake = None
            handshake_frame = self._build_handshake_frame()
            self._log_raw_frame("send_handshake", handshake_frame)
            ws.send(handshake_frame)
            try:
                result.ready = ws.recv()
            except websocket.WebSocketTimeoutException:
                result.ready = None
            event_frame = self._build_event_frame(event, self._serialize_payload(payload))
            self._log_raw_frame("send_event", event_frame)
            ws.send(event_frame)
            if wait_for_response:
                frames = 0
                while frames < max_response_frames:
                    try:
                        message = ws.recv()
                    except websocket.WebSocketTimeoutException:
                        break
                    except websocket.WebSocketConnectionClosedException:
                        break
                    if message is None:
                        break
                    result.responses.append(message)
                    frames += 1
        finally:
            try:
                ws.close()
            except Exception:
                pass
        return result

    def send_frame(
        self,
        frame: str,
        cookies: Optional[str] = None,
        wait_for_response: bool = True,
        max_response_frames: int = 1,
    ) -> SocketSendResult:
        """Send a raw Socket.IO text frame (e.g., '42[...]')."""

        header_list = self._build_header_list(cookies)
        sslopt = self._ssl_options()
        ws = websocket.create_connection(
            self.url,
            timeout=self.timeout,
            header=header_list if header_list else None,
            sslopt=sslopt,
        )
        result = SocketSendResult(handshake=None, ready=None, responses=[])
        try:
            try:
                result.handshake = ws.recv()
            except websocket.WebSocketTimeoutException:
                result.handshake = None
            handshake_frame = self._build_handshake_frame()
            self._log_raw_frame("send_handshake", handshake_frame)
            ws.send(handshake_frame)
            try:
                result.ready = ws.recv()
            except websocket.WebSocketTimeoutException:
                result.ready = None
            self._log_raw_frame("send_frame", frame)
            ws.send(frame)
            if wait_for_response:
                frames = 0
                while frames < max_response_frames:
                    try:
                        message = ws.recv()
                    except websocket.WebSocketTimeoutException:
                        break
                    except websocket.WebSocketConnectionClosedException:
                        break
                    if message is None:
                        break
                    result.responses.append(message)
                    frames += 1
        finally:
            try:
                ws.close()
            except Exception:
                pass
        return result


def send_socketio_event(
    url: str,
    event: str,
    payload: PayloadType,
    namespace: Optional[str] = None,
    cookies: Optional[str] = None,
    timeout: float = 10.0,
    headers: Optional[Dict[str, str]] = None,
    verify_ssl: bool = False,
    wait_for_response: bool = True,
    max_response_frames: int = 1,
) -> SocketSendResult:
    """Helper wrapper to send a Socket.IO event in one call."""

    sender = SocketIOSender(
        url=url,
        namespace=namespace,
        timeout=timeout,
        headers=headers,
        verify_ssl=verify_ssl,
    )
    return sender.send_event(
        event=event,
        payload=payload,
        cookies=cookies,
        wait_for_response=wait_for_response,
        max_response_frames=max_response_frames,
    )
