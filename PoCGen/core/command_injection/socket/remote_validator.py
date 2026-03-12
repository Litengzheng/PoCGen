from __future__ import annotations

from typing import List, Optional
from urllib.parse import urljoin, urlparse, urlunparse

from PoCGen.core.command_injection.socket.socket_sender import SocketIOSender
from PoCGen.core.models import SocketEventMessage, ValidationResult


def _resolve_url(event_url: str, event_path: Optional[str], target: Optional[str]) -> str:
    def _normalize_ws(url: str) -> str:
        parsed = urlparse(url)
        if parsed.scheme in {"ws", "wss"}:
            return url
        if parsed.scheme in {"http", "https"}:
            ws_scheme = "wss" if parsed.scheme == "https" else "ws"
            return urlunparse((ws_scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
        return url

    if event_url and event_url.strip().lower().startswith(("ws://", "wss://", "http://", "https://")):
        return _normalize_ws(event_url.strip())
    if target:
        base = _normalize_ws(target.rstrip("/") + "/")
        if event_url:
            return urljoin(base, event_url.lstrip("/"))
        if event_path:
            return urljoin(base, event_path.lstrip("/"))
        return base.rstrip("/")
    if event_url:
        return _normalize_ws(event_url)
    if event_path:
        return event_path
    raise ValueError("Socket event is missing a resolvable URL")


def validate_socket_events(
    events: List[SocketEventMessage],
    target: Optional[str],
) -> List[ValidationResult]:
    results: List[ValidationResult] = []
    for idx, event in enumerate(events):
        try:
            url = _resolve_url(event.url, event.path, target)
        except Exception as exc:
            results.append(
                ValidationResult(
                    request_index=idx,
                    url=event.url or target or "",
                    status_code=None,
                    success=False,
                    error=str(exc),
                )
            )
            continue

        sender = SocketIOSender(
            url=url,
            namespace=event.namespace,
            headers=event.headers or None,
        )
        try:
            if event.raw_frame:
                resp = sender.send_frame(
                    frame=event.raw_frame,
                    cookies=event.cookies,
                    wait_for_response=event.wait_for_response,
                    max_response_frames=event.max_response_frames,
                )
            else:
                resp = sender.send_event(
                    event=event.event or "",
                    payload=event.payload,
                    cookies=event.cookies,
                    wait_for_response=event.wait_for_response,
                    max_response_frames=event.max_response_frames,
                )
            preview_parts = []
            if resp.handshake:
                preview_parts.append(f"handshake={resp.handshake}")
            if resp.ready:
                preview_parts.append(f"ready={resp.ready}")
            if resp.responses:
                preview_parts.append(
                    "responses=" + ";".join(resp.responses[:3])
                )
            preview = " | ".join(preview_parts)
            results.append(
                ValidationResult(
                    request_index=idx,
                    url=url,
                    status_code=None,
                    success=True,
                    response_preview=preview,
                )
            )
        except Exception as exc:
            results.append(
                ValidationResult(
                    request_index=idx,
                    url=url,
                    status_code=None,
                    success=False,
                    error=str(exc),
                )
            )
    return results