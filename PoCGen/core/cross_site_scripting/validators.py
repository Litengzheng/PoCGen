from __future__ import annotations

from typing import List, Tuple

from PoCGen.core.models import HTTPMessage


def validate_http_message(msg: HTTPMessage) -> List[str]:
    errors: List[str] = []
    if msg.version.upper() not in {"HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/2.0"}:
        errors.append(f"Unsupported HTTP version: {msg.version}")
    if not msg.method or not msg.path:
        errors.append("Missing method or path")
    if "Host" not in msg.headers:
        errors.append("Missing Host header")
    if "Content-Length" in msg.headers:
        try:
            declared = int(msg.headers["Content-Length"]) if msg.headers.get("Content-Length") else 0
            actual = len(msg.body.encode("utf-8"))
            if declared != actual:
                errors.append(f"Content-Length mismatch: declared {declared}, actual {actual}")
        except Exception:
            errors.append("Invalid Content-Length header")
    return errors


def parse_and_validate(raw: str) -> Tuple[HTTPMessage, List[str]]:
    msg = HTTPMessage.parse(raw)
    return msg, validate_http_message(msg)
