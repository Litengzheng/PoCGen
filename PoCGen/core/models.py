from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class HTTPMessage:
    method: str
    path: str
    version: str
    headers: Dict[str, str]
    body: str

    @staticmethod
    def parse(raw: str) -> "HTTPMessage":
        lines = raw.splitlines()
        if not lines:
            raise ValueError("Empty HTTP message")
        start = lines[0].strip()
        parts = start.split()
        if len(parts) < 3:
            raise ValueError(f"Invalid request line: {start}")
        method, path, version = parts[0], parts[1], parts[2]

        headers: Dict[str, str] = {}
        i = 1
        while i < len(lines):
            line = lines[i]
            i += 1
            if line.strip() == "":
                break
            if ":" not in line:
                # skip malformed header
                continue
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
        body = "\n".join(lines[i:]) if i < len(lines) else ""
        return HTTPMessage(method=method, path=path, version=version, headers=headers, body=body)


@dataclass
class SocketEventMessage:
    url: str
    path: Optional[str] = None
    event: Optional[str] = None
    payload: Any = None
    raw_frame: Optional[str] = None
    namespace: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Optional[str] = None
    wait_for_response: bool = True
    max_response_frames: int = 1

    @staticmethod
    def parse(raw: str) -> "SocketEventMessage":
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("Socket event payload must be a JSON object")
        url = str(data.get("url") or "").strip()
        path = str(data.get("path") or "").strip()
        if not url and not path:
            raise ValueError("Missing socket URL or path")
        payload = data.get("payload")
        raw_frame = data.get("frame") or data.get("raw_frame")
        event = None
        if raw_frame is None:
            event = str(data.get("event") or "").strip()
            if not event:
                raise ValueError("Missing socket event name or frame")
        namespace = data.get("namespace")
        headers_raw = data.get("headers") or {}
        if not isinstance(headers_raw, dict):
            raise ValueError("headers must be an object")
        headers = {str(k): str(v) for k, v in headers_raw.items()}
        cookies = data.get("cookies")
        if (cookies is None or str(cookies).strip() == "") and "Cookie" in headers:
            cookies = headers.pop("Cookie")
        wait_for_response = bool(
            data.get("wait_for_response") if data.get("wait_for_response") is not None else True
        )
        max_response_frames = int(data.get("max_response_frames") or 1)
        return SocketEventMessage(
            url=url,
            path=path or None,
            event=event,
            payload=payload,
            raw_frame=str(raw_frame) if raw_frame is not None else None,
            namespace=str(namespace).strip() if namespace else None,
            headers=headers,
            cookies=str(cookies).strip() if cookies else None,
            wait_for_response=wait_for_response,
            max_response_frames=max_response_frames,
        )

    def to_json(self) -> str:
        data = {
            "url": self.url,
            "path": self.path,
            "event": self.event,
            "namespace": self.namespace,
            "headers": self.headers,
            "cookies": self.cookies,
            "wait_for_response": self.wait_for_response,
            "max_response_frames": self.max_response_frames,
            "payload": self.payload,
            "frame": self.raw_frame,
        }
        return json.dumps(data, ensure_ascii=False, indent=2)


@dataclass
class ValidationResult:
    request_index: int
    url: str
    status_code: Optional[int]
    success: bool
    response_preview: str = ""
    error: Optional[str] = None


@dataclass
class AttemptResult:
    attempt_index: int
    raw_output: str
    requests: List[HTTPMessage]
    saved_paths: List[str]
    validation_results: Optional[List[ValidationResult]]
    monitor_hit: bool
    monitor_summary: Optional[str]
    feedback: Optional[str]
    socket_events: Optional[List[SocketEventMessage]] = None


@dataclass
class GenerationResult:
    raw_output: str
    requests: List[HTTPMessage]
    saved_paths: List[str]
    validation_results: Optional[List[ValidationResult]] = None
    attempts: Optional[List[AttemptResult]] = None
    success: Optional[bool] = None
    socket_events: Optional[List[SocketEventMessage]] = None


class VulnHandler:
    name: str = "base"

    def build_messages(
        self,
        description: str,
        code_texts: List[str],
        target: Optional[str],
        attacker_url: Optional[str] = None,
        target_profile: Optional[str] = None,
    ) -> List[dict]:
        raise NotImplementedError

    def post_process(self, raw_output: str) -> List[str]:
        """Split raw output into individual HTTP messages (as strings)."""
        # naive split on two consecutive newlines separating requests
        chunks: List[str] = []
        buf: List[str] = []
        for line in raw_output.splitlines():
            if line.strip() == "" and buf and buf[-1].strip() == "":
                # double blank -> boundary
                chunk = "\n".join([l for l in buf if l is not None])
                if chunk.strip():
                    chunks.append(chunk.strip())
                buf = []
            else:
                buf.append(line)
        if buf:
            chunk = "\n".join(buf).strip()
            if chunk:
                chunks.append(chunk)
        # If still a single block, try to split by two newlines
        if len(chunks) <= 1:
            parts = [p.strip() for p in raw_output.strip().split("\n\n") if p.strip()]
            if len(parts) > 1:
                return parts
        return chunks if chunks else ([raw_output.strip()] if raw_output.strip() else [])
