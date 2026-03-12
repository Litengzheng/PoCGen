from __future__ import annotations

import os
import re
import time
from typing import List, Tuple

from PoCGen.core.models import HTTPMessage
from .validators import parse_and_validate


def split_messages(raw_output: str) -> List[str]:
    """Split combined LLM output into discrete HTTP request blocks."""
    text = raw_output.strip("\n\r ")
    if not text:
        return []

    norm = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = norm.split("\n")

    method_re = re.compile(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+[^\r\n]+\s+HTTP/\d\.\d\s*$")
    request_line_idxs: List[int] = [i for i, ln in enumerate(lines) if method_re.match(ln or "")] 

    if len(request_line_idxs) <= 1:
        return [text]

    blocks: List[str] = []
    for idx, start in enumerate(request_line_idxs):
        end = request_line_idxs[idx + 1] if idx + 1 < len(request_line_idxs) else len(lines)
        block = "\n".join(lines[start:end]).strip("\n")
        if block:
            blocks.append(block)
    return blocks


def parse_and_filter(raw_messages: List[str]) -> List[Tuple[HTTPMessage, List[str]]]:
    results: List[Tuple[HTTPMessage, List[str]]] = []
    for msg_str in raw_messages:
        try:
            msg, errs = parse_and_validate(msg_str)
            results.append((msg, errs))
        except Exception as exc:
            results.append((HTTPMessage(method="", path="", version="", headers={}, body=msg_str), [f"Parse error: {exc}"]))
    return results


def save_messages(raw_messages: List[str], output_dir: str) -> List[str]:
    os.makedirs(output_dir, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    paths: List[str] = []
    for idx, raw in enumerate(raw_messages, start=1):
        fname = f"poc_{ts}_{idx:02d}.http"
        fpath = os.path.join(output_dir, fname)
        counter = 1
        while os.path.exists(fpath):
            fname = f"poc_{ts}_{idx:02d}_{counter}.http"
            fpath = os.path.join(output_dir, fname)
            counter += 1
        normalized = _adjust_content_length(raw)
        with open(fpath, "w", encoding="utf-8") as fh:
            fh.write(normalized)
        paths.append(fpath)
    return paths


def _adjust_content_length(raw: str) -> str:
    """Ensure Content-Length matches the actual UTF-8 byte size of the body."""
    original = raw
    text = raw.replace("\r\n", "\n").replace("\r", "\n")
    if "\n\n" in text:
        head, body = text.split("\n\n", 1)
        sep = "\n\n"
    else:
        head, body, sep = text, "", "\n\n"

    body_len = len(body.encode("utf-8"))
    lines = head.split("\n") if head else []
    found = False
    for idx, line in enumerate(lines):
        if line.lower().startswith("content-length:"):
            lines[idx] = f"Content-Length: {body_len}"
            found = True
            break
    if not found and body:
        lines.append(f"Content-Length: {body_len}")

    new_head = "\n".join(lines)
    rebuilt = new_head + sep + body if body or (sep in original) else new_head
    if "\r\n" in original:
        rebuilt = rebuilt.replace("\n", "\r\n")
    return rebuilt
