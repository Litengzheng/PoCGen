from __future__ import annotations

from typing import Dict, List, Optional

import httpx

from PoCGen.config.config import SETTINGS
from PoCGen.core.models import HTTPMessage, ValidationResult


def _resolve_url(message: HTTPMessage, target: str) -> str:
    from urllib.parse import urljoin

    path = message.path or "/"
    if path.startswith("http://") or path.startswith("https://"):
        return path
    base = target.rstrip("/") + "/"
    return urljoin(base, path.lstrip("/"))


def _prepare_headers(headers: Dict[str, str]) -> Dict[str, str]:
    cleaned: Dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() == "content-length":
            continue
        cleaned[key] = value
    return cleaned


def validate_http_requests(
    requests: List[HTTPMessage],
    target: str,
    session: Optional[httpx.Client] = None,
) -> List[ValidationResult]:
    """Replay HTTP requests against the target to validate PoC behavior."""
    results: List[ValidationResult] = []
    client_kwargs = {
        "timeout": SETTINGS.validation_timeout,
        "verify": False,
    }
    if SETTINGS.http_proxy:
        client_kwargs["proxies"] = SETTINGS.http_proxy

    client_ctx = session or httpx.Client(**client_kwargs)
    owns_client = session is None
    try:
        for idx, message in enumerate(requests):
            url = _resolve_url(message, target)
            body_bytes = message.body.encode("utf-8", errors="ignore") if message.body else None
            try:
                resp = client_ctx.request(
                    message.method or "POST",
                    url,
                    headers=_prepare_headers(message.headers),
                    content=body_bytes,
                )
                preview = resp.text[:500]
                results.append(
                    ValidationResult(
                        request_index=idx,
                        url=str(url),
                        status_code=resp.status_code,
                        success=resp.status_code < 500,
                        response_preview=preview,
                    )
                )
            except Exception as exc:
                results.append(
                    ValidationResult(
                        request_index=idx,
                        url=str(url),
                        status_code=None,
                        success=False,
                        error=str(exc),
                    )
                )
    finally:
        if owns_client:
            client_ctx.close()

    return results
