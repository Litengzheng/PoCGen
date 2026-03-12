from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class TargetSample:
    url: str
    status_code: int
    content_type: Optional[str]
    encoding: Optional[str]
    body_preview: str
    request_template: str
    response_headers: str
    post_samples: List[str] = field(default_factory=list)
    cookies_header: Optional[str] = None
    socket_samples: List[str] = field(default_factory=list)

    def as_prompt_block(self) -> str:
        ct = self.content_type or "unknown"
        enc = self.encoding or "unknown"
        parts = [
            "Sample Target HTTP Interaction:\n",
            f"Request template used to reach target:\n{self.request_template}\n",
            f"Response status: HTTP {self.status_code}\n",
            f"Response headers (truncated):\n{self.response_headers}\n",
            f"Body preview (truncated):\n{self.body_preview}\n",
        ]
        if self.post_samples:
            # Include the first captured POST request (full raw HTTP) to guide the LLM.
            first = self.post_samples[0]
            parts.append("Captured POST sample (raw HTTP):\n" + first + "\n")
        if self.cookies_header:
            parts.append("Captured cookies (set as Cookie header):\n" + self.cookies_header + "\n")
        if self.socket_samples:
            parts.append("Captured Socket.IO frames:\n")
            for idx, sample in enumerate(self.socket_samples[:3], start=1):
                snippet = sample
                if len(snippet) > 1200:
                    snippet = snippet[:1200] + "\n... <truncated>"
                parts.append(f"[Sample #{idx}]\n{snippet}\n")
        return "".join(parts)
