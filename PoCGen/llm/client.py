from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from openai import OpenAI
from openai import OpenAIError
from pydantic import BaseModel

from PoCGen.config.config import SETTINGS


class ProviderConfig(BaseModel):
    name: str
    base_url: str
    api_key: str
    model: str

    def build_client(self, timeout: Optional[int]) -> OpenAI:
        kwargs: Dict[str, Any] = {
            "api_key": self.api_key,
        }
        base = (self.base_url or "").strip()
        if base:
            kwargs["base_url"] = base.rstrip("/")
        if timeout:
            kwargs["timeout"] = timeout
        return OpenAI(**kwargs)


class ChatMessage(BaseModel):
    role: str
    content: str


class LLMClient:
    def __init__(
        self,
        provider: Optional[str] = None,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        timeout_seconds: Optional[int] = None,
    ) -> None:
        settings = SETTINGS.llm

        self.timeout = timeout_seconds or settings.timeout_seconds
        self._provider = self._build_provider(
            provider_name=provider,
            base_url_override=base_url,
            api_key_override=api_key,
            model_override=model,
        )
        self._client = self._provider.build_client(self.timeout)

    def _build_provider(
        self,
        provider_name: Optional[str],
        base_url_override: Optional[str],
        api_key_override: Optional[str],
        model_override: Optional[str],
    ) -> ProviderConfig:
        settings = SETTINGS.llm
        providers = {k.lower(): v for k, v in settings.providers.items()}
        if not providers:
            raise RuntimeError("No LLM providers configured")

        key = (provider_name or settings.default_provider).lower()
        provider_settings = providers.get(key)
        if provider_settings is None:
            # Fallback to first available provider
            key, provider_settings = next(iter(providers.items()))

        return ProviderConfig(
            name=key,
            base_url=base_url_override or provider_settings.base_url,
            api_key=api_key_override or provider_settings.api_key,
            model=model_override or provider_settings.model,
        )

    def chat(self, messages: List[ChatMessage], temperature: float = 0.2, max_tokens: int = 4000) -> str:
        payload: Dict[str, Any] = {
            "model": self._provider.model,
            "messages": [m.model_dump() for m in messages],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        try:
            response = self._client.chat.completions.create(**payload)
        except OpenAIError as exc:
            raise RuntimeError(f"LLM API error: {exc}") from exc

        try:
            return response.choices[0].message.content
        except Exception:
            return json.dumps(response.model_dump(mode="json"), ensure_ascii=False)

    def close(self) -> None:
        close_method = getattr(self._client, "close", None)
        if callable(close_method):
            close_method()


__all__ = ["LLMClient", "ChatMessage"]
