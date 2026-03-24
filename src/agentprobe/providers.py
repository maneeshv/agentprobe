"""
LLM Provider abstraction for the attacker model.

Supports:
- OpenAI-compatible APIs (OpenAI, OpenRouter, Grok/xAI, Together, Groq, Fireworks, DeepSeek, etc.)
- Anthropic Messages API (native)
- Google Gemini API (native)
"""

import json
from dataclasses import dataclass

import httpx


@dataclass
class LLMResponse:
    """Normalized response from any provider."""
    content: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0


# Known provider presets — base URL + default model
PROVIDER_PRESETS: dict[str, dict[str, str]] = {
    "openai": {
        "api_base": "https://api.openai.com/v1",
        "default_model": "gpt-4o",
        "provider_type": "openai",
    },
    "openrouter": {
        "api_base": "https://openrouter.ai/api/v1",
        "default_model": "openai/gpt-4o",
        "provider_type": "openai",
    },
    "anthropic": {
        "api_base": "https://api.anthropic.com",
        "default_model": "claude-sonnet-4-20250514",
        "provider_type": "anthropic",
    },
    "grok": {
        "api_base": "https://api.x.ai/v1",
        "default_model": "grok-3",
        "provider_type": "openai",
    },
    "xai": {
        "api_base": "https://api.x.ai/v1",
        "default_model": "grok-3",
        "provider_type": "openai",
    },
    "gemini": {
        "api_base": "https://generativelanguage.googleapis.com/v1beta",
        "default_model": "gemini-2.5-flash",
        "provider_type": "gemini",
    },
    "google": {
        "api_base": "https://generativelanguage.googleapis.com/v1beta",
        "default_model": "gemini-2.5-flash",
        "provider_type": "gemini",
    },
    "together": {
        "api_base": "https://api.together.xyz/v1",
        "default_model": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "provider_type": "openai",
    },
    "groq": {
        "api_base": "https://api.groq.com/openai/v1",
        "default_model": "llama-3.3-70b-versatile",
        "provider_type": "openai",
    },
    "deepseek": {
        "api_base": "https://api.deepseek.com",
        "default_model": "deepseek-chat",
        "provider_type": "openai",
    },
    "fireworks": {
        "api_base": "https://api.fireworks.ai/inference/v1",
        "default_model": "accounts/fireworks/models/llama-v3p3-70b-instruct",
        "provider_type": "openai",
    },
}


def detect_provider_type(api_base: str) -> str:
    """Auto-detect provider type from API base URL."""
    api_base = api_base.lower().rstrip("/")
    if "anthropic.com" in api_base:
        return "anthropic"
    if "generativelanguage.googleapis.com" in api_base:
        return "gemini"
    # Everything else is OpenAI-compatible
    return "openai"


class AttackerLLM:
    """Unified interface for attacker LLM across providers."""

    def __init__(
        self,
        provider: str | None = None,
        api_base: str | None = None,
        api_key: str = "",
        model: str | None = None,
        temperature: float = 0.9,
    ):
        """
        Args:
            provider: Provider preset name (openai, anthropic, grok, gemini, etc.)
                     If set, auto-configures api_base and default model.
            api_base: API base URL (overrides provider preset)
            api_key: API key
            model: Model name (overrides provider default)
            temperature: Sampling temperature
        """
        # Resolve provider preset
        preset = PROVIDER_PRESETS.get(provider or "", {})

        self.api_base = (api_base or preset.get("api_base", "https://openrouter.ai/api/v1")).rstrip("/")
        self.api_key = api_key
        self.model = model or preset.get("default_model", "gpt-4o")
        self.temperature = temperature

        # Determine provider type
        if provider and provider in PROVIDER_PRESETS:
            self.provider_type = PROVIDER_PRESETS[provider]["provider_type"]
        else:
            self.provider_type = detect_provider_type(self.api_base)

    async def chat(
        self,
        client: httpx.AsyncClient,
        system_prompt: str,
        user_message: str,
        max_tokens: int = 2000,
    ) -> LLMResponse:
        """Send a chat request to the attacker LLM."""
        if self.provider_type == "anthropic":
            return await self._chat_anthropic(client, system_prompt, user_message, max_tokens)
        elif self.provider_type == "gemini":
            return await self._chat_gemini(client, system_prompt, user_message, max_tokens)
        else:
            return await self._chat_openai(client, system_prompt, user_message, max_tokens)

    async def _chat_openai(
        self, client: httpx.AsyncClient,
        system_prompt: str, user_message: str, max_tokens: int,
    ) -> LLMResponse:
        """OpenAI-compatible API (works for OpenAI, OpenRouter, Grok, Together, Groq, etc.)"""
        resp = await client.post(
            f"{self.api_base}/chat/completions",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message},
                ],
                "temperature": self.temperature,
                "max_tokens": max_tokens,
            },
            timeout=60.0,
        )
        resp.raise_for_status()
        data = resp.json()

        usage = data.get("usage", {})
        return LLMResponse(
            content=data["choices"][0]["message"]["content"],
            model=data.get("model", self.model),
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
        )

    async def _chat_anthropic(
        self, client: httpx.AsyncClient,
        system_prompt: str, user_message: str, max_tokens: int,
    ) -> LLMResponse:
        """Anthropic Messages API."""
        resp = await client.post(
            f"{self.api_base}/v1/messages",
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            json={
                "model": self.model,
                "max_tokens": max_tokens,
                "system": system_prompt,
                "messages": [
                    {"role": "user", "content": user_message},
                ],
                "temperature": self.temperature,
            },
            timeout=60.0,
        )
        resp.raise_for_status()
        data = resp.json()

        # Anthropic returns content as array of blocks
        content = ""
        for block in data.get("content", []):
            if block.get("type") == "text":
                content += block["text"]

        usage = data.get("usage", {})
        return LLMResponse(
            content=content,
            model=data.get("model", self.model),
            input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
        )

    async def _chat_gemini(
        self, client: httpx.AsyncClient,
        system_prompt: str, user_message: str, max_tokens: int,
    ) -> LLMResponse:
        """Google Gemini API."""
        resp = await client.post(
            f"{self.api_base}/models/{self.model}:generateContent",
            params={"key": self.api_key},
            headers={"Content-Type": "application/json"},
            json={
                "system_instruction": {
                    "parts": [{"text": system_prompt}],
                },
                "contents": [
                    {
                        "role": "user",
                        "parts": [{"text": user_message}],
                    },
                ],
                "generationConfig": {
                    "temperature": self.temperature,
                    "maxOutputTokens": max_tokens,
                },
            },
            timeout=60.0,
        )
        resp.raise_for_status()
        data = resp.json()

        # Extract text from Gemini response
        content = ""
        for candidate in data.get("candidates", []):
            for part in candidate.get("content", {}).get("parts", []):
                content += part.get("text", "")

        usage = data.get("usageMetadata", {})
        return LLMResponse(
            content=content,
            model=self.model,
            input_tokens=usage.get("promptTokenCount", 0),
            output_tokens=usage.get("candidatesTokenCount", 0),
        )
