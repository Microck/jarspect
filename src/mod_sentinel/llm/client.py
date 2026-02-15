from __future__ import annotations

import json
from abc import ABC, abstractmethod

import httpx

from mod_sentinel.settings import Settings, get_settings


class LLMClient(ABC):
    @abstractmethod
    def complete_text(self, system_prompt: str, user_prompt: str) -> str:
        """Return raw model response text."""

    def complete_json(self, system_prompt: str, user_prompt: str) -> dict:
        raw = self.complete_text(system_prompt=system_prompt, user_prompt=user_prompt)
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError("LLM JSON response must be an object")
        return parsed


class StubLLMClient(LLMClient):
    def __init__(self, response_payload: dict | None = None) -> None:
        self._response_payload = response_payload or {
            "file_system": {
                "reads": ["config/suspicious.cfg"],
                "writes": ["mods/cache.bin"],
                "rationale": "Static findings include direct file write APIs.",
                "confidence": 0.73,
            },
            "network": {
                "domains": ["payload.example.invalid"],
                "urls": ["https://payload.example.invalid/bootstrap"],
                "ports": [443],
                "rationale": "URLConnection and HTTP client patterns suggest remote calls.",
                "confidence": 0.81,
            },
            "persistence": {
                "likely": True,
                "mechanisms": ["startup task registration (predicted)"],
                "rationale": "Combination of process and file indicators points to persistence setup.",
                "confidence": 0.64,
            },
            "risk_summary": "Predicted behavior indicates remote network access and local file changes.",
            "confidence": 0.74,
        }

    def complete_text(self, system_prompt: str, user_prompt: str) -> str:
        _ = (system_prompt, user_prompt)
        return json.dumps(self._response_payload)


class FoundryLLMClient(LLMClient):
    def __init__(
        self, endpoint: str | None, api_key: str | None, model: str | None
    ) -> None:
        if not endpoint:
            raise ValueError("FOUNDRY_ENDPOINT is required for FoundryLLMClient")
        if not api_key:
            raise ValueError("FOUNDRY_API_KEY is required for FoundryLLMClient")
        if not model:
            raise ValueError("FOUNDRY_MODEL is required for FoundryLLMClient")

        self._endpoint = endpoint.rstrip("/")
        self._api_key = api_key
        self._model = model

    def complete_text(self, system_prompt: str, user_prompt: str) -> str:
        response = httpx.post(
            f"{self._endpoint}/chat/completions",
            headers={"api-key": self._api_key},
            json={
                "model": self._model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": 0,
            },
            timeout=60,
        )
        response.raise_for_status()
        payload = response.json()
        return str(payload["choices"][0]["message"]["content"])


def build_llm_client(settings: Settings | None = None) -> LLMClient:
    active = settings or get_settings()
    if active.llm_provider == "stub":
        return StubLLMClient()
    if active.llm_provider == "foundry":
        return FoundryLLMClient(
            endpoint=active.foundry_endpoint,
            api_key=active.foundry_api_key,
            model=active.foundry_model,
        )
    raise ValueError(f"Unsupported LLM provider: {active.llm_provider}")
