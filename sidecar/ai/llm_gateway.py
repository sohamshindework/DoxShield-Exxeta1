"""The one place DoxShield talks to a language model (CLAUDE.md: "LLM calls go
only through llm_gateway.py").

Modes (``DOXSHIELD_LLM_MODE``):

* ``off`` (default) — no model. Callers get ``LLMResult(ok=False, error="unavailable")``
  and must use their deterministic fallback. Nothing is ever fabricated.
* ``ollama`` — local Ollama only. The host must be a loopback address; any other
  host is refused, so no prompt can leave the machine through this gateway.
* ``record`` — like ``ollama``, and appends each response to the recording file.
* ``replay`` — returns recorded responses by task name, in order. Used by tests and
  CI so they need no model, network or API key.

M4 deliberately supports no hosted provider and no API keys. Hosted models are an
M7/M9 decision and need explicit authorisation for what data may be sent.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
MAX_PROMPT_CHARS = 12_000
MAX_RESPONSE_CHARS = 20_000


@dataclass
class LLMResult:
    ok: bool
    text: str = ""
    error: str | None = None
    model: str | None = None
    mode: str = "off"


def is_loopback_url(url: str) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return False
    return host in LOOPBACK_HOSTS


class LLMGateway:
    """Base gateway: the ``off`` mode."""

    mode = "off"

    @property
    def available(self) -> bool:
        return False

    def status(self) -> dict[str, Any]:
        return {"mode": self.mode, "available": self.available, "model": None,
                "data_leaves_machine": False}

    async def complete(self, task: str, system: str, user: str) -> LLMResult:
        return LLMResult(ok=False, error="unavailable", mode=self.mode)


class ReplayGateway(LLMGateway):
    """Returns pre-recorded responses for each ``task`` in order."""

    mode = "replay"

    def __init__(self, responses: dict[str, list[str]] | None = None,
                 path: str | Path | None = None) -> None:
        data: dict[str, list[str]] = {}
        if path:
            data = json.loads(Path(path).read_text())
        if responses:
            data.update(responses)
        self._queues: dict[str, list[str]] = {k: list(v) for k, v in data.items()}
        self.calls: list[dict[str, str]] = []  # what was sent, for tests

    @property
    def available(self) -> bool:
        return True

    def status(self) -> dict[str, Any]:
        return {**super().status(), "model": "replay"}

    async def complete(self, task: str, system: str, user: str) -> LLMResult:
        self.calls.append({"task": task, "system": system, "user": user})
        queue = self._queues.get(task) or []
        if not queue:
            return LLMResult(ok=False, error="no_recording", mode=self.mode, model="replay")
        return LLMResult(ok=True, text=queue.pop(0), mode=self.mode, model="replay")


class OllamaGateway(LLMGateway):
    """Local Ollama. Refuses non-loopback hosts."""

    mode = "ollama"

    def __init__(self, host: str, model: str, timeout: float = 60.0,
                 record_path: str | Path | None = None) -> None:
        self.host = host.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.record_path = Path(record_path) if record_path else None
        self._local = is_loopback_url(self.host)
        if self.record_path:
            self.mode = "record"

    @property
    def available(self) -> bool:
        return self._local

    def status(self) -> dict[str, Any]:
        return {"mode": self.mode, "available": self.available, "model": self.model,
                "host_is_local": self._local, "data_leaves_machine": False,
                **({} if self._local else {"error": "non_local_host_refused"})}

    async def complete(self, task: str, system: str, user: str) -> LLMResult:
        if not self._local:
            return LLMResult(ok=False, error="non_local_host_refused", mode=self.mode)
        if len(system) + len(user) > MAX_PROMPT_CHARS:
            return LLMResult(ok=False, error="prompt_too_large", mode=self.mode)
        try:
            async with httpx.AsyncClient(timeout=self.timeout, trust_env=False) as client:
                resp = await client.post(f"{self.host}/api/chat", json={
                    "model": self.model, "stream": False, "format": "json",
                    "messages": [{"role": "system", "content": system},
                                 {"role": "user", "content": user}],
                    "options": {"temperature": 0.0, "num_predict": 1200},
                })
                resp.raise_for_status()
                text = str(resp.json().get("message", {}).get("content", ""))
        except httpx.TimeoutException:
            return LLMResult(ok=False, error="timeout", mode=self.mode, model=self.model)
        except (httpx.HTTPError, ValueError) as exc:
            return LLMResult(ok=False, error=f"unavailable: {type(exc).__name__}",
                             mode=self.mode, model=self.model)
        text = text[:MAX_RESPONSE_CHARS]
        if self.record_path:
            self._record(task, text)
        return LLMResult(ok=True, text=text, mode=self.mode, model=self.model)

    def _record(self, task: str, text: str) -> None:
        path = self.record_path
        if path is None:
            return
        data: dict[str, list[str]] = {}
        if path.exists():
            data.update(json.loads(path.read_text()))
        data.setdefault(task, []).append(text)
        path.write_text(json.dumps(data, indent=2))


@dataclass
class _Env:
    mode: str = field(default_factory=lambda: os.getenv("DOXSHIELD_LLM_MODE", "off").strip())


def get_gateway() -> LLMGateway:
    """Build the gateway selected by the environment. Unknown modes are ``off``."""
    mode = _Env().mode.lower()
    host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    model = os.getenv("OLLAMA_MODEL", "mistral")
    if mode == "ollama":
        return OllamaGateway(host, model)
    if mode == "record":
        return OllamaGateway(host, model,
                             record_path=os.getenv("DOXSHIELD_LLM_RECORDING",
                                                   "llm_recording.json"))
    if mode == "replay":
        path = os.getenv("DOXSHIELD_LLM_RECORDING", "")
        return ReplayGateway(path=path) if path and Path(path).exists() else ReplayGateway()
    return LLMGateway()
