"""Minimal local-model client (Ollama on 127.0.0.1) with schema-constrained JSON output.

Agents only ever receive JSON back; callers validate it again before use, because
model output is untrusted input to deterministic code.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
MODEL = os.environ.get("NORTHSTAR_MODEL", "qwen3:14b")


class LLMError(RuntimeError):
    pass


def chat_json(system: str, user: str, schema: dict[str, Any], *, model: str = MODEL,
              timeout: float = 300.0, retries: int = 2) -> dict[str, Any]:
    """Ask the local model for one JSON object matching `schema`."""
    if not OLLAMA_URL.startswith(("http://127.0.0.1", "http://localhost")):
        raise LLMError("agents only talk to a local model")
    body = {
        "model": model,
        "stream": False,
        "format": schema,
        "think": False,
        "options": {"temperature": 0.2},
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
    }
    last: Exception | None = None
    for _ in range(retries + 1):
        request = urllib.request.Request(f"{OLLAMA_URL}/api/chat", data=json.dumps(body).encode(),
                                         headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = json.loads(response.read())
            content = payload["message"]["content"]
            value = json.loads(content)
            if not isinstance(value, dict):
                raise LLMError("model returned non-object JSON")
            return value
        except (urllib.error.URLError, KeyError, ValueError, LLMError) as exc:
            last = exc
    raise LLMError(f"local model call failed: {last}")


def available(model: str = MODEL) -> bool:
    try:
        with urllib.request.urlopen(f"{OLLAMA_URL}/api/tags", timeout=5) as response:
            names = {m["name"] for m in json.loads(response.read()).get("models", [])}
        return model in names or f"{model}:latest" in names
    except (urllib.error.URLError, ValueError):
        return False
