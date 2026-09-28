"""Read append-only analyst labels; undo entries reverse the latest label per case."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def read(path: Path) -> dict[str, dict[str, Any]]:
    history: dict[str, list[dict[str, Any]]] = {}
    if path.exists():
        with path.open() as handle:
            for line in handle:
                if not line.strip():
                    continue
                entry = json.loads(line)
                if entry.get("by") != "analyst":
                    continue
                stack = history.setdefault(entry["case_id"], [])
                if entry.get("action") == "undo":
                    if stack:
                        stack.pop()
                elif entry.get("verdict"):
                    stack.append(entry)
    return {case_id: entries[-1] for case_id, entries in history.items() if entries}
