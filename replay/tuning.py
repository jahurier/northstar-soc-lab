"""Apply approved detection tuning (detections/tuning.json) to Hayabusa detections.

Every reader of detections (coverage, benign noise, Jev corpus, detection agent, console
summary) goes through `adjust()`, so an approved exclusion or level change takes effect
everywhere at once. Tuning is data, reviewed in Git; nothing here edits rule files.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

TUNING = Path(__file__).resolve().parents[1] / "detections" / "tuning.json"
EMPTY = {"version": 0, "exclusions": [], "level_changes": []}


def load(path: Path = TUNING) -> dict[str, Any]:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return dict(EMPTY)


def fields(details: Any) -> dict[str, str]:
    if not isinstance(details, dict):
        return {}
    return {str(k): str(v)[:200] for k, v in details.items() if isinstance(v, (str, int)) and str(v).strip()}


def matches(row: dict[str, str], rule: dict[str, Any]) -> bool:
    value = row.get(rule.get("field", ""))
    if value is None:
        return False
    a, b = value.lower(), str(rule.get("value", "")).lower()
    return {"equals": a == b, "endswith": a.endswith(b), "contains": b in a}.get(rule.get("match"), False)


class Tuning:
    def __init__(self, data: dict[str, Any] | None = None) -> None:
        data = data if data is not None else load()
        self.version = data.get("version", 0)
        self.exclusions: dict[str, list[dict[str, Any]]] = {}
        for rule in data.get("exclusions", []):
            self.exclusions.setdefault(rule["rule_id"], []).append(rule)
        self.levels = {c["rule_id"]: c["to"] for c in data.get("level_changes", [])}

    def adjust(self, detection: dict[str, Any]) -> dict[str, Any] | None:
        """Return the detection as tuned (level possibly lowered), or None if excluded."""
        rule_id = detection.get("RuleID")
        rules = self.exclusions.get(rule_id)
        if rules:
            row = fields(detection.get("Details"))
            if any(matches(row, rule) for rule in rules):
                return None
        if rule_id in self.levels:
            return {**detection, "Level": self.levels[rule_id]}
        return detection
