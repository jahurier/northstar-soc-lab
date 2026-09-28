"""Audit whether installed Elastic rules can query Northstar's indexed mock events.

    python3 -m siem.prebuilt_readiness

The report is read-only. A rule needs a matching index and its declared fields
before an alert comparison is possible; query semantics need further review.
ES|QL's FROM clause is checked separately because those rules do not use a
rule-level index list.
"""

from __future__ import annotations

import fnmatch
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from .ingest import INDEX_PREFIX, map_event
from .kibana import request

ROOT = Path(__file__).resolve().parents[1]
SOURCES = (ROOT / "runs" / "world-events.jsonl", ROOT / "runs" / "red-replay" / "campaign-events.jsonl")


def fields(value: dict[str, Any], prefix: str = "") -> set[str]:
    found = set()
    for key, item in value.items():
        name = f"{prefix}.{key}" if prefix else key
        if isinstance(item, dict):
            found.update(fields(item, name))
        else:
            found.add(name)
    return found


def queries_index(rule: dict[str, Any], index: str) -> bool:
    if rule.get("type") == "esql":
        match = re.search(r"\bfrom\s+([^|\n]+)", rule.get("query", ""), re.I)
        if not match:
            return False
        # Strip metadata and inline comments after the source expression.
        source = re.split(r"\bmetadata\b|//", match.group(1), maxsplit=1, flags=re.I)[0]
        patterns = [p.strip() for p in source.split(",")]
    else:
        patterns = rule.get("index") or []
    return any(fnmatch.fnmatchcase(index, pattern) for pattern in patterns if pattern)


def audit(rules: list[dict[str, Any]], events: list[dict[str, Any]]) -> dict[str, Any]:
    if not events:
        raise ValueError("at least one mapped Northstar event is required")
    per_event_fields = [fields(map_event(event)) for event in events]
    present = set().union(*per_event_fields)
    indices = sorted({INDEX_PREFIX + "-" + event["timestamp"][:10].replace("-", ".")
                      for event in events})
    counts = Counter()
    enabled_sources = []
    for rule in rules:
        counts["installed"] += 1
        counts["enabled"] += bool(rule.get("enabled"))
        index_match = any(queries_index(rule, index) for index in indices)
        required = {entry["name"] for entry in rule.get("required_fields", [])}
        if rule.get("enabled"):
            enabled_sources.append({"name": rule.get("name", "unnamed"), "type": rule.get("type"),
                                    "source_indices": rule.get("index") or [],
                                    "required_fields": sorted(required),
                                    "missing_fields": sorted(required - present),
                                    "queries_northstar": index_match})
        if not index_match:
            continue
        counts["index_matches"] += 1
        if any(required <= available for available in per_event_fields):
            counts["index_and_declared_fields_match"] += 1
    for key in ("installed", "enabled", "index_matches", "index_and_declared_fields_match"):
        counts[key] += 0
    return {"source_indices": indices, "sample_events": len(events),
            "available_fields": sorted(present), "enabled_rule_sources": enabled_sources,
            **dict(counts)}


def main() -> None:
    events = [json.loads(line) for path in SOURCES for line in path.read_text().splitlines() if line.strip()]
    rules = []
    page = 1
    while True:
        data = request("GET", f"/api/detection_engine/rules/_find?per_page=100&page={page}")
        rules.extend(data.get("data", []))
        if len(rules) >= data.get("total", 0):
            break
        page += 1
    print(json.dumps(audit(rules, events), indent=2))


if __name__ == "__main__":
    main()
