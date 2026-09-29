"""Import normalized alert records into the local Northstar review workbench.

Input is JSONL with one alert per line. No truth label or expected model answer
is accepted. Imported records stay local in runs/imported-cases.jsonl.
"""

from __future__ import annotations

import argparse
import json
import math
import re
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "runs" / "imported-cases.jsonl"
FIELDS = {"id", "timestamp", "source", "host", "user", "rule_id", "rule_title",
          "severity", "details"}
CASE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}\Z")
SEVERITIES = {"low", "med", "high", "crit"}
MAX_ROWS = 5000
MAX_LINE = 65536


def _string(record: dict[str, Any], field: str, limit: int = 200) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"{field} must be a nonempty string of at most {limit} characters")
    return value.strip()


def normalize(record: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(record, dict) or set(record) != FIELDS:
        raise ValueError(f"fields must be exactly: {', '.join(sorted(FIELDS))}")
    case_id = _string(record, "id", 80)
    if not CASE_ID.fullmatch(case_id):
        raise ValueError("id must use letters, digits, dots, underscores, or hyphens")
    timestamp = _string(record, "timestamp", 40)
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be ISO 8601 with a timezone") from exc
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    source = _string(record, "source", 40).lower()
    if source not in {"endpoint", "identity", "cloud", "network", "other"}:
        raise ValueError("source must be endpoint, identity, cloud, network, or other")
    severity = _string(record, "severity", 10).lower()
    if severity not in SEVERITIES:
        raise ValueError("severity must be low, med, high, or crit")
    host = _string(record, "host", 100)
    user = _string(record, "user", 100)
    rule_id = _string(record, "rule_id", 100)
    title = _string(record, "rule_title", 200)
    details = record["details"]
    if not isinstance(details, dict) or len(details) > 30 or any(
            not isinstance(key, str) or len(key) > 80 or
            not isinstance(value, (str, int, float, bool, type(None))) or
            isinstance(value, float) and not math.isfinite(value) or
            isinstance(value, str) and len(value) > 2000
            for key, value in details.items()):
        raise ValueError("details must be an object of at most 30 short scalar fields")
    return {
        "case_id": case_id,
        "metadata": {"dataset": "imported-local", "dataset_label": "unlabeled",
                     "recording": case_id, "dataset_tactic": "unlabeled", "domain": source,
                     "split": "unlabeled", "label_quality": "unlabeled",
                     "provenance": "imported"},
        "state": {
            "alert": {"source": source, "channel": source, "event_id": rule_id,
                      "timestamp": timestamp, "computer": host, "details": details},
            "detection": {"engine": "local-import", "rule_title": title,
                          "rule_id": rule_id, "level": severity,
                          "status": "imported", "mitre_tactics": [], "mitre_tags": []},
            "asset_context": {"computer": host},
            "identity_context": {"user": user},
            "enrichment": {},
        },
    }


def import_file(source: Path, output: Path = DEFAULT_OUTPUT) -> int:
    if source.resolve() == output.resolve():
        raise ValueError("input and output must differ")
    cases: list[dict[str, Any]] = []
    seen: set[str] = set()
    with source.open() as handle:
        for number, line in enumerate(handle, 1):
            if len(line.encode("utf-8")) > MAX_LINE:
                raise ValueError(f"line {number} exceeds {MAX_LINE} bytes")
            if not line.strip():
                continue
            if len(cases) >= MAX_ROWS:
                raise ValueError(f"input exceeds {MAX_ROWS} records")
            try:
                case = normalize(json.loads(line))
            except (ValueError, TypeError) as exc:
                raise ValueError(f"invalid record on line {number}: {exc}") from exc
            if case["case_id"] in seen:
                raise ValueError(f"duplicate id on line {number}")
            seen.add(case["case_id"])
            cases.append(case)
    if not cases:
        raise ValueError("input has no records")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    try:
        with temporary.open("w") as handle:
            for case in cases:
                handle.write(json.dumps(case, sort_keys=True) + "\n")
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)
    return len(cases)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    count = import_file(args.input, args.output)
    print(json.dumps({"imported": count, "provenance": "imported",
                      "labels": "unlabeled", "output": str(args.output)}))


if __name__ == "__main__":
    main()
