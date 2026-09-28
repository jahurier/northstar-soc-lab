"""Index safe crAPI log metadata, keeping raw target logs private and separate."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from siem.ingest import _request
from siem.setup import load_env

INDEX_PREFIX = "northstar-redrange-crapi"
HTTP = re.compile(r'"(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) [^" ]+ HTTP/[0-9.]+"\s+(\d{3})')
DOCKER_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$")


def map_line(run_id: str, service: str, position: int, line: str) -> tuple[str, dict[str, Any]] | None:
    timestamp, sep, message = line.partition(" ")
    if not sep:
        return None
    try:
        if not DOCKER_TIME.fullmatch(timestamp):
            return None
        datetime.strptime(timestamp[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None
    identifier = hashlib.sha256(f"{run_id}|{service}|{position}".encode()).hexdigest()
    document: dict[str, Any] = {
        "@timestamp": timestamp,
        "event": {"id": identifier, "kind": "event", "action": "container_log",
                  "category": ["web"], "dataset": "northstar.redrange.crapi"},
        "host": {"name": service},
        "northstar": {"run_id": run_id, "provenance": "external_live_range",
                      "source_service": service,
                      "message_sha256": hashlib.sha256(message.encode()).hexdigest()},
        "tags": ["northstar", "red-range", "disposable-crapi"],
    }
    match = HTTP.search(message)
    if match:
        document["http"] = {"request": {"method": match.group(1)},
                            "response": {"status_code": int(match.group(2))}}
    return identifier, document


def ingest(folder: Path, run_id: str) -> dict[str, Any]:
    rows = []
    for path in sorted((folder / "defender-telemetry").glob("*.log")):
        service = path.stem
        for position, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
            mapped = map_line(run_id, service, position, line)
            if mapped:
                rows.append(mapped)
    if not rows:
        return {"indexed": 0, "reason": "no timestamped target logs"}
    password = load_env()["ELASTIC_PASSWORD"]
    for offset in range(0, len(rows), 500):
        lines = []
        for identifier, document in rows[offset:offset + 500]:
            index = INDEX_PREFIX + "-" + document["@timestamp"][:10].replace("-", ".")
            lines.append(json.dumps({"index": {"_index": index, "_id": identifier}}))
            lines.append(json.dumps(document))
        result = _request("POST", "/_bulk", ("\n".join(lines) + "\n").encode(), password,
                          "application/x-ndjson")
        if result.get("errors"):
            raise RuntimeError("Elastic rejected Red Range telemetry")
    return {"indexed": len(rows), "index_pattern": INDEX_PREFIX + "-*",
            "raw_messages_indexed": False}
