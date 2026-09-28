"""Map mock-world and passive-replay observations to ECS and bulk-index locally.

Ground-truth files and Jev expected labels are never accepted as input. Repeated
runs use stable document IDs, so ingestion is idempotent.

    python3 -m siem.ingest --input runs/world-events.jsonl --dry-run
    python3 -m siem.ingest --input runs/world-events.jsonl
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import urllib.request
from pathlib import Path
from typing import Any

from .setup import load_env

URL = "http://127.0.0.1:9200"
INDEX_PREFIX = "northstar-events"
ALLOWED_PROVENANCE = {"simulated", "recorded_telemetry_replay"}
TEMPLATE = {
    "index_patterns": [INDEX_PREFIX + "-*"],
    "template": {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {"properties": {
            "@timestamp": {"type": "date"},
            "event": {"properties": {"id": {"type": "keyword"}, "code": {"type": "keyword"},
                                     "action": {"type": "keyword"}, "kind": {"type": "keyword"},
                                     "category": {"type": "keyword"}, "type": {"type": "keyword"},
                                     "dataset": {"type": "keyword"}, "outcome": {"type": "keyword"}}},
            "host": {"properties": {"name": {"type": "keyword"}}},
            "user": {"properties": {"name": {"type": "keyword"}}},
            "source": {"properties": {"ip": {"type": "ip"}}},
            "process": {"properties": {"command_line": {"type": "wildcard"}}},
            "winlog": {"properties": {"channel": {"type": "keyword"}}},
            "northstar": {"properties": {"run_id": {"type": "keyword"},
                                         "provenance": {"type": "keyword"},
                                         "event_type": {"type": "keyword"},
                                         "rule": {"type": "keyword"},
                                         "level": {"type": "keyword"}}},
        }},
    },
}


def map_event(event: dict[str, Any]) -> dict[str, Any]:
    if event.get("provenance") not in ALLOWED_PROVENANCE:
        raise ValueError("only public simulator/replay observations may be ingested")
    for key in ("event_id", "run_id", "timestamp", "host", "event_type"):
        if not isinstance(event.get(key), str) or not event[key]:
            raise ValueError(f"event missing {key}")
    kind = event["event_type"]
    category = "authentication" if "login" in kind else "process" if "process" in kind else \
        "file" if "file" in kind else "intrusion_detection" if kind == "recorded_detection" else "host"
    event_type = "start" if kind in ("process_start", "recorded_detection") else "info"
    details = event.get("details") or {}
    if not isinstance(details, dict):
        raise ValueError("details must be an object")
    document = {
        "@timestamp": event["timestamp"],
        "event": {"id": event["event_id"], "action": kind, "kind": "event", "category": [category],
                  "type": [event_type], "dataset": "northstar.replay" if
                  event["provenance"] == "recorded_telemetry_replay" else "northstar.sim"},
        "host": {"name": event["host"]},
        "northstar": {"run_id": event["run_id"], "provenance": event["provenance"],
                      "event_type": kind},
        "tags": ["northstar", "mock-lab"],
    }
    if event.get("user"):
        document["user"] = {"name": event["user"]}
    if isinstance(event.get("event_code"), (str, int)) and not isinstance(event["event_code"], bool):
        document["event"]["code"] = str(event["event_code"])
    if isinstance(event.get("channel"), str) and event["channel"]:
        document["winlog"] = {"channel": event["channel"]}
    if details.get("outcome") in ("success", "failure"):
        document["event"]["outcome"] = details["outcome"]
    source_ip = details.get("source_ip")
    if source_ip:
        try:
            document["source"] = {"ip": str(ipaddress.ip_address(source_ip))}
        except ValueError:
            pass
    if isinstance(details.get("command_line"), str):
        document["process"] = {"command_line": details["command_line"]}
    if event.get("rule"):
        document["northstar"]["rule"] = event["rule"]
    if event.get("level"):
        document["northstar"]["level"] = event["level"]
    return document


def document_id(event: dict[str, Any]) -> str:
    return hashlib.sha256(f"{event['run_id']}|{event['event_id']}".encode()).hexdigest()


def _request(method: str, path: str, data: bytes, password: str, content_type: str,
             url: str = URL) -> dict[str, Any]:
    auth = base64.b64encode(f"elastic:{password}".encode()).decode()
    req = urllib.request.Request(url + path, data=data, method=method,
                                 headers={"Authorization": "Basic " + auth,
                                          "Content-Type": content_type})
    with urllib.request.urlopen(req, timeout=60) as response:
        return json.loads(response.read())


def ingest(rows: list[dict[str, Any]], password: str, url: str = URL) -> int:
    _request("PUT", "/_index_template/northstar-events", json.dumps(TEMPLATE).encode(), password,
             "application/json", url)
    for offset in range(0, len(rows), 500):
        lines = []
        for event in rows[offset:offset + 500]:
            document = map_event(event)
            index = INDEX_PREFIX + "-" + event["timestamp"][:10].replace("-", ".")
            lines.append(json.dumps({"index": {"_index": index, "_id": document_id(event)}}))
            lines.append(json.dumps(document))
        result = _request("POST", "/_bulk", ("\n".join(lines) + "\n").encode(), password,
                          "application/x-ndjson", url)
        if result.get("errors"):
            raise RuntimeError("Elasticsearch bulk indexing reported item errors")
    return len(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    rows = [json.loads(line) for line in args.input.read_text().splitlines() if line.strip()]
    for row in rows:
        map_event(row)  # reject truth/case files before any network request
    if args.dry_run:
        print(json.dumps({"validated_events": len(rows), "network_requests": 0}))
        return
    count = ingest(rows, load_env()["ELASTIC_PASSWORD"])
    print(json.dumps({"indexed_events": count, "index_pattern": INDEX_PREFIX + "-*"}))


if __name__ == "__main__":
    main()
