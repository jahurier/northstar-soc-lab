"""Build paired single-alert and whole-chain Jev cases from the mock company day.

All added observations are synthetic. A planted authorization record is supplied
only for mock maintenance that the simulator actually designated as approved.
Ground truth and scenario family remain outside `state`.

    python3 -m sim.incidents --output-dir runs
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .generate import RUNS, load_world


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _observation(timestamp: str, source: str, description: str, **facts: Any) -> dict[str, Any]:
    return {"timestamp": timestamp, "source": source, "observation": description, "facts": facts}


def _near(timestamp: str, minutes: int) -> str:
    return (datetime.fromisoformat(timestamp.replace("Z", "+00:00")) + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")


def _context(case: dict[str, Any], events: dict[str, dict[str, Any]]) -> dict[str, Any]:
    alert = case["state"]["alert"]
    family = case["metadata"]["scenario_family"]
    when, host, user = alert["timestamp"], alert["computer"], case["state"]["identity_context"]["user"]
    token = hashlib.sha256(case["case_id"].encode()).hexdigest()[:8].upper()
    if family == "approved_maintenance":
        return {
            "observations": [
                _observation(_near(when, -12), "change_calendar", "Scheduled workstation maintenance opened",
                             host=host, owner=user),
                _observation(_near(when, -3), "task_scheduler", "Approved patch task started",
                             host=host, account=user),
                _observation(_near(when, 8), "change_calendar", "Maintenance task completed in window",
                             host=host, outcome="success"),
            ],
            "approved_work_record": {"record_id": f"CHG-{token}", "status": "approved",
                                     "scope": {"host": host, "account": user},
                                     "source": "synthetic_change_calendar"},
            "software_trust": {"publisher": "Northstar IT", "verification": "mock_inventory_match",
                               "source": "synthetic_software_inventory"},
        }
    if family == "scheduled_backup":
        return {
            "observations": [
                _observation(_near(when, -10), "backup_scheduler", "Scheduled backup job started",
                             host=host, account=user),
                _observation(_near(when, 12), "backup_scheduler", "Backup job completed",
                             host=host, account=user, outcome="success"),
            ],
            "approved_work_record": {"record_id": f"JOB-{token}", "status": "scheduled",
                                     "scope": {"host": host, "account": user},
                                     "source": "synthetic_backup_scheduler"},
        }
    if family == "credential_spray":
        evidence = [events[event_id] for event_id in case["metadata"]["evidence_event_ids"]]
        return {"observations": [
            _observation(item["timestamp"], "identity_log", "Authentication attempt",
                         host=item["host"], account=item["user"],
                         source_ip=item["details"].get("source_ip"),
                         outcome=item["details"].get("outcome"))
            for item in evidence]}
    if family == "encoded_execution":
        return {"observations": [
            _observation(_near(when, -4), "identity_log", "Interactive session began",
                         host=host, account=user, source_segment="unrecognized_lab_segment"),
            _observation(_near(when, 2), "endpoint_log", "Child process started outside a scheduled task",
                         host=host, account=user),
        ]}
    if family == "bulk_collection":
        return {"observations": [
            _observation(_near(when, -7), "file_audit", "Unscheduled access to shared files began",
                         host=host, account=user),
            _observation(_near(when, 5), "file_audit", "Read volume exceeded this account's usual batch",
                         host=host, account=user, observed_files=420),
        ]}
    return {"observations": []}


def paired_cases(cases: list[dict[str, Any]], events: list[dict[str, Any]]) -> tuple[list[dict], list[dict]]:
    event_index = {event["event_id"]: event for event in events}
    single = deepcopy(cases)
    chains = deepcopy(cases)
    world = load_world()
    for case in [*single, *chains]:
        state = case["state"]
        state["detection"].pop("status", None)
        host = state["alert"]["computer"]
        user = state["identity_context"]["user"]
        asset = world["hosts"].get(host, {})
        account = world["users"].get(user, {})
        state["asset_context"] = {"computer": host, "role": asset.get("role"),
                                  "team": asset.get("team"), "ip": asset.get("ip")}
        state["identity_context"] = {"user": user, "role": account.get("persona"),
                                     "team": account.get("team")}
        details = state["alert"].get("details") or {}
        for key, value in details.items():
            if isinstance(value, str):
                details[key] = re.sub(r"<synthetic[^>]*>", "[content redacted]", value)
        case["metadata"]["context_version"] = "synthetic_single_v2"
    for case in chains:
        context = _context(case, event_index)
        case["state"]["enrichment"]["incident_context"] = context
        case["metadata"]["context_version"] = "synthetic_incident_chain_v2"
        case["metadata"]["incident_id"] = "INC-" + hashlib.sha256(case["case_id"].encode()).hexdigest()[:12].upper()
    return single, chains


def _write(path: Path, rows: list[dict]) -> None:
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    temp.replace(path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--input-dir", type=Path, default=RUNS)
    parser.add_argument("--output-dir", type=Path, default=RUNS)
    args = parser.parse_args()
    cases = _load_jsonl(args.input_dir / "world-cases.jsonl")
    events = _load_jsonl(args.input_dir / "world-events.jsonl")
    single, chains = paired_cases(cases, events)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    _write(args.output_dir / "world-single-cases.jsonl", single)
    _write(args.output_dir / "world-chain-cases.jsonl", chains)
    print(json.dumps({"single": len(single), "chains": len(chains),
                      "paired_ids_equal": {c["case_id"] for c in single} == {c["case_id"] for c in chains}}))


if __name__ == "__main__":
    main()
