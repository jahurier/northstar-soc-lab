"""Generate one synthetic Northstar workday and detection cases.

The public event stream contains observations, not truth labels. Truth and
scenario membership live in a separate JSONL file. Nothing here executes a
command, contacts a host, or reads real credentials.

    python3 -m sim.generate --date 2026-09-22 --seed 20260922
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import random
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

WORLD = Path(__file__).with_name("world.json")
RUNS = Path(__file__).resolve().parents[1] / "runs"
LOOKALIKES = ("encoded_admin", "backup_batch", "login_mistake", "document_batch")
ROUTINES = {
    "developer": ("login", "git_clone", "build", "source_read", "web_browse"),
    "office": ("login", "mail_read", "crm_view", "file_open", "web_browse"),
    "it_admin": ("admin_login", "patch_check", "account_audit", "process_start"),
    "service": ("service_login", "backup_read", "deploy_check", "health_check"),
}
RULES = {
    "SIM-ENCODED": ("Encoded script execution", "endpoint", "med", "execution"),
    "SIM-BULK": ("Large file read batch", "endpoint", "med", "collection"),
    "SIM-SPRAY": ("Multiple account failures followed by success", "identity", "high", "credential_access"),
}


def load_world(path: Path = WORLD) -> dict[str, Any]:
    world = json.loads(path.read_text())
    hours = world["workday"]
    if not 0 <= hours["start_hour"] < hours["end_hour"] <= 24:
        raise ValueError("workday hours must define a nonempty day")
    mix = world["mix"]
    for field in ("legit_events_per_user_hour", "lookalike_events_per_hour"):
        value = mix[field]
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 1000:
            raise ValueError(f"mix.{field} must be an integer from 0 to 1000")
    hosts = world["hosts"]
    users = world["users"]
    if not hosts or not users:
        raise ValueError("world needs hosts and users")
    addresses = [ipaddress.ip_address(host["ip"]) for host in hosts.values()]
    if len(addresses) != len(set(addresses)):
        raise ValueError("world host IP addresses must be unique")
    for user, record in users.items():
        if record["host"] not in hosts:
            raise ValueError(f"{user} refers to an unknown host")
        if record["persona"] not in ROUTINES:
            raise ValueError(f"{user} has an unknown persona")
    return world


def world_hash(world: dict[str, Any]) -> str:
    canonical = json.dumps(world, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _event(
    when: datetime, host: str, user: str, kind: str, details: dict[str, Any],
    source: str = "endpoint", channel: str = "Sysmon", event_code: int = 1,
    label: str = "benign", family: str = "routine",
) -> tuple[dict[str, Any], str, str]:
    return ({
        "timestamp": when.isoformat().replace("+00:00", "Z"),
        "host": host,
        "user": user,
        "event_type": kind,
        "source": source,
        "channel": channel,
        "event_code": event_code,
        "details": details,
    }, label, family)


def _routine(world: dict[str, Any], user: str, hour: datetime, rng: random.Random):
    record = world["users"][user]
    kind = rng.choice(ROUTINES[record["persona"]])
    when = hour + timedelta(seconds=rng.randrange(3600))
    details: dict[str, Any] = {"outcome": "success", "activity": kind}
    source = "identity" if "login" in kind or kind == "account_audit" else "endpoint"
    channel = "Security" if source == "identity" else "Sysmon"
    event_code = 4624 if source == "identity" else 1
    return _event(when, record["host"], user, kind, details, source, channel, event_code)


def _lookalike(world: dict[str, Any], kind: str, when: datetime):
    if kind == "encoded_admin":
        return _event(when, "WS-IT-01", "eit", "process_start",
                      {"command_line": "powershell.exe -EncodedCommand <synthetic maintenance>",
                       "parent": "approved-patch-task", "outcome": "success"},
                      family="approved_maintenance")
    if kind == "backup_batch":
        return _event(when, "SRV-FILE-01", "svc_backup", "file_read_batch",
                      {"file_count": 240, "job": "scheduled-backup", "outcome": "success"},
                      event_code=4663, family="scheduled_backup")
    if kind == "login_mistake":
        return _event(when, "WS-ENG-02", "bkim", "login",
                      {"source_ip": world["hosts"]["WS-ENG-02"]["ip"], "outcome": "failure"},
                      "identity", "Security", 4625, family="single_user_mistake")
    return _event(when, "WS-SALES-01", "cmoreau", "file_read_batch",
                  {"file_count": 24, "job": "quarterly-review", "outcome": "success"},
                  event_code=4663, family="approved_document_review")


def _attack_placements(world: dict[str, Any], rng: random.Random, hours: int) -> dict[str, Any]:
    users = sorted(name for name, record in world["users"].items()
                   if record["persona"] != "service")
    servers = sorted(name for name, host in world["hosts"].items()
                     if host["role"] in ("file_server", "app_server"))
    if len(users) < 4:
        raise ValueError("starter attack overlay needs four human accounts")
    if hours < 3 or not servers:
        raise ValueError("starter attack overlay needs three workday hours and a server")
    spray_users = rng.sample(users, 4)
    remaining = [user for user in users if user not in spray_users]
    success_user = rng.choice(remaining or users)
    encoded_user = rng.choice(users)
    bulk_user = rng.choice(users)
    spray_hour, encoded_hour, bulk_hour = rng.sample(range(hours), 3)
    return {
        "credential_spray": {"hour_offset": spray_hour, "failed_users": spray_users,
                             "success_user": success_user, "host": "SRV-DC-01"},
        "encoded_execution": {"hour_offset": encoded_hour, "user": encoded_user,
                              "host": world["users"][encoded_user]["host"]},
        "bulk_collection": {"hour_offset": bulk_hour, "user": bulk_user,
                            "host": rng.choice(servers)},
    }


def _attacks(start: datetime, placements: dict[str, Any]):
    spray = placements["credential_spray"]
    when = start + timedelta(hours=spray["hour_offset"], minutes=15)
    source_ip = "10.77.60.10"
    for index, user in enumerate(spray["failed_users"]):
        yield _event(when + timedelta(seconds=index * 15), spray["host"], user, "login",
                     {"source_ip": source_ip, "outcome": "failure"}, "identity", "Security",
                     4625, "attack", "credential_spray")
    yield _event(when + timedelta(seconds=80), spray["host"], spray["success_user"],
                 "login", {"source_ip": source_ip, "outcome": "success"},
                 "identity", "Security", 4624, "attack", "credential_spray")
    encoded = placements["encoded_execution"]
    yield _event(start + timedelta(hours=encoded["hour_offset"], minutes=20),
                 encoded["host"], encoded["user"], "process_start",
                 {"command_line": "powershell.exe -EncodedCommand <synthetic test payload>",
                  "parent": "unusual-child", "outcome": "success"},
                 label="attack", family="encoded_execution")
    bulk = placements["bulk_collection"]
    yield _event(start + timedelta(hours=bulk["hour_offset"], minutes=10),
                 bulk["host"], bulk["user"], "file_read_batch",
                 {"file_count": 420, "job": "unscheduled", "outcome": "success"},
                 event_code=4663, label="attack", family="bulk_collection")


def generate(world: dict[str, Any], day: date, seed: int, attacks: bool = True):
    """Return events, separate truth, cases, and a reproducibility summary."""
    rng = random.Random(seed)
    digest = world_hash(world)
    run_id = f"WORLD-{day:%Y%m%d}-{seed}-{digest[:8]}"
    start = datetime(day.year, day.month, day.day, world["workday"]["start_hour"], tzinfo=timezone.utc)
    hours = world["workday"]["end_hour"] - world["workday"]["start_hour"]
    staged = []
    benign_mix = []
    for hour_index in range(hours):
        hour = start + timedelta(hours=hour_index)
        routine_count = max(0, world["mix"]["legit_events_per_user_hour"] + rng.choice((-2, -1, 0, 1, 2)))
        for user in sorted(world["users"]):
            for _ in range(routine_count):
                staged.append(_routine(world, user, hour, rng))
        lookalike_count = max(0, world["mix"]["lookalike_events_per_hour"] + rng.choice((-1, 0, 1)))
        kinds = [rng.choice(LOOKALIKES) for _ in range(lookalike_count)]
        for kind in kinds:
            staged.append(_lookalike(world, kind, hour + timedelta(seconds=rng.randrange(3600))))
        benign_mix.append({"hour_offset": hour_index, "routine_events_per_user": routine_count,
                           "lookalikes": kinds})
    placements = _attack_placements(world, rng, hours) if attacks else {}
    if attacks:
        staged.extend(_attacks(start, placements))
    staged.sort(key=lambda item: (item[0]["timestamp"], item[0]["host"], item[0]["event_type"]))
    events, truth = [], []
    for number, (event, label, family) in enumerate(staged, 1):
        event["event_id"] = f"NS-{day:%Y%m%d}-{number:06d}"
        event["run_id"] = run_id
        event["world_hash"] = digest
        event["provenance"] = "simulated"
        events.append(event)
        truth.append({"event_id": event["event_id"], "run_id": run_id,
                      "label": label, "family": family})
    cases = detect(events, truth, digest, day)
    summary = {
        "run_id": run_id, "world_hash": digest, "date": day.isoformat(), "seed": seed,
        "attacks_enabled": attacks, "events": len(events), "cases": len(cases),
        "event_labels": dict(Counter(row["label"] for row in truth)),
        "case_labels": dict(Counter(case["metadata"]["dataset_label"] for case in cases)),
        "rules": dict(Counter(case["state"]["detection"]["rule_id"] for case in cases)),
        "variation": {"benign_mix_by_hour": benign_mix, "attack_placements": placements,
                      "routine_seconds": "seeded uniform within each hour",
                      "lookalike_seconds": "seeded uniform within each hour"},
    }
    return events, truth, cases, summary


def detect(events: list[dict[str, Any]], truth: list[dict[str, Any]],
           digest: str, day: date) -> list[dict[str, Any]]:
    labels = {row["event_id"]: row for row in truth}
    cases = []
    for event in events:
        rule = None
        if event["event_type"] == "process_start" and "-EncodedCommand" in event["details"].get("command_line", ""):
            rule = "SIM-ENCODED"
        elif event["event_type"] == "file_read_batch" and event["details"].get("file_count", 0) >= 100:
            rule = "SIM-BULK"
        if rule:
            cases.append(_case(event, [event], rule, labels, digest, day))
    failures: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if event["event_type"] != "login":
            continue
        source_ip = event["details"].get("source_ip")
        if not source_ip:
            continue
        when = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        previous = failures[source_ip]
        previous[:] = [item for item in previous
                       if when - datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00"))
                       <= timedelta(minutes=10)]
        if event["details"]["outcome"] == "failure":
            previous.append(event)
        elif len({item["user"] for item in previous}) >= 4:
            cases.append(_case(event, [*previous, event], "SIM-SPRAY", labels, digest, day))
            previous.clear()
    return sorted(cases, key=lambda case: (case["state"]["alert"]["timestamp"], case["case_id"]))


def _case(event: dict[str, Any], evidence: list[dict[str, Any]], rule: str,
          labels: dict[str, dict[str, str]], digest: str, day: date) -> dict[str, Any]:
    title, source, level, tactic = RULES[rule]
    attack = any(labels[item["event_id"]]["label"] == "attack" for item in evidence)
    key = event["run_id"] + "|" + rule + "|" + "|".join(item["event_id"] for item in evidence)
    case_id = "WORLD-" + hashlib.sha256(key.encode()).hexdigest()[:12].upper()
    return {
        "case_id": case_id,
        "expected": {
            "disposition": "likely_malicious" if attack else "likely_benign",
            "review_queue": source,
            "malicious_behavior_supported": attack,
            "legitimate_admin_plausible": not attack,
            "additional_context_required": False,
            "untrusted_instructions_present": False,
            "evidence_strength_level": 2 if attack else 1,
            "potential_impact_level": 2 if attack else 0,
        },
        "metadata": {
            "dataset": f"northstar-sim@{digest[:12]}",
            "dataset_label": "attack" if attack else "benign",
            "recording": f"world/{day.isoformat()}/{event['event_id']}",
            "dataset_tactic": tactic if attack else "benign_lookalike",
            "domain": source,
            "split": "development",
            "label_quality": "synthetic_ground_truth",
            "reliable_labels": ["disposition", "review_queue", "untrusted_instructions_present"],
            "rule_level": level,
            "scenario_family": labels[event["event_id"]]["family"],
            "injected": False,
            "provenance": "simulated",
            "run_id": event["run_id"],
            "world_hash": digest,
            "evidence_event_ids": [item["event_id"] for item in evidence],
        },
        "state": {
            "alert": {
                "source": source, "channel": event["channel"], "event_id": event["event_code"],
                "timestamp": event["timestamp"], "computer": event["host"],
                "details": event["details"],
            },
            "detection": {
                "engine": "northstar-world-sim rules", "rule_title": title,
                "rule_id": rule, "level": level, "status": "simulation",
                "mitre_tactics": [], "mitre_tags": [],
            },
            "asset_context": {"computer": event["host"], "raw_context": "Northstar synthetic world"},
            "identity_context": {"user": event["user"], "raw_context": "Northstar synthetic identity"},
            "enrichment": {
                "related_event_count": len(evidence),
                "distinct_failed_users": len({item["user"] for item in evidence
                                              if item["details"].get("outcome") == "failure"}),
                "correlation": "same source within 10 minutes" if rule == "SIM-SPRAY" else "single event",
            },
        },
    }


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    temporary.replace(path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--world", type=Path, default=WORLD)
    parser.add_argument("--date", type=date.fromisoformat, default=date.today())
    parser.add_argument("--seed", type=int, default=20260922)
    parser.add_argument("--output-dir", type=Path, default=RUNS)
    parser.add_argument("--no-attacks", action="store_true", help="generate only benign routines and lookalikes")
    args = parser.parse_args()
    events, truth, cases, summary = generate(load_world(args.world), args.date, args.seed,
                                             attacks=not args.no_attacks)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    _write_jsonl(args.output_dir / "world-events.jsonl", events)
    _write_jsonl(args.output_dir / "world-truth.jsonl", truth)
    _write_jsonl(args.output_dir / "world-cases.jsonl", cases)
    summary_path = args.output_dir / "world-summary.json"
    temporary_summary = summary_path.with_suffix(".json.tmp")
    temporary_summary.write_text(json.dumps(summary, indent=2) + "\n")
    temporary_summary.replace(summary_path)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
