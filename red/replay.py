"""Build a timed mock-company timeline from existing recorded detections.

This module reads v3 Jev cases from the development split. It never executes
recorded commands or generates new attack steps. Dataset truth stays in a
separate file; the public timeline contains only detection observations.

    python3 -m red.replay list --corpus runs/otrf-development-v3-alerts.jsonl
    python3 -m red.replay build --corpus runs/otrf-development-v3-alerts.jsonl \
        --campaign LSASS_campaign_03 --seed 7 --output-dir runs/red-demo
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sim.generate import load_world, world_hash

DEFAULT_CORPUS = Path(__file__).resolve().parents[1] / "runs" / "otrf-development-v3-alerts.jsonl"
DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / "runs" / "red-replay"
TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def campaign_for(case: dict[str, Any]) -> str | None:
    metadata = case.get("metadata") or {}
    recording = str(metadata.get("recording") or "").split("/")
    if (not str(metadata.get("dataset") or "").startswith("otrf@")
            or metadata.get("context_version") != "v3"
            or metadata.get("split") != "development"
            or metadata.get("injected")
            or len(recording) < 3 or recording[0] != "compound"):
        return None
    return recording[1]


def load_cases(path: Path) -> list[dict[str, Any]]:
    cases = []
    with path.open() as handle:
        for line in handle:
            if line.strip():
                case = json.loads(line)
                if campaign_for(case):
                    cases.append(case)
    return cases


def catalog(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for case in cases:
        name = campaign_for(case)
        if name:
            groups.setdefault(name, []).append(case)
    out = []
    for name, rows in sorted(groups.items()):
        tags = {tag for case in rows for tag in case["state"]["detection"].get("mitre_tags", [])
                if isinstance(tag, str) and TECHNIQUE.fullmatch(tag)}
        out.append({
            "campaign": name,
            "cases": len(rows),
            "recordings": len({case["metadata"]["recording"] for case in rows}),
            "rule_techniques_observed": sorted(tags),
            "technique_scope": "Sigma rule tags across this campaign, not a per-stage attribution",
            "label_quality": "weak_recording_label",
        })
    return out


def _parse_time(value: Any) -> datetime | None:
    try:
        timestamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if timestamp.tzinfo is None or not 2000 <= timestamp.year <= 2100:
        return None
    return timestamp.astimezone(timezone.utc)


def build(cases: list[dict[str, Any]], world: dict[str, Any], campaign: str,
          day: date, seed: int, *, max_cases: int = 100) -> tuple[list[dict], list[dict], dict]:
    if not 1 <= max_cases <= 200:
        raise ValueError("max_cases must be from 1 to 200")
    selected = [case for case in cases if campaign_for(case) == campaign]
    if not selected:
        raise ValueError(f"no development-split v3 cases for campaign {campaign!r}")
    parsed = [_parse_time(case["state"]["alert"].get("timestamp")) for case in selected]
    timed = all(parsed) and len(set(parsed)) > 1
    if timed:
        selected.sort(key=lambda case: (_parse_time(case["state"]["alert"]["timestamp"]), case["case_id"]))
    else:
        selected.sort(key=lambda case: case["case_id"])
    if len(selected) > max_cases:
        # Evenly sample the whole recording instead of taking only its opening.
        positions = [round(i * (len(selected) - 1) / (max_cases - 1)) for i in range(max_cases)] if max_cases > 1 else [0]
        selected = [selected[i] for i in positions]

    rng = random.Random(seed)
    hosts = sorted(world["hosts"])
    rng.shuffle(hosts)
    source_hosts = sorted({str(case["state"]["alert"].get("computer") or "unknown") for case in selected})
    host_map = {source: hosts[i % len(hosts)] for i, source in enumerate(source_hosts)}
    start = datetime(day.year, day.month, day.day, world["workday"]["start_hour"], tzinfo=timezone.utc)
    span = timedelta(hours=world["workday"]["end_hour"] - world["workday"]["start_hour"] - 1)
    raw_times = [_parse_time(case["state"]["alert"].get("timestamp")) for case in selected]
    use_dwell = timed and len(set(raw_times)) > 1
    digest = hashlib.sha256(f"{world_hash(world)}|{campaign}|{day}|{seed}|{max_cases}".encode()).hexdigest()[:12]
    run_id = f"REPLAY-{digest.upper()}"
    events, truth = [], []
    for i, case in enumerate(selected):
        if use_dwell:
            fraction = (raw_times[i] - raw_times[0]) / (raw_times[-1] - raw_times[0])
        else:
            fraction = i / max(1, len(selected) - 1)
        when = start + span * fraction
        alert, detection = case["state"]["alert"], case["state"]["detection"]
        event_id = f"{run_id}-{i + 1:04d}"
        events.append({
            "event_id": event_id, "run_id": run_id,
            "timestamp": when.isoformat().replace("+00:00", "Z"),
            "host": host_map[str(alert.get("computer") or "unknown")],
            "source": alert.get("source"), "channel": alert.get("channel"),
            "event_code": alert.get("event_id"), "event_type": "recorded_detection",
            "rule": detection["rule_title"], "level": detection["level"],
            "provenance": "recorded_telemetry_replay",
        })
        truth.append({
            "event_id": event_id, "recorded_case_id": case["case_id"],
            "recording": case["metadata"]["recording"],
            "dataset_label": case["metadata"]["dataset_label"],
            "label_quality": "weak_recording_label",
            "campaign": campaign,
        })
    summary = {
        "run_id": run_id, "campaign": campaign, "events": len(events),
        "recordings": len({case["metadata"]["recording"] for case in selected}),
        "source_context": "v3 development split", "label_quality": "weak_recording_label",
        "time_mapping": "recorded order and relative dwell scaled to workday" if use_dwell else "stable case order, evenly spaced; source timestamps unusable",
        "host_map": host_map, "executes_actions": False,
        "truth_file": "campaign-truth.jsonl",
    }
    return events, truth, summary


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    temp.replace(path)


def write_run(output_dir: Path, events: list[dict], truth: list[dict], summary: dict) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_jsonl(output_dir / "campaign-events.jsonl", events)
    _write_jsonl(output_dir / "campaign-truth.jsonl", truth)
    temp = output_dir / "campaign-summary.json.tmp"
    temp.write_text(json.dumps(summary, indent=2) + "\n")
    temp.replace(output_dir / "campaign-summary.json")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("action", choices=("list", "build"))
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--campaign")
    parser.add_argument("--world", type=Path)
    parser.add_argument("--date", type=date.fromisoformat, default=date.today())
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--max-cases", type=int, default=100)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    cases = load_cases(args.corpus)
    if args.action == "list":
        print(json.dumps(catalog(cases), indent=2))
        return
    if not args.campaign:
        parser.error("build requires --campaign from the catalog")
    world = load_world(args.world) if args.world else load_world()
    events, truth, summary = build(cases, world, args.campaign, args.date, args.seed,
                                   max_cases=args.max_cases)
    write_run(args.output_dir, events, truth, summary)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
