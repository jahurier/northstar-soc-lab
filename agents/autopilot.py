"""Autopilot: one SOC cycle end to end on a fresh simulated company day.

    python3 -m agents.autopilot cycle [--jev] [--seed N] [--blue 3]
    python3 -m agents.autopilot list

A cycle: generate a seeded Northstar day (routines, benign look-alikes, planted attacks) ->
build incident chains -> optionally ask Jev (paid, off by default, capped) -> shadow-v4
policy -> blue agent case notes and proposals (local model) -> score against planted truth.

Nothing executes: every blue proposal is written with gate_status "awaiting_human".
Truth is read only by the scorer, after the pipeline has produced its answers.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any

from sim.generate import generate, load_world
from sim.incidents import paired_cases

from . import blue, detection, llm

REPO = Path(__file__).resolve().parents[1]
JEV = Path(os.environ.get("JEV_TEST", os.path.expanduser("~/Projects/jev-test")))
ROOT = REPO / "runs" / "autopilot"
CYCLES = ROOT / "cycles.jsonl"
FAILURES = ROOT / "failures.jsonl"
JEV_CASE_CAP = 40  # hard ceiling on paid Jev calls per cycle


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _policy():
    sys.path.insert(0, str(JEV))
    from jev_security_eval.policy import POLICY_VERSION, recommend  # noqa: E402
    return POLICY_VERSION, recommend


def detection_stage() -> str:
    """Propose at most one new tuning candidate per day; never apply it."""
    if not llm.available():
        return "skipped: local model unavailable"
    today = date.today().isoformat()
    if any(row.get("at", "").startswith(today) and row.get("detection", "").startswith("proposed ")
           for row in cycles(1000)):
        return "already proposed today"
    stats = detection.load_stats()
    ranked = sorted(stats["rules"], key=lambda rid: -stats["rules"][rid]["benign_alerts"])
    attempted = {row["rule_id"] for row in detection.read_proposals().values()}
    next_rule = next((rid for rid in ranked if rid not in attempted), None)
    if next_rule is None:
        return "no new noisy-rule candidate in cached statistics"
    proposals = detection.propose(top=1, rule_ids=[next_rule])
    if not proposals:
        return "no candidate produced"
    proposal = proposals[0]
    return f"proposed {proposal['id']} ({proposal['status']}); human gate retained"


def run_cycle(seed: int | None = None, use_jev: bool = False, blue_limit: int = 3,
              log=print) -> dict[str, Any]:
    started = time.time()
    seed = seed if seed is not None else int(started) % 1_000_000_000
    world = load_world()
    events, truth, cases, summary = generate(world, date.today(), seed)
    _, chains = paired_cases(cases, events)
    cycle_id = f"CYCLE-{time.strftime('%Y%m%d-%H%M%S')}-{seed}"
    folder = ROOT / cycle_id
    folder.mkdir(parents=True, exist_ok=True)
    _write_jsonl(folder / "chain-cases.jsonl", chains)
    _write_jsonl(folder / "truth.jsonl", truth)  # scorer only
    log(f"{cycle_id}: {len(events)} events, {len(chains)} incident cases")

    try:
        detection_status = detection_stage()
    except Exception as exc:
        detection_status = f"error: {type(exc).__name__}"
    log(f"Detection agent: {detection_status}")

    results: list[dict[str, Any]] = []
    jev_status = "off"
    if use_jev:
        capped = chains[:JEV_CASE_CAP]
        _write_jsonl(folder / "jev-input.jsonl", capped)
        out = folder / "jev-results.jsonl"
        proc = subprocess.run([sys.executable, "-m", "jev_security_eval", "run", "--input", str(folder / "jev-input.jsonl"),
                               "--output", str(out), "--workers", "4"], cwd=JEV, capture_output=True, text=True)
        results = _read_jsonl(out)
        jev_status = f"{sum(isinstance(r.get('response'), dict) for r in results)}/{len(capped)} answered" \
                     + ("" if proc.returncode == 0 else " (errors)")
        log(f"Jev: {jev_status}")

    policy_version, recommend = _policy()
    decisions = {}
    for row in results:
        if isinstance(row.get("response"), dict):
            state = next(c["state"] for c in chains if c["case_id"] == row["case_id"])
            decisions[row["case_id"]] = recommend(row["response"]["answers"], state)["recommendation"]

    proposals: list[dict[str, Any]] = []
    blue_status = "skipped: local model unavailable"
    if llm.available():
        try:
            proposals = blue.propose(chains, results, limit=blue_limit)
            blue.save_proposals(blue.read_proposals() + proposals)  # keep earlier proposals
            _write_jsonl(folder / "blue-proposals.jsonl", proposals)
            blue_status = f"{len(proposals)} proposals"
        except Exception as exc:  # a model hiccup must not kill the loop
            blue_status = f"error: {type(exc).__name__}"
    log(f"Blue agent: {blue_status}")

    # ---- score against planted truth (read only now) ----
    attack_cases = [c for c in chains if c["metadata"]["dataset_label"] == "attack"]
    benign_cases = [c for c in chains if c["metadata"]["dataset_label"] == "benign"]
    answered = {r["case_id"]: r["response"]["answers"]["disposition"]["choice"]
                for r in results if isinstance(r.get("response"), dict)}
    attack_hosts = {c["state"]["alert"]["computer"] for c in attack_cases}
    disruptive = [p for p in proposals if p["note"]["action"] in blue.DISRUPTIVE]
    record = {
        "cycle_id": cycle_id, "at": time.strftime("%Y-%m-%dT%H:%M:%S"), "seed": seed,
        "events": len(events), "cases": len(chains), "planted_attacks": len(attack_cases),
        "benign_cases": len(benign_cases), "jev": jev_status, "policy": policy_version,
        "detection": detection_status,
        "jev_attack_called_malicious": sum(answered.get(c["case_id"]) == "likely_malicious" for c in attack_cases),
        "jev_benign_called_benign": sum(answered.get(c["case_id"]) == "likely_benign" for c in benign_cases),
        "escalated": dict(Counter(decisions.values())).get("escalate_for_containment_approval", 0),
        "escalated_attacks": sum(decisions.get(c["case_id"]) == "escalate_for_containment_approval" for c in attack_cases),
        "blue": blue_status, "blue_proposals": len(proposals),
        "blue_disruptive": len(disruptive),
        "blue_disruptive_on_attack_hosts": sum(p["host"] in attack_hosts for p in disruptive),
        "awaiting_human": len(proposals), "executed": 0,
        "seconds": round(time.time() - started, 1),
    }
    ROOT.mkdir(parents=True, exist_ok=True)
    with CYCLES.open("a") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    log(f"cycle done in {record['seconds']}s")
    return record


def cycles(limit: int = 50) -> list[dict[str, Any]]:
    return list(reversed(_read_jsonl(CYCLES)))[:limit]


def record_failure(error_type: str) -> None:
    """Keep failed attempts across console restarts without persisting exception text."""
    ROOT.mkdir(parents=True, exist_ok=True)
    with FAILURES.open("a") as handle:
        handle.write(json.dumps({"at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                                 "error_type": error_type}) + "\n")


def failures(limit: int = 10) -> list[dict[str, str]]:
    return list(reversed(_read_jsonl(FAILURES)))[:limit]


def main(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(description="Northstar autopilot")
    sub = parser.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("cycle")
    c.add_argument("--seed", type=int)
    c.add_argument("--jev", action="store_true", help="paid: send up to 40 incident cases to Jev")
    c.add_argument("--blue", type=int, default=3)
    sub.add_parser("list")
    args = parser.parse_args(argv)
    if args.cmd == "cycle":
        print(json.dumps(run_cycle(args.seed, args.jev, args.blue), indent=2))
    else:
        for r in cycles():
            print(f"{r['at']}  {r['cycle_id']}  attacks {r['planted_attacks']}  jev {r['jev']}  "
                  f"blue {r['blue']}  awaiting {r['awaiting_human']}")


if __name__ == "__main__":
    main(sys.argv[1:])
