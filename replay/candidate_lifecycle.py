"""Gate and activate recorded-data Sigma candidates after an analyst request.

Activation reruns the gate, replays every registered dataset with the base rules
plus active candidates, and only then publishes the new detection files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .datasets import ACTIVE_CURRENT, ACTIVE_ROOT, DATASETS, HAYABUSA_VERSION, active_generation
from .hayabusa import FLAGS, HAYABUSA_BIN, HAYABUSA_DIR
from .rule_gate import gate

REPO = Path(__file__).resolve().parents[1]
REGISTRY = REPO / "detections" / "candidate-gates.json"
CANDIDATES = REPO / "detections" / "candidates"
ACTIVE = REPO / "detections" / "active"


def candidates() -> list[dict[str, Any]]:
    if not REGISTRY.is_file():
        return []
    rows = json.loads(REGISTRY.read_text())["candidates"]
    active_ids = set((active_generation() or {}).get("candidates", []))
    for row in rows:
        source = CANDIDATES / row["file"]
        row["source_matches_gate"] = source.is_file() and hashlib.sha256(source.read_bytes()).hexdigest() == row["sha256"]
        row["active"] = row["id"] in active_ids
    return rows


def _bundle(path: Path, new_rule: Path) -> None:
    shutil.copytree(Path(HAYABUSA_DIR) / "rules", path)
    destination = path / "sigma" / "northstar"
    destination.mkdir(parents=True, exist_ok=True)
    for row in candidates():
        if row["active"]:
            source = ACTIVE / row["file"]
            if not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest() != row["sha256"]:
                raise RuntimeError("published active rule differs from its gated source")
            shutil.copy2(source, destination / source.name)
    shutil.copy2(new_rule, destination / new_rule.name)


def activate(candidate_id: str) -> dict[str, Any]:
    row = next((item for item in candidates() if item["id"] == candidate_id), None)
    if row is None:
        raise ValueError("unknown candidate")
    if row["active"] or not row["gate"]["candidate_gate_passed"] or not row["source_matches_gate"]:
        raise ValueError("candidate is already active, unvalidated, or changed since its gate")
    rule = CANDIDATES / row["file"]
    fresh = gate(rule, row["dataset"], row["recording"],
                 row["validation_dataset"], row["validation_recording"])
    if not fresh["candidate_gate_passed"]:
        raise ValueError("fresh replay gate did not pass")
    root = Path(ACTIVE_ROOT)
    root.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="gen-", dir=root))
    copied_rule = False
    try:
        bundle = work / "rules"
        _bundle(bundle, rule)
        for name, dataset in DATASETS.items():
            output = work / f"{name}-hayabusa-{HAYABUSA_VERSION}.jsonl"
            command = [HAYABUSA_BIN, "dfir-timeline", "-d", dataset.path]
            if dataset.json_input:
                command.append("-J")
            command += ["-r", str(bundle), "-c", str(bundle / "config"),
                        *FLAGS, "-o", str(output)]
            completed = subprocess.run(command, cwd=HAYABUSA_DIR,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if completed.returncode or not output.is_file():
                raise RuntimeError("active-rule replay failed for " + name)
            print("replayed " + name, flush=True)
        # Existing detection outputs stay intact. One pointer publishes the
        # complete new generation after every dataset replay has succeeded.
        ACTIVE.mkdir(parents=True, exist_ok=True)
        shutil.copy2(rule, ACTIVE / rule.name)
        copied_rule = True
        prior = active_generation() or {}
        manifest = {"generation": work.name,
                    "candidates": sorted(set(prior.get("candidates", [])) | {candidate_id}),
                    "activated_at": datetime.now(timezone.utc).isoformat(),
                    "last_gate": fresh}
        temporary = Path(ACTIVE_CURRENT).with_suffix(".json.tmp")
        temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        os.replace(temporary, ACTIVE_CURRENT)
    except Exception:
        shutil.rmtree(work, ignore_errors=True)
        if copied_rule:
            (ACTIVE / rule.name).unlink(missing_ok=True)
        raise
    return {"candidate": candidate_id, "gate": fresh, "datasets_replayed": list(DATASETS)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("action", choices=("activate",))
    parser.add_argument("candidate_id")
    args = parser.parse_args()
    print(json.dumps(activate(args.candidate_id), indent=2))


if __name__ == "__main__":
    main()
