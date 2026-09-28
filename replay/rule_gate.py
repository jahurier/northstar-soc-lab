"""Replay-gate a draft Sigma rule against target, validation, and goodware.

    python3 -m replay.rule_gate RULE.yml DATASET RECORDING
    python3 -m replay.rule_gate RULE.yml DATASET RECORDING \
      --validation-dataset DATASET --validation-recording RECORDING

This is a candidate gate, not deployment. A full pass requires a new med+
recording hit, a distinct positive validation recording, and zero hits on the
entire goodware baseline.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from .coverage import MED_PLUS, hits_by_recording
from .datasets import DATASETS
from .hayabusa import FLAGS, HAYABUSA_BIN, HAYABUSA_DIR


def _run(rule: Path, source: Path, output: Path, *, json_input: bool = False) -> list[dict[str, Any]]:
    input_flag = "-d" if source.is_dir() else "-f"
    argv = [HAYABUSA_BIN, "dfir-timeline", input_flag, str(source)]
    if json_input:
        argv.append("-J")
    argv += ["-r", str(rule), "-c", str(Path(HAYABUSA_DIR) / "rules" / "config"),
             *FLAGS, "-o", str(output)]
    completed = subprocess.run(argv, cwd=HAYABUSA_DIR, capture_output=True, text=True, timeout=180)
    if completed.returncode:
        raise RuntimeError(f"Hayabusa failed ({completed.returncode}): {completed.stderr[-400:]}")
    return [json.loads(line) for line in output.read_text().splitlines() if line.strip()]


def _source(dataset_name: str, recording: str) -> tuple[Any, Path]:
    dataset = DATASETS[dataset_name]
    if dataset.label != "attack":
        raise ValueError("selected dataset must contain attack recordings")
    root = Path(dataset.path).resolve()
    source = (root / recording).resolve()
    if not source.is_relative_to(root) or not source.is_file():
        raise ValueError("recording must be a file within the selected dataset")
    return dataset, source


def gate(rule: Path, dataset_name: str, recording: str,
         validation_dataset: str | None = None, validation_recording: str | None = None) -> dict[str, Any]:
    if bool(validation_dataset) != bool(validation_recording):
        raise ValueError("validation dataset and recording must be supplied together")
    dataset, source = _source(dataset_name, recording)
    validation = _source(validation_dataset, validation_recording) if validation_dataset else None
    if validation and validation[1] == source:
        raise ValueError("validation must use a distinct recording")
    rule = rule.resolve()
    if not rule.is_file() or rule.suffix not in (".yml", ".yaml"):
        raise ValueError("rule must be a Sigma YAML file")
    previous = bool(hits_by_recording(dataset).get(recording, set()) & MED_PLUS)
    with tempfile.TemporaryDirectory(prefix="northstar-rule-gate-") as folder:
        work = Path(folder)
        attack = _run(rule, source, work / "attack.jsonl", json_input=dataset.json_input)
        positive = (_run(rule, validation[1], work / "validation.jsonl",
                         json_input=validation[0].json_input) if validation else [])
        benign = _run(rule, Path(DATASETS["baseline"].path), work / "benign.jsonl")
    result = {"rule": rule.name, "dataset": dataset_name, "recording": recording,
              "previously_med_plus_detected": previous, "candidate_attack_hits": len(attack),
              "candidate_benign_hits": len(benign),
              "validation_dataset": validation_dataset,
              "validation_recording": validation_recording,
              "validation_attack_hits": len(positive)}
    result["target_gate_passed"] = bool(attack) and not benign and not previous
    result["candidate_gate_passed"] = result["target_gate_passed"] and bool(positive)
    result["tested_target_coverage_delta"] = int(result["candidate_gate_passed"])
    result["validation"] = "distinct positive hit" if positive else "separate positive recording still required"
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("rule", type=Path)
    parser.add_argument("dataset")
    parser.add_argument("recording")
    parser.add_argument("--validation-dataset")
    parser.add_argument("--validation-recording")
    args = parser.parse_args()
    print(json.dumps(gate(args.rule, args.dataset, args.recording,
                          args.validation_dataset, args.validation_recording), indent=2))
