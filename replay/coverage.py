"""Sigma-only baseline: per-dataset, per-tactic recording coverage and benign noise.

For attack datasets: how many recordings produce any (low+) and med+ detections.
For benign datasets: which med+ rules fire on goodware (false-positive candidates).

    python3 -m replay.coverage DATASET [DATASET ...]
"""

from __future__ import annotations

import glob
import json
import os
import sys
from collections import Counter, defaultdict

from .datasets import DATASETS, Dataset
from .tuning import Tuning

MED_PLUS = {"med", "high", "crit"}


def recordings(dataset: Dataset) -> list[str]:
    pattern = "**/*.json" if dataset.json_input else "**/*.evtx"
    root = dataset.path.rstrip("/") + "/"
    return sorted(p[len(root):] for p in glob.glob(root + pattern, recursive=True))


def hits_by_recording(dataset: Dataset) -> dict[str, set[str]]:
    root = dataset.path.rstrip("/") + "/"
    levels: dict[str, set[str]] = defaultdict(set)
    tuning = Tuning()
    with open(dataset.detections) as handle:
        for line in handle:
            detection = tuning.adjust(json.loads(line))
            if detection is not None:
                levels[detection["EvtxFile"].removeprefix(root)].add(detection["Level"])
    return levels


def attack_coverage(dataset: Dataset) -> list[tuple[str, int, int, int]]:
    levels = hits_by_recording(dataset)
    table: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    for recording in recordings(dataset):
        row = table[dataset.tactic_label(recording)]
        row[0] += 1
        row[1] += bool(levels.get(recording))
        row[2] += bool(levels.get(recording, set()) & MED_PLUS)
    return [(tactic, *row) for tactic, row in sorted(table.items())]


def benign_noise(dataset: Dataset, top: int = 15) -> tuple[int, int, list[tuple[str, str, int, int]]]:
    root = dataset.path.rstrip("/") + "/"
    alerts: Counter[tuple[str, str]] = Counter()
    files: dict[tuple[str, str], set[str]] = defaultdict(set)
    tuning = Tuning()
    with open(dataset.detections) as handle:
        for line in handle:
            detection = tuning.adjust(json.loads(line))
            if detection is not None and detection["Level"] in MED_PLUS:
                key = (detection["Level"], detection["RuleTitle"])
                alerts[key] += 1
                files[key].add(detection["EvtxFile"].removeprefix(root))
    noisy = [(level, title, count, len(files[(level, title)])) for (level, title), count in alerts.most_common(top)]
    return len(recordings(dataset)), sum(alerts.values()), noisy


def main(names: list[str]) -> int:
    if not names or any(name not in DATASETS for name in names):
        sys.exit(__doc__ + f"\nDatasets: {', '.join(DATASETS)}")
    for name in names:
        dataset = DATASETS[name]
        if not os.path.exists(dataset.detections):
            print(f"## {name}: no detections file\n")
            continue
        if dataset.label == "benign":
            total, alerts, noisy = benign_noise(dataset)
            print(f"## {name} (benign, {total} recordings): {alerts} med+ alerts\n")
            print("| Level | Rule | Alerts | Recordings |\n| --- | --- | ---: | ---: |")
            for level, title, count, recs in noisy:
                print(f"| {level} | {title} | {count} | {recs} |")
        else:
            rows = attack_coverage(dataset)
            totals = [sum(r[i] for r in rows) for i in (1, 2, 3)]
            print(f"## {name} (attack)\n")
            print("| Tactic | Recordings | Any hit | Med+ hit |\n| --- | ---: | ---: | ---: |")
            for tactic, total, any_hit, med in rows:
                print(f"| {tactic} | {total} | {any_hit} | {med} |")
            pct = 100 * totals[2] / totals[0] if totals[0] else 0
            print(f"| **total** | **{totals[0]}** | **{totals[1]}** | **{totals[2]} ({pct:.0f}%)** |")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
