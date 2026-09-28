"""Score Jev and the weak dataset labels against analyst adjudications.

    python3 -m replay.adjudication

Uses adjudications/queue.json (strata reasons, kept out of the UI) and the latest verdict
per case in adjudications/labels.jsonl. Reports, per stratum: how many are labeled, how
often the analyst agrees with Jev's disposition, and how often the weak dataset label
("attack recording" / "goodware") matched the analyst's malicious-or-not call.
"""

from __future__ import annotations

import json
import os
from collections import defaultdict
from pathlib import Path

from adjudications.ledger import read as read_analyst_labels

REPO = Path(__file__).resolve().parents[1]
QUEUE = REPO / "adjudications" / "queue.json"
LABELS = REPO / "adjudications" / "labels.jsonl"
RESULTS = Path(os.path.expanduser("~/Projects/jev-test/artifacts/replay-multi-results.jsonl"))


def main() -> int:
    queue = json.loads(QUEUE.read_text())["cases"]
    labels = {case_id: entry["verdict"] for case_id, entry in read_analyst_labels(LABELS).items()}
    wanted = {c["case_id"] for c in queue}
    jev, weak = {}, {}
    with open(RESULTS) as handle:
        for line in handle:
            row = json.loads(line)
            if row["case_id"] in wanted and isinstance(row.get("response"), dict):
                jev[row["case_id"]] = row["response"]["answers"]["disposition"]["choice"]
                weak[row["case_id"]] = row["metadata"]["dataset_label"]
    by = defaultdict(lambda: {"n": 0, "labeled": 0, "agree_jev": 0, "weak_label_right": 0})
    for case in queue:
        s = by[case["reason"]]
        s["n"] += 1
        verdict = labels.get(case["case_id"])
        if not verdict:
            continue
        s["labeled"] += 1
        s["agree_jev"] += verdict == jev.get(case["case_id"])
        s["weak_label_right"] += (verdict == "likely_malicious") == (weak.get(case["case_id"]) == "attack")
    total = sum(s["labeled"] for s in by.values())
    print(f"Adjudicated {total}/{len(queue)} queue cases\n")
    print(f"{'stratum':70} {'labeled':>8} {'=Jev':>6} {'weak ok':>8}")
    for reason, s in by.items():
        pct = lambda x: f"{x}/{s['labeled']}" if s["labeled"] else "—"
        print(f"{reason[:70]:70} {s['labeled']:>3}/{s['n']:<4} {pct(s['agree_jev']):>6} {pct(s['weak_label_right']):>8}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
