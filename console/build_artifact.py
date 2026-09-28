"""Build the standalone (published) console: index.html + a stratified real-data sample.

The local server serves the same index.html with live data; this bakes a sample in
so the page works with no server. Output goes outside the repo because it embeds
dataset-derived content.

    python3 -m console.build_artifact OUTPUT.html [--per-dataset-scale 1.0]
"""

from __future__ import annotations

import json
import random
import sys
from collections import defaultdict
from pathlib import Path

from .server import INDEX, Store

QUOTA = {"evtx-attack": 70, "e2m": 60, "otrf": 90, "deepblue": 25, "yamato": 15, "baseline": 90}


def build(output: str, seed: int = 7) -> int:
    boot = Store().bootstrap()
    by = defaultdict(list)
    for row in boot["events"]:
        by[(row["ds"], bool(row["inj"]))].append(row)
    rng = random.Random(seed)
    sample = []
    for ds, quota in QUOTA.items():
        clean, injected = by[(ds, False)], by[(ds, True)]
        sample += rng.sample(clean, min(quota, len(clean)))
        sample += rng.sample(injected, min(max(3, quota // 7), len(injected)))
    rng.shuffle(sample)
    data = {k: boot[k] for k in ("noisy_top", "noisy_rule_count", "benign_alerts", "coverage", "totals")}
    data.update(mode="artifact", events=sample)
    html = INDEX.read_text().replace("__TOKEN__", "")
    html = html.replace("__DATA__", json.dumps(data, separators=(",", ":")).replace("</", "<\\/"))
    Path(output).write_text(html)
    print(f"{output}: {len(sample)} events, {len(html) // 1024} KB")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(build(sys.argv[1]))
