"""Index one minimized host metric into the LOCAL lab, then read it back.

This verifies local transport and provenance separation. It does not install
Fleet, collect host logs, or establish production readiness.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from replay.datasets import RUNS
from siem.setup import load_env, request

ROOT = Path(RUNS) / "production-pilot"
INDEX = "northstar-pilot-local"


def document(run_id: str, *, load: float, free_bytes: int) -> dict[str, Any]:
    if not run_id.startswith("local-") or len(run_id) > 64:
        raise ValueError("invalid local test run id")
    return {"@timestamp": datetime.now(timezone.utc).isoformat(),
            "event": {"kind": "metric", "dataset": "northstar.pilot.local_probe"},
            "northstar": {"run_id": run_id, "provenance": "local_test"},
            "system": {"load": {"one_minute": round(float(load), 3)},
                       "filesystem": {"free_bytes": int(free_bytes)}}}


def run() -> dict[str, Any]:
    run_id = "local-" + secrets.token_hex(8)
    free_bytes = shutil.disk_usage(Path.home()).free
    payload = document(run_id, load=os.getloadavg()[0], free_bytes=free_bytes)
    password = load_env()["ELASTIC_PASSWORD"]
    indexed = request("PUT", f"/{INDEX}/_doc/{run_id}?refresh=wait_for", payload, password)
    fetched = request("GET", f"/{INDEX}/_doc/{run_id}", None, password)
    verified = indexed.get("result") in ("created", "updated") and fetched.get("_source") == payload
    record = {"run_id": run_id, "provenance": "local_test", "index": INDEX,
              "verified": bool(verified), "events": 1, "fleet_verified": False,
              "production_source_enrolled": False}
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    ROOT.chmod(0o700)
    path = ROOT / (run_id + ".json")
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as handle:
        json.dump(record, handle, sort_keys=True)
        handle.write("\n")
    if not verified:
        raise RuntimeError("local Elastic write/read verification failed")
    return record


if __name__ == "__main__":
    print(json.dumps(run(), sort_keys=True))
