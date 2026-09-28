#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO"
PYTHON_BIN="${PYTHON_BIN:-python3}"
"$PYTHON_BIN" - <<'PY'
import sys
if sys.version_info < (3, 9):
    raise SystemExit("Northstar requires Python 3.9 or newer")
PY
export LAB_DATA="$REPO/runs/lab-data"
export JEV_TEST="$REPO/runs/no-jev-test"
mkdir -p "$LAB_DATA"
"$PYTHON_BIN" -m sim.generate --date 2026-09-22 --seed 20260922
echo "Northstar local demo: http://127.0.0.1:8787 (Ctrl+C to stop)"
exec "$PYTHON_BIN" -m console.server --port 8787
