#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO"
PYTHON_BIN="${PYTHON_BIN:-python3}"
DAY="2026-09-22"
SEED="20260922"
PORT="8787"
SIMULATE=1
CASES=""
RESULTS=""
usage() {
  echo "usage: ./quickstart.sh [--date YYYY-MM-DD] [--seed N] [--port N] [--no-attacks] [--no-sim] [--cases FILE] [--results FILE]"
}
SIM_ARGS=()
while (($#)); do
  case "$1" in
    --date|--seed|--port|--cases|--results)
      if (($# < 2)); then usage >&2; exit 2; fi
      case "$1" in
        --date) DAY="$2" ;;
        --seed) SEED="$2" ;;
        --port) PORT="$2" ;;
        --cases) CASES="$2" ;;
        --results) RESULTS="$2" ;;
      esac
      shift 2 ;;
    --no-attacks) SIM_ARGS+=(--no-attacks); shift ;;
    --no-sim) SIMULATE=0; shift ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
"$PYTHON_BIN" - <<'PY'
import sys
if sys.version_info < (3, 9):
    raise SystemExit("Northstar requires Python 3.9 or newer")
PY
export LAB_DATA="$REPO/runs/lab-data"
export JEV_TEST="$REPO/runs/no-jev-test"
mkdir -p "$LAB_DATA"
if [[ -n "$CASES" ]]; then
  "$PYTHON_BIN" -m lab.import_cases --input "$CASES"
fi
if [[ -n "$RESULTS" ]]; then
  export NORTHSTAR_RESULTS="$RESULTS"
fi
if ((SIMULATE)); then
  "$PYTHON_BIN" -m sim.generate --date "$DAY" --seed "$SEED" "${SIM_ARGS[@]}"
else
  export NORTHSTAR_SIM_CASES="$REPO/runs/no-sim-cases.jsonl"
fi
echo "Northstar local workbench: http://127.0.0.1:$PORT (Ctrl+C to stop)"
exec "$PYTHON_BIN" -m console.server --port "$PORT"
