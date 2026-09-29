"""Start the portable Northstar workbench on macOS, Linux, or Windows.

    python -m lab.workbench
    python -m lab.workbench --no-sim --cases examples/cases.jsonl \
        --results examples/typed-results.jsonl
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import date
from pathlib import Path

from .import_cases import import_file

ROOT = Path(__file__).resolve().parents[1]
RUNS = ROOT / "runs"


def _port(value: str) -> int:
    port = int(value)
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def _file(value: str) -> Path:
    path = Path(value).resolve()
    if not path.is_file():
        raise argparse.ArgumentTypeError("file does not exist")
    return path


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--date", type=date.fromisoformat, default=date(2026, 9, 22))
    parser.add_argument("--seed", type=int, default=20260922)
    parser.add_argument("--port", type=_port, default=8787)
    parser.add_argument("--no-attacks", action="store_true")
    parser.add_argument("--no-sim", action="store_true", help="show imported cases without the sample world")
    parser.add_argument("--cases", type=_file, help="normalized alert JSONL to import")
    parser.add_argument("--results", type=_file, help="saved typed-result JSONL to replay")
    parser.add_argument("--prepare-only", action="store_true", help=argparse.SUPPRESS)
    return parser.parse_args(argv)


def prepare(args: argparse.Namespace) -> dict[str, int]:
    if sys.version_info < (3, 12):
        raise SystemExit("Northstar requires Python 3.12 or newer")
    RUNS.mkdir(parents=True, exist_ok=True)
    os.environ["LAB_DATA"] = str(RUNS / "lab-data")
    os.environ["JEV_TEST"] = str(RUNS / "no-jev-test")
    os.environ["NORTHSTAR_PORTABLE"] = "1"
    os.environ["NORTHSTAR_RESULTS"] = str(args.results) if args.results else str(RUNS / "no-results.jsonl")
    os.environ["NORTHSTAR_IMPORTED_CASES"] = (str(RUNS / "imported-cases.jsonl") if args.cases
                                             else str(RUNS / "no-imported-cases.jsonl"))
    if args.cases:
        imported = import_file(args.cases, RUNS / "imported-cases.jsonl")
    else:
        imported = 0
    if args.no_sim:
        os.environ["NORTHSTAR_SIM_CASES"] = str(RUNS / "no-sim-cases.jsonl")
        return {"imported_cases": imported, "simulated_cases": 0}
    os.environ["NORTHSTAR_SIM_CASES"] = str(RUNS / "world-cases.jsonl")
    command = [sys.executable, "-m", "sim.generate", "--date", args.date.isoformat(),
               "--seed", str(args.seed), "--output-dir", str(RUNS)]
    if args.no_attacks:
        command.append("--no-attacks")
    generated = subprocess.run(command, cwd=str(ROOT), env=os.environ.copy(),
                               capture_output=True, text=True, check=True)
    summary = json.loads(generated.stdout)
    return {"imported_cases": imported, "simulated_cases": summary["cases"]}


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    summary = prepare(args)
    print(f"Northstar ready: {summary['imported_cases']} imported and "
          f"{summary['simulated_cases']} simulated cases", flush=True)
    if args.prepare_only:
        return
    from console import server  # environment must be set before console imports
    try:
        httpd = server.make_server(args.port)
    except OSError as exc:
        raise SystemExit(f"Could not bind 127.0.0.1:{args.port}: {exc}") from exc
    print(f"Open http://127.0.0.1:{args.port} (Ctrl+C to stop)", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
