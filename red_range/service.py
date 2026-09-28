"""Plan isolated Swarm campaigns and monitor source-backed rehearsals."""

from __future__ import annotations

import hashlib
import json
import secrets
import shutil
import threading
import time
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from red import replay
from replay.datasets import RUNS
from sim.generate import load_world

ROOT = Path(RUNS) / "red-range"
LABS = {
    "crapi": "crAPI · vulnerable API lab",
    "juiceshop": "Juice Shop · vulnerable web app",
    "vampi": "VAmPI · vulnerable REST API",
    "dvga": "DVGA · vulnerable GraphQL API",
}
SUITES = {
    "api-security": {"label": "API security", "labs": ("crapi", "vampi")},
    "owasp-top10": {"label": "OWASP Top 10", "labs": ("crapi", "juiceshop", "vampi")},
    "graphql-audit": {"label": "GraphQL audit", "labs": ("dvga",)},
    "bug-bounty": {"label": "Broad web sweep", "labs": tuple(LABS)},
}
PLAN_BLOCKERS = (
    "No isolated runner with verified egress policy is connected",
    "No reviewed, hash-bound campaign scope has been activated",
    "No defender telemetry capture is connected to this range",
    "Active Pentest Swarm launch is not wired into Northstar",
)


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + secrets.token_hex(4) + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    temporary.replace(path)


def prepare_plan(lab: str, suites: list[str], *, root: Path = ROOT) -> dict[str, Any]:
    """Save a reviewable draft for a bundled lab, without installing or running tools."""
    if not isinstance(lab, str) or lab not in LABS:
        raise ValueError("choose a bundled lab from the catalog")
    if (not isinstance(suites, list) or not 1 <= len(suites) <= 4 or
            any(not isinstance(suite, str) for suite in suites) or
            len(suites) != len(set(suites))):
        raise ValueError("choose one to four distinct suites")
    for suite in suites:
        if suite not in SUITES or lab not in SUITES[suite]["labs"]:
            raise ValueError("suite is not available for the selected lab")
    manifest_path = root / "range" / "build-manifest.json"
    runner_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest() if manifest_path.is_file() else None
    policy_path = Path(__file__).with_name("active.py")
    policy_hash = hashlib.sha256(policy_path.read_bytes()).hexdigest() if lab == "crapi" and runner_hash else None
    scope = {"target_class": "bundled_disposable_lab", "lab": lab,
             "suites": sorted(suites), "provider": "local_ollama", "safe_mode": True,
             "jev_in_scanner": False, "max_minutes": 30 * len(suites),
             "network_policy": "isolated_runner_required", "status": "draft",
             "runner_manifest_sha256": runner_hash, "runner_policy_sha256": policy_hash}
    canonical = json.dumps(scope, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    blockers = (["Exact scope activation phrase required", "Runtime preflight repeats at launch"]
                if lab == "crapi" and runner_hash else list(PLAN_BLOCKERS))
    plan = {**scope, "sha256": digest, "created_at": datetime.now(timezone.utc).isoformat(),
            "blockers": blockers}
    _write_json(root / "plans" / (digest + ".json"), plan)
    return plan


def load_plans(root: Path = ROOT) -> list[dict[str, Any]]:
    plans = [json.loads(path.read_text()) for path in (root / "plans").glob("*.json")]
    return sorted(plans, key=lambda plan: plan.get("created_at", ""))


class RehearsalManager:
    """Stream only saved detection observations for a selected recording suite."""

    def __init__(self, *, root: Path = ROOT, corpus: Path = replay.DEFAULT_CORPUS,
                 step_seconds: float = 0.08) -> None:
        self.root = root
        self.corpus = corpus
        self.step_seconds = step_seconds
        self.lock = threading.Lock()
        self.stop_signal = threading.Event()
        self.current_id: str | None = None
        self._recover_interrupted()

    def _recover_interrupted(self) -> None:
        for path in (self.root / "rehearsals").glob("*/status.json"):
            try:
                status = json.loads(path.read_text())
                if status.get("status") in ("running", "stopping"):
                    status["status"] = "interrupted"
                    status["ended_at"] = datetime.now(timezone.utc).isoformat()
                    _write_json(path, status)
            except (OSError, ValueError):
                continue

    def catalog(self) -> list[dict[str, Any]]:
        return replay.catalog(replay.load_cases(self.corpus)) if self.corpus.exists() else []

    def _status(self, run_id: str) -> dict[str, Any]:
        return json.loads((self.root / "rehearsals" / run_id / "status.json").read_text())

    def view(self) -> dict[str, Any]:
        statuses = []
        for path in (self.root / "rehearsals").glob("*/status.json"):
            try:
                statuses.append(json.loads(path.read_text()))
            except (OSError, ValueError):
                continue
        statuses.sort(key=lambda item: item["started_at"], reverse=True)
        return {"recorded_catalog": self.catalog(), "rehearsals": statuses[:10],
                "current_id": self.current_id,
                "labs": [{"id": key, "label": value} for key, value in LABS.items()],
                "suites": [{"id": key, **value} for key, value in SUITES.items()],
                "active_readiness": {"scanner_installed": shutil.which("pentestswarm") is not None,
                                     "ready": False, "blockers": list(PLAN_BLOCKERS)},
                "plans": load_plans(self.root)[-10:]}

    def start(self, campaigns: list[str], *, seed: int = 7) -> dict[str, Any]:
        if (not isinstance(campaigns, list) or not 1 <= len(campaigns) <= 4 or
                any(not isinstance(name, str) for name in campaigns) or
                len(campaigns) != len(set(campaigns))):
            raise ValueError("choose one to four distinct recorded campaigns")
        if isinstance(seed, bool) or not isinstance(seed, int) or abs(seed) > 1_000_000_000:
            raise ValueError("seed must be an integer within ±1 billion")
        with self.lock:
            if self.current_id is not None:
                raise RuntimeError("a Red Range rehearsal is already running")
            if not self.corpus.exists():
                raise ValueError("recorded development corpus is unavailable")
            cases = replay.load_cases(self.corpus)
            known = {item["campaign"] for item in replay.catalog(cases)}
            if any(name not in known for name in campaigns):
                raise ValueError("campaign is not in the recorded catalog")
            events, truth = [], []
            for index, name in enumerate(campaigns):
                source_events, source_truth, _ = replay.build(cases, load_world(), name,
                                                             date.today(), seed + index)
                events.extend({**event, "suite": name} for event in source_events)
                truth.extend(source_truth)
            run_id = "RR-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)
            folder = self.root / "rehearsals" / run_id
            _write_jsonl(folder / "source-events.jsonl", events)
            _write_jsonl(folder / "source-truth.jsonl", truth)
            status = {"id": run_id, "kind": "passive_recorded_rehearsal", "status": "running",
                      "campaigns": campaigns, "seed": seed, "processed": 0, "total": len(events),
                      "started_at": datetime.now(timezone.utc).isoformat(), "ended_at": None,
                      "current_suite": None, "recent": [], "executes_actions": False,
                      "source_label_quality": "weak_recording_label"}
            _write_json(folder / "status.json", status)
            self.stop_signal = threading.Event()
            self.current_id = run_id
            threading.Thread(target=self._run, args=(run_id, events, self.stop_signal), daemon=True).start()
            return status

    def _run(self, run_id: str, events: list[dict[str, Any]], stop: threading.Event) -> None:
        folder = self.root / "rehearsals" / run_id
        status = self._status(run_id)
        try:
            with (folder / "observed-events.jsonl").open("w") as handle:
                for event in events:
                    if stop.wait(self.step_seconds):
                        break
                    handle.write(json.dumps(event, sort_keys=True) + "\n")
                    handle.flush()
                    status["processed"] += 1
                    status["current_suite"] = event["suite"]
                    status["recent"] = (status["recent"] + [{"suite": event["suite"],
                                          "timestamp": event["timestamp"], "rule": event["rule"],
                                          "level": event["level"]}])[-12:]
                    with self.lock:
                        if stop.is_set():
                            status["status"] = "stopping"
                        _write_json(folder / "status.json", status)
            status["status"] = "stopped" if stop.is_set() else "complete"
        except Exception:
            status["status"] = "failed"
            status["error_type"] = "RehearsalError"
        finally:
            status["ended_at"] = datetime.now(timezone.utc).isoformat()
            with self.lock:
                _write_json(folder / "status.json", status)
                if self.current_id == run_id:
                    self.current_id = None

    def stop(self) -> dict[str, Any]:
        with self.lock:
            if self.current_id is None:
                raise RuntimeError("no Red Range rehearsal is running")
            run_id = self.current_id
            self.stop_signal.set()
            status = self._status(run_id)
            status["status"] = "stopping"
            _write_json(self.root / "rehearsals" / run_id / "status.json", status)
            return status
