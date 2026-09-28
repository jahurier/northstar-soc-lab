"""Read-only Blue review of completed, isolated Red Range telemetry.

Only Elastic aggregations are sent to the local model. No raw log lines, scanner
findings, credentials, or human labels enter this workflow.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from replay.datasets import RUNS
from red_range.service import ROOT as RED_ROOT
from siem.setup import load_env, request
from . import llm

ROOT = Path(RUNS) / "blue-watch"
PROMPT = Path(__file__).with_name("prompts") / "blue_watch.md"
INTERVALS = (5, 15, 30, 60)
SCHEMA = {"type": "object", "properties": {
    "summary": {"type": "string"},
    "observations": {"type": "array", "items": {"type": "string"}},
    "uncertainties": {"type": "array", "items": {"type": "string"}},
    "next_checks": {"type": "array", "items": {"type": "string"}},
}, "required": ["summary", "observations", "uncertainties", "next_checks"]}


def _save(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    tmp = path.with_name(path.name + ".tmp")
    with os.fdopen(os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600), "w") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
    tmp.replace(path)


def eligible_runs(root: Path = RED_ROOT) -> list[dict[str, Any]]:
    runs = []
    for path in (root / "live-runs").glob("rr-*/status.json"):
        try:
            row = json.loads(path.read_text())
            if (row.get("id") == path.parent.name and row.get("lab") == "crapi" and
                    row.get("status") == "complete" and row.get("elastic") == "indexed" and
                    row.get("telemetry") == "saved" and row.get("jev_calls") == 0):
                runs.append({"id": row["id"], "ended_at": row["ended_at"],
                             "suites": row.get("suites", [])})
        except (OSError, ValueError, KeyError):
            continue
    return sorted(runs, key=lambda row: row["ended_at"], reverse=True)


def aggregate(run_id: str) -> dict[str, Any]:
    if not run_id.startswith("rr-") or len(run_id) > 60 or not all(
            char.isalnum() or char == "-" for char in run_id):
        raise ValueError("invalid Red Range run id")
    query = {"size": 0, "track_total_hits": True,
             "query": {"term": {"northstar.run_id.keyword": run_id}},
             "aggs": {"services": {"terms": {"field": "northstar.source_service.keyword", "size": 30}},
                      "methods": {"terms": {"field": "http.request.method.keyword", "size": 20}},
                      "statuses": {"terms": {"field": "http.response.status_code", "size": 20}}}}
    answer = request("POST", "/northstar-redrange-crapi-*/_search", query,
                     load_env()["ELASTIC_PASSWORD"])
    count = int(answer["hits"]["total"]["value"])
    buckets = answer["aggregations"]
    snapshot = {"run_id": run_id, "source": "sanitized_elastic_aggregations",
                "provenance": "external_live_range", "events": count,
                "services": {str(b["key"]): b["doc_count"] for b in buckets["services"]["buckets"]},
                "methods": {str(b["key"]): b["doc_count"] for b in buckets["methods"]["buckets"]},
                "statuses": {str(b["key"]): b["doc_count"] for b in buckets["statuses"]["buckets"]},
                "limitations": ["Container log metadata only; no request path, source IP, or payload",
                                "No mapped alert rule or baseline; counts alone do not prove compromise",
                                "Collected at run end; this is post-run review, not live detection"]}
    if count <= 0:
        raise RuntimeError("no indexed Red Range telemetry for the selected run")
    return snapshot


def analyze(snapshot: dict[str, Any]) -> dict[str, Any]:
    if not llm.available():
        raise RuntimeError("local Blue model is unavailable")
    raw = llm.chat_json(PROMPT.read_text(), json.dumps(snapshot, sort_keys=True), SCHEMA, timeout=180)
    def lines(key: str) -> list[str]:
        value = raw.get(key)
        return [str(item)[:300] for item in value[:6] if isinstance(item, str)] if isinstance(value, list) else []
    return {"summary": str(raw.get("summary") or "")[:500],
            "observations": lines("observations"),
            "uncertainties": lines("uncertainties"),
            "next_checks": lines("next_checks")}


class BlueWatch:
    def __init__(self, root: Path = ROOT, red_root: Path = RED_ROOT) -> None:
        self.root, self.red_root = root, red_root
        self.lock = threading.Lock()
        self.wakeup = threading.Event()
        self.busy = False
        self.error: str | None = None
        self.config = {"enabled": False, "interval": 15}
        try:
            saved = json.loads((root / "config.json").read_text())
            if isinstance(saved.get("enabled"), bool) and saved.get("interval") in INTERVALS:
                self.config = {"enabled": saved["enabled"], "interval": saved["interval"]}
        except (OSError, ValueError, TypeError):
            pass
        threading.Thread(target=self._loop, daemon=True).start()

    def _notes(self) -> list[dict[str, Any]]:
        notes = []
        for path in self.root.glob("rr-*.json"):
            try:
                note = json.loads(path.read_text())
                if note.get("source") == "blue_watch":
                    notes.append(note)
            except (OSError, ValueError):
                continue
        return sorted(notes, key=lambda row: row["created_at"], reverse=True)

    def view(self) -> dict[str, Any]:
        with self.lock:
            busy, error, config = self.busy, self.error, dict(self.config)
        runs = eligible_runs(self.red_root)
        notes = self._notes()
        return {"enabled": config["enabled"], "interval": config["interval"],
                "busy": busy, "error": error, "runs": runs[:10], "notes": notes[:10],
                "model": llm.MODEL, "mode": "read_only_post_run", "jev_calls": 0,
                "response_execution": False}

    def control(self, body: dict[str, Any]) -> dict[str, Any]:
        action = body.get("action")
        if action not in ("start", "stop", "run_once"):
            raise ValueError("choose start, stop, or run_once")
        interval = body.get("interval", self.config["interval"])
        if isinstance(interval, bool) or interval not in INTERVALS:
            raise ValueError("interval must be 5, 15, 30, or 60 minutes")
        with self.lock:
            if action == "run_once" and self.busy:
                raise RuntimeError("Blue Watch is already reviewing a run")
            if action in ("start", "stop"):
                self.config = {"enabled": action == "start", "interval": interval}
                _save(self.root / "config.json", self.config)
            if action == "run_once":
                self.busy = True
                threading.Thread(target=self._run, args=(body.get("run_id"),), daemon=True).start()
        self.wakeup.set()
        return self.view()

    def _run(self, run_id: str | None = None) -> None:
        try:
            runs = eligible_runs(self.red_root)
            ids = {row["id"] for row in runs}
            if run_id is not None and (not isinstance(run_id, str) or run_id not in ids):
                raise ValueError("select an eligible completed Red Range run")
            previous = {row["run_id"] for row in self._notes()}
            selected = run_id or next((row["id"] for row in runs if row["id"] not in previous), None)
            if selected is None:
                with self.lock:
                    self.error = None
                return
            snapshot = aggregate(selected)
            note = analyze(snapshot)
            digest = hashlib.sha256(json.dumps(snapshot, sort_keys=True).encode()).hexdigest()
            record = {"source": "blue_watch", "run_id": selected,
                      "created_at": datetime.now(timezone.utc).isoformat(),
                      "model": llm.MODEL, "input_sha256": digest,
                      "input": snapshot, "response": note,
                      "gate_status": "analyst_review", "execution_status": "not_executed",
                      "label_status": "unlabeled"}
            _save(self.root / (selected + ".json"), record)
            with self.lock:
                self.error = None
        except Exception as exc:
            with self.lock:
                self.error = type(exc).__name__
        finally:
            with self.lock:
                self.busy = False

    def _loop(self) -> None:
        while True:
            with self.lock:
                enabled, interval, busy = self.config["enabled"], self.config["interval"], self.busy
                if enabled and not busy:
                    self.busy = True
            if enabled and not busy:
                self._run()
            self.wakeup.wait(interval * 60 if enabled else 60)
            self.wakeup.clear()
