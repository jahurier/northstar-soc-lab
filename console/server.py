"""Northstar SOC local console: serves the UI and runs allowlisted lab jobs.

Guardrails:
- Binds to 127.0.0.1 only; requests with any other Host header are refused
  (blocks DNS-rebinding from web pages).
- Every POST needs the per-start token embedded in the served page and a matching
  Origin, so other sites cannot trigger jobs.
- Jobs are a fixed allowlist of argument lists (no shell, no user-supplied commands).
  Paid Jev runs require an explicit confirmation field.
- Analyst verdicts are appended to adjudications/labels.jsonl (latest per case wins).

    python3 -m console.server [--port 8787]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
import threading
import time
from collections import Counter, defaultdict
from datetime import date
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from agents import detection as detection_agent
from agents import blue as blue_agent
from agents import blue_watch
from adjudications.ledger import read as read_analyst_labels
from replay import hayabusa
from replay import candidate_lifecycle
from replay import pentest_swarm_reports
from replay.coverage import attack_coverage
from replay.datasets import DATASETS, RUNS
from replay.tuning import Tuning, load as load_tuning
from red import replay as red_replay
from red_range import service as red_range_service
from red_range import active as red_range_active
from sim.generate import load_world

REPO = Path(__file__).resolve().parents[1]
JEV = Path(os.environ.get("JEV_TEST", os.path.expanduser("~/Projects/jev-test")))
CORPUS_NAME = "replay-multi"
CORPUS = JEV / "data" / f"{CORPUS_NAME}-alerts.jsonl"
RESULTS = JEV / "artifacts" / f"{CORPUS_NAME}-results.jsonl"
SIM_CASES = REPO / "runs" / "world-cases.jsonl"
SIM_RESULTS = JEV / "artifacts" / "world-sim-results.jsonl"
SIM_REPORT = JEV / "artifacts" / "world-sim-report.json"
INCIDENT_SINGLE_RESULTS = JEV / "artifacts" / "world-single-v2-results.jsonl"
INCIDENT_CHAIN_RESULTS = JEV / "artifacts" / "world-chain-v2-results.jsonl"
LABELS = REPO / "adjudications" / "labels.jsonl"
QUEUE = REPO / "adjudications" / "queue.json"
AI_INITIAL = REPO / "adjudications" / "ai-verdicts-2026-09-23.jsonl"
AI_REVISED = REPO / "adjudications" / "ai-disagreement-review-2026-09-24.jsonl"
JOB_DIR = Path(RUNS) / "jobs"
SUMMARY_CACHE = Path(RUNS) / "console-summary.json"
INDEX = Path(__file__).with_name("index.html")
VERDICTS = {"likely_malicious", "likely_benign", "needs_context", "unsupported"}
MED_PLUS = {"med", "high", "crit"}
QUESTION_VERSION = "security-triage-v2"
PY = sys.executable


# ---------------------------------------------------------------- jobs
def job_specs() -> dict[str, dict[str, Any]]:
    specs: dict[str, dict[str, Any]] = {}
    for name, dataset in DATASETS.items():
        specs[f"sigma:{name}"] = {
            "label": f"Replay Sigma over {name}",
            "argv": hayabusa.command(dataset),
            "cwd": hayabusa.HAYABUSA_DIR,
            "cost": "free · local",
        }
    specs.update(
        {
            "manifest-validate": {
                "label": "Validate all scenario scopes and approval hashes",
                "argv": [PY, "-m", "lab.validate", *[str(path) for path in sorted((REPO / "scenarios").glob("*.json"))]],
                "cwd": str(REPO), "cost": "free · local, no execution",
            },
            "corpus": {
                "label": "Rebuild Jev corpus from all detections",
                "argv": [PY, "-m", "replay.hayabusa_to_jev", str(CORPUS), *DATASETS],
                "cwd": str(REPO),
                "cost": "free · local",
                "after": "reload",
            },
            "summary": {"label": "Recompute coverage and benign noise", "internal": True,
                        "cost": "free · local", "after": "reload"},
            "world-sim": {
                "label": "Generate a seeded Northstar company day",
                "argv": [PY, "-m", "sim.generate", "--output-dir", str(REPO / "runs")],
                "cwd": str(REPO), "cost": "free · local", "after": "reload",
            },
            "world-benign-check": {
                "label": "Generate an isolated benign-only control day",
                "argv": [PY, "-m", "sim.generate", "--no-attacks", "--output-dir",
                         str(Path(RUNS) / "control-bench" / "benign")],
                "cwd": str(REPO), "cost": "free · local, separate output",
            },
            "detection-stats": {"label": "Measure rule noise for the detection agent",
                                "argv": [PY, "-m", "agents.detection", "stats"], "cwd": str(REPO),
                                "cost": "free · local"},
            "detection-agent": {"label": "Detection agent: propose tuning (top 5 noisy rules)",
                                "argv": [PY, "-m", "agents.detection", "propose", "--top", "5"], "cwd": str(REPO),
                                "cost": "free · local model (~3 min)", "after": "detections"},
            "detection-agent-one": {"label": "Detection agent: check one noisy rule",
                                    "argv": [PY, "-m", "agents.detection", "propose", "--top", "1"],
                                    "cwd": str(REPO), "cost": "free · local model", "after": "detections"},
            "blue-agent": {"label": "Blue agent: group incidents and draft five gated case notes",
                           "argv": [PY, "-m", "agents.blue", "propose", "--input",
                                    str(REPO / "runs" / "world-chain-cases.jsonl"), "--results",
                                    str(JEV / "artifacts" / "world-chain-v2-results.jsonl"), "--limit", "5"],
                           "cwd": str(REPO), "cost": "free · local model", "after": "blue"},
            "blue-agent-one": {"label": "Blue agent: draft one gated incident note",
                               "argv": [PY, "-m", "agents.blue", "propose", "--input",
                                        str(REPO / "runs" / "world-chain-cases.jsonl"), "--results",
                                        str(JEV / "artifacts" / "world-chain-v2-results.jsonl"), "--limit", "1"],
                               "cwd": str(REPO), "cost": "free · local model", "after": "blue"},
            "elastic-readiness": {"label": "Check Elastic rule and telemetry compatibility",
                                  "argv": [PY, "-m", "siem.prebuilt_readiness"], "cwd": str(REPO),
                                  "cost": "free · read-only local Elastic"},
            "tests": {"label": "Run lab test suite", "argv": [PY, "-m", "unittest", "discover", "-s", "tests", "-t", "."],
                      "cwd": str(REPO), "cost": "free · local"},
            "jev-doctor": {"label": "Check Jev connectivity", "argv": [PY, "-m", "jev_security_eval", "doctor"],
                           "cwd": str(JEV), "cost": "free · no inference"},
            "jev-smoke": {
                "label": "Jev smoke test (5 cases)",
                "argv": [PY, "-m", "jev_security_eval", "run", "--input", str(CORPUS), "--output",
                         str(JEV / "artifacts" / f"{CORPUS_NAME}-smoke.jsonl"), "--limit", "5", "--workers", "1",
                         "--max-retries", "0"],
                "cwd": str(JEV),
                "cost": "paid · up to 5 calls, ~11.5k input tokens",
                "confirm": "RUN",
            },
            "jev-full": {
                "label": "Full Jev evaluation (3,543 cases)",
                "argv": ["sh", "scripts/run_replay_evaluation.sh"],
                "cwd": str(JEV),
                "cost": "paid · 3,548 cases, ~8.2M input tokens before retries",
                "confirm": "RUN",
                "after": "reload",
            },
            "jev-world-smoke": {
                "label": "Jev Northstar simulation smoke (5 cases)",
                "argv": [PY, "-m", "jev_security_eval", "run", "--input", str(SIM_CASES),
                         "--output", str(SIM_RESULTS), "--limit", "5", "--workers", "1", "--resume",
                         "--max-retries", "0"],
                "cwd": str(JEV), "cost": "paid · up to 5 calls, ~11.5k input tokens",
                "confirm": "RUN", "after": "reload",
            },
            "jev-world-full": {
                "label": "Jev Northstar simulation evaluation (23 cases)",
                "argv": [PY, "-m", "jev_security_eval", "run", "--input", str(SIM_CASES),
                         "--output", str(SIM_RESULTS), "--workers", "2", "--resume",
                         "--max-retries", "0"],
                "cwd": str(JEV), "cost": "paid · up to 23 calls, ~53k input tokens",
                "confirm": "RUN", "after": "reload",
            },
            "jev-world-report": {
                "label": "Report on stored Jev world results",
                "argv": [PY, "-m", "jev_security_eval", "report",
                         "--input", str(SIM_RESULTS), "--output", str(SIM_REPORT)],
                "cwd": str(JEV), "cost": "free · local",
            },
            "jev-world-validate": {
                "label": "Validate current simulated Jev case schema",
                "argv": [PY, "-m", "jev_security_eval", "validate", "--input", str(SIM_CASES)],
                "cwd": str(JEV), "cost": "free · local, no inference",
            },
            "policy-audit": {
                "label": "Audit shadow policy on matching saved Jev answers",
                "argv": [PY, "scripts/audit_escalation.py", str(SIM_RESULTS), str(SIM_CASES)],
                "cwd": str(JEV), "cost": "free · local, no inference",
            },
            "rescore": {
                "label": "Rescore stored Jev results under shadow-v3",
                "argv": [PY, "scripts/rescore_policy.py", str(RESULTS), str(CORPUS)],
                "cwd": str(JEV),
                "cost": "free · local",
            },
        }
    )
    for candidate in candidate_lifecycle.candidates():
        if candidate["gate"]["candidate_gate_passed"] and candidate["source_matches_gate"] and not candidate["active"]:
            specs["candidate:" + candidate["id"]] = {
                "label": "Activate " + candidate["file"] + " and recompute coverage",
                "argv": [PY, "-m", "replay.candidate_lifecycle", "activate", candidate["id"]],
                "cwd": str(REPO), "cost": "free · full local replay", "confirm": "ACTIVATE",
                "after": "detections", "after_internal": True,
            }
    return specs


class Jobs:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.jobs: dict[str, dict[str, Any]] = {}
        self.running: str | None = None
        JOB_DIR.mkdir(parents=True, exist_ok=True)

    def start(self, kind: str, confirm: str | None, on_internal) -> dict[str, Any]:
        specs = job_specs()
        if kind not in specs:
            raise ValueError(f"unknown job {kind!r}")
        spec = specs[kind]
        if spec.get("confirm") and confirm != spec["confirm"]:
            raise PermissionError(f"type {spec['confirm']} to confirm this paid job")
        with self.lock:
            if self.running:
                raise RuntimeError(f"job {self.running} is still running")
            job_id = f"{time.strftime('%Y%m%d-%H%M%S')}-{kind.replace(':', '-')}"
            log = JOB_DIR / f"{job_id}.log"
            job = {"id": job_id, "kind": kind, "label": spec["label"], "status": "running",
                   "started": time.time(), "ended": None, "returncode": None, "log": str(log),
                   "after": spec.get("after")}
            self.jobs[job_id] = job
            self.running = job_id
        threading.Thread(target=self._run, args=(job, spec, on_internal), daemon=True).start()
        return job

    def _run(self, job: dict[str, Any], spec: dict[str, Any], on_internal) -> None:
        code = 1
        with open(job["log"], "w") as log:
            try:
                if spec.get("internal"):
                    log.write("recomputing summary…\n")
                    log.flush()
                    on_internal(log)
                    code = 0
                else:
                    log.write("$ " + " ".join(spec["argv"]) + "\n")
                    log.flush()
                    proc = subprocess.Popen(spec["argv"], cwd=spec["cwd"], stdout=log, stderr=subprocess.STDOUT)
                    code = proc.wait()
                    if code == 0 and spec.get("after_internal"):
                        on_internal(log)
            except Exception as exc:  # report, never crash the server
                log.write(f"error: {exc}\n")
                code = 1
        with self.lock:
            job.update(status="ok" if code == 0 else "failed", returncode=code, ended=time.time())
            self.running = None

    def listing(self) -> list[dict[str, Any]]:
        out = []
        for job in sorted(self.jobs.values(), key=lambda j: j["started"], reverse=True)[:20]:
            tail = ""
            try:
                with open(job["log"], errors="replace") as handle:
                    tail = "".join(handle.readlines()[-40:])
            except OSError:
                pass
            out.append({**{k: v for k, v in job.items() if k != "log"}, "tail": tail})
        return out

    def clear_completed(self) -> int:
        """Remove finished jobs from the session list, keeping active jobs and log files."""
        with self.lock:
            finished = [job_id for job_id, job in self.jobs.items() if job["status"] != "running"]
            for job_id in finished:
                del self.jobs[job_id]
            return len(finished)


# ---------------------------------------------------------------- data
def _mtimes() -> dict[str, Any]:
    stamp: dict[str, Any] = {n: os.path.getmtime(d.detections) for n, d in DATASETS.items() if os.path.exists(d.detections)}
    stamp["tuning_version"] = load_tuning().get("version", 0)
    return stamp


def compute_summary(log=None) -> dict[str, Any]:
    base = DATASETS["baseline"]
    noisy: Counter[tuple[str, str, str]] = Counter()
    files: dict[str, set[str]] = defaultdict(set)
    tuning = Tuning()
    if os.path.exists(base.detections):
        with open(base.detections) as handle:
            for line in handle:
                d = tuning.adjust(json.loads(line))
                if d is not None and d["Level"] in MED_PLUS:
                    noisy[(d["RuleID"], d["RuleTitle"], d["Level"])] += 1
                    files[d["RuleID"]].add(d["EvtxFile"])
    coverage = {}
    for name, dataset in DATASETS.items():
        if dataset.label == "attack" and os.path.exists(dataset.detections):
            coverage[name] = attack_coverage(dataset)
            if log:
                log.write(f"coverage {name} done\n")
                log.flush()
    summary = {
        "mtimes": _mtimes(),
        "noisy_ids": sorted({k[0] for k in noisy}),
        "noisy_top": [{"rule": t, "level": lv, "alerts": c, "files": len(files[i])}
                      for (i, t, lv), c in noisy.most_common(10)],
        "benign_alerts": sum(noisy.values()),
        "coverage": coverage,
        "tuning_version": tuning.version,
    }
    SUMMARY_CACHE.parent.mkdir(parents=True, exist_ok=True)
    SUMMARY_CACHE.write_text(json.dumps(summary))
    return summary


def load_summary() -> dict[str, Any]:
    try:
        cached = json.loads(SUMMARY_CACHE.read_text())
        if cached.get("mtimes") == _mtimes():
            return cached
    except (OSError, ValueError):
        pass
    return compute_summary()


def _snip(details: dict[str, Any]) -> str:
    keys = ("Cmdline", "CmdLine", "ScriptBlock", "Proc", "TgtObj", "Tgt", "TgtFile", "Path", "Svc", "Key", "SrcIP", "TgtUser", "User")
    lower = {str(k).lower(): (k, v) for k, v in details.items()}
    for key in keys:
        if key.lower() in lower:
            name, value = lower[key.lower()]
            if isinstance(value, (str, int)) and str(value).strip():
                return f"{name}: {str(value).replace(chr(13), ' ').replace(chr(10), ' ')[:140]}"
    return ""


def paired_incident_evaluation() -> dict[str, Any] | None:
    """Summarize only successful Jev answers paired by planted-truth case ID."""
    arms = []
    for path in (INCIDENT_SINGLE_RESULTS, INCIDENT_CHAIN_RESULTS):
        if not path.exists():
            return None
        rows = {}
        with open(path) as handle:
            for line in handle:
                row = json.loads(line)
                answers = (row.get("response") or {}).get("answers") or {}
                disposition = (answers.get("disposition") or {}).get("choice")
                if disposition:
                    rows[row["case_id"]] = (row["metadata"]["dataset_label"], disposition)
        arms.append(rows)
    paired = set(arms[0]) & set(arms[1])
    if not paired:
        return None
    if any(arms[0][case_id][0] != arms[1][case_id][0] for case_id in paired):
        raise ValueError("paired incident evaluation labels disagree")
    result = {"paired": len(paired), "attack_total": 0, "benign_total": 0,
              "single_attack_correct": 0, "chain_attack_correct": 0,
              "single_benign_correct": 0, "chain_benign_correct": 0}
    for case_id in paired:
        label = arms[0][case_id][0]
        kind = "attack" if label == "attack" else "benign"
        expected = "likely_malicious" if kind == "attack" else "likely_benign"
        result[f"{kind}_total"] += 1
        for arm, rows in zip(("single", "chain"), arms):
            result[f"{arm}_{kind}_correct"] += rows[case_id][1] == expected
    return result


class Store:
    """Corpus, real Jev answers when present, summary panels, and adjudications."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.reload()

    def reload(self) -> None:
        summary = load_summary()
        noisy_ids = set(summary["noisy_ids"])
        answers = {}
        for results_path in (RESULTS, SIM_RESULTS):
            if not results_path.exists():
                continue
            with open(results_path) as handle:
                for line in handle:
                    row = json.loads(line)
                    if (isinstance(row.get("response"), dict) and
                            row.get("question_version") == QUESTION_VERSION and
                            isinstance(row.get("state_sha256"), str)):
                        answers[(row["case_id"], row["state_sha256"])] = row["response"]["answers"]
        cases, rows = {}, []
        matched_answers = {}
        for corpus in (CORPUS, SIM_CASES):
            if not corpus.exists():
                continue
            with open(corpus) as handle:
                for line in handle:
                    case = json.loads(line)
                    if case["case_id"] in cases:
                        raise ValueError(f"duplicate case_id in {corpus}: {case['case_id']}")
                    cases[case["case_id"]] = case
                    digest = hashlib.sha256(json.dumps(case["state"], sort_keys=True,
                                                       separators=(",", ":")).encode("utf-8")).hexdigest()
                    answer = answers.get((case["case_id"], digest))
                    if answer is not None:
                        matched_answers[case["case_id"]] = answer
                    rows.append(self._row(case, noisy_ids, answer))
        with self.lock:
            self.summary, self.cases, self.rows, self.answers = summary, cases, rows, matched_answers

    @staticmethod
    def _row(case: dict[str, Any], noisy_ids: set[str], jev: dict[str, Any] | None) -> dict[str, Any]:
        s, m = case["state"], case["metadata"]
        a, d = s["alert"], s["detection"]
        user = s["identity_context"].get("user")
        return {
            "id": case["case_id"], "ds": m["dataset"].split("@")[0], "label": m["dataset_label"],
            "provenance": m.get("provenance", "recorded"),
            "label_quality": m.get("label_quality", "weak_dataset"),
            "tactic": m["dataset_tactic"], "rec": m["recording"].split("/")[-1][:70], "split": m["split"],
            "rule": d["rule_title"], "lvl": d["level"], "mitre": (d.get("mitre_tags") or [])[:3],
            "tac": (d.get("mitre_tactics") or [])[:2], "host": (a.get("computer") or "")[:40],
            "ch": a.get("channel"), "eid": a.get("event_id"), "src": a["source"], "ts": a.get("timestamp"),
            "snip": _snip(a.get("details") or {}), "inj": a.get("reviewer_note"),
            "noisy": d["rule_id"] in noisy_ids, "user": user[:40] if isinstance(user, str) else "",
            "jev": jev,
        }

    def bootstrap(self) -> dict[str, Any]:
        with self.lock:
            summary, rows = self.summary, self.rows
            attack_recs = sum(r[1] for rows_ in summary["coverage"].values() for r in rows_)
            med = sum(r[3] for rows_ in summary["coverage"].values() for r in rows_)
            return {
                "mode": "local",
                "events": rows,
                "noisy_top": summary["noisy_top"],
                "noisy_rule_count": len(summary["noisy_ids"]),
                "benign_alerts": summary["benign_alerts"],
                "coverage": summary["coverage"],
                "totals": {"cases": len(rows), "recorded_cases": sum(r["provenance"] == "recorded" for r in rows),
                           "simulated_cases": sum(r["provenance"] == "simulated" for r in rows),
                           "attack_recordings": attack_recs, "med_any": med,
                           "real_jev": sum(r["jev"] is not None for r in rows)},
                "labels": read_labels(),
                # Reasons stay server-side: they would reveal the label and bias the analyst.
                "adjudication_queue": [c["case_id"] for c in json.loads(QUEUE.read_text())["cases"]]
                                      if QUEUE.exists() else [],
                "incident_evaluation": paired_incident_evaluation(),
                "jobs": {k: {"label": v["label"], "cost": v["cost"], "confirm": v.get("confirm")}
                         for k, v in job_specs().items()},
            }

    def case(self, case_id: str) -> dict[str, Any] | None:
        with self.lock:
            case = self.cases.get(case_id)
            return None if case is None else {**case, "jev": self.answers.get(case_id)}


def read_labels() -> dict[str, dict[str, Any]]:
    return read_analyst_labels(LABELS)


def write_label(case_id: str, verdict: str, note: str) -> dict[str, Any]:
    if verdict not in VERDICTS:
        raise ValueError(f"verdict must be one of {sorted(VERDICTS)}")
    entry = {"case_id": case_id, "verdict": verdict, "note": note[:500], "at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
             "by": "analyst"}
    LABELS.parent.mkdir(parents=True, exist_ok=True)
    with open(LABELS, "a") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


def undo_label(case_id: str) -> dict[str, Any]:
    if case_id not in read_labels():
        raise ValueError("case has no analyst label to undo")
    entry = {"case_id": case_id, "action": "undo", "at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
             "by": "analyst"}
    with open(LABELS, "a") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")
    return {"undone": entry, "label": read_labels().get(case_id)}


def ai_verdict_after_label(case_id: str) -> dict[str, Any] | None:
    if case_id not in read_labels():
        return None
    if not QUEUE.exists() or case_id not in {case["case_id"] for case in json.loads(QUEUE.read_text())["cases"]}:
        return None
    answer = None
    for path in (AI_INITIAL, AI_REVISED):
        if path.exists():
            with path.open() as handle:
                for line in handle:
                    row = json.loads(line)
                    if row["case_id"] == case_id:
                        answer = {"verdict": row["verdict"], "rationale": row["rationale"],
                                  "by": row["by"], "reviewed_at": row["reviewed_at"]}
    return answer


def _ollama(path: str, timeout: float = 3.0) -> Any:
    import urllib.request
    from agents import llm
    with urllib.request.urlopen(f"{llm.OLLAMA_URL}{path}", timeout=timeout) as response:
        return json.loads(response.read())


def agents_view() -> dict[str, Any]:
    from agents import llm
    status: dict[str, Any] = {"ollama": {"url": llm.OLLAMA_URL, "model": llm.MODEL, "reachable": False}}
    try:
        status["ollama"].update(reachable=True, version=_ollama("/api/version").get("version"),
                                installed=[{"name": m["name"], "gb": round(m.get("size", 0) / 1e9, 1)}
                                           for m in _ollama("/api/tags").get("models", [])],
                                loaded=[m["name"] for m in _ollama("/api/ps").get("models", [])])
    except Exception as exc:  # report unreachable, never fail the page
        status["ollama"]["error"] = str(exc)[:120]
    proposals = list(detection_agent.read_proposals().values())
    runs = [p for p in proposals if p.get("seconds")]
    status["detection_agent"] = {
        "proposals": len(proposals),
        "statuses": dict(Counter(p["status"] for p in proposals)),
        "last_run": max((p["at"] for p in proposals), default=None),
        "models": sorted({p.get("model", "?") for p in proposals}),
        "avg_seconds": round(sum(p["seconds"] for p in runs) / len(runs), 1) if runs else None,
        "tuning_version": load_tuning().get("version", 0),
    }
    def count(path: Path) -> tuple[int, str | None]:
        n, model = 0, None
        if path.exists():
            with open(path) as handle:
                for line in handle:
                    row = json.loads(line)
                    if isinstance(row.get("response"), dict):
                        n += 1
                        model = model or row["response"].get("model")
        return n, model
    replay_n, replay_model = count(RESULTS)
    sim_n, sim_model = count(SIM_RESULTS)
    status["jev"] = {"replay_results": replay_n, "sim_results": sim_n, "model": replay_model or sim_model}
    return status


def ping_model() -> dict[str, Any]:
    from agents import llm
    started = time.time()
    reply = llm.chat_json("Reply with JSON only.", "Say hello from the Northstar SOC in five words or fewer, "
                          "and name one Windows event log channel.",
                          {"type": "object", "properties": {"greeting": {"type": "string"}, "channel": {"type": "string"}},
                           "required": ["greeting", "channel"]}, timeout=180)
    return {"model": llm.MODEL, "seconds": round(time.time() - started, 1), "reply": reply}


def detections_view() -> dict[str, Any]:
    proposals = list(detection_agent.read_proposals().values())
    for record in proposals:
        record["risks"] = detection_agent.risks(record["proposal"])
    tuning = json.loads(detection_agent.TUNING.read_text()) if detection_agent.TUNING.exists() else \
        {"version": 0, "exclusions": [], "level_changes": []}
    from agents import llm
    return {"proposals": sorted(proposals, key=lambda r: r["at"], reverse=True), "tuning": tuning,
            "model": llm.MODEL, "model_ready": llm.available(),
            "candidates": candidate_lifecycle.candidates()}


def campaign_view() -> dict[str, Any]:
    if not red_replay.DEFAULT_CORPUS.exists():
        return {"ready": False, "catalog": [], "summary": None, "events": []}
    catalog = red_replay.catalog(red_replay.load_cases(red_replay.DEFAULT_CORPUS))
    summary_path = red_replay.DEFAULT_OUTPUT / "campaign-summary.json"
    events_path = red_replay.DEFAULT_OUTPUT / "campaign-events.jsonl"
    summary = json.loads(summary_path.read_text()) if summary_path.exists() else None
    events = ([json.loads(line) for line in events_path.read_text().splitlines() if line]
              if summary and events_path.exists() else [])
    return {"ready": True, "catalog": catalog, "summary": summary, "events": events}


def showcase_view(store: Store, red_live: red_range_active.ActiveManager,
                  watch: blue_watch.BlueWatch) -> dict[str, Any]:
    """Small, provenance-labeled overview; no raw cases, logs, or secrets."""
    from agents import autopilot as ap
    with store.lock:
        recorded = sum(row["provenance"] == "recorded" for row in store.rows)
        simulated = sum(row["provenance"] == "simulated" for row in store.rows)
        real_jev = sum(row["provenance"] == "recorded" and row["jev"] is not None
                       for row in store.rows)
    queue = json.loads(QUEUE.read_text())["cases"] if QUEUE.exists() else []
    labels = read_labels()
    red_runs = red_live.view()["runs"]
    blue_notes = watch.view()["notes"]
    cycles = ap.cycles(1)
    pilot = None
    for path in sorted((Path(RUNS) / "production-pilot").glob("local-*.json"), reverse=True):
        try:
            candidate = json.loads(path.read_text())
            if candidate.get("provenance") == "local_test" and candidate.get("verified") is True:
                pilot = {"verified": True, "fleet_verified": False,
                         "production_source_enrolled": False}
                break
        except (OSError, ValueError):
            continue
    red = red_runs[0] if red_runs else None
    blue = blue_notes[0] if blue_notes else None
    comparison = None
    for metrics_path in (REPO / "docs" / "metrics.json", REPO / "public" / "metrics.json"):
        if not metrics_path.is_file():
            continue
        saved = json.loads(metrics_path.read_text())
        if saved.get("provenance") != "planted_synthetic_truth":
            continue
        comparison = {"cases": saved["cases"], "model": saved["model"],
                      "context": saved["comparison"]["type"],
                      "arms": {name: {field: saved["arms"][name][field] for field in (
                          "correct", "planted_attack", "planted_benign", "latency_ms", "tokens")}
                               for name in ("single", "chain")}}
        break
    return {"environment": "local_test_lab", "production_assets_connected": False,
            "recorded": {"cases": recorded, "state_matched_jev": real_jev,
                         "triage_queue": len(queue),
                         "human_labels_in_queue": sum(row["case_id"] in labels for row in queue)},
            "simulated": {"cases": simulated, "last_cycle": {
                "at": cycles[0].get("at"), "events": cycles[0].get("events"),
                "planted_attacks": cycles[0].get("planted_attacks"),
                "blue_proposals": cycles[0].get("blue_proposals"),
            } if cycles else None},
            "red_range": {"run_id": red.get("id"), "status": red.get("status"),
                          "suites": red.get("suites", []), "elastic": red.get("elastic"),
                          "report_files": red.get("report_files", 0)} if red else None,
            "blue_watch": {"notes": len(blue_notes), "latest": {
                "run_id": blue.get("run_id"), "events": blue.get("input", {}).get("events"),
                "summary": blue.get("response", {}).get("summary"),
                "execution_status": blue.get("execution_status"),
            } if blue else None},
            "local_pilot": pilot,
            "saved_comparison": comparison,
            "boundaries": {"paid_jev_calls_started_here": 0,
                           "host_response_actions_enabled": False,
                           "blue_watch_mode": "post_run_read_only"}}


def jev_map_view(store: Store, case_id: str | None = None) -> dict[str, Any]:
    """Return only state-matched saved typed judgments, without case text or labels."""
    with store.lock:
        matched = [row for row in store.rows if isinstance(row.get("jev"), dict)]
        cases = dict(store.cases)
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in matched:
        disposition = (row["jev"].get("disposition") or {}).get("choice", "unknown")
        key = (row["provenance"], str(disposition))
        if len(groups[key]) < 8:
            groups[key].append({"id": row["id"], "rule": row["rule"][:90],
                                "provenance": row["provenance"],
                                "disposition": disposition})
    # Interleave outcome/source groups so playback visibly changes its route.
    ordered_groups = [groups[key] for key in sorted(groups)]
    catalog = [group[index] for index in range(8) for group in ordered_groups
               if index < len(group)]
    selected = case_id or next((item["id"] for item in catalog
                                if item["disposition"] == "likely_malicious"),
                               catalog[0]["id"] if catalog else None)
    if selected and selected not in {item["id"] for item in catalog}:
        raise ValueError("choose a listed state-matched Jev case")
    detail = None
    if selected:
        case = cases[selected]
        digest = hashlib.sha256(json.dumps(case["state"], sort_keys=True,
                                           separators=(",", ":")).encode("utf-8")).hexdigest()
        for path in (RESULTS, SIM_RESULTS):
            if not path.exists():
                continue
            with path.open() as handle:
                for line in handle:
                    saved = json.loads(line)
                    if (saved.get("case_id") != selected or saved.get("state_sha256") != digest or
                            saved.get("question_version") != QUESTION_VERSION or
                            not isinstance(saved.get("response"), dict)):
                        continue
                    answers = saved["response"].get("answers")
                    if not isinstance(answers, dict):
                        continue
                    policy = saved.get("policy") or {}
                    from agents.autopilot import _policy
                    current_policy_version, recommend = _policy()
                    reproduced = recommend(answers, case["state"])
                    policy_matches = all(reproduced.get(name) == policy.get(name) for name in (
                        "recommendation", "reason", "queue", "queue_basis"))
                    approval_required = (policy.get("recommendation") ==
                                         "escalate_for_containment_approval")
                    detail = {"id": selected, "provenance": case["metadata"].get("provenance"),
                              "rule": case["state"]["detection"].get("rule_title"),
                              "alert_source": case["state"]["alert"].get("source"),
                              "state_sha256": digest, "question_version": QUESTION_VERSION,
                              "model": saved["response"].get("model"),
                              "latency_ms": saved.get("latency_ms"),
                              "answers": {name: answers.get(name) for name in (
                                  "disposition", "malicious_behavior_supported",
                                  "legitimate_admin_plausible", "additional_context_required",
                                  "evidence_strength", "potential_impact",
                                  "untrusted_instructions_present", "review_queue")},
                              "saved_policy": {name: policy.get(name) for name in (
                                  "recommendation", "reason", "queue", "queue_basis")},
                              "routes": [
                                  {"id": "queue", "status": "saved_route",
                                   "detail": policy.get("queue")},
                                  {"id": "blue", "status": "not_dispatched",
                                   "detail": "No per-case Blue Watch run"},
                                  {"id": "approval", "status": "required" if approval_required
                                   else "not_required", "detail": "Human gate"},
                                  {"id": "response", "status": "disabled",
                                   "detail": "No host action"},
                              ],
                              "verification": {"state_hash_match": True,
                                               "question_version_match": True,
                                               "policy_match": policy_matches,
                                               "current_policy_version": current_policy_version,
                                               "execution_status": "not_executed"},
                              "saved_answer_only": True, "new_jev_calls": 0}
                    # Store.reload uses the most recent matching saved answer.
    return {"catalog": catalog, "selected": detail,
            "interpretation": "Saved typed outputs and saved shadow-policy route; not model internals"}


def build_campaign(body: dict[str, Any]) -> dict[str, Any]:
    if not red_replay.DEFAULT_CORPUS.exists():
        raise ValueError("development v3 corpus is missing")
    seed, max_cases = body.get("seed", 7), body.get("max_cases", 100)
    if isinstance(seed, bool) or not isinstance(seed, int) or abs(seed) > 1_000_000_000:
        raise ValueError("seed must be an integer within ±1 billion")
    if isinstance(max_cases, bool) or not isinstance(max_cases, int):
        raise ValueError("max_cases must be an integer")
    day = date.fromisoformat(str(body.get("date", date.today().isoformat())))
    cases = red_replay.load_cases(red_replay.DEFAULT_CORPUS)
    events, truth, summary = red_replay.build(cases, load_world(), str(body.get("campaign", "")),
                                              day, seed, max_cases=max_cases)
    red_replay.write_run(red_replay.DEFAULT_OUTPUT, events, truth, summary)
    return {"summary": summary, "events": events}


class Autopilot:
    """Background SOC loop. Every proposal still stops at the human gate; Jev is opt-in."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.running = False
        self.busy = False
        self.interval = 15
        self.use_jev = False
        self.next_at: float | None = None
        self.last_error: str | None = None
        self.log: list[str] = []

    def _note(self, line: str) -> None:
        self.log = (self.log + [time.strftime("%H:%M:%S ") + line])[-40:]

    def _cycle(self) -> None:
        from agents import autopilot as ap
        with self.lock:
            if self.busy:
                return
            self.busy = True
        try:
            ap.run_cycle(use_jev=self.use_jev, log=self._note)
            self.last_error = None
        except Exception as exc:
            self.last_error = type(exc).__name__
            ap.record_failure(self.last_error)
            self._note("error: " + self.last_error)
        finally:
            self.busy = False

    def _loop(self) -> None:
        while self.running:
            self._cycle()
            self.next_at = time.time() + self.interval * 60
            while self.running and time.time() < self.next_at:
                time.sleep(1)
        self.next_at = None

    def control(self, body: dict[str, Any]) -> dict[str, Any]:
        action = body.get("action")
        if "interval" in body:
            interval = body["interval"]
            if isinstance(interval, bool) or interval not in (5, 15, 30, 60):
                raise ValueError("interval must be 5, 15, 30, or 60 minutes")
            self.interval = interval
        if "jev" in body:
            if body["jev"] and body.get("confirm") != "RUN":
                raise PermissionError("type RUN to let autopilot spend Jev calls (up to 40 per cycle)")
            self.use_jev = bool(body["jev"])
            self._note(f"Jev {'ON (paid)' if self.use_jev else 'off'}")
        if action == "start" and not self.running:
            self.running = True
            self._note(f"autopilot started, every {self.interval} min")
            threading.Thread(target=self._loop, daemon=True).start()
        elif action == "stop":
            self.running = False
            self._note("autopilot stopped")
        elif action == "run_once":
            if self.busy:
                raise RuntimeError("a cycle is already running")
            threading.Thread(target=self._cycle, daemon=True).start()
        return self.view()

    def view(self) -> dict[str, Any]:
        from agents import autopilot as ap
        return {"running": self.running, "busy": self.busy, "interval": self.interval, "jev": self.use_jev,
                "next_at": self.next_at, "last_error": self.last_error, "failures": ap.failures(5),
                "log": self.log[-15:],
                "cycles": ap.cycles(30)}


# ---------------------------------------------------------------- http
class Handler(BaseHTTPRequestHandler):
    server_version = "NorthstarConsole/1"
    store: Store
    jobs: Jobs
    autopilot: Autopilot
    red_range: red_range_service.RehearsalManager
    red_live: red_range_active.ActiveManager
    blue_watch: blue_watch.BlueWatch
    token: str
    port: int
    campaign_lock = threading.Lock()

    def log_message(self, fmt: str, *args: Any) -> None:  # quiet access log
        return

    def _allowed_host(self) -> bool:
        return self.headers.get("Host") in {f"127.0.0.1:{self.port}", f"localhost:{self.port}"}

    def _send(self, status: int, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: Any) -> None:
        self._send(status, json.dumps(payload).encode(), "application/json")

    def do_GET(self) -> None:
        if not self._allowed_host():
            return self._json(HTTPStatus.FORBIDDEN, {"error": "host not allowed"})
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            html = INDEX.read_text().replace("__DATA__", "null").replace("__TOKEN__", self.token)
            return self._send(HTTPStatus.OK, html.encode(), "text/html; charset=utf-8")
        if path == "/api/bootstrap":
            return self._json(HTTPStatus.OK, self.store.bootstrap())
        if path.startswith("/api/case/"):
            case = self.store.case(path.rsplit("/", 1)[-1])
            return self._json(HTTPStatus.OK if case else HTTPStatus.NOT_FOUND, case or {"error": "no such case"})
        if path.startswith("/api/ai-verdict/"):
            answer = ai_verdict_after_label(path.rsplit("/", 1)[-1])
            return self._json(HTTPStatus.OK if answer else HTTPStatus.NOT_FOUND,
                              answer or {"error": "AI review is available after your label is saved"})
        if path == "/api/jobs":
            return self._json(HTTPStatus.OK, {"running": self.jobs.running, "jobs": self.jobs.listing()})
        if path == "/api/detections":
            return self._json(HTTPStatus.OK, detections_view())
        if path == "/api/pentest-swarm":
            return self._json(HTTPStatus.OK, pentest_swarm_reports.load_summary())
        if path == "/api/agents":
            return self._json(HTTPStatus.OK, agents_view())
        if path == "/api/autopilot":
            return self._json(HTTPStatus.OK, self.autopilot.view())
        if path == "/api/blue":
            return self._json(HTTPStatus.OK, {"proposals": blue_agent.read_proposals(),
                                               "model_ready": blue_agent.llm.available()})
        if path == "/api/blue-watch":
            return self._json(HTTPStatus.OK, self.blue_watch.view())
        if path == "/api/showcase":
            return self._json(HTTPStatus.OK, showcase_view(self.store, self.red_live,
                                                            self.blue_watch))
        if path == "/api/jev-map":
            selected = parse_qs(urlparse(self.path).query).get("case_id", [None])[0]
            try:
                return self._json(HTTPStatus.OK, jev_map_view(self.store, selected))
            except ValueError as exc:
                return self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        if path == "/api/campaigns":
            with self.campaign_lock:
                return self._json(HTTPStatus.OK, campaign_view())
        if path == "/api/red-range":
            data = self.red_range.view()
            for plan in data["plans"]:
                try:
                    red_range_active.validate_plan(plan, plan["sha256"], root=self.red_live.root)
                    plan["launchable"] = True
                except (ValueError, KeyError, OSError):
                    plan["launchable"] = False
            data["active"] = self.red_live.view()
            data["active_readiness"]["configured"] = (
                red_range_active.live.SCANNER.is_file() and
                (self.red_live.root / "range" / "crapi-compose.json").is_file() and
                (self.red_live.root / "range" / "build-manifest.json").is_file() and
                (self.red_live.root / "range" / "scanner-image.json").is_file() and
                (self.red_live.root / "range" / "scanner-config.json").is_file() and
                all((red_range_active.live.TOOL_DIR / name).is_file() for name in
                    ("httpx", "nuclei", "ffuf", "katana")) and
                red_range_active.live.TEMPLATES.is_dir() and
                red_range_active.live.WORDLIST.is_file())
            if data["active_readiness"]["configured"]:
                data["active_readiness"]["ready"] = True
                data["active_readiness"]["scanner_installed"] = True
                data["active_readiness"]["blockers"] = [
                    "Exact scope activation phrase required",
                    "Network, target, and local model probes rerun at launch",
                ]
            return self._json(HTTPStatus.OK, data)
        return self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:
        if not self._allowed_host():
            return self._json(HTTPStatus.FORBIDDEN, {"error": "host not allowed"})
        origin = self.headers.get("Origin")
        if origin and urlparse(origin).netloc != self.headers.get("Host"):
            return self._json(HTTPStatus.FORBIDDEN, {"error": "cross-origin request refused"})
        if not secrets.compare_digest(self.headers.get("X-Console-Token", ""), self.token):
            return self._json(HTTPStatus.FORBIDDEN, {"error": "missing or wrong console token"})
        try:
            length = min(int(self.headers.get("Content-Length", "0")), 64_000)
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid JSON"})
        path = urlparse(self.path).path
        try:
            if path == "/api/adjudicate":
                if self.store.case(str(body.get("case_id"))) is None:
                    return self._json(HTTPStatus.NOT_FOUND, {"error": "no such case"})
                return self._json(HTTPStatus.OK, write_label(str(body["case_id"]), str(body.get("verdict")),
                                                             str(body.get("note", ""))))
            if path == "/api/adjudicate/undo":
                if self.store.case(str(body.get("case_id"))) is None:
                    return self._json(HTTPStatus.NOT_FOUND, {"error": "no such case"})
                return self._json(HTTPStatus.OK, undo_label(str(body["case_id"])))
            if path == "/api/jobs":
                def internal(log):
                    compute_summary(log)
                    self.store.reload()
                job = self.jobs.start(str(body.get("kind")), body.get("confirm"), internal)
                return self._json(HTTPStatus.ACCEPTED, {k: v for k, v in job.items() if k != "log"})
            if path == "/api/jobs/clear":
                return self._json(HTTPStatus.OK, {"cleared": self.jobs.clear_completed()})
            if path == "/api/campaigns/build":
                with self.campaign_lock:
                    return self._json(HTTPStatus.OK, build_campaign(body))
            if path == "/api/red-range/plan":
                plan = red_range_service.prepare_plan(body.get("lab"), body.get("suites"),
                                                      root=self.red_range.root)
                return self._json(HTTPStatus.OK, plan)
            if path == "/api/red-range/rehearsal":
                return self._json(HTTPStatus.ACCEPTED,
                                  self.red_range.start(body.get("campaigns"), seed=body.get("seed", 7)))
            if path == "/api/red-range/stop":
                return self._json(HTTPStatus.OK, self.red_range.stop())
            if path == "/api/red-range/live":
                return self._json(HTTPStatus.ACCEPTED,
                                  self.red_live.start(body.get("sha256"), body.get("confirm")))
            if path == "/api/red-range/live/stop":
                return self._json(HTTPStatus.OK, self.red_live.stop())
            if path == "/api/autopilot":
                return self._json(HTTPStatus.OK, self.autopilot.control(body))
            if path == "/api/lab/shutdown":
                # Detached so it can stop this server too; same token/Host/Origin guards as every POST.
                log = open(REPO / "runs" / "lab-down.log", "w")
                subprocess.Popen(["/bin/bash", str(REPO / "northstar.sh"), "down"], cwd=str(REPO),
                                 stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                return self._json(HTTPStatus.ACCEPTED, {"shutting_down": True})
            if path == "/api/agents/ping":
                try:
                    return self._json(HTTPStatus.OK, ping_model())
                except Exception as exc:
                    return self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": str(exc)[:200]})
            if path == "/api/blue/review":
                entry = blue_agent.review(str(body.get("id", "")), str(body.get("decision", "")))
                return self._json(HTTPStatus.OK, entry)
            if path == "/api/blue-watch":
                return self._json(HTTPStatus.ACCEPTED, self.blue_watch.control(body))
            if path == "/api/detections/approve":
                record = detection_agent.approve(str(body.get("id")), bool(body.get("accept_risk")))
                recompute = None
                try:  # approved tuning changes coverage and noise: refresh the console summary
                    def internal(log):
                        compute_summary(log)
                        self.store.reload()
                    recompute = self.jobs.start("summary", None, internal)["id"]
                except RuntimeError:
                    pass  # another job is running; the summary cache refreshes on the next load
                return self._json(HTTPStatus.OK, {"approved": record["id"], "recompute_job": recompute})
            if path == "/api/reload":
                self.store.reload()
                return self._json(HTTPStatus.OK, {"ok": True})
        except PermissionError as exc:
            return self._json(HTTPStatus.FORBIDDEN, {"error": str(exc)})
        except (ValueError, KeyError) as exc:
            return self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except RuntimeError as exc:
            return self._json(HTTPStatus.CONFLICT, {"error": str(exc)})
        return self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})


def make_server(port: int) -> ThreadingHTTPServer:
    Handler.store = Store()
    Handler.jobs = Jobs()
    Handler.autopilot = Autopilot()
    Handler.red_range = red_range_service.RehearsalManager()
    Handler.red_live = red_range_active.ActiveManager()
    Handler.blue_watch = blue_watch.BlueWatch()
    Handler.token = secrets.token_urlsafe(24)
    Handler.port = port
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()
    print("loading corpus and summary (first run computes benign-noise cache, ~40 s)…", flush=True)
    try:
        server = make_server(args.port)
    except OSError as exc:
        if exc.errno != 48 and "in use" not in str(exc):
            raise
        sys.exit(f"Port {args.port} is busy — the console is probably already running: open "
                 f"http://127.0.0.1:{args.port}\nTo start a second copy: python3 -m console.server --port {args.port + 1}\n"
                 f"To find what holds it: lsof -nP -iTCP:{args.port} -sTCP:LISTEN")
    print(f"Northstar SOC console → http://127.0.0.1:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
