"""Bounded crAPI scanner runs in the verified isolated Docker range."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from red_range import live
from red_range import telemetry as telemetry_module
from red_range.service import ROOT, _write_json

OBJECTIVES = {
    "api-security": "Assess API security in the disposable crAPI lab",
    "owasp-top10": "Assess OWASP Top 10 web and API risks in the disposable crAPI lab",
    "bug-bounty": "Assess the disposable crAPI lab within the approved scope",
}
MAX_SECONDS = 1800


def validate_plan(plan: dict[str, Any], digest: str, *, root: Path = ROOT) -> None:
    if plan.get("lab") != "crapi" or plan.get("status") != "draft":
        raise ValueError("only a saved crAPI draft can launch")
    suites = plan.get("suites")
    if not isinstance(suites, list) or not suites or any(s not in OBJECTIVES for s in suites):
        raise ValueError("the crAPI draft contains an unsupported suite")
    manifest = root / "range" / "build-manifest.json"
    if not manifest.is_file() or plan.get("runner_manifest_sha256") != hashlib.sha256(manifest.read_bytes()).hexdigest():
        raise ValueError("prepare a new draft for the current pinned range build")
    policy = Path(__file__)
    if plan.get("runner_policy_sha256") != hashlib.sha256(policy.read_bytes()).hexdigest():
        raise ValueError("prepare a new draft for the current scanner policy")
    scope = {key: plan[key] for key in ("target_class", "lab", "suites", "provider",
                                        "safe_mode", "jev_in_scanner", "max_minutes",
                                        "network_policy", "status", "runner_manifest_sha256",
                                        "runner_policy_sha256")}
    canonical = json.dumps(scope, sort_keys=True, separators=(",", ":"))
    expected = hashlib.sha256(canonical.encode()).hexdigest()
    if expected != digest or plan.get("sha256") != digest:
        raise ValueError("campaign scope hash does not match its saved draft")
    if (scope["provider"] != "local_ollama" or scope["safe_mode"] is not True or
            scope["jev_in_scanner"] is not False or
            scope["max_minutes"] != 30 * len(suites) or
            scope["network_policy"] != "isolated_runner_required"):
        raise ValueError("campaign draft has unsafe settings")


def scanner_runtime_image(root: Path = ROOT) -> str:
    record = json.loads((root / "range" / "scanner-image.json").read_text())
    image_id = record["runtime_image_id"]
    if not isinstance(image_id, str) or not image_id.startswith("sha256:"):
        raise RuntimeError("scanner runtime image is not pinned")
    dockerfile = Path(__file__).with_name("scanner.Dockerfile")
    if record.get("dockerfile_sha256") != hashlib.sha256(dockerfile.read_bytes()).hexdigest():
        raise RuntimeError("scanner runtime Dockerfile changed")
    details = json.loads(live.command(["docker", "image", "inspect", image_id]))[0]
    if details["Id"] != image_id:
        raise RuntimeError("scanner runtime image changed")
    return image_id


def scanner_command(run_id: str, suite: str, report_dir: Path,
                    *, seconds: int = MAX_SECONDS) -> list[str]:
    if suite not in OBJECTIVES or not run_id.startswith("rr-") or not 1 <= seconds <= MAX_SECONDS:
        raise ValueError("unknown scanner profile or run")
    return ["docker", "run", "--rm", "--name", run_id + "-scanner",
            "--label", "northstar.red-range.active=true",
            "--label", "northstar.red-range.run=" + run_id,
            "--network", live.NETWORK, "--cap-drop", "ALL", "--security-opt",
            "no-new-privileges", "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m",
            "--pids-limit", "256", "--memory", "2g", "--cpus", "2",
            "-e", "HOME=/tmp",
            "-e", "PATH=/opt/red-tools:/usr/local/bin:/usr/bin:/bin",
            "-v", str(live.SCANNER) + ":/usr/local/bin/pentestswarm:ro",
            "-v", str(live.TOOL_DIR) + ":/opt/red-tools:ro",
            "-v", str(live.TEMPLATES) + ":/tmp/nuclei-templates:ro",
            "-v", str(live.WORDLIST) + ":/usr/share/seclists/Discovery/Web-Content/common.txt:ro",
            "-v", str(live.ROOT / "range" / "scanner-config.json") + ":/config.json:ro",
            "-v", str(report_dir) + ":/reports:rw",
            scanner_runtime_image(),
            "/usr/bin/timeout", str(seconds), "/usr/local/bin/pentestswarm",
            "scan", "http://crapi-web", "--scope", "crapi-web", "--provider", "ollama",
            "--config", "/config.json", "--mode", "manual", "--safe-mode",
            "--active-scan=true", "--swarm", "--strict", "--dashboard=false", "--follow",
            "--objective", OBJECTIVES[suite], "--output", "/reports", "--format", "all"]


def _read_status(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def _capture_target_logs(folder: Path, started_at: str) -> list[dict[str, Any]]:
    output = folder / "defender-telemetry"
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    output.chmod(0o700)
    records = []
    compose = json.loads(live.COMPOSE.read_text())
    for service in sorted(set(compose["services"]) - {"model-relay"}):
        result = subprocess.run(["docker", "compose", "-f", str(live.COMPOSE),
                                 "ps", "-q", service], capture_output=True, text=True, timeout=15)
        if result.returncode or not result.stdout.strip():
            records.append({"service": service, "capture": "missing"})
            continue
        path = output / (service.replace(".", "_") + ".log")
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as handle:
            subprocess.run(["docker", "logs", "--timestamps", "--since", started_at, result.stdout.strip()],
                           stdout=handle, stderr=subprocess.STDOUT, timeout=30)
        path.chmod(0o600)
        data = path.read_bytes()
        records.append({"service": service, "capture": "saved", "bytes": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(), "lines": data.count(b"\n")})
    return records


def _capture_reports(folder: Path) -> list[dict[str, Any]]:
    output = []
    base = folder / "reports"
    if not base.is_dir():
        return output
    for directory, _, files in os.walk(base, followlinks=False):
        for name in sorted(files):
            path = Path(directory) / name
            if path.is_symlink() or not path.is_file():
                continue
            data = path.read_bytes()
            output.append({"path": str(path.relative_to(base)), "bytes": len(data),
                           "sha256": hashlib.sha256(data).hexdigest()})
    return output


class ActiveManager:
    def __init__(self, *, root: Path = ROOT) -> None:
        self.root = root
        self.lock = threading.Lock()
        self.stop_signal = threading.Event()
        self.current_id: str | None = None
        self.current_container: str | None = None
        self._recover()

    def _recover(self) -> None:
        for path in (self.root / "live-runs").glob("*/status.json"):
            try:
                status = _read_status(path)
                if status.get("status") in ("running", "stopping"):
                    status["status"] = "interrupted"
                    status["ended_at"] = datetime.now(timezone.utc).isoformat()
                    _write_json(path, status)
                    if self.root == ROOT:
                        subprocess.run(["docker", "stop", "-t", "10", status["id"] + "-scanner"],
                                       capture_output=True, timeout=20)
            except (OSError, ValueError):
                continue

    def view(self) -> dict[str, Any]:
        statuses = []
        for path in (self.root / "live-runs").glob("*/status.json"):
            try:
                status = _read_status(path)
                if status.get("status") in ("running", "stopping"):
                    started = datetime.fromisoformat(status["started_at"])
                    status["elapsed_seconds"] = max(0, int((datetime.now(timezone.utc) - started).total_seconds()))
                    suite = status.get("current_suite")
                    if suite in OBJECTIVES:
                        log_path = path.parent / (suite + "-scanner.log")
                        if log_path.is_file():
                            status["scanner_log_bytes"] = log_path.stat().st_size
                statuses.append(status)
            except (OSError, ValueError):
                continue
        statuses.sort(key=lambda item: item["started_at"], reverse=True)
        return {"current_id": self.current_id, "runs": statuses[:10]}

    def start(self, digest: str, confirmation: str) -> dict[str, Any]:
        if not isinstance(digest, str) or len(digest) != 64 or not all(c in "0123456789abcdef" for c in digest):
            raise ValueError("select a saved campaign scope hash")
        if confirmation != "ACTIVATE " + digest[:12]:
            raise PermissionError("type ACTIVATE and the first 12 scope hash characters")
        path = self.root / "plans" / (digest + ".json")
        if not path.is_file():
            raise ValueError("campaign draft was not found")
        plan = json.loads(path.read_text())
        validate_plan(plan, digest, root=self.root)
        if not live.SCANNER.is_file() or not (self.root / "range" / "scanner-config.json").is_file():
            raise RuntimeError("pinned scanner or local model configuration is missing")
        preflight = live.probe()
        with self.lock:
            if self.current_id is not None:
                raise RuntimeError("an active Red Range run is already in progress")
            run_id = "rr-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)
            folder = self.root / "live-runs" / run_id
            folder.mkdir(mode=0o700, parents=True, exist_ok=False)
            folder.chmod(0o700)
            status = {"id": run_id, "kind": "isolated_crapi_live_scan", "status": "running",
                      "lab": "crapi", "suites": plan["suites"], "scope_sha256": digest,
                      "scanner_source_commit": live.SOURCE_COMMIT,
                      "scanner_sha256": hashlib.sha256(live.SCANNER.read_bytes()).hexdigest(),
                      "started_at": datetime.now(timezone.utc).isoformat(),
                      "max_minutes": plan["max_minutes"],
                      "ended_at": None, "current_suite": None, "finished_suites": [],
                      "safe_mode": True, "strict_model_errors": True,
                      "jev_calls": 0, "network": live.NETWORK,
                      "preflight": preflight, "telemetry": "pending", "elastic": "pending"}
            _write_json(folder / "status.json", status)
            self.current_id = run_id
            self.stop_signal = threading.Event()
            threading.Thread(target=self._run, args=(folder, status, self.stop_signal), daemon=True).start()
            return status

    def _run(self, folder: Path, status: dict[str, Any], stop: threading.Event) -> None:
        try:
            deadline = time.monotonic() + status["max_minutes"] * 60
            for suite in status["suites"]:
                if stop.is_set():
                    break
                remaining = min(MAX_SECONDS, int(deadline - time.monotonic()))
                if remaining < 1:
                    status["status"] = "timed_out"
                    break
                report_dir = folder / "reports" / suite
                report_dir.mkdir(mode=0o700, parents=True)
                command = scanner_command(status["id"], suite, report_dir, seconds=remaining)
                with self.lock:
                    self.current_container = status["id"] + "-scanner"
                    status["current_suite"] = suite
                    _write_json(folder / "status.json", status)
                log_path = folder / (suite + "-scanner.log")
                with os.fdopen(os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as log:
                    process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
                    while process.poll() is None and not stop.is_set() and time.monotonic() < deadline + 30:
                        time.sleep(0.5)
                    if stop.is_set() or process.poll() is None:
                        subprocess.run(["docker", "stop", "-t", "10", self.current_container],
                                       capture_output=True, timeout=20)
                    code = process.wait(timeout=30)
                status["finished_suites"].append({"suite": suite, "exit_code": code})
                if code:
                    status["status"] = "stopped" if stop.is_set() else "timed_out" if code == 124 else "failed"
                    break
            else:
                status["status"] = "complete"
            if stop.is_set():
                status["status"] = "stopped"
        except Exception:
            status["status"] = "failed"
            status["error_type"] = "ScannerRunnerError"
        finally:
            try:
                reports = _capture_reports(folder)
                _write_json(folder / "report-manifest.json", {"run_id": status["id"], "files": reports})
                status["report_files"] = len(reports)
                if status["status"] == "complete" and not reports:
                    status["status"] = "incomplete_report"
            except Exception:
                status["report_files"] = 0
                if status["status"] == "complete":
                    status["status"] = "incomplete_report"
            try:
                telemetry = _capture_target_logs(folder, status["started_at"])
                status["telemetry"] = "saved"
                _write_json(folder / "telemetry-manifest.json",
                            {"run_id": status["id"], "source": "disposable_crapi_container_logs",
                             "records": telemetry})
                try:
                    indexed = telemetry_module.ingest(folder, status["id"])
                    status["elastic"] = "indexed"
                    _write_json(folder / "elastic-ingest.json", indexed)
                except Exception:
                    status["elastic"] = "ingest_failed"
            except Exception:
                status["telemetry"] = "capture_failed"
            status["ended_at"] = datetime.now(timezone.utc).isoformat()
            with self.lock:
                _write_json(folder / "status.json", status)
                self.current_id = None
                self.current_container = None

    def stop(self) -> dict[str, Any]:
        with self.lock:
            if self.current_id is None:
                raise RuntimeError("no active Red Range run is in progress")
            self.stop_signal.set()
            folder = self.root / "live-runs" / self.current_id
            status = _read_status(folder / "status.json")
            status["status"] = "stopping"
            _write_json(folder / "status.json", status)
            container = self.current_container
        if container:
            subprocess.run(["docker", "stop", "-t", "10", container], capture_output=True, timeout=20)
        return status
