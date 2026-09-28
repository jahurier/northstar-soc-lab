"""Prepare and verify a disposable crAPI range with no scanner egress route."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any

from red_range.service import ROOT

SOURCE_COMMIT = "249f06ce8149bfd1f472597420e8303134c1c5d8"
NETWORK = "northstar-red-range"
RELAY_NETWORK = "northstar-red-range-relay-egress"
PROJECT = "northstar_red_range_crapi"
SOURCE = ROOT / "vendor" / "pentest-swarm"
SOURCE_COMPOSE = SOURCE / "deploy" / "lab" / "crapi" / "docker-compose.yml"
SCANNER = ROOT / "vendor" / "pentestswarm-linux-arm64"
COMPOSE = ROOT / "range" / "crapi-compose.json"
RELAY = Path(__file__).with_name("ollama_relay.py")
RELAY_IMAGE = "python:3.12-slim"
LOCK = Path(__file__).with_name("image-lock-2026-09-24.json")
TOOL_LOCK = Path(__file__).with_name("tool-lock-2026-09-24.json")
TOOL_DIR = ROOT / "vendor" / "tool-gopath" / "bin" / "linux_arm64"
CONTENT_LOCK = Path(__file__).with_name("content-lock-2026-09-24.json")
TEMPLATES = ROOT / "vendor" / "nuclei-templates"
WORDLIST = ROOT / "vendor" / "wordlists" / "common.txt"


def command(argv: list[str], *, cwd: Path | None = None) -> str:
    result = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise RuntimeError("range prerequisite failed: " + argv[0] + " " + argv[1])
    return result.stdout.strip()


def image_digest(tag: str) -> str:
    details = json.loads(command(["docker", "image", "inspect", tag]))[0]
    digests = details.get("RepoDigests") or []
    if not digests:
        raise RuntimeError("pulled image has no digest: " + tag)
    return digests[0]


def isolated_compose(source: dict[str, Any], images: dict[str, str],
                     relay_image: str, relay_path: Path) -> dict[str, Any]:
    """Remove all host exposure and attach crAPI only to the internal network."""
    result = json.loads(json.dumps(source))
    result["name"] = PROJECT
    result["networks"] = {
        "range": {"external": True, "name": NETWORK},
        "relay_egress": {"external": True, "name": RELAY_NETWORK},
    }
    for name, cfg in result["services"].items():
        cfg["image"] = images[name]
        cfg.pop("ports", None)
        cfg.pop("network_mode", None)
        cfg.pop("extra_hosts", None)
        cfg["networks"] = {"range": None}
        cfg["labels"] = {"northstar.red-range": "crapi"}
        for mount in cfg.get("volumes", []):
            if mount.get("type") == "bind" and name == "crapi-identity" and mount.get("target") == "/app/keys":
                mount["type"] = "volume"
                mount["source"] = "identity-keys"
            elif mount.get("type") != "volume":
                raise ValueError("crAPI source contains an unexpected host bind mount")
    result.setdefault("volumes", {})["identity-keys"] = {}
    for name, cfg in result.get("volumes", {}).items():
        cfg["name"] = PROJECT + "_" + name
    result["services"]["model-relay"] = {
        "image": relay_image,
        "command": ["python3", "/relay.py"],
        "extra_hosts": ["host.docker.internal:host-gateway"],
        "volumes": [{"type": "bind", "source": str(relay_path),
                     "target": "/relay.py", "read_only": True}],
        "networks": {"range": None, "relay_egress": None},
        "security_opt": ["no-new-privileges:true"],
        "cap_drop": ["ALL"],
        "read_only": True,
        "tmpfs": ["/tmp"],
        "labels": {"northstar.red-range": "model-relay"},
    }
    validate_compose(result)
    return result


def validate_compose(compose: dict[str, Any]) -> None:
    for name, cfg in compose["services"].items():
        allowed = {"range", "relay_egress"} if name == "model-relay" else {"range"}
        if set(cfg.get("networks", {})) != allowed or cfg.get("ports") or cfg.get("network_mode"):
            raise ValueError("service escapes the Red Range network: " + name)
        if name != "model-relay" and cfg.get("extra_hosts"):
            raise ValueError("crAPI service has an unexpected host alias")
        if "@sha256:" not in cfg.get("image", ""):
            raise ValueError("service image is not pinned: " + name)


def prepare(root: Path = ROOT) -> dict[str, Any]:
    if command(["git", "rev-parse", "HEAD"], cwd=SOURCE) != SOURCE_COMMIT:
        raise RuntimeError("Pentest Swarm source does not match the pinned commit")
    lock = json.loads(LOCK.read_text())
    if lock["source_commit"] != SOURCE_COMMIT:
        raise RuntimeError("image lock references a different scanner source")
    source = json.loads(command(["docker", "compose", "-f", str(SOURCE_COMPOSE),
                                 "config", "--format", "json"]))
    images = lock["crapi_images"]
    if set(images) != set(source["services"]):
        raise RuntimeError("image lock does not match the crAPI service list")
    for reference in [*images.values(), lock["relay_image"], lock["probe_image"]]:
        command(["docker", "image", "inspect", reference])
    result = isolated_compose(source, images, lock["relay_image"], RELAY)
    folder = root / "range"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "crapi-compose.json"
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    path.write_text(payload)
    os.chmod(path, 0o600)
    record = {"source_commit": SOURCE_COMMIT,
              "compose_sha256": hashlib.sha256(payload.encode()).hexdigest(),
              "scanner_binary_sha256": hashlib.sha256(SCANNER.read_bytes()).hexdigest(),
              "scanner_config_sha256": hashlib.sha256((folder / "scanner-config.json").read_bytes()).hexdigest(),
              "scanner_image_record_sha256": hashlib.sha256((folder / "scanner-image.json").read_bytes()).hexdigest(),
              "tool_lock_sha256": hashlib.sha256(TOOL_LOCK.read_bytes()).hexdigest(),
              "content_lock_sha256": hashlib.sha256(CONTENT_LOCK.read_bytes()).hexdigest(),
              "service_images": {name: cfg["image"] for name, cfg in result["services"].items()},
              "network": NETWORK, "host_ports": 0}
    (folder / "build-manifest.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    return record


def check_network() -> None:
    details = json.loads(command(["docker", "network", "inspect", NETWORK]))[0]
    if not details["Internal"] or details["Name"] != NETWORK:
        raise RuntimeError("Red Range network is not internal")


def verify_artifacts() -> dict[str, Any]:
    record = json.loads((ROOT / "range" / "build-manifest.json").read_text())
    if record["source_commit"] != SOURCE_COMMIT or command(["git", "rev-parse", "HEAD"], cwd=SOURCE) != SOURCE_COMMIT:
        raise RuntimeError("Pentest Swarm source pin changed")
    if hashlib.sha256(COMPOSE.read_bytes()).hexdigest() != record["compose_sha256"]:
        raise RuntimeError("crAPI range compose changed after review")
    if hashlib.sha256(SCANNER.read_bytes()).hexdigest() != record["scanner_binary_sha256"]:
        raise RuntimeError("scanner binary changed after review")
    if hashlib.sha256((ROOT / "range" / "scanner-config.json").read_bytes()).hexdigest() != record["scanner_config_sha256"]:
        raise RuntimeError("local model configuration changed after review")
    if hashlib.sha256((ROOT / "range" / "scanner-image.json").read_bytes()).hexdigest() != record["scanner_image_record_sha256"]:
        raise RuntimeError("scanner runtime image record changed after review")
    if hashlib.sha256(TOOL_LOCK.read_bytes()).hexdigest() != record["tool_lock_sha256"]:
        raise RuntimeError("scanner tool lock changed after review")
    tools = json.loads(TOOL_LOCK.read_text())["tools"]
    for name, spec in tools.items():
        if hashlib.sha256((TOOL_DIR / name).read_bytes()).hexdigest() != spec["sha256"]:
            raise RuntimeError("pinned scanner tool changed: " + name)
    if hashlib.sha256(CONTENT_LOCK.read_bytes()).hexdigest() != record["content_lock_sha256"]:
        raise RuntimeError("scanner content lock changed after review")
    content = json.loads(CONTENT_LOCK.read_text())
    if command(["git", "rev-parse", "HEAD"], cwd=TEMPLATES) != content["nuclei_templates_commit"]:
        raise RuntimeError("offline nuclei templates changed")
    if hashlib.sha256(WORDLIST.read_bytes()).hexdigest() != content["wordlist_sha256"]:
        raise RuntimeError("offline scanner wordlist changed")
    return record


def check_runtime() -> dict[str, Any]:
    check_network()
    verify_artifacts()
    compose = json.loads(COMPOSE.read_text())
    validate_compose(compose)
    ids = command(["docker", "compose", "-f", str(COMPOSE), "ps", "-q"]).splitlines()
    if len(ids) != len(compose["services"]):
        raise RuntimeError("not all crAPI range services are running")
    for ident in ids:
        info = json.loads(command(["docker", "inspect", ident]))[0]
        name = info["Config"]["Labels"]["com.docker.compose.service"]
        expected = {NETWORK, RELAY_NETWORK} if name == "model-relay" else {NETWORK}
        attached = set(info["NetworkSettings"]["Networks"])
        if attached != expected or info["HostConfig"]["PortBindings"]:
            raise RuntimeError("range service network or port boundary failed")
        if info["Config"]["Image"] != compose["services"][name]["image"]:
            raise RuntimeError("range service image differs from pinned compose")
        if not info["State"]["Running"]:
            raise RuntimeError("range service is not running")
    return {"services": len(ids), "network_internal": True, "host_ports": 0,
            "model_relay_only_dual_homed": True}


def probe() -> dict[str, bool]:
    """Verify the target/model path and deny routes before every active run."""
    check_runtime()
    script = ("import json,urllib.request; "
              "a=urllib.request.urlopen('http://crapi-web/health',timeout=10); "
              "b=urllib.request.urlopen('http://model-relay:11434/api/tags',timeout=10); "
              "assert a.status==200 and b.status==200 and "
              "any(m.get('name')=='qwen3:14b' for m in json.load(b).get('models',[]))")
    lock = json.loads(LOCK.read_text())
    result = subprocess.run(["docker", "run", "--rm", "--network", NETWORK,
                             "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                             lock["relay_image"], "python3", "-c", script],
                            capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError("crAPI or local model relay failed the range probe")
    denied = ("timeout 2 bash -c '</dev/tcp/203.0.113.1/80' 2>/dev/null && exit 1; "
              "timeout 2 bash -c '</dev/tcp/host.docker.internal/8787' 2>/dev/null && exit 1; "
              "timeout 2 bash -c '</dev/tcp/host.docker.internal/11434' 2>/dev/null && exit 1; "
              "exit 0")
    result = subprocess.run(["docker", "run", "--rm", "--network", NETWORK,
                             "--add-host", "host.docker.internal:host-gateway",
                             lock["probe_image"], "bash", "-lc", denied],
                            capture_output=True, timeout=15)
    if result.returncode:
        raise RuntimeError("scanner network can reach a forbidden destination")
    return {"target_healthy": True, "local_model_reachable_via_relay": True,
            "external_blocked": True, "host_console_blocked": True,
            "direct_host_model_blocked": True}


def compose_up() -> dict[str, Any]:
    check_network()
    if not COMPOSE.exists():
        prepare()
    validate_compose(json.loads(COMPOSE.read_text()))
    log_path = ROOT / "range" / "compose-up.log"
    with os.fdopen(os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as handle:
        result = subprocess.run(["docker", "compose", "-f", str(COMPOSE), "up", "-d",
                                 "--wait", "--wait-timeout", "600"], stdout=handle,
                                stderr=subprocess.STDOUT, timeout=720)
    if result.returncode:
        raise RuntimeError("crAPI range did not become ready; inspect private compose log")
    return check_runtime()


def compose_down(*, remove_volumes: bool = True) -> None:
    if COMPOSE.exists():
        log_path = ROOT / "range" / "compose-down.log"
        with os.fdopen(os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as handle:
            argv = ["docker", "compose", "-f", str(COMPOSE), "down"]
            if remove_volumes:
                argv.append("-v")
            subprocess.run(argv,
                           stdout=handle, stderr=subprocess.STDOUT, timeout=180, check=True)
