"""Install, start, inspect, or dispose the pinned crAPI Red Range.

    python3 -m red_range.setup up
    python3 -m red_range.setup status
    python3 -m red_range.setup resume
    python3 -m red_range.setup pause
    python3 -m red_range.setup down
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import time
import urllib.request
from pathlib import Path

from red_range import live
from red_range.service import ROOT

SCANNER_IMAGE = ROOT / "range" / "scanner-image.json"
SCANNER_CONFIG = ROOT / "range" / "scanner-config.json"
DOCKERFILE = Path(__file__).with_name("scanner.Dockerfile")


def _run(argv: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    ROOT.mkdir(parents=True, exist_ok=True)
    log = ROOT / "range" / "setup.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    with os.fdopen(os.open(log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600), "ab") as handle:
        result = subprocess.run(argv, cwd=cwd, env=env, stdout=handle,
                                stderr=subprocess.STDOUT, timeout=1200)
    log.chmod(0o600)
    if result.returncode:
        raise RuntimeError("setup step failed: " + argv[0] + " (see private setup log)")


def _network(name: str, internal: bool) -> None:
    result = subprocess.run(["docker", "network", "inspect", name], capture_output=True)
    if result.returncode:
        args = ["docker", "network", "create", "--driver", "bridge"]
        if internal:
            args.append("--internal")
        _run(args + [name])
    detail = json.loads(live.command(["docker", "network", "inspect", name]))[0]
    if detail["Internal"] is not internal or detail["Driver"] != "bridge":
        raise RuntimeError("existing range network has the wrong isolation policy")


def _source() -> None:
    if not live.SOURCE.exists():
        _run(["git", "clone", "--filter=blob:none", "--no-checkout",
              "https://github.com/Armur-Ai/Pentest-Swarm-AI.git", str(live.SOURCE)])
        _run(["git", "checkout", live.SOURCE_COMMIT], cwd=live.SOURCE)
    if live.command(["git", "rev-parse", "HEAD"], cwd=live.SOURCE) != live.SOURCE_COMMIT:
        raise RuntimeError("local Pentest Swarm checkout differs from pinned source")


def _images() -> dict:
    lock = json.loads(live.LOCK.read_text())
    if lock["source_commit"] != live.SOURCE_COMMIT:
        raise RuntimeError("image lock does not match pinned source")
    for reference in [*lock["crapi_images"].values(), lock["relay_image"], lock["probe_image"]]:
        result = subprocess.run(["docker", "image", "inspect", reference], capture_output=True)
        if result.returncode:
            _run(["docker", "pull", reference])
    return lock


def _scanner(lock: dict) -> None:
    previous = ROOT / "range" / "build-manifest.json"
    if live.SCANNER.is_file() and previous.is_file():
        saved = json.loads(previous.read_text())
        if hashlib.sha256(live.SCANNER.read_bytes()).hexdigest() != saved["scanner_binary_sha256"]:
            raise RuntimeError("existing scanner binary differs from the last reviewed build")
    if not live.SCANNER.is_file():
        env = {**os.environ, "GOOS": "linux", "GOARCH": "arm64", "CGO_ENABLED": "0",
               "GOTOOLCHAIN": "auto"}
        _run(["go", "build", "-trimpath", "-o", str(live.SCANNER), "./cmd/pentestswarm"],
             cwd=live.SOURCE, env=env)
    dockerfile_hash = hashlib.sha256(DOCKERFILE.read_bytes()).hexdigest()
    if not SCANNER_IMAGE.is_file():
        _run(["docker", "build", "-f", str(DOCKERFILE), "--build-arg",
              "BASE_IMAGE=" + lock["relay_image"], "-t", "northstar-red-range-scanner:pilot",
              str(DOCKERFILE.parents[1])])
        image = json.loads(live.command(["docker", "image", "inspect",
                                        "northstar-red-range-scanner:pilot"]))[0]
        SCANNER_IMAGE.write_text(json.dumps({"base_image": lock["relay_image"],
                                             "runtime_image_id": image["Id"],
                                             "dockerfile_sha256": dockerfile_hash}, indent=2) + "\n")
    record = json.loads(SCANNER_IMAGE.read_text())
    if record["base_image"] != lock["relay_image"] or record.get("dockerfile_sha256") != dockerfile_hash:
        raise RuntimeError("scanner image was built from a different Dockerfile or base")
    expected_config = {"orchestrator": {"provider": "ollama", "model": "qwen3:14b",
                       "endpoint": "http://model-relay:11434", "max_tokens": 4096,
                       "context_window": 32768}, "intelligence": {"enabled": False}}
    if not SCANNER_CONFIG.is_file():
        SCANNER_CONFIG.write_text(json.dumps(expected_config, indent=2) + "\n")
        SCANNER_CONFIG.chmod(0o600)
    if json.loads(SCANNER_CONFIG.read_text()) != expected_config:
        raise RuntimeError("scanner configuration differs from the local-only profile")


def _tools() -> None:
    lock = json.loads(live.TOOL_LOCK.read_text())
    if lock["platform"] != "linux/arm64":
        raise RuntimeError("scanner tool lock targets an unsupported platform")
    tool_root = ROOT / "vendor" / "tool-gopath"
    env = {**os.environ, "GOPATH": str(tool_root), "GOOS": "linux", "GOARCH": "arm64",
           "CGO_ENABLED": "0", "GOTOOLCHAIN": "auto"}
    env.pop("GOBIN", None)
    for name, spec in lock["tools"].items():
        path = live.TOOL_DIR / name
        if not path.is_file():
            _run(["go", "install", spec["module"]], cwd=Path("/private/tmp"), env=env)
        if hashlib.sha256(path.read_bytes()).hexdigest() != spec["sha256"]:
            raise RuntimeError("scanner tool differs from locked binary: " + name)


def _content() -> None:
    lock = json.loads(live.CONTENT_LOCK.read_text())
    if not live.TEMPLATES.exists():
        _run(["git", "clone", "--filter=blob:none", "--no-checkout",
              "https://github.com/projectdiscovery/nuclei-templates.git", str(live.TEMPLATES)])
        _run(["git", "checkout", lock["nuclei_templates_commit"]], cwd=live.TEMPLATES)
    if live.command(["git", "rev-parse", "HEAD"], cwd=live.TEMPLATES) != lock["nuclei_templates_commit"]:
        raise RuntimeError("nuclei templates differ from pinned source")
    if not live.WORDLIST.is_file():
        live.WORDLIST.parent.mkdir(parents=True, exist_ok=True)
        url = ("https://raw.githubusercontent.com/danielmiessler/SecLists/" +
               lock["wordlist_source_commit"] + "/" + lock["wordlist_path"])
        with urllib.request.urlopen(url, timeout=30) as response:
            live.WORDLIST.write_bytes(response.read(1_000_000))
    if hashlib.sha256(live.WORDLIST.read_bytes()).hexdigest() != lock["wordlist_sha256"]:
        raise RuntimeError("scanner wordlist differs from pinned source")


def up() -> dict:
    active = subprocess.run(["docker", "ps", "-q", "--filter",
                             "label=northstar.red-range.active=true"],
                            capture_output=True, text=True, timeout=15)
    if active.returncode or active.stdout.strip():
        raise RuntimeError("stop the active scanner before changing the crAPI range")
    arch = live.command(["docker", "info", "--format", "{{.Architecture}}"])
    if arch not in ("aarch64", "arm64"):
        raise RuntimeError("this pinned scanner build currently supports Docker ARM64 only")
    _network(live.NETWORK, True)
    _network(live.RELAY_NETWORK, False)
    _source()
    lock = _images()
    _scanner(lock)
    _tools()
    _content()
    live.prepare()
    state = live.compose_up()
    state["probe"] = live.probe()
    return state


def _active_containers() -> list[str]:
    result = subprocess.run(["docker", "ps", "-q", "--filter",
                             "label=northstar.red-range.active=true"],
                            capture_output=True, text=True, timeout=15, check=True)
    return result.stdout.splitlines()


def resume() -> dict:
    if not (ROOT / "range" / "build-manifest.json").is_file():
        raise RuntimeError("prepare the disposable crAPI range with setup up first")
    if not _active_containers():
        live.compose_up()
    return {"range": "running", "probe": live.probe()}


def _stop_via_console() -> bool:
    base = "http://127.0.0.1:8787"
    try:
        page = urllib.request.urlopen(base, timeout=5).read().decode()
        match = re.search(r'const TOKEN="([^"]+)"', page)
        if not match:
            return False
        state = json.load(urllib.request.urlopen(base + "/api/red-range", timeout=5))
        if not state["active"]["current_id"]:
            return False
        request = urllib.request.Request(
            base + "/api/red-range/live/stop", data=b"{}", method="POST",
            headers={"Content-Type": "application/json", "Origin": base,
                     "X-Console-Token": match.group(1)})
        urllib.request.urlopen(request, timeout=30).close()
        for _ in range(120):
            state = json.load(urllib.request.urlopen(base + "/api/red-range", timeout=5))
            if not state["active"]["current_id"]:
                return True
            time.sleep(1)
    except (OSError, ValueError, KeyError):
        return False
    return False


def _console_busy() -> bool | None:
    try:
        with urllib.request.urlopen("http://127.0.0.1:8787/api/red-range", timeout=5) as response:
            return bool(json.load(response)["active"]["current_id"])
    except (OSError, ValueError, KeyError):
        return None


def pause() -> dict:
    if _active_containers():
        if not _stop_via_console():
            raise RuntimeError("active scanner did not finish stopping; keep the lab running")
    if _active_containers():
        raise RuntimeError("active scanner still present; keep the lab running")
    for _ in range(120):
        busy = _console_busy()
        if busy is not True:
            break
        time.sleep(1)
    else:
        raise RuntimeError("live range telemetry has not finished; keep the lab running")
    live.compose_down(remove_volumes=False)
    return {"range": "paused", "volumes_removed": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("action", choices=("up", "status", "down", "resume", "pause"))
    args = parser.parse_args()
    if args.action == "up":
        print(json.dumps(up(), sort_keys=True))
    elif args.action == "status":
        print(json.dumps(live.check_runtime(), sort_keys=True))
    elif args.action == "resume":
        print(json.dumps(resume(), sort_keys=True))
    elif args.action == "pause":
        print(json.dumps(pause(), sort_keys=True))
    else:
        if _active_containers():
            raise RuntimeError("stop the active scanner before disposing the crAPI range")
        live.compose_down()
        print(json.dumps({"range": "disposed", "volumes_removed": True}))


if __name__ == "__main__":
    main()
