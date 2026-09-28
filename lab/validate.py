"""Fail-closed scenario manifest validator for the Northstar lab.

Scope is enforced here in code, not in prompts. Anything unknown is rejected:
undeclared hosts, tools outside the allowlist, addresses outside the lab CIDR,
protected zones, external URLs, secret-like strings, and missing cleanup.

    python3 -m lab.validate scenarios/*.json
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any

INVENTORY_PATH = Path(__file__).with_name("inventory.json")

RISK_CLASSES = ("observe", "simulate", "exercise", "disrupt")
STATUSES = ("draft", "approved", "retired")
MUTATING = {"exercise", "disrupt"}
MAX_WINDOW_MINUTES = 120
SCENARIO_ID = re.compile(r"^LAB-[A-Z]+-\d{3}$")
SEMVER = re.compile(r"^\d+\.\d+\.\d+$")
URL = re.compile(r"\b[a-z][a-z0-9+.-]*://([^/\s:]+)", re.IGNORECASE)
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
SECRET_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*\S+"),
)
REQUIRED = {
    "scenario_id": str,
    "version": str,
    "owner": str,
    "risk_class": str,
    "status": str,
    "attack_mapping": list,
    "hypothesis": str,
    "scope": dict,
    "benign_control": dict,
    "steps": list,
    "expected_evidence": list,
    "expected_triage": dict,
    "cleanup": list,
}
SCOPE_REQUIRED = {
    "source_identities": list,
    "source_hosts": list,
    "target_hosts": list,
    "target_ports": list,
    "allowed_tools": list,
    "time_window_minutes": int,
}


def load_inventory(path: Path = INVENTORY_PATH) -> dict[str, Any]:
    with open(path) as handle:
        return json.load(handle)


def manifest_hash(manifest: dict[str, Any]) -> str:
    """Hash of canonical JSON; approvals bind to this value."""
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def validate(manifest: Any, inventory: dict[str, Any] | None = None) -> list[str]:
    """Return every violation; an empty list means the manifest is in scope."""
    inventory = inventory or load_inventory()
    if not isinstance(manifest, dict):
        return ["manifest must be a JSON object"]
    errors = _check_types(manifest, REQUIRED, "")
    if errors:
        return errors

    if not SCENARIO_ID.match(manifest["scenario_id"]):
        errors.append("scenario_id must look like LAB-DOMAIN-001")
    if not SEMVER.match(manifest["version"]):
        errors.append("version must be semantic (1.0.0)")
    if manifest["status"] not in STATUSES:
        errors.append(f"status must be one of {STATUSES}")
    risk = manifest["risk_class"]
    if risk not in RISK_CLASSES:
        errors.append(f"risk_class must be one of {RISK_CLASSES}; prohibited actions have no class")
        return errors

    errors += _check_scope(manifest["scope"], risk, inventory)
    errors += _check_control_and_steps(manifest)
    if risk in MUTATING and not manifest["cleanup"]:
        errors.append(f"{risk} scenarios require at least one cleanup step")
    if risk == "disrupt" and not manifest.get("approval", {}).get("per_action"):
        errors.append("disrupt scenarios require approval.per_action = true")
    errors += _check_strings(manifest, inventory)
    return errors


def _check_types(obj: dict[str, Any], required: dict[str, type], prefix: str) -> list[str]:
    errors = []
    for key, kind in required.items():
        if key not in obj:
            errors.append(f"missing {prefix}{key}")
        elif not isinstance(obj[key], kind) or (kind is int and isinstance(obj[key], bool)):
            errors.append(f"{prefix}{key} must be {kind.__name__}")
    return errors


def _check_scope(scope: dict[str, Any], risk: str, inventory: dict[str, Any]) -> list[str]:
    errors = _check_types(scope, SCOPE_REQUIRED, "scope.")
    if errors:
        return errors
    hosts = inventory["hosts"]
    for field in ("source_hosts", "target_hosts"):
        for host in scope[field]:
            if _host_name(host, inventory) not in hosts:
                errors.append(f"scope.{field}: {host!r} is not a declared lab host")
    for host in scope["target_hosts"]:
        record = hosts.get(_host_name(host, inventory))
        if record and record["zone"] in inventory["protected_target_zones"]:
            errors.append(f"scope.target_hosts: {host!r} is in protected zone {record['zone']}")
    if risk in MUTATING and not scope["target_hosts"]:
        errors.append(f"{risk} scenarios must declare exact target hosts")
    for port in scope["target_ports"]:
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            errors.append(f"scope.target_ports: {port!r} is not a valid port")
    for tool in scope["allowed_tools"]:
        allowed_classes = inventory["tools"].get(tool)
        if allowed_classes is None:
            errors.append(f"scope.allowed_tools: {tool!r} is not in the tool allowlist")
        elif risk not in allowed_classes:
            errors.append(f"scope.allowed_tools: {tool!r} is not allowed for {risk}")
    window = scope["time_window_minutes"]
    if not 1 <= window <= MAX_WINDOW_MINUTES:
        errors.append(f"scope.time_window_minutes must be 1-{MAX_WINDOW_MINUTES}")
    return errors


def _check_control_and_steps(manifest: dict[str, Any]) -> list[str]:
    errors = []
    control = manifest["benign_control"]
    for key in ("description", "differs_by"):
        if not isinstance(control.get(key), str) or not control[key].strip():
            errors.append(f"benign_control.{key} is required")
    if not manifest["steps"]:
        errors.append("steps must not be empty")
    for index, step in enumerate(manifest["steps"], 1):
        for key in ("action", "expected", "stop_condition"):
            if not isinstance(step, dict) or not str(step.get(key, "")).strip():
                errors.append(f"steps[{index}].{key} is required")
    if not manifest["expected_evidence"]:
        errors.append("expected_evidence must not be empty")
    for index, evidence in enumerate(manifest["expected_evidence"], 1):
        if not isinstance(evidence, dict) or evidence.get("correlation_key") != "run_id":
            errors.append(f"expected_evidence[{index}] must correlate on run_id")
    if "detection" not in manifest["expected_triage"]:
        errors.append("expected_triage.detection pass condition is required")
    return errors


def _check_strings(manifest: dict[str, Any], inventory: dict[str, Any]) -> list[str]:
    errors = []
    lab = ipaddress.ip_network(inventory["lab_cidr"])
    suffix = "." + inventory["dns_suffix"]
    for path, text in _strings(manifest):
        for host in URL.findall(text):
            if not (host.lower().endswith(suffix) or _host_name(host, inventory) in inventory["hosts"]):
                errors.append(f"{path}: URL host {host!r} is outside {inventory['dns_suffix']}")
        for literal in IPV4.findall(text):
            try:
                network = ipaddress.ip_network(literal, strict=False)
            except ValueError:
                errors.append(f"{path}: invalid address {literal!r}")
                continue
            if not network.subnet_of(lab):
                errors.append(f"{path}: address {literal!r} is outside {lab}")
        if any(pattern.search(text) for pattern in SECRET_PATTERNS):
            errors.append(f"{path}: looks like a credential; use synthetic references only")
    return errors


def _strings(value: Any, path: str = "$"):
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _strings(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _strings(item, f"{path}[{index}]")


def _host_name(host: str, inventory: dict[str, Any]) -> str:
    suffix = "." + inventory["dns_suffix"]
    return host[: -len(suffix)] if host.endswith(suffix) else host


def main(paths: list[str]) -> int:
    if not paths:
        print(__doc__)
        return 2
    inventory = load_inventory()
    failed = 0
    for path in paths:
        try:
            with open(path) as handle:
                manifest = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"REJECT {path}: {exc}")
            failed += 1
            continue
        errors = validate(manifest, inventory)
        if errors:
            failed += 1
            print(f"REJECT {path}")
            for error in errors:
                print(f"  - {error}")
        else:
            print(f"OK     {path}  sha256={manifest_hash(manifest)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
