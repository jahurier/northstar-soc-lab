"""Validate a credential-free production pilot manifest before any deployment.

This is a static declaration gate. A passing manifest does not prove that TLS,
backups, Fleet, or endpoint collection actually work; those need live checks.

    python3 -m production.pilot check --manifest /private/path/pilot.json
"""

from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

LAB_NETWORK = ipaddress.ip_network("10.77.0.0/16")
FORBIDDEN_KEYS = ("password", "secret", "token", "api_key", "private_key", "credential")


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _host(value: Any) -> bool:
    host = _text(value)
    if not host or any(char.isspace() for char in host) or "/" in host or "@" in host:
        return False
    try:
        address = ipaddress.ip_address(host)
        return not (address.is_loopback or address.is_unspecified or address.is_link_local or
                    address in LAB_NETWORK)
    except ValueError:
        return host.lower() not in ("localhost", "host.docker.internal") and "." in host


def _url(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError:
        return False
    return (parsed.scheme == "https" and _host(parsed.hostname) and port is not None and
            not parsed.username and not parsed.password and not parsed.path.strip("/") and
            not parsed.query and not parsed.fragment)


def _secret_fields(value: Any, prefix: str = "") -> list[str]:
    found = []
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if any(term in str(key).lower() for term in FORBIDDEN_KEYS):
                found.append(path)
            found.extend(_secret_fields(item, path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(_secret_fields(item, f"{prefix}[{index}]"))
    return found


def validate(manifest: Any) -> list[str]:
    if not isinstance(manifest, dict):
        return ["manifest must be a JSON object"]
    errors = []
    forbidden = _secret_fields(manifest)
    if forbidden:
        errors.append("manifest contains credential-shaped fields; use a secret store, not this file")
    if manifest.get("environment") != "production_pilot":
        errors.append("environment must be production_pilot")
    monitor = manifest.get("monitoring")
    source = manifest.get("source")
    ops = manifest.get("operations")
    if not isinstance(monitor, dict) or not isinstance(source, dict) or not isinstance(ops, dict):
        return errors + ["monitoring, source, and operations objects are required"]
    if not _host(monitor.get("host")):
        errors.append("monitoring.host must identify a dedicated non-lab host")
    if monitor.get("dedicated") is not True:
        errors.append("monitoring.dedicated must be true")
    if monitor.get("os") not in ("linux", "windows"):
        errors.append("monitoring.os must be linux or windows")
    for name in ("elastic_url", "kibana_url", "fleet_url"):
        if not _url(monitor.get(name)):
            errors.append(f"monitoring.{name} must be an HTTPS URL with an explicit port")
    if monitor.get("tls_verification") != "required":
        errors.append("monitoring.tls_verification must be required")
    if not _text(monitor.get("off_host_backup_location")):
        errors.append("monitoring.off_host_backup_location is required")
    if not isinstance(monitor.get("retention_days"), int) or isinstance(monitor.get("retention_days"), bool) or not 1 <= monitor["retention_days"] <= 365:
        errors.append("monitoring.retention_days must be 1-365")
    if not _host(source.get("host")):
        errors.append("source.host must identify a non-lab host")
    if _text(source.get("host")).lower() == _text(monitor.get("host")).lower():
        errors.append("monitoring and source hosts must be separate")
    if source.get("os") not in ("linux", "windows", "macos"):
        errors.append("source.os must be linux, windows, or macos")
    if source.get("criticality") != "noncritical":
        errors.append("source.criticality must be noncritical for the first pilot")
    if not _text(source.get("owner")) or not _text(source.get("approval_ref")):
        errors.append("source.owner and source.approval_ref are required")
    if source.get("policy") != "system_logs_metrics_only":
        errors.append("source.policy must be system_logs_metrics_only")
    if source.get("response_actions_enabled") is not False:
        errors.append("source.response_actions_enabled must be false")
    if source.get("red_range_access") is not False:
        errors.append("source.red_range_access must be false")
    if not _text(ops.get("on_call_owner")):
        errors.append("operations.on_call_owner is required")
    if not _text(ops.get("alert_route")):
        errors.append("operations.alert_route is required")
    if ops.get("data_handling_reviewed") is not True:
        errors.append("operations.data_handling_reviewed must be true")
    return errors


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("action", choices=("check",))
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args()
    try:
        manifest = json.loads(args.manifest.read_text())
        errors = validate(manifest)
    except (OSError, ValueError):
        errors = ["manifest could not be read as JSON"]
    print(json.dumps({"static_gate": "pass" if not errors else "blocked", "blockers": errors,
                      "live_deployment_verified": False}, indent=2))
    if errors:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
