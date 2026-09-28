"""Read-only Raspberry Pi readiness inventory; prints no identity or credentials.

Run on a Pi with Python 3: python3 pi_audit.py
This gathers facts only. It never changes SSH, firewall, packages, or services.
"""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any


def _command(*args: str) -> str | None:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=5, check=False)
        return result.stdout.strip() if result.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def _os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return {}
    values = {}
    for line in lines:
        name, sep, value = line.partition("=")
        if sep and name in ("ID", "VERSION_ID", "VERSION_CODENAME"):
            values[name.lower()] = value.strip().strip('"')
    return values


def _memory_gib(path: Path = Path("/proc/meminfo")) -> float | None:
    try:
        for line in path.read_text().splitlines():
            if line.startswith("MemTotal:"):
                return round(int(line.split()[1]) / 1024 / 1024, 2)
    except (OSError, ValueError, IndexError):
        pass
    return None


def collect() -> dict[str, Any]:
    disk = shutil.disk_usage("/")
    source = _command("findmnt", "-n", "-o", "SOURCE", "/")
    if source and source.startswith("/dev/mmcblk"):
        root_medium = "mmc_or_sd"
    elif source and source.startswith("/dev/nvme"):
        root_medium = "nvme"
    elif source and source.startswith("/dev/sd"):
        root_medium = "usb_or_sata_block_device"
    else:
        root_medium = "unknown"
    ssh_effective = _command("sshd", "-T")
    ssh = {}
    if ssh_effective:
        for line in ssh_effective.splitlines():
            name, _, value = line.partition(" ")
            if name in ("passwordauthentication", "pubkeyauthentication", "permitrootlogin"):
                ssh[name] = value
    return {"os": _os_release(), "architecture": platform.machine(),
            "memory_gib": _memory_gib(),
            "root_disk_gib": round(disk.total / 1024**3, 1),
            "root_free_gib": round(disk.free / 1024**3, 1),
            "root_medium": root_medium,
            "ssh_active": _command("systemctl", "is-active", "ssh"),
            "ssh_effective": ssh or "unavailable",
            "time_sync": _command("timedatectl", "show", "-p", "NTPSynchronized", "--value"),
            "automatic_updates_active": _command("systemctl", "is-active", "unattended-upgrades"),
            "firewall_service_active": _command("systemctl", "is-active", "ufw"),
            "audit_only": True, "hardening_verified": False}


if __name__ == "__main__":
    print(json.dumps(collect(), indent=2, sort_keys=True))
