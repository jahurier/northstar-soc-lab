"""SOC context for Jev states (context v3): lineage, software prevalence, rule history, nearby activity.

Leakage guards:
- Known-good inventory and rule history are built ONLY from development-split goodware
  recordings; evaluate on the holdout split.
- Log-pipeline metadata (shipper tags, ports, receive times, raw Message) is dropped:
  it differs by dataset source and would reveal where an alert came from.
- Recording names, dataset names, and labels never enter the state.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .datasets import DATASETS, RUNS
from .tuning import Tuning

INDEX_CACHE = Path(RUNS) / "context-index-v3.json"
BENIGN_INDEX_CACHE = Path(RUNS) / "context-benign-index-v4.json"
WINDOW = timedelta(minutes=30)
PROCESS_KEYS = ("Proc", "Image", "SrcProc")
LINEAGE_FIELDS = {  # curated field -> candidate source keys in Details / ExtraFieldInfo
    "image": ("Proc", "Image", "SrcProc"),
    "command_line": ("Cmdline", "CommandLine", "ScriptBlock"),
    "parent_command_line": ("ParentCmdline", "ParentCommandLine"),
    "parent_image": ("ParentImage", "ParentProc"),
    "integrity_level": ("IntegrityLevel",),
    "current_directory": ("CurrentDirectory",),
    "target_process": ("TgtProc",),
    "target_user": ("TgtUser",),
    "file_path": ("Path", "TgtFile"),
    "service": ("Svc",),
}
KEEP_DETAIL_KEYS = {"Proc", "Image", "Cmdline", "ParentCmdline", "User", "SrcProc", "TgtProc", "TgtUser", "SrcUser",
                    "Path", "TgtFile", "Svc", "ScriptBlock", "Access", "SrcIP", "TgtIP", "TgtPort", "Rule",
                    "EventType", "Hashes", "Company", "Description", "Product"}


def _norm_image(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip().lower()


def _image(detection: dict[str, Any]) -> str | None:
    details = detection.get("Details") or {}
    for key in PROCESS_KEYS:
        image = _norm_image(details.get(key))
        if image:
            return image
    return None


def _baseline_host(recording: str) -> str:
    return recording.split("/")[0] if "/" in recording else recording


def build_index() -> dict[str, Any]:
    """Known-good inventory and rule history from development-split goodware only."""
    from .hayabusa_to_jev import split_for  # local import avoids a cycle
    base = DATASETS["baseline"]
    root = base.path.rstrip("/") + "/"
    images: dict[str, set[str]] = defaultdict(set)
    rules: dict[str, dict[str, Any]] = defaultdict(lambda: {"fires": 0, "hosts": set()})
    hosts: set[str] = set()
    tuning = Tuning()
    if os.path.exists(base.detections):
        with open(base.detections) as handle:
            for line in handle:
                d = tuning.adjust(json.loads(line))
                if d is None:
                    continue
                recording = d["EvtxFile"].removeprefix(root)
                if split_for(f"baseline/{recording}") != "development":
                    continue
                host = _baseline_host(recording)
                hosts.add(host)
                image = _image(d)
                if image:
                    images[image].add(host)
                if d["Level"] in ("med", "high", "crit"):
                    rules[d["RuleID"]]["fires"] += 1
                    rules[d["RuleID"]]["hosts"].add(host)
    index = {
        "known_good_hosts": len(hosts),
        "images": {k: len(v) for k, v in images.items()},
        "rules": {k: {"fires": v["fires"], "hosts": len(v["hosts"])} for k, v in rules.items()},
    }
    INDEX_CACHE.write_text(json.dumps(index))
    return index


def load_index() -> dict[str, Any]:
    try:
        return json.loads(INDEX_CACHE.read_text())
    except (OSError, ValueError):
        return build_index()


def build_benign_index() -> dict[str, Any]:
    """Publisher/product claim prevalence from development goodware only."""
    from .hayabusa_to_jev import split_for
    base = DATASETS["baseline"]
    root = base.path.rstrip("/") + "/"
    publishers: dict[str, set[str]] = defaultdict(set)
    products: dict[str, set[str]] = defaultdict(set)
    tuning = Tuning()
    with open(base.detections) as handle:
        for line in handle:
            detection = tuning.adjust(json.loads(line))
            if detection is None:
                continue
            recording = detection["EvtxFile"].removeprefix(root)
            if split_for(f"baseline/{recording}") != "development":
                continue
            host = _baseline_host(recording)
            details = detection.get("Details") or {}
            company = details.get("Company")
            product = details.get("Product")
            if isinstance(company, str) and company.strip():
                publishers[company.strip().lower()].add(host)
            if isinstance(product, str) and product.strip():
                products[product.strip().lower()].add(host)
    index = {"publisher_hosts": {key: len(value) for key, value in publishers.items()},
             "product_hosts": {key: len(value) for key, value in products.items()}}
    BENIGN_INDEX_CACHE.write_text(json.dumps(index))
    return index


def load_benign_index() -> dict[str, Any]:
    try:
        return json.loads(BENIGN_INDEX_CACHE.read_text())
    except (OSError, ValueError):
        return build_benign_index()


INSTALLER_NAMES = ("msiexec.exe", "winget.exe", "setup.exe", "installer.exe")


def benign_evidence_v4(detection: dict[str, Any], benign_index: dict[str, Any], clean) -> dict[str, Any]:
    """Describe observed benign cues without claiming an unobserved authorization."""
    details = detection.get("Details") or {}
    extra = detection.get("ExtraFieldInfo") or {}
    company = _pick([details, extra], ("Company",))
    product = _pick([details, extra], ("Product",))
    parent = _pick([details, extra], ("ParentImage", "ParentProc"))
    parent_cmd = _pick([details, extra], ("ParentCmdline", "ParentCommandLine"))
    installer_like = bool(parent and any(name in parent.lower() for name in INSTALLER_NAMES))
    return clean({
        "publisher": {"claim": company, "claim_source": "event_metadata" if company else "not_observed",
                      "signature_verification": "not_observed",
                      "seen_on_development_goodware_hosts": benign_index["publisher_hosts"].get(company.lower(), 0)
                      if company else None},
        "product": {"claim": product,
                    "seen_on_development_goodware_hosts": benign_index["product_hosts"].get(product.lower(), 0)
                    if product else None},
        "installer_lineage": {"parent_image": parent, "parent_command_line": parent_cmd,
                              "installer_like_parent": installer_like,
                              "authorization": "unknown"},
        "change_ticket": {"status": "not_available_in_recorded_telemetry"},
    })


def _pick(sources: list[dict[str, Any]], keys: tuple[str, ...]) -> str | None:
    for source in sources:
        for key in keys:
            value = source.get(key)
            if isinstance(value, (str, int)) and str(value).strip():
                return str(value)[:600]
    return None


def _ts(value: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def context_v3(detection: dict[str, Any], hits: list[dict[str, Any]], index: dict[str, Any],
               clean) -> dict[str, Any]:
    """Build the v3 alert/enrichment blocks for one detection. `clean` truncates/sanitizes."""
    details = detection.get("Details") or {}
    extra = detection.get("ExtraFieldInfo") or {}
    sources = [details, extra]
    lineage = {name: _pick(sources, keys) for name, keys in LINEAGE_FIELDS.items()}
    lineage = {k: v for k, v in lineage.items() if v}

    image = _image(detection)
    known = index["known_good_hosts"] or 1
    seen = index["images"].get(image, 0) if image else None
    history = index["rules"].get(detection["RuleID"], {"fires": 0, "hosts": 0})

    when = _ts(detection.get("Timestamp"))
    nearby = []
    if when:
        for other in hits:
            if other is detection or other.get("RuleID") == detection.get("RuleID"):
                continue
            t = _ts(other.get("Timestamp"))
            if t and abs(t - when) <= WINDOW:
                nearby.append({"rule": other["RuleTitle"], "level": other["Level"],
                               "minutes_from_alert": round((t - when).total_seconds() / 60, 1)})
    nearby.sort(key=lambda r: abs(r["minutes_from_alert"]))

    alert = {
        "details": clean({k: v for k, v in details.items() if k in KEEP_DETAIL_KEYS}),
        "process": clean(lineage),
    }
    enrichment = {
        "software_inventory": {
            "image": image,
            "seen_on_known_good_hosts": seen,
            "known_good_hosts_total": index["known_good_hosts"],
            "note": "count of known-good reference machines where this binary produced telemetry",
        } if image else {"image": None, "note": "no process image in this event"},
        "rule_history": {
            "fires_on_known_good_hosts": history["fires"],
            "known_good_hosts_affected": history["hosts"],
            "known_good_hosts_total": index["known_good_hosts"],
        },
        "nearby_activity": {
            "window_minutes": int(WINDOW.total_seconds() // 60),
            "other_alerts_same_host": len(nearby),
            "closest": nearby[:6],
        },
    }
    return {"alert": alert, "enrichment": enrichment}


# ------------------------------------------------------------------ pseudonymization
SYSTEM_ACCOUNTS = {"system", "local service", "network service", "nt authority", "nt service",
                   "administrator", "administrators", "users", "everyone", "dwm-1", "umfd-0", "umfd-1", "n/a", "-"}
GENERIC_LABELS = {"local", "lan", "com", "net", "org", "corp", "internal", "localdomain"}


def _alias(kind: str, value: str) -> str:
    return f"{kind}-{hashlib.sha256(value.lower().encode()).hexdigest()[:5]}"


class Pseudonymizer:
    """Replace source-identifying hosts, domains, and user names with stable neutral aliases."""

    def __init__(self, detections) -> None:
        mapping: dict[str, str] = {}
        for d in detections:
            computer = str(d.get("Computer") or "")
            if computer:
                labels = computer.split(".")
                mapping.setdefault(labels[0].lower(), _alias("host", labels[0]))
                for label in labels[1:]:
                    if label.lower() not in GENERIC_LABELS and len(label) > 2:
                        mapping.setdefault(label.lower(), "corp")
            for key in ("User", "TgtUser", "SrcUser"):
                value = (d.get("Details") or {}).get(key)
                if isinstance(value, str) and "\\" in value:
                    domain, user = value.split("\\", 1)
                    if domain.lower() not in SYSTEM_ACCOUNTS and len(domain) > 2:
                        mapping.setdefault(domain.lower(), "CORP")
                    if user.lower() not in SYSTEM_ACCOUNTS and len(user) > 2 and not user.endswith("$"):
                        mapping.setdefault(user.lower(), _alias("user", user))
        self.mapping = mapping
        words = sorted(mapping, key=len, reverse=True)
        self.pattern = re.compile(r"(?<![A-Za-z0-9])(" + "|".join(re.escape(w) for w in words) + r")(?![A-Za-z0-9])",
                                  re.IGNORECASE) if words else None

    def text(self, value: str) -> str:
        if not self.pattern:
            return value
        return self.pattern.sub(lambda m: self.mapping[m.group(0).lower()], value)

    def apply(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, dict):
            return {k: self.apply(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.apply(v) for v in value]
        return value
