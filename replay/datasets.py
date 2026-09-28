"""Registry of replayed datasets: where they live, how they are labeled, and provenance.

Every dataset is untrusted content under ~/LabData/quarantine. `label` is the
dataset-level ground truth: attack captures (which still contain background noise)
or goodware baselines. Tactic comes from the dataset's own folder layout and is
kept in metadata only, never in the Jev state.
"""

from __future__ import annotations

import os
import re
import json
from dataclasses import dataclass
from typing import Callable

LAB_DATA = os.environ.get("LAB_DATA", os.path.expanduser("~/LabData"))
QUARANTINE = os.path.join(LAB_DATA, "quarantine")
RUNS = os.path.join(LAB_DATA, "runs")
HAYABUSA_VERSION = "4.1.0"
ACTIVE_ROOT = os.path.join(RUNS, "active-detections")
ACTIVE_CURRENT = os.path.join(ACTIVE_ROOT, "current.json")


def active_generation() -> dict | None:
    if not os.path.exists(ACTIVE_CURRENT):
        return None
    with open(ACTIVE_CURRENT) as handle:
        manifest = json.load(handle)
    if not re.fullmatch(r"gen-[A-Za-z0-9_-]+", str(manifest.get("generation", ""))):
        raise ValueError("invalid active detections generation")
    return manifest


def _first_folder(recording: str) -> str:
    return recording.split("/")[0] if "/" in recording else "uncategorized"


def _mitre_folder(recording: str) -> str:
    folder = _first_folder(recording)
    if folder == "EVTX_full_APT_attack_steps":
        return "multi_stage"
    return re.sub(r"^TA\d{4}-", "", folder)


def _otrf(recording: str) -> str:
    parts = recording.split("/")
    if parts[0] == "atomic" and len(parts) > 2:
        return parts[2]
    if parts[0] == "compound" and len(parts) > 1:
        return f"campaign_{parts[1]}"
    return "uncategorized"


def _baseline(recording: str) -> str:
    return f"benign_{_first_folder(recording)}"


@dataclass(frozen=True)
class Dataset:
    name: str
    root: str
    source: str
    commit: str
    license: str
    label: str  # "attack" or "benign"
    tactic: Callable[[str], str]
    json_input: bool = False

    @property
    def detections(self) -> str:
        manifest = active_generation()
        if manifest:
            return os.path.join(ACTIVE_ROOT, manifest["generation"],
                                f"{self.name}-hayabusa-{HAYABUSA_VERSION}.jsonl")
        return os.path.join(RUNS, f"{self.name}-hayabusa-{HAYABUSA_VERSION}.jsonl")

    @property
    def path(self) -> str:
        return os.path.join(QUARANTINE, self.root)

    def tactic_label(self, recording: str) -> str:
        return self.tactic(recording).lower().replace(" ", "_").replace("-", "_")


DATASETS = {
    d.name: d
    for d in (
        Dataset("evtx-attack", "EVTX-ATTACK-SAMPLES", "github.com/sbousseaden/EVTX-ATTACK-SAMPLES",
                "4ceed2f", "GPL-3.0", "attack", _first_folder),
        Dataset("e2m", "EVTX-to-MITRE-Attack", "github.com/mdecrevoisier/EVTX-to-MITRE-Attack",
                "4748560", "CC0-1.0", "attack", _mitre_folder),
        Dataset("yamato", "hayabusa-sample-evtx/YamatoSecurity",
                "github.com/Yamato-Security/hayabusa-sample-evtx", "0845333", "unspecified",
                "attack", _first_folder),
        Dataset("deepblue", "hayabusa-sample-evtx/DeepBlueCLI",
                "github.com/Yamato-Security/hayabusa-sample-evtx", "0845333", "unspecified",
                "attack", lambda recording: "deepblue"),
        Dataset("otrf", "otrf-json", "github.com/OTRF/Security-Datasets", "d9d40ef", "MIT",
                "attack", _otrf, json_input=True),
        Dataset("baseline", "evtx-baseline", "github.com/NextronSystems/evtx-baseline v0.8.5",
                "v0.8.5", "Apache-2.0", "benign", _baseline),
    )
}
