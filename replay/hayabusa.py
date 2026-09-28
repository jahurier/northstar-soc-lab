"""Hayabusa command lines for replaying a registered dataset (shared by scripts and the console)."""

from __future__ import annotations

import os

from .datasets import ACTIVE_ROOT, LAB_DATA, Dataset, active_generation

HAYABUSA_DIR = os.path.join(LAB_DATA, "tools", "hayabusa-4.1.0")
HAYABUSA_BIN = os.path.join(HAYABUSA_DIR, "hayabusa-4.1.0-mac-aarch64")
# Minimum level `low` keeps output bounded: info-level output for OTRF alone exceeded 1 GB.
FLAGS = ["-w", "-q", "-K", "-N", "-C", "-O", "-U", "-Q", "-t", "jsonl", "-p", "super-verbose", "-m", "low"]


def command(dataset: Dataset) -> list[str]:
    args = [HAYABUSA_BIN, "dfir-timeline", "-d", dataset.path]
    if dataset.json_input:
        args.append("-J")
    manifest = active_generation()
    if manifest:
        bundle = os.path.join(ACTIVE_ROOT, manifest["generation"], "rules")
        if not os.path.isdir(bundle):
            raise RuntimeError("active candidate rule bundle is missing; rebuild before replay")
        args.extend(["-r", bundle, "-c", os.path.join(bundle, "config")])
    return args + FLAGS + ["-o", dataset.detections]
