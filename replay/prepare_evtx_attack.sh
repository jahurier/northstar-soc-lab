#!/bin/sh
# Reproduce the Phase 1 EVTX-ATTACK-SAMPLES slice: fetch pinned data and tool,
# run Sigma via Hayabusa, and build the Jev corpus. Dataset content is untrusted:
# it stays in ~/LabData/quarantine and is never executed or committed.
set -eu
LAB="${LAB_DATA:-$HOME/LabData}"
EVTX_COMMIT=4ceed2f4706daf601c212a8f91c113dd85349a2c
HB_VERSION=4.1.0
HB_SHA256=08a65fc7f65225fbcd3daa2cc82b59f0a099ab862d7a2252fca3e2f02077255e
REPO="$(cd "$(dirname "$0")/.." && pwd)"

mkdir -p "$LAB/quarantine" "$LAB/tools" "$LAB/runs"
touch "$LAB/.metadata_never_index"

if [ ! -d "$LAB/quarantine/EVTX-ATTACK-SAMPLES" ]; then
  git clone -q https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git "$LAB/quarantine/EVTX-ATTACK-SAMPLES"
fi
git -C "$LAB/quarantine/EVTX-ATTACK-SAMPLES" fetch -q --depth 1 origin "$EVTX_COMMIT" 2>/dev/null || true
git -C "$LAB/quarantine/EVTX-ATTACK-SAMPLES" checkout -q "$EVTX_COMMIT"

HB_DIR="$LAB/tools/hayabusa-$HB_VERSION"
if [ ! -x "$HB_DIR/hayabusa-$HB_VERSION-mac-aarch64" ]; then
  curl -sSL -o "$LAB/tools/hayabusa.zip" \
    "https://github.com/Yamato-Security/hayabusa/releases/download/v$HB_VERSION/hayabusa-$HB_VERSION-mac-aarch64.zip"
  echo "$HB_SHA256  $LAB/tools/hayabusa.zip" | shasum -a 256 -c -
  unzip -q -o "$LAB/tools/hayabusa.zip" -d "$HB_DIR"
  chmod +x "$HB_DIR/hayabusa-$HB_VERSION-mac-aarch64"
fi

DETECTIONS="$LAB/runs/evtx-attack-hayabusa-$HB_VERSION.jsonl"
(cd "$HB_DIR" && "./hayabusa-$HB_VERSION-mac-aarch64" dfir-timeline \
  -d "$LAB/quarantine/EVTX-ATTACK-SAMPLES" -w -q -K -N -C -O -U -t jsonl \
  -p super-verbose -o "$DETECTIONS")

cd "$REPO"
python3 -m replay.hayabusa_to_jev "$DETECTIONS" "$LAB/quarantine/EVTX-ATTACK-SAMPLES" \
  "${JEV_CORPUS:-$HOME/Projects/jev-test/data/evtx-attack-alerts.jsonl}"
