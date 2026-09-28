#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
python3 -m siem.setup init
docker compose --env-file siem/.env -f siem/compose.yaml up -d elasticsearch
python3 -m siem.setup configure-kibana
docker compose --env-file siem/.env -f siem/compose.yaml up -d kibana
python3 -m siem.ingest --input runs/world-events.jsonl
python3 -m siem.ingest --input runs/red-replay/campaign-events.jsonl
python3 -m siem.kibana
echo "Elastic local lab ready: http://127.0.0.1:5601 (login password is in siem/.env)"
