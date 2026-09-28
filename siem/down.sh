#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
docker compose --env-file siem/.env -f siem/compose.yaml down
