#!/usr/bin/env bash
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO"
exec "${PYTHON_BIN:-python3}" -m lab.workbench "$@"
