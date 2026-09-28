#!/bin/bash
# Northstar SOC lab: one command to start or stop everything.
#
#   ./northstar.sh up       start Ollama, Docker + Elastic, configured Red Range, console; open browser
#   ./northstar.sh down     pause Red Range, stop console, SIEM, and Ollama; quit Docker if idle
#   ./northstar.sh status   show what is running
#
# Options: --no-siem (skip Elastic, saves ~3 GB RAM), --no-open (don't open the browser)
# Everything listens on 127.0.0.1 only. Stopping keeps all data, indexes, and results.

set -u
export PATH="/opt/homebrew/bin:/usr/local/bin:$HOME/opt/anaconda3/bin:$PATH"
REPO="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO"
PORT=8787
RUNDIR="$REPO/runs"
PIDFILE="$RUNDIR/console.pid"
LOG="$RUNDIR/console.log"
RED_RANGE_MANIFEST="${LAB_DATA:-$HOME/LabData}/runs/red-range/range/build-manifest.json"
mkdir -p "$RUNDIR"

WITH_SIEM=1
OPEN=1
for arg in "${@:2}"; do
  case "$arg" in
    --no-siem) WITH_SIEM=0 ;;
    --no-open) OPEN=0 ;;
    *) echo "unknown option: $arg"; exit 2 ;;
  esac
done

t() { perl -e 'alarm shift; exec @ARGV' "$@"; }  # run with a timeout (seconds); macOS has no `timeout`

say()  { printf '\033[1;36m▸\033[0m %s\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }

console_pid() {
  lsof -nP -tiTCP:$PORT -sTCP:LISTEN 2>/dev/null | head -1
}

wait_for() {  # wait_for SECONDS COMMAND...
  local limit=$1; shift
  for _ in $(seq 1 "$limit"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}

ollama_up()    { curl -s --max-time 3 http://127.0.0.1:11434/api/version >/dev/null; }
# Healthy engine = `docker info` answers with a version within 8 s (a wedged engine returns HTTP 500).
docker_up()    { local v; v=$(t 8 docker info --format '{{.ServerVersion}}' 2>/dev/null) && [[ $v =~ ^[0-9] ]]; }
elastic_up()   { t 10 docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^siem-elasticsearch'; }
console_up()   { curl -s --max-time 3 -o /dev/null http://127.0.0.1:$PORT/api/jobs; }

up() {
  say "SOC console"
  if console_up; then ok "already running (pid $(console_pid))"; else
    python3 - "$REPO" "$LOG" "$PORT" "$PIDFILE" <<'PY'
import subprocess
import sys
from pathlib import Path

repo, log, port, pidfile = sys.argv[1:]
with open(log, "ab") as output:
    child = subprocess.Popen([sys.executable, "-m", "console.server", "--port", port],
                             cwd=repo, stdout=output, stderr=subprocess.STDOUT,
                             start_new_session=True)
Path(pidfile).write_text(str(child.pid) + "\n")
PY
    wait_for 90 console_up && ok "started → http://127.0.0.1:$PORT" || { warn "console did not start — see runs/console.log"; exit 1; }
  fi
  [ "$OPEN" = 1 ] && open "http://127.0.0.1:$PORT"

  say "Local model (Ollama)"
  if ollama_up; then ok "already running"; else
    brew services start ollama >/dev/null 2>&1
    wait_for 30 ollama_up && ok "started (127.0.0.1:11434)" || warn "Ollama did not start; agents will report it unreachable"
  fi

  if [ "$WITH_SIEM" = 1 ]; then
    say "Docker"
    if docker_up; then ok "already running"; else
      t 90 docker desktop start >/dev/null 2>&1 || open -a Docker
      echo "  waiting for the Docker engine (up to 2 min)…"
      if wait_for 120 docker_up; then ok "started"
      else
        echo "  engine unhealthy — restarting Docker Desktop once…"
        t 240 docker desktop restart >/dev/null 2>&1
        wait_for 120 docker_up && ok "started after restart" || { warn "Docker did not start; skipping SIEM"; WITH_SIEM=0; }
      fi
    fi
  fi

  if [ "$WITH_SIEM" = 1 ]; then
    say "Elastic SIEM"
    if elastic_up; then ok "already running (Kibana http://127.0.0.1:5601)"; else
      echo "  starting Elasticsearch + Kibana and loading events (1–3 min)…"
      if t 600 sh siem/up.sh >"$RUNDIR/siem-up.log" 2>&1; then ok "started (Kibana http://127.0.0.1:5601)"
      else warn "SIEM start had errors — see runs/siem-up.log"; fi
    fi
  fi

  if [ "$WITH_SIEM" = 1 ] && [ -f "$RED_RANGE_MANIFEST" ]; then
    say "Disposable crAPI Red Range"
    if t 180 python3 -m red_range.setup resume >"$RUNDIR/red-range-resume.log" 2>&1; then
      ok "running on the isolated Docker network"
    else
      warn "could not resume; see runs/red-range-resume.log"
    fi
  fi

  echo
  status
}

down() {
  if docker_up && [ -f "$RED_RANGE_MANIFEST" ]; then
    say "Disposable crAPI Red Range"
    if t 360 python3 -m red_range.setup pause >"$RUNDIR/red-range-pause.log" 2>&1; then
      ok "paused (volumes and run evidence kept)"
    else
      warn "could not safely pause; see runs/red-range-pause.log"
      return 1
    fi
  fi

  say "SOC console"
  pid=$(console_pid)
  if [ -n "$pid" ] && ps -p "$pid" -o command= | grep -q "console.server"; then
    kill "$pid" && ok "stopped"
  else ok "not running"; fi
  rm -f "$PIDFILE"

  say "Elastic SIEM"
  if docker_up && elastic_up; then
    t 120 sh siem/down.sh >/dev/null 2>&1 && ok "stopped (indexes kept)" || warn "could not stop; run: sh siem/down.sh"
  else ok "not running"; fi

  say "Docker"
  if docker_up; then
    if [ -z "$(t 10 docker ps -q 2>/dev/null)" ]; then
      { t 120 docker desktop stop >/dev/null 2>&1 || osascript -e 'quit app "Docker"' >/dev/null 2>&1; } && ok "stopped (no other containers were running)"
    else warn "left running: other containers are active"; fi
  else ok "not running"; fi

  say "Local model (Ollama)"
  if ollama_up; then brew services stop ollama >/dev/null 2>&1 && ok "stopped (frees model memory)"; else ok "not running"; fi
}

status() {
  row() { printf '  %-18s %s\n' "$1" "$2"; }
  echo "Northstar lab status"
  ollama_up  && row "Local model" "running · 127.0.0.1:11434" || row "Local model" "stopped"
  docker_up  && row "Docker" "running" || row "Docker" "stopped"
  elastic_up && row "Elastic SIEM" "running · http://127.0.0.1:5601" || row "Elastic SIEM" "stopped"
  if [ -f "$RED_RANGE_MANIFEST" ]; then
    t 30 python3 -m red_range.setup status >/dev/null 2>&1 && row "crAPI Red Range" "running · isolated" || row "crAPI Red Range" "paused or unhealthy"
  else row "crAPI Red Range" "not configured"; fi
  console_up && row "SOC console" "running · http://127.0.0.1:$PORT" || row "SOC console" "stopped"
  printf '  %-18s %s\n' "Free disk" "$(df -h "$HOME" | awk 'NR==2{print $4}')"
}

case "${1:-status}" in
  up|start) up ;;
  down|stop) down ;;
  status) status ;;
  *) echo "usage: $0 up|down|status [--no-siem] [--no-open]"; exit 2 ;;
esac
