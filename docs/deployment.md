# Deployment requirements

## Tier 1: portable offline demo

- Python 3.9 or newer and Bash on a local workstation.
- A browser able to reach `127.0.0.1:8787`.
- Run `./quickstart.sh` for synthetic data, or `./quickstart.sh --no-sim
  --cases /path/to/alerts.jsonl` for your own normalized alerts. Runtime
  data stays in ignored `runs/`.
- No network service, account, model, or paid API call is required.

The console binds to loopback. It has a per-start token on mutating endpoints,
checks the Host header, and exposes only a fixed job allowlist. It is intended
for one operator on a trusted workstation, not public web hosting.

## Tier 2: local model and recorded replay

- Ollama with the configured `qwen3:14b` model for optional local blue and
  detection-agent notes. Set `NORTHSTAR_MODEL` only if using another tested
  local model. The model endpoint must remain loopback.
- Public recorded datasets and Hayabusa 4.1.0 for replay coverage. Place
  downloads under `LAB_DATA/quarantine` and keep generated detections under
  `LAB_DATA/runs`. This repository does not redistribute those datasets or
  Hayabusa binaries; check each upstream license before reuse.
- No separate checkout is needed to replay typed results through the bundled
  policy. If you choose to produce new Jev API answers, use your own authorized
  runner; the portable workbench does not bundle one. Supply its saved JSONL
  via `--results`. The question version and case-state hash must match.
  Cost and approve any paid evaluation before running it.

## Tier 3: full local macOS range

- macOS on Apple Silicon, Docker Desktop, Homebrew, Ollama, and Go for the
  current pinned crAPI scanner build. The range setup currently checks for an
  ARM64 Docker engine.
- Enough free storage and memory for Docker images, Elasticsearch, Kibana, the
  local model, and the disposable crAPI target. Size this on the actual host.
- Run `python3 -m red_range.setup up` once to prepare pinned components, then
  use `./northstar.sh up` and `./northstar.sh down`. The shell launcher is
  macOS-specific. `./northstar.sh up --no-siem` omits Elastic.
- Keep `siem/.env` private. `siem/env.example` documents variables without
  supplying a credential. Do not commit runtime configuration or run output.

The range's tool, content, and image locks are versioned source files. Setup
downloads their pinned upstream components; the source snapshot is not a
self-contained offline Docker image bundle. Red Range only targets the
disposable crAPI environment through its reviewed scope.

## Production gap

This package has no enrolled production telemetry source, always-on hardened
deployment, multi-user identity boundary, response integration, blind
validation cohort, or production operating procedure. Treat the Raspberry Pi
and VM ideas as future deployment work until those controls and resource tests
exist. Do not expose the console to a public interface.
