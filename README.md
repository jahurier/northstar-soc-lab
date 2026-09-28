# Northstar SOC Lab

Northstar is a local security-operations **concept lab**. It asks a practical
question: can a typed decision layer help a small SOC route alerts, compare
evidence, and propose next steps while deterministic policy and a human retain
control of consequential actions?

The lab combines a synthetic company day, recorded-detection adapters, Jev
triage integration, a shadow policy, an analyst queue, a local blue-model note,
and an optional disposable crAPI range. The console makes provenance and held
actions visible. It is a test environment, not a production SOC or an autonomous
response system.

## Run the portable concept demo

Requires Python 3.9 or newer, Bash, and a local browser. No API account, Docker,
Ollama, downloaded datasets, or credentials are needed for this tier.

```bash
./quickstart.sh
```

Open <http://127.0.0.1:8787>. The script generates a deterministic synthetic
company day, then serves the console on loopback. Press Ctrl+C to stop it. The
**Console** visual uses modeled answers for demonstration. The **Jev decision
map** requires separately saved, state-matched Jev API answers and is empty in
the data-free public snapshot. No paid call starts during quickstart.

## What is in the system

| Layer | Role | Default public-demo state |
| --- | --- | --- |
| Company simulator | Generates routine activity, benign lookalikes, and fixed synthetic scenarios | Available offline |
| Detection/replay adapters | Process recorded telemetry when datasets and Hayabusa are installed | No recorded data included |
| Jev | Returns typed Choice, Score, and Noul judgments for case state | Optional separate integration; no results bundled |
| Shadow policy | Applies conservative thresholds and trusted-source queue fallback | Proposes only; never contains or closes |
| Analyst queue | Holds independent human verdicts | Empty on a fresh install |
| Blue agent/Watch | Local-model proposals and post-run summary | Optional Ollama; no action execution |
| Elastic and crAPI range | Optional local evidence and isolated disposable target | Not started by quickstart |

See [architecture](docs/architecture.md), [deployment requirements](docs/deployment.md),
the [five-minute walkthrough](docs/demo.md), [measured results](docs/results.md), and
[safety and evidence rules](docs/safety-and-evidence.md).

## Saved comparison snapshot

On the **same 23 planted synthetic cases**, a saved Jev run compared one alert
with whole-chain context. These are small, inspected lab results, not a
production accuracy or cross-model benchmark.

| Measure | Single alert | Whole chain |
| --- | ---: | ---: |
| Correct disposition on planted cases | 21/23 | 22/23 |
| Planted malicious classified likely malicious | 1/3 | 2/3 |
| Planted benign classified likely benign | 20/20 | 20/20 |
| Median saved API latency | 304.3 ms | 289.0 ms |
| p95 saved API latency | 733.4 ms | 801.7 ms |

The [full comparison](docs/results.md) defines correctness, shows token use,
and explains the limits of a 23-case synthetic sample. No response was
executed against a host.

## What this demonstrates

The browser can show how one case becomes typed judgments, how policy routes
those judgments, what is held for analyst or approval, and whether the current
policy reproduces a saved decision. The saved-cohort animation shows case
records, not hundreds of executing agents. Northstar does **not** establish
claims about production detection accuracy, autonomous containment, or speed
and cost relative to another agent system.

This snapshot intentionally excludes private Git history, local run evidence,
human and model review files, raw recordings, saved API responses, `.env` files,
and credentials. Runtime queue, label, proposal, and tuning files are ignored by
Git; `adjudications/queue.example.json` shows the empty format. No reuse
license has been selected.
