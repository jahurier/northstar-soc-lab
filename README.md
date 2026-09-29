# Northstar

**An open-source, local SOC decision workbench.** Bring security alerts into one
case queue, review typed AI decisions against a fixed policy, and save an
independent analyst verdict. You can explore it with the included synthetic
company day, or import your own normalized alerts.

Northstar is useful when you need to answer: *What evidence was available? What
did the decision layer return? Which rule routed the case? What did the analyst
decide?* The console keeps those records separate and makes the route visible.
It runs on one operator's machine and does not act on real hosts.

## Inside the local workbench

These screens come from the public checkout with its two supplied, unlabeled
alerts and **manually authored** typed results. No model account, API call, or
host action was involved in the capture.

| Overview: case provenance and a separate reference evaluation | Triage: analyst queue and selected case |
| --- | --- |
| ![Northstar Overview with imported-case counts and saved comparison](docs/images/overview.png) | ![Triage queue with a selected example case and typed judgments](docs/images/triage.png) |

| Console: modeled visual replay | Control checks: choose one validation stage |
| --- | --- |
| ![Modeled alert-to-policy pipeline in the local Console](docs/images/console-pipeline.png) | ![Control checks for simulation, policy, agents, and recorded replay](docs/images/control-checks.png) |

| Agents & tools: current connection status | Decision map: example answer through policy and human gate |
| --- | --- |
| ![Agents and tools showing optional integrations inactive in the clean checkout](docs/images/agents-tools.png) | ![Manually authored example decision reaching policy verification and a human approval gate](docs/images/decision-map-example.png) |

The Console animates **modeled outcomes**; its counter is not a record of host
actions. The Agents view shows optional services as inactive on this clean
install. The example decision map replays saved records marked `manual-example`.

### Saved Jev API replay

![Maintainer's saved Jev decision map with typed outputs](docs/images/jev-decision-map.png)

![Short replay across the maintainer's saved Jev decisions](docs/images/jev-decision-map.gif)

The image and animation above show the maintainer's separate **40-case saved
Jev run**. They show decision records, not hidden model internals or live
parallel agents. [Screenshot and data provenance](docs/showcase.md).

## Run it locally

The core workbench needs **Python 3.12 or newer** and a browser on Windows,
macOS, or Linux. Python 3.14 is the recommended version; get it from
[python.org](https://www.python.org/downloads/) if needed. There is no package
install, Docker, model download, account, or paid call for this path.

```text
git clone https://github.com/jahurier/northstar-soc-lab.git
cd northstar-soc-lab
python -m lab.workbench
```

On macOS or Linux, use `python3 -m lab.workbench` if `python` names another
interpreter. On Windows, `py -3.14 -m lab.workbench` selects Python 3.14 when
installed. Open <http://127.0.0.1:8787>; press Ctrl+C to stop. The optional
`./quickstart.sh` wrapper runs the same command on macOS and Linux.

The default launch generates a deterministic synthetic company day. Change its
mix with `--seed 42`, or generate benign activity only with `--no-attacks`.
For the supplied two-case import and typed-decision replay:

```text
python -m lab.workbench --no-sim --cases examples/cases.jsonl --results examples/typed-results.jsonl
```

Open **Overview** for provenance and measured reference results, **Triage** to
review and label the cases, and **Jev decision map** to inspect the two saved
routes. The included results are marked `manual-example` and are not an
accuracy test. If port 8787 is in use, add `--port 8788`.

## Use your own alerts

1. Map alerts into the [nine-field JSONL format](docs/user-guide.md). Northstar
   rejects truth labels on import and marks new cases **unlabeled**.
2. Run `python -m lab.workbench --no-sim --cases /path/to/alerts.jsonl`.
   Review and label in **Triage**. Human labels stay in ignored local files.
3. If you have a saved typed-result JSONL file, add `--results
   /path/to/results.jsonl`. A result must match the case ID, question version,
   and exact state SHA-256. The map replays it and checks `shadow-v4` policy.

| Capability | Included in the core workbench | Optional extension |
| --- | --- | --- |
| Cases | Synthetic generator and normalized alert import | Recorded telemetry replay |
| Decision layer | Typed result replay and versioned policy check | Your own authorized Jev runner |
| Analyst work | Triage queue and separate human verdict ledger | Local blue-agent notes |
| Range | Passive replay only | Isolated crAPI target and Elastic on supported macOS setup |

The free package does not bundle a Jev API runner or make paid calls. Optional
integrations have separate requirements; the full local range currently targets
**macOS on Apple Silicon**, while the core workbench uses Python and works across
the three desktop operating systems. See [deployment requirements](docs/deployment.md),
[architecture](docs/architecture.md), [walkthrough](docs/demo.md), and
[data and safety rules](docs/safety-and-evidence.md).

## Reference evaluation

On the **same 23 planted synthetic cases**, a saved Jev run classified 21/23
correctly from single alerts and 22/23 with whole-chain context. Median saved
API latency was 304.3 ms and 289.0 ms respectively; p95 was 733.4 ms and
801.7 ms. [Definitions, token counts, and limits](docs/results.md) accompany
the published aggregate. This small, inspected cohort does not measure your
data, production accuracy, end-to-end SOC speed, or a cross-model advantage.

## License and scope

Released under [Apache-2.0](LICENSE). Optional tools, models, Docker images,
and recorded datasets have their own licenses and are not redistributed here.
Northstar is a single-operator local workbench, not a hosted multi-user SOC or
an autonomous containment system.
