# Use Northstar with your own cases

The portable workbench accepts **normalized alerts**, one JSON object per line.
It does not ingest arbitrary SIEM exports directly; map your source fields into
this small format first. The importer stores a local copy in
`runs/imported-cases.jsonl` and marks every case **unlabeled**. It never reads
an attack/benign answer from input.

## Alert format

```json
{"id":"CASE-001","timestamp":"2026-09-22T10:15:00Z","source":"endpoint","host":"DEMO-WS-01","user":"demo.user","rule_id":"RULE-1","rule_title":"Unexpected child process","severity":"med","details":{"ProcessName":"sample.exe","Outcome":"blocked"}}
```

All nine fields are required, with no extra fields. `id` is unique and uses
letters, digits, dots, underscores, or hyphens. `timestamp` needs a timezone.
`source` is `endpoint`, `identity`, `cloud`, `network`, or `other`; the first
three can supply a trusted queue fallback. `severity` is `low`, `med`, `high`,
or `crit`. `details` is a short object of scalar fields. The importer accepts
at most 5,000 cases and 64 KiB per line. Use local data handling appropriate
to the alerts you import: this is a single-operator workbench, not a shared
tenant boundary.

```text
python -m lab.workbench --no-sim --cases /path/to/alerts.jsonl
```

On Windows, quote a path containing spaces, for example
`--cases "C:\Data\SOC alerts\alerts.jsonl"`.

**Triage** shows each imported case. Without a saved typed answer, Northstar
shows a fixed `needs_context` placeholder and sends it to analyst review. It
does not guess a benign or malicious verdict from the lack of a label. Your
verdicts are saved separately in ignored `adjudications/labels.jsonl`. To
re-import after editing the input, stop the console and run the command again;
the validated import replaces the prior imported set.

## Replay saved typed answers

If you have a separately produced Jev-style result file, use:

```text
python -m lab.workbench --no-sim --cases /path/to/alerts.jsonl --results /path/to/typed-results.jsonl
```

Each result line needs `case_id`, `state_sha256`,
`question_version: "security-triage-v2"`, a `response` containing a model name
and typed `answers`, plus the saved `policy` route. See
[`examples/typed-results.jsonl`](../examples/typed-results.jsonl) for the full
shape. That example is **manually authored**, not a Jev API result. Northstar
only displays an answer when its case ID, question version, and SHA-256 of the
canonical case `state` match. The decision map then recomputes the bundled
`shadow-v4` recommendation and displays whether it matches the saved route.
The case state itself remains in your local `runs/` directory.

The matching hash is calculated as follows:

```python
import hashlib, json
state = case["state"]
state_sha256 = hashlib.sha256(
    json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")
).hexdigest()
```

If the original model run did not save a policy route, the map can still show
its typed answers, but policy reproduction reports a mismatch because there
is no saved route to compare. The portable package does not include a Jev API
runner; supplying `--results` makes no model or paid network call.

## Workbench options

| Option | Effect |
| --- | --- |
| `--no-sim` | Hide the bundled synthetic cases for this session |
| `--cases FILE` | Validate and import your alert JSONL |
| `--results FILE` | Replay state-matched typed result JSONL |
| `--date YYYY-MM-DD` | Change the synthetic workday |
| `--seed N` | Reproduce a different synthetic mix and placement |
| `--no-attacks` | Generate a benign-only synthetic control day |
| `--port N` | Use another loopback port |

The workbench serves on loopback only and writes local runtime files under
ignored paths. Stop it with Ctrl+C. [Deployment options](deployment.md) cover
recorded telemetry, the local model, Elastic, and the isolated crAPI range.
