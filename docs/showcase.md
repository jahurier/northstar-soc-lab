# What the showcase actually shows

The Overview separates recorded, imported, and synthetic case counts. Its
comparison panel is a **reference** from one saved 23-case synthetic Jev
experiment. Those numbers do not update when you import your own alerts and
are not a benchmark of your environment.

The [Jev decision map screenshot](images/jev-decision-map.png) replays one of
the maintainer's saved, state-matched Jev API results over recorded replay
cases. The [short animation](images/jev-decision-map.gif) shows the selected
case moving across the cohort. The map lays out Choice,
Score, and Noul outputs; a pinned shadow policy applies deterministic gates;
the result converges on a queue or human approval. The saved policy is checked
against the bundled policy version. This 40-case replay is separate from the
23-case synthetic comparison. It is a **decision-record visualization**,
not a recording of Jev's hidden internals or executing parallel agents.

To see the same interaction without an account, run:

```text
python -m lab.workbench --no-sim --cases examples/cases.jsonl --results examples/typed-results.jsonl
```

The two example results are manually authored and marked `manual-example` in
the interface. One route holds for more context; the other reaches a human
containment-approval gate. Neither performs a host action. Replace these files
with your own case and saved result JSONL to inspect your decisions.

For measured classification, latency, and token counts from the maintainer's
saved Jev experiment, see [results](results.md). For the supported data format,
see the [user guide](user-guide.md).
