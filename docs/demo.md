# Five-minute Northstar workbench walkthrough

1. Run `python -m lab.workbench` and open <http://127.0.0.1:8787>. The synthetic day
   contains 1,312 generated events and 25 detection cases at the pinned seed.
   These counts are simulation output, not detector performance.
2. On **Overview**, point out the provenance cards. Recorded cases, Blue Watch,
   Elastic, and Red Range can be empty on a clean install. The **Saved Jev
   comparison** below them remains available because it contains only an
   aggregate from the separate paired synthetic experiment.
3. Open **Console** and play the visual pipeline. Its browser answers are
   modeled to teach the control flow. They are not the saved API comparison.
4. Open **Jev decision map**. In the clean public install it reports no saved
   state-matched Jev cases. The [architecture diagram](architecture.md) shows
   the intended Choice/Score/Noul fanout; after a separately authorized Jev
   evaluation, the map can replay saved typed answers and verify the policy
   route without another API call.
5. Return to **Overview** or read [measured results](results.md): on the same
   23 planted cases, correct dispositions were 21/23 from single alerts and
   22/23 from whole chains. Compare p50 and p95 API latency and token totals.
   Explain that three attack cases and no blind production cohort cannot
   establish general accuracy or a model-to-model speedup.

To demonstrate a reusable workflow, restart with `python -m lab.workbench --no-sim
--cases examples/cases.jsonl --results examples/typed-results.jsonl`. Overview
now counts two imported cases. Triage holds unlabeled cases for review; the Jev
decision map replays two **manually authored** typed results under the bundled
shadow policy. Replace the example files with your own normalized alerts and
saved results. [User guide](user-guide.md) defines their format.

The optional full local range adds Elastic and a disposable crAPI target after
the pinned setup. Its status can be shown separately; it is not needed for this
walkthrough and is never launched by `lab.workbench`.
