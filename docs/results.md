# Saved Jev comparison: single alert and whole chain

This is a **paired 23-case synthetic experiment**. The same planted cases were
sent to jev-1.13.0 with security-triage-v2; one arm presented a
single alert and the other presented its chain context. The numbers below were
computed from saved response files. No new API call or tuning was made for this
public summary.

| Measure | Single alert | Whole chain |
| --- | ---: | ---: |
| Correct disposition, all cases | 21/23 (91.3%) | 22/23 (95.7%) |
| Planted malicious classified likely malicious | 1/3 (33.3%) | 2/3 (66.7%) |
| Planted benign classified likely benign | 20/20 (100.0%) | 20/20 (100.0%) |
| Median saved API latency | 304.3 ms | 289.0 ms |
| p95 saved API latency, nearest rank | 733.4 ms | 801.7 ms |
| Input tokens, all 23 requests | 37,256 | 44,395 |
| Output tokens, all 23 requests | 5,194 | 5,196 |

**How it worked:** the single-alert arm left two of three planted malicious
cases at `needs_context`; chain context moved one of those to
`likely_malicious`. Both arms classified all 20 planted benign cases as
`likely_benign`. The shadow policy recommended **no automatic containment**
in either arm; no host action executed. See [architecture](architecture.md) for
the route from typed answers to the human gate.

**How to read speed:** latency is observed per-request API elapsed time in the
saved files, not end-to-end SOC time or agent throughput. The whole-chain arm
had a slightly lower median and a higher p95 on this small sample. Its extra
context also used more input tokens. These figures do not establish a speed
advantage over another model or agent system.

**How to read accuracy:** the denominator is planted synthetic truth, not a
blind real-world analyst set. A `needs_context` answer counts as not correctly
classified in this table; it may still be a conservative triage response. With
only three planted malicious cases, the attack fraction is highly unstable.
Recorded dataset folder labels are weaker and are not used in this table.

The machine-readable [aggregate](metrics.json) contains no case IDs, state,
human labels, raw responses, credentials, or per-case timings. The source files
remain private in the separate Jev evaluation workspace. The widely shared
193×/444× figures are **not Northstar measurements** and are not claimed here.
