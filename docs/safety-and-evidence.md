# Safety and evidence

Northstar keeps evidence classes separate:

| Source | Meaning |
| --- | --- |
| Synthetic truth | Planted by the company-day generator; useful for local checks |
| Recorded folder label | Weak dataset metadata, not an analyst verdict |
| Saved Jev answer | Typed model output tied to case hash and question version |
| Provisional model review | A separate model opinion, never a human label |
| Human adjudication | Explicit analyst verdict in its own append-only ledger |
| Shadow-policy route | A recommendation and queue, not an executed action |

The public package starts with an empty analyst queue and ledger. An empty
queue example is provided; runtime adjudication files are ignored by Git.
Imported cases are unlabeled, and the manually authored typed-result example
is not model performance evidence. The package omits local review artifacts
and raw recordings. Do not infer accuracy or production readiness from browser
demo answers, planted cases, or a small inspected cohort.

The simulator and passive replay do not run commands against hosts. The optional
crAPI range uses a disposable target, pinned tools, a bounded runtime, and an
isolated Docker network. Its live activation is a separate deliberate action.
Blue output is a proposal; it cannot contain a host or modify an account.

Jev API use is optional and paid. Do not run a paid cohort as part of installation
or CI. Keep API credentials in local secret storage, outside this repository;
never put them in examples, screenshots, logs, issues, or commits.

Public release review checks the fresh export, not the development Git tree.
The export deliberately has no prior commit authors or remotes. Northstar's
own source is Apache-2.0; optional datasets, models, images, templates, and
scanner components retain their upstream licenses.
