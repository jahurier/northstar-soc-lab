# Architecture and point of the lab

The design separates **judgment**, **policy**, **work**, and **verification**. Jev
can answer typed questions about a case. Code interprets those answers under a
versioned shadow policy. Agents and tools may collect or summarize evidence in
their own bounded roles. A human gate remains before consequential actions.

```mermaid
flowchart TD
    S[Recorded or synthetic case state] --> J[Jev typed judgments]
    J --> C[Choice: disposition and queue]
    J --> N[Noul: support, context, instruction signals]
    J --> Q[Score: evidence and impact]
    C --> P[Versioned shadow policy]
    N --> P
    Q --> P
    P --> T[Specialist triage queue]
    P --> A[Human approval gate]
    P -. optional .-> B[Local blue-model note]
    T --> V[State hash and policy verification]
    A --> V
    B -. no per-case dispatch in current lab .-> V
    V --> H[Proposed next state; no host response]
```

The **portable demo** runs only the simulator and console. The console's
browser animation is modeled. When separate Jev results are supplied, the
decision map replays saved typed outputs and checks that the current policy
reproduces the saved recommendation. This verifies a decision record, not a
downstream investigation or endpoint response.

The **recorded replay** path consumes external datasets, runs Hayabusa, builds
case state, and stores truth and observations separately. Source-folder labels
are weak: a recording may contain background activity. The analyst queue must
be labeled independently before it can support performance claims.

The **optional range** uses a disposable crAPI target and pinned scanner
components on an isolated Docker network. It is separate from the passive
replay and synthetic simulator. A plan and explicit activation gate bound each
live run; it cannot target arbitrary hosts through this console.

The intended future loop is state → typed decision → bounded route → evidence
work → verification → new state. Today's lab has pieces of that loop, with
human review and non-execution made explicit. It is not a 300-agent swarm.
