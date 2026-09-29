"""Conservative, non-executing shadow policy for typed case judgments.

This is the pinned shadow-v4 policy used for the saved Northstar comparison.
It is bundled so public decision replay does not require another checkout.
Thresholds are unchanged; this module does not tune on the published cohort.
"""

from __future__ import annotations

from typing import Any


# Provisional development thresholds. Select production thresholds from a blind
# validation set and the consequences of each action.
DISPOSITION_CONFIDENCE_FLOOR = 0.70
MALICIOUS_SIGNAL_FLOOR = 0.80
ADMIN_PLAUSIBILITY_CEILING = 0.25
# The seed run separated labeled context-deficient cases (0.93-0.94) from all
# other cases (<= 0.68). Keep a conservative provisional gate at 0.80 and retune
# it only on a larger development set; do not infer a production threshold from
# this small synthetic corpus.
ADDITIONAL_CONTEXT_CEILING = 0.80
CORROBORATED_EVIDENCE_SCORE = 1.75
# shadow-v4 (2026-09-23): lowered from 1.75. Jev scores impact conservatively by design
# ("do not rate hypothetical impact"), and impact<1.75 alone blocked many malicious calls.
# Chosen from a pre-declared candidate set on the validation split (max attack escalation
# with <=1/57 benign escalated); lowering MALICIOUS_SIGNAL_FLOOR leaked benign cases and was
# rejected. Single holdout test, v2 context: attack escalation 6.3% -> 10.4%, benign 3 -> 3.
# With context v3: 16.0% -> 25.7%, benign 0 -> 0.
MATERIAL_IMPACT_SCORE = 1.25
# Injected-queue finding: the injection Noul was 0.95-0.97 while the model's
# queue changed. Above this ceiling, event text must not choose routing.
UNTRUSTED_INSTRUCTION_CEILING = 0.50
# Provisional: the 35 injected queue errors had confidence 0.37-0.58, so this
# floor was chosen after seeing them. Revalidate on a paraphrased holdout.
QUEUE_CONFIDENCE_FLOOR = 0.60
POLICY_VERSION = "shadow-v4"

# Collector-populated `alert.source` values with an unambiguous queue. The
# source must come from sensor provenance, never from alert free text.
SOURCE_QUEUES = {"endpoint": "endpoint", "identity": "identity", "cloud": "cloud"}

ALLOWED_RECOMMENDATIONS = {
    "analyst_review",
    "analyst_review_low_priority",
    "route_and_tag",
    "escalate_for_containment_approval",
}


def recommend(
    answers: dict[str, Any] | None, state: dict[str, Any] | None = None
) -> dict[str, str]:
    """Return a non-executing recommendation; never suppress or contain."""
    if not answers:
        return _result("analyst_review", "missing or invalid Jev answers", "threat_hunting")

    try:
        disposition = answers["disposition"]
        queue, queue_basis, injected = _route(answers, state)
        malicious = float(answers["malicious_behavior_supported"]["noul"])
        admin_plausible = float(answers["legitimate_admin_plausible"]["noul"])
        needs_context = float(answers["additional_context_required"]["noul"])
        evidence = float(answers["evidence_strength"]["score"])
        impact = float(answers["potential_impact"]["score"])
    except (KeyError, TypeError, ValueError):
        return _result("analyst_review", "incomplete Jev answers", "threat_hunting")

    if disposition.get("confidence", 0.0) < DISPOSITION_CONFIDENCE_FLOOR:
        return _result(
            "analyst_review", "disposition confidence below pilot floor", queue, queue_basis
        )
    if needs_context > ADDITIONAL_CONTEXT_CEILING:
        return _result("analyst_review", "additional context is required", queue, queue_basis)
    if disposition.get("choice") in {"needs_context", "unsupported"}:
        return _result(
            "analyst_review", f"disposition is {disposition.get('choice')}", queue, queue_basis
        )

    escalate = (
        disposition.get("choice") == "likely_malicious"
        and malicious >= MALICIOUS_SIGNAL_FLOOR
        and admin_plausible <= ADMIN_PLAUSIBILITY_CEILING
        and evidence >= CORROBORATED_EVIDENCE_SCORE
        and impact >= MATERIAL_IMPACT_SCORE
    )
    if injected and not escalate:
        return _result(
            "analyst_review",
            "untrusted instructions present; event text cannot lower priority",
            queue,
            queue_basis,
        )
    if escalate:
        return _result(
            "escalate_for_containment_approval",
            "corroborated malicious activity with material potential impact",
            queue,
            queue_basis,
        )

    if disposition.get("choice") == "likely_benign" and admin_plausible >= 0.75:
        return _result(
            "analyst_review_low_priority",
            "supported benign administrative explanation; pilot never auto-closes",
            queue,
            queue_basis,
        )

    return _result(
        "route_and_tag", "typed disposition passed pilot routing gates", queue, queue_basis
    )


def _route(answers: dict[str, Any], state: dict[str, Any] | None) -> tuple[str, str, bool]:
    """Choose the queue, preferring trusted source over model routing when unsafe."""
    model_queue = answers["review_queue"]["choice"]
    queue_confidence = float(answers["review_queue"].get("confidence", 0.0))
    injection = float(answers["untrusted_instructions_present"]["noul"])
    injected = injection > UNTRUSTED_INSTRUCTION_CEILING
    if not injected and queue_confidence >= QUEUE_CONFIDENCE_FLOOR:
        return model_queue, "model", injected
    source = ((state or {}).get("alert") or {}).get("source")
    if source in SOURCE_QUEUES:
        return SOURCE_QUEUES[source], "alert_source", injected
    if injected:
        return "threat_hunting", "injection_fallback", injected
    return model_queue, "model_low_confidence", injected


def _result(
    recommendation: str, reason: str, queue: str, queue_basis: str = "none"
) -> dict[str, str]:
    if recommendation not in ALLOWED_RECOMMENDATIONS:
        raise ValueError(f"unsafe recommendation: {recommendation}")
    return {
        "recommendation": recommendation,
        "reason": reason,
        "queue": queue,
        "queue_basis": queue_basis,
    }
