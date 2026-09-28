"""Local-model blue agent: group alerts, draft notes, and queue gated proposals.

The model never executes an action. Review records mark a proposal accepted or
rejected for the mock workflow; no endpoint, identity, or network API is called.

    python3 -m agents.blue propose --input runs/world-chain-cases.jsonl --limit 5
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from . import llm

REPO = Path(__file__).resolve().parents[1]
PROPOSALS = REPO / "runs" / "blue-proposals.jsonl"
REVIEWS = REPO / "runs" / "blue-reviews.jsonl"
QUESTION_VERSION = "security-triage-v2"
PROMPT = Path(__file__).with_name("prompts") / "blue.md"
ACTIONS = {"investigate", "request_context", "isolate_host", "disable_account"}
DISRUPTIVE = {"isolate_host", "disable_account"}
SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "evidence": {"type": "array", "items": {"type": "string"}},
        "uncertainties": {"type": "array", "items": {"type": "string"}},
        "action": {"type": "string", "enum": sorted(ACTIONS)},
        "target": {"type": "string"},
        "rationale": {"type": "string"},
    },
    "required": ["summary", "evidence", "uncertainties", "action", "target", "rationale"],
}


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _timestamp(case: dict[str, Any]) -> datetime:
    return datetime.fromisoformat(case["state"]["alert"]["timestamp"].replace("Z", "+00:00"))


def group_cases(cases: list[dict[str, Any]], window_minutes: int = 60) -> list[dict[str, Any]]:
    """Bound incidents by host, account, and time since the first alert."""
    if not 1 <= window_minutes <= 240:
        raise ValueError("window_minutes must be 1-240")
    buckets: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for case in cases:
        state = case["state"]
        key = (str(state["alert"].get("computer") or "unknown"),
               str(state["identity_context"].get("user") or "unknown"))
        buckets.setdefault(key, []).append(case)
    groups = []
    for (host, user), rows in sorted(buckets.items()):
        rows.sort(key=lambda case: (_timestamp(case), case["case_id"]))
        active: list[dict[str, Any]] = []
        for case in rows:
            if active and _timestamp(case) - _timestamp(active[0]) > timedelta(minutes=window_minutes):
                groups.append(_group(host, user, active))
                active = []
            active.append(case)
        if active:
            groups.append(_group(host, user, active))
    return sorted(groups, key=lambda group: (group["first_seen"], group["id"]))


def _group(host: str, user: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    ids = [case["case_id"] for case in rows]
    digest = hashlib.sha256("|".join(ids).encode()).hexdigest()[:12].upper()
    return {"id": "BLUE-" + digest, "host": host, "user": user,
            "first_seen": rows[0]["state"]["alert"]["timestamp"],
            "case_ids": ids, "cases": rows}


def _prompt_state(group: dict[str, Any], answers: dict[str, dict[str, Any]]) -> dict[str, Any]:
    alerts = []
    for case in group["cases"][:12]:
        state = case["state"]
        result = answers.get(case["case_id"], {})
        response = result.get("response") or {}
        judgment = response.get("answers") or {}
        alerts.append({
            "timestamp": state["alert"].get("timestamp"),
            "detection": {k: state["detection"].get(k) for k in ("rule_title", "level")},
            "details": state["alert"].get("details", {}),
            "enrichment": state.get("enrichment", {}),
            "jev_disposition": judgment.get("disposition"),
            "policy_recommendation": (result.get("policy") or {}).get("recommendation"),
        })
    return {"incident": {"host": group["host"], "user": group["user"],
                          "first_seen": group["first_seen"], "alerts": alerts}}


def _validated_note(raw: dict[str, Any], group: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    issues = []
    action = raw.get("action")
    if action not in ACTIONS:
        action = "investigate"
        issues.append("model action outside allowlist")
    expected_target = group["host"] if action == "isolate_host" else group["user"] if action == "disable_account" else "none"
    if action in DISRUPTIVE and raw.get("target") != expected_target:
        action = "investigate"
        expected_target = "none"
        issues.append("model target did not match incident asset/account")
    note = {
        "summary": str(raw.get("summary") or "")[:500],
        "evidence": [str(value)[:300] for value in raw.get("evidence", [])[:8]],
        "uncertainties": [str(value)[:300] for value in raw.get("uncertainties", [])[:8]],
        "action": action,
        "target": expected_target,
        "rationale": str(raw.get("rationale") or "")[:500],
    }
    return note, issues


def propose(cases: list[dict[str, Any]], results: list[dict[str, Any]], *, limit: int = 5) -> list[dict[str, Any]]:
    if not 1 <= limit <= 50:
        raise ValueError("limit must be 1-50")
    if not llm.available():
        raise RuntimeError(f"local model {llm.MODEL} is not available")
    state_hashes = {case["case_id"]: hashlib.sha256(json.dumps(case["state"], sort_keys=True,
                            separators=(",", ":")).encode("utf-8")).hexdigest() for case in cases}
    answers = {row["case_id"]: row for row in results
               if isinstance(row.get("response"), dict) and
               row.get("question_version") == QUESTION_VERSION and
               row.get("state_sha256") == state_hashes.get(row.get("case_id"))}
    def priority(group: dict[str, Any]) -> float:
        scores = []
        for case_id in group["case_ids"]:
            result = answers.get(case_id) or {}
            judgments = (result.get("response") or {}).get("answers") or {}
            malicious = (judgments.get("malicious_behavior_supported") or {}).get("noul", 0)
            disposition = (judgments.get("disposition") or {}).get("choice")
            scores.append(float(malicious) + (2 if disposition == "likely_malicious" else 0))
        return max(scores, default=0)
    groups = sorted(group_cases(cases), key=lambda group: (-priority(group), group["first_seen"]))
    proposals = []
    for group in groups[:limit]:
        state = _prompt_state(group, answers)
        raw = llm.chat_json(PROMPT.read_text(), json.dumps(state, sort_keys=True), SCHEMA, timeout=180)
        note, issues = _validated_note(raw, group)
        proposals.append({
            "id": group["id"], "case_ids": group["case_ids"], "host": group["host"],
            "user": group["user"], "first_seen": group["first_seen"],
            "model": llm.MODEL, "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "note": note, "validation_issues": issues,
            "gate_status": "awaiting_human", "execution_status": "not_executed",
        })
    return proposals


def save_proposals(rows: list[dict[str, Any]], path: Path = PROPOSALS) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    temporary.replace(path)


def read_proposals(path: Path = PROPOSALS) -> list[dict[str, Any]]:
    rows = _read_jsonl(path)
    reviews = {row["proposal_id"]: row for row in _read_jsonl(REVIEWS)}
    return [{**row, "review": reviews.get(row["id"])} for row in rows]


def review(proposal_id: str, decision: str, *, proposals_path: Path = PROPOSALS,
           reviews_path: Path = REVIEWS) -> dict[str, Any]:
    if decision not in ("approve", "reject"):
        raise ValueError("decision must be approve or reject")
    if proposal_id not in {row["id"] for row in _read_jsonl(proposals_path)}:
        raise ValueError("unknown blue proposal")
    entry = {"proposal_id": proposal_id, "decision": decision,
             "at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "execution_status": "not_executed"}
    reviews_path.parent.mkdir(parents=True, exist_ok=True)
    with reviews_path.open("a") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("action", choices=("propose", "list"))
    parser.add_argument("--input", type=Path, default=REPO / "runs" / "world-chain-cases.jsonl")
    parser.add_argument("--results", type=Path,
                        default=Path.home() / "Projects" / "jev-test" / "artifacts" / "world-chain-v2-results.jsonl")
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--output", type=Path, default=PROPOSALS)
    args = parser.parse_args()
    if args.action == "list":
        print(json.dumps(read_proposals(args.output), indent=2))
        return
    proposals = propose(_read_jsonl(args.input), _read_jsonl(args.results), limit=args.limit)
    save_proposals(proposals, args.output)
    print(json.dumps({"proposals": len(proposals), "output": str(args.output),
                      "executed": 0, "awaiting_human": len(proposals)}))


if __name__ == "__main__":
    main()
