"""Detection agent: propose Sigma tuning from measured noise, then gate it on real replays.

    python3 -m agents.detection stats              # measure (cached)
    python3 -m agents.detection propose [--top 5]  # local model proposes, gate evaluates
    python3 -m agents.detection approve PROPOSAL_ID
    python3 -m agents.detection list

The model only proposes. `gate()` is deterministic: a proposal passes only if every
attack recording that was detected (med+) before is still detected after, the rule's
own attack hits are unchanged, and benign alerts go down. Approved tuning is written
to detections/tuning.json (versioned in Git) and never applied by the model itself.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from replay.datasets import DATASETS, RUNS
from replay.tuning import TUNING, Tuning, load as load_tuning
from replay.tuning import fields as _fields, matches

from . import llm

REPO = Path(__file__).resolve().parents[1]
PROMPT = Path(__file__).with_name("prompts") / "detection.md"
PROPOSALS = REPO / "detections" / "proposals.jsonl"
STATS_CACHE = Path(RUNS) / "detection-stats.json"
MED_PLUS = {"med", "high", "crit"}
TOP_VALUES = 8
SCHEMA = {
    "type": "object",
    "properties": {
        "action": {"type": "string", "enum": ["add_exclusion", "lower_level", "no_change"]},
        "field": {"type": "string"},
        "match": {"type": "string", "enum": ["equals", "endswith", "contains"]},
        "value": {"type": "string"},
        "rationale": {"type": "string"},
    },
    # All fields required: the model must always commit to a concrete field/match/value
    # (ignored for no_change / lower_level). Omitted fields made every proposal invalid.
    "required": ["action", "field", "match", "value", "rationale"],
}


# ------------------------------------------------------------------ measurement
def _stream(dataset_names: Iterable[str]):
    for name in dataset_names:
        dataset = DATASETS[name]
        if not os.path.exists(dataset.detections):
            continue
        root = dataset.path.rstrip("/") + "/"
        tuning = Tuning()  # measure what remains after approved tuning
        with open(dataset.detections) as handle:
            for line in handle:
                d = tuning.adjust(json.loads(line))
                if d is not None and d["Level"] in MED_PLUS:
                    yield name, d["EvtxFile"].removeprefix(root), d


def build_stats(top: int = 12) -> dict[str, Any]:
    attack = [n for n, d in DATASETS.items() if d.label == "attack"]
    benign = [n for n, d in DATASETS.items() if d.label == "benign"]
    rules: dict[str, dict[str, Any]] = {}
    benign_counts: Counter[str] = Counter()
    for _, _, d in _stream(benign):
        benign_counts[d["RuleID"]] += 1
        rules.setdefault(d["RuleID"], {"title": d["RuleTitle"], "level": d["Level"]})
    candidates = {rid for rid, _ in benign_counts.most_common(top)}

    benign_values: dict[str, dict[str, Counter[str]]] = defaultdict(lambda: defaultdict(Counter))
    for _, _, d in _stream(benign):
        if d["RuleID"] in candidates:
            for k, v in _fields(d.get("Details")).items():
                benign_values[d["RuleID"]][k][v] += 1

    attack_values: dict[str, dict[str, Counter[str]]] = defaultdict(lambda: defaultdict(Counter))
    rec_total: Counter[str] = Counter()
    rule_hits: dict[str, list[list[Any]]] = defaultdict(list)  # candidate rule -> [rec, fields]
    for name, rec, d in _stream(attack):
        key = f"{name}/{rec}"
        rec_total[key] += 1
        if d["RuleID"] in candidates:
            fields = _fields(d.get("Details"))
            rule_hits[d["RuleID"]].append([key, fields])
            for k, v in fields.items():
                attack_values[d["RuleID"]][k][v] += 1

    out = {"generated": time.strftime("%Y-%m-%dT%H:%M:%S"), "tuning_version": load_tuning().get("version", 0),
           "attack_recordings_detected": len(rec_total),
           "rec_total": dict(rec_total), "rules": {}}
    for rid in candidates:
        out["rules"][rid] = {
            **rules[rid],
            "benign_alerts": benign_counts[rid],
            "attack_hits": len(rule_hits[rid]),
            "attack_recordings": len({h[0] for h in rule_hits[rid]}),
            "benign_top": {k: c.most_common(TOP_VALUES) for k, c in benign_values[rid].items()},
            "attack_top": {k: c.most_common(TOP_VALUES) for k, c in attack_values[rid].items()},
            "attack_hit_fields": rule_hits[rid],
            # benign alert field rows are summarized by counts; the gate re-streams for exact numbers
        }
    STATS_CACHE.write_text(json.dumps(out))
    return out


def load_stats() -> dict[str, Any]:
    if STATS_CACHE.exists():
        cached = json.loads(STATS_CACHE.read_text())
        if cached.get("tuning_version") == load_tuning().get("version", 0):
            return cached
    return build_stats()


# ------------------------------------------------------------------ gate
def validate(proposal: dict[str, Any], rule: dict[str, Any]) -> str | None:
    action = proposal.get("action")
    if action not in ("add_exclusion", "lower_level", "no_change"):
        return "unknown action"
    if action == "add_exclusion":
        field, value = proposal.get("field"), proposal.get("value")
        if field not in rule["benign_top"]:
            return f"field {field!r} is not in the benign statistics"
        if proposal.get("match") not in ("equals", "endswith", "contains"):
            return "invalid match type"
        if not value or len(str(value)) < 4:
            return "exclusion value is empty or too broad"
    return None


USER_WRITABLE = ("\\users\\", "\\temp\\", "\\appdata\\", "\\downloads\\", "\\programdata\\", "\\public\\")


def risks(proposal: dict[str, Any]) -> list[str]:
    """Generalization risks the replay gate cannot see: data says safe, attackers may disagree."""
    if proposal.get("action") != "add_exclusion":
        return []
    value = str(proposal.get("value", "")).lower().replace("/", "\\")
    found = []
    if any(part in value + "\\" for part in USER_WRITABLE):
        found.append("excludes a user-writable location attackers commonly use")
    stripped = value.strip("\\")
    if "\\" not in stripped:
        found.append("filename-only match is spoofable by renaming a binary")
    if proposal.get("match") == "contains":
        found.append("'contains' match is broad")
    return found


def gate(proposal: dict[str, Any], rule_id: str, stats: dict[str, Any],
         benign_rows: list[dict[str, str]]) -> dict[str, Any]:
    """Replay the proposal over stored detections and return before/after metrics."""
    rule = stats["rules"][rule_id]
    action = proposal["action"]
    hits = rule["attack_hit_fields"]
    if action == "no_change":
        return {"passed": False, "reason": "no change proposed"}
    suppressed_attack = [h for h in hits if action == "lower_level" or matches(h[1], proposal)]
    suppressed_benign = sum(1 for f in benign_rows if action == "lower_level" or matches(f, proposal))
    lost = Counter(h[0] for h in suppressed_attack)
    recordings_lost = [rec for rec, n in lost.items() if stats["rec_total"].get(rec, 0) - n <= 0]
    metrics = {
        "benign_alerts_before": len(benign_rows),
        "benign_alerts_after": len(benign_rows) - suppressed_benign,
        "rule_attack_hits_before": len(hits),
        "rule_attack_hits_after": len(hits) - len(suppressed_attack),
        "attack_recordings_lost": len(recordings_lost),
    }
    if recordings_lost:
        reason = f"{len(recordings_lost)} attack recording(s) would go undetected"
    elif suppressed_attack:
        reason = f"suppresses {len(suppressed_attack)} of this rule's attack hits"
    elif suppressed_benign == 0:
        reason = "does not reduce benign alerts"
    else:
        reason = f"removes {suppressed_benign:,} benign alerts with no attack loss"
    passed = not recordings_lost and not suppressed_attack and suppressed_benign > 0
    return {"passed": passed, "reason": reason, "risks": risks(proposal), **metrics}


def benign_rows_for(rule_ids: Iterable[str]) -> dict[str, list[dict[str, str]]]:
    """One pass over the benign detections, collecting field rows for the given rules."""
    wanted = set(rule_ids)
    rows: dict[str, list[dict[str, str]]] = {rid: [] for rid in wanted}
    benign = [n for n, d in DATASETS.items() if d.label == "benign"]
    for _, _, d in _stream(benign):
        if d["RuleID"] in wanted:
            rows[d["RuleID"]].append(_fields(d.get("Details")))
    return rows


# ------------------------------------------------------------------ agent loop
def _prompt_for(rule_id: str, rule: dict[str, Any]) -> str:
    def block(top: dict[str, list]) -> str:
        return "\n".join(f"  {k}: " + "; ".join(f"{v!r} x{c}" for v, c in vals) for k, vals in top.items()) or "  (none)"
    return (f"Rule: {rule['title']} (id {rule_id}, level {rule['level']})\n"
            f"Benign baseline alerts: {rule['benign_alerts']}\n"
            f"Attack hits: {rule['attack_hits']} across {rule['attack_recordings']} attack recordings\n\n"
            f"Benign sample, top values per field:\n{block(rule['benign_top'])}\n\n"
            f"Attack sample, top values per field:\n{block(rule['attack_top'])}\n")


def propose(top: int, auto_approve: bool = False,
            rule_ids: list[str] | None = None) -> list[dict[str, Any]]:
    if not llm.available():
        sys.exit(f"local model {llm.MODEL} is not available in Ollama; run: ollama pull {llm.MODEL}")
    stats = load_stats()
    system = PROMPT.read_text()
    ranked = sorted(stats["rules"].items(), key=lambda kv: -kv[1]["benign_alerts"])
    if rule_ids is not None:
        wanted = set(rule_ids)
        ranked = [item for item in ranked if item[0] in wanted]
    ranked = ranked[:top]
    benign_rows = benign_rows_for(rid for rid, _ in ranked)
    out = []
    for rule_id, rule in ranked:
        started = time.time()
        try:
            proposal = llm.chat_json(system, _prompt_for(rule_id, rule), SCHEMA)
        except llm.LLMError as exc:
            proposal = {"action": "no_change", "rationale": f"model error: {exc}"}
        problem = validate(proposal, rule)
        verdict = {"passed": False, "reason": f"invalid proposal: {problem}"} if problem else \
            gate(proposal, rule_id, stats, benign_rows[rule_id])
        record = {
            "id": "DET-" + hashlib.sha256(f"{rule_id}{json.dumps(proposal, sort_keys=True)}".encode()).hexdigest()[:10],
            "at": time.strftime("%Y-%m-%dT%H:%M:%S"), "agent": "detection", "model": llm.MODEL,
            "rule_id": rule_id, "rule_title": rule["title"], "proposal": proposal, "gate": verdict,
            "status": ("approved" if auto_approve and not verdict.get("risks") else "awaiting_approval")
                      if verdict["passed"] else "rejected_by_gate",
            "seconds": round(time.time() - started, 1),
        }
        PROPOSALS.parent.mkdir(parents=True, exist_ok=True)
        with open(PROPOSALS, "a") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        if record["status"] == "approved":
            apply(record, by="auto-approve")
        flag = f"  RISK: {'; '.join(verdict['risks'])}" if verdict.get("risks") else ""
        print(f"{record['id']}  {rule['title'][:48]:48}  {proposal.get('action'):13}  "
              f"{'PASS' if verdict['passed'] else 'FAIL'}  {verdict['reason']}{flag}")
        out.append(record)
    return out


def read_proposals() -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    if PROPOSALS.exists():
        for line in PROPOSALS.read_text().splitlines():
            if line.strip():
                r = json.loads(line)
                records[r["id"]] = r
    return records


def apply(record: dict[str, Any], by: str) -> None:
    tuning = json.loads(TUNING.read_text()) if TUNING.exists() else {"version": 0, "exclusions": [], "level_changes": []}
    p = record["proposal"]
    if p["action"] == "add_exclusion":
        tuning["exclusions"].append({"rule_id": record["rule_id"], "rule_title": record["rule_title"],
                                     "field": p["field"], "match": p["match"], "value": p["value"],
                                     "proposal": record["id"], "approved_by": by, "gate": record["gate"]})
    elif p["action"] == "lower_level":
        tuning["level_changes"].append({"rule_id": record["rule_id"], "rule_title": record["rule_title"],
                                        "to": "low", "proposal": record["id"], "approved_by": by})
    tuning["version"] += 1
    TUNING.parent.mkdir(parents=True, exist_ok=True)
    TUNING.write_text(json.dumps(tuning, indent=2) + "\n")


def approve(proposal_id: str, accept_risk: bool = False) -> dict[str, Any]:
    records = read_proposals()
    record = records.get(proposal_id)
    if record is None:
        raise KeyError(f"no proposal {proposal_id}")
    if not record["gate"].get("passed"):
        raise ValueError("gate rejected this proposal; it cannot be approved")
    if record["status"] == "approved":
        raise ValueError("already approved")
    found = risks(record["proposal"])
    if found and not accept_risk:
        raise PermissionError("risky exclusion: " + "; ".join(found) + " — accept the risk explicitly to approve")
    record["status"] = "approved"
    with open(PROPOSALS, "a") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    apply(record, by="analyst" + (" (accepted risk)" if found else ""))
    return record


def main(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(description="Northstar detection agent")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("stats")
    p = sub.add_parser("propose")
    p.add_argument("--top", type=int, default=5)
    p.add_argument("--auto-approve", action="store_true")
    a = sub.add_parser("approve")
    a.add_argument("proposal_id")
    a.add_argument("--accept-risk", action="store_true")
    sub.add_parser("list")
    args = parser.parse_args(argv)
    if args.cmd == "stats":
        s = build_stats()
        for rid, r in sorted(s["rules"].items(), key=lambda kv: -kv[1]["benign_alerts"]):
            print(f"{r['benign_alerts']:>7,} benign  {r['attack_hits']:>5} attack hits  {r['attack_recordings']:>3} recs  {r['title']}")
    elif args.cmd == "propose":
        propose(args.top, args.auto_approve)
    elif args.cmd == "approve":
        try:
            approve(args.proposal_id, args.accept_risk)
        except (KeyError, ValueError, PermissionError) as exc:
            sys.exit(str(exc))
        print(f"approved {args.proposal_id}; tuning version {json.loads(TUNING.read_text())['version']}")
    else:
        for r in read_proposals().values():
            found = risks(r["proposal"])
            print(f"{r['id']}  {r['status']:18}  {r['rule_title'][:50]:50}  {r['gate'].get('reason', '')}"
                  + (f"  RISK: {'; '.join(found)}" if found else ""))


if __name__ == "__main__":
    main(sys.argv[1:])
