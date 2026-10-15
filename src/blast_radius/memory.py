"""Agent memory in the graph (Track 2): triage decisions as precedent (F5) and drift detection (F6).

A decision stores the exact exposure it was made against. When the dependency graph changes so
that a new exposure appears, the decision is marked stale and the agent raises it again.
"""
import json
import uuid
from datetime import datetime, timezone

from blast_radius.analysis import _rows, cypher
from blast_radius.db import graph

VERDICTS = ("not_affected", "risk_accepted", "fix_planned", "fixed")


def _signatures(vuln_id: str, service: str) -> list[str]:
    rows = _rows("exposure_signatures", id=vuln_id, service=service)
    return sorted(json.dumps([r["path"], r["chain"]]) for r in rows)


def record_decision(vuln_id: str, service: str, verdict: str, reason: str, person: str) -> dict:
    if verdict not in VERDICTS:
        raise ValueError(f"verdict must be one of {VERDICTS}")
    sigs = _signatures(vuln_id, service)
    decision_id = f"DEC-{uuid.uuid4().hex[:8]}"
    at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    res = graph().query(cypher("record_decision"), {"id": vuln_id, "service": service, "person": person,
                                                     "decision_id": decision_id, "verdict": verdict,
                                                     "reason": reason, "at": at, "signatures": sigs})
    if not res.result_set:
        raise ValueError(f"unknown advisory {vuln_id!r} or service {service!r}")
    return {"decision": decision_id, "verdict": verdict, "service": service, "vulnerability": vuln_id,
            "at": at, "exposure_paths_recorded": len(sigs)}


def recall_precedent(vuln_id: str) -> list[dict]:
    return _rows("recall_precedent", id=vuln_id)


def check_drift() -> list[dict]:
    """Re-derive each current decision's exposure; mark decisions stale when new exposure appeared."""
    stale = []
    g = graph()
    for d in _rows("current_decisions"):
        if d["status"] != "current":
            continue
        now = set(_signatures(d["vuln"], d["service"]))
        new = sorted(now - set(d["signatures"] or []))
        if new:
            chains = [" → ".join(json.loads(s)[1]) for s in new]
            reason = f"{len(new)} new exposure path(s) since the decision: " + "; ".join(chains[:3])
            g.query("MATCH (d:Decision {id: $id}) SET d.status = 'stale', d.stale_reason = $reason,"
                    " d.stale_at = $at", {"id": d["id"], "reason": reason,
                                          "at": datetime.now(timezone.utc).isoformat(timespec="seconds")})
            stale.append({"decision": d["id"], "vulnerability": d["vuln"], "service": d["service"],
                          "verdict": d["verdict"], "made_by": d["person"], "new_paths": chains})
    return stale


# ------------------------------------------------ keep memory across graph rebuilds

def export_memory() -> list[dict]:
    try:
        return _rows("current_decisions")
    except Exception:
        return []  # graph does not exist yet


def import_memory(decisions: list[dict]) -> int:
    g = graph()
    restored = 0
    for d in decisions:
        res = g.query(cypher("record_decision"), {"id": d["vuln"], "service": d["service"], "person": d["person"],
                                                  "decision_id": d["id"], "verdict": d["verdict"],
                                                  "reason": d["reason"], "at": d["at"],
                                                  "signatures": d["signatures"] or []})
        if res.result_set and d["status"] != "current":
            g.query("MATCH (d:Decision {id: $id}) SET d.status = $status, d.stale_reason = $why",
                    {"id": d["id"], "status": d["status"], "why": d["stale_reason"]})
        restored += len(res.result_set)
    return restored


# ------------------------------------------------ episodic memory: what was asked and what it cited

def log_turn(session_id: str, question: str, answer: str, tool_calls: list[dict]) -> None:
    vulns = sorted({c["input"].get("vulnerability_id") for c in tool_calls if c["input"].get("vulnerability_id")})
    services = sorted({c["input"].get("service") for c in tool_calls if c["input"].get("service")})
    graph().query(cypher("log_turn"), {
        "session": session_id, "question": question, "answer": answer,
        "tools": [c["tool"] for c in tool_calls], "vulns": vulns, "services": services,
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    })
