"""Agent memory in the graph (Track 2): triage decisions as precedent (F5) and drift detection (F6).

A decision stores the exact exposure it was made against. When the dependency graph changes so
that a new exposure appears, the decision is marked stale and the agent raises it again.
"""
import json
import time
import uuid
from datetime import datetime, timezone

from blast_radius.analysis import _rows, cypher, trace
from blast_radius.db import graph

VERDICTS = ("not_affected", "risk_accepted", "fix_planned", "fixed")


def _signatures(vuln_id: str, service: str) -> list[str]:
    rows = _rows("exposure_signatures", id=vuln_id, service=service)
    return sorted(json.dumps([r["path"], r["chain"]]) for r in rows)


def _name(name_at_version: str) -> str:
    return name_at_version.rsplit("@", 1)[0]  # keeps scoped names like @koa/router


def _via(signatures: list[str]) -> list[str]:
    """Packages a decision's exposure ran through: every hop of every chain except the vulnerable one."""
    return sorted({_name(n) for s in signatures for n in json.loads(s)[1][:-1]})


def record_decision(vuln_id: str, service: str, verdict: str, reason: str, person: str) -> dict:
    if verdict not in VERDICTS:
        raise ValueError(f"verdict must be one of {VERDICTS}")
    sigs = _signatures(vuln_id, service)
    decision_id = f"DEC-{uuid.uuid4().hex[:8]}"
    at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    params = {"id": vuln_id, "service": service, "person": person, "decision_id": decision_id,
              "verdict": verdict, "reason": reason, "at": at, "signatures": sigs, "via": _via(sigs)}
    started = time.perf_counter()
    res = graph().query(cypher("record_decision"), params)
    trace("cypher", "record_decision", cypher("record_decision"), params, (time.perf_counter() - started) * 1000,
          len(res.result_set))
    if not res.result_set:
        raise ValueError(f"unknown advisory {vuln_id!r} or service {service!r}")
    return {"decision": decision_id, "verdict": verdict, "service": service, "vulnerability": vuln_id,
            "at": at, "exposure_paths_recorded": len(sigs)}


def record_not_affected(vuln_id: str, person: str) -> dict:
    """Turn a proof of safety (F4) into memory: a not_affected decision for every service that installs
    a package the advisory concerns, citing what was searched. Each one records no exposure paths, so
    a later deploy that brings in an affected version makes it stale (F6)."""
    from blast_radius.analysis import exposure
    from blast_radius.ingest.osv import snapshot_date

    ex = exposure(vuln_id)
    if ex["exposed"]:
        raise ValueError(f"{vuln_id} reaches {len(ex['services'])} service(s) in production; nothing to certify")
    proof = ex["safety_proof"]
    services = sorted({s for p in proof["packages"] for x in p["installed"] for s in x["services"]})
    if not services:
        raise ValueError(f"no service installs a package {vuln_id} concerns")
    evidence = "; ".join(f"{p['package']} affected {' | '.join(p['affected_ranges'])}, installed "
                         f"{', '.join(sorted({x['version'] for x in p['installed']})) or 'nowhere'}"
                         for p in proof["packages"])
    reason = (f"Proof of safety: no production dependency path reaches an affected version ({evidence}). "
              f"Searched every install at any depth in all services; advisory data as of {snapshot_date()}.")
    if proof["dev_only_exposure"]:
        reason += f" Dev tooling only in: {', '.join(proof['dev_only_exposure'])}."
    made = [record_decision(vuln_id, s, "not_affected", reason, person) for s in services]
    return {"vulnerability": vuln_id, "services": services, "decisions": [d["decision"] for d in made],
            "reason": reason}


def recall_precedent(vuln_id: str) -> list[dict]:
    """Decisions on this advisory, then on the same package, then on advisories reached through the
    same dependency chain (`match` says which, `via` names the shared packages)."""
    rows = [{**r, "match": "advisory" if r["same_advisory"] else "package", "via": []}
            for r in _rows("recall_precedent", id=vuln_id)]
    via = sorted({_name(n) for r in _rows("exposure_paths", id=vuln_id, include_dev=True) for n in r["chain"] or []})
    seen = {r["decision"] for r in rows}
    if via:
        rows += [{**r, "match": "path", "package": None} for r in _rows("path_precedent", id=vuln_id, via=via)
                 if r["decision"] not in seen]
    return rows


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


def check_recovered() -> list[dict]:
    """Stale decisions whose exposure is back inside what was decided (e.g. a deploy was rolled back)."""
    back = []
    for d in _rows("current_decisions"):
        if d["status"] == "stale" and set(_signatures(d["vuln"], d["service"])) <= set(d["signatures"] or []):
            graph().query("MATCH (d:Decision {id: $id}) SET d.status = 'current', d.stale_reason = null",
                          {"id": d["id"]})
            back.append({"decision": d["id"], "vulnerability": d["vuln"], "service": d["service"],
                         "verdict": d["verdict"]})
    return back


def backfill_via() -> int:
    """Give decisions recorded before VIA edges existed their path packages (path precedent)."""
    rows = graph().ro_query("MATCH (d:Decision) WHERE NOT (d)-[:VIA]->() RETURN d.id, d.signatures").result_set
    for decision_id, sigs in rows:
        graph().query("MATCH (d:Decision {id: $id}), (p:Package) WHERE p.name IN $via CREATE (d)-[:VIA]->(p)",
                      {"id": decision_id, "via": _via(sigs or [])})
    return len(rows)


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
                                                  "signatures": d["signatures"] or [],
                                                  "via": _via(d["signatures"] or [])})
        if res.result_set and d["status"] != "current":
            g.query("MATCH (d:Decision {id: $id}) SET d.status = $status, d.stale_reason = $why",
                    {"id": d["id"], "status": d["status"], "why": d["stale_reason"]})
        restored += len(res.result_set)
    return restored


def export_history() -> list[dict]:
    try:
        return _rows("session_history")
    except Exception:
        return []  # graph does not exist yet


def import_history(turns: list[dict]) -> int:
    """Write sessions and questions back after a rebuild, re-linking each to the nodes it cited.
    A cited advisory or service missing from the new graph is dropped; the question is kept."""
    g = graph()
    for t in turns:
        g.query(cypher("log_turn"), {"session": t["session"], "question": t["question"], "answer": t["answer"],
                                     "tools": t["tools"] or [], "vulns": t["vulns"], "services": t["services"],
                                     "at": t["at"]})
    return len(turns)


# ------------------------------------------------ episodic memory: what was asked and what it cited

def log_turn(session_id: str, question: str, answer: str, tool_calls: list[dict]) -> None:
    vulns = sorted({c["input"].get("vulnerability_id") for c in tool_calls if c["input"].get("vulnerability_id")})
    services = sorted({c["input"].get("service") for c in tool_calls if c["input"].get("service")})
    graph().query(cypher("log_turn"), {
        "session": session_id, "question": question, "answer": answer,
        "tools": [c["tool"] for c in tool_calls], "vulns": vulns, "services": services,
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    })
