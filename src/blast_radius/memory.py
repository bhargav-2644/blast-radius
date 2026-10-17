"""Agent memory in the graph (Track 2): triage decisions as precedent (F5) and drift detection (F6).

A decision stores the exact exposure it was made against, and its status is re-derived from the graph
after every change (D-051): `stale` when a new exposure path appeared, `disputed` when it says fixed but
paths remain, `verified` when a planned or claimed fix left no path, `current` otherwise. A newer
decision on the same advisory and service supersedes the older one, which is kept as history.
"""
import json
import time
import uuid
from datetime import datetime, timezone

from blast_radius.analysis import _rows, cypher, trace
from blast_radius.db import graph

VERDICTS = ("not_affected", "risk_accepted", "fix_planned", "fixed")
FIX_VERDICTS = ("fix_planned", "fixed")


def _signatures(vuln_id: str, service: str) -> list[str]:
    rows = _rows("exposure_signatures", id=vuln_id, service=service)
    return sorted(json.dumps([r["path"], r["chain"]]) for r in rows)


def _name(name_at_version: str) -> str:
    return name_at_version.rsplit("@", 1)[0]  # keeps scoped names like @koa/router


def _via(signatures: list[str]) -> list[str]:
    """Packages a decision's exposure ran through: every hop of every chain except the vulnerable one."""
    return sorted({_name(n) for s in signatures for n in json.loads(s)[1][:-1]})


def _chain(sig: str) -> str:
    return " → ".join(json.loads(sig)[1])


def _status(verdict: str, recorded: list[str] | None, now: list[str]) -> tuple[str, str | None]:
    """What the graph says about a decision today, and why (D-051)."""
    then = set(recorded or [])
    if verdict in FIX_VERDICTS and not now:
        return "verified", (f"no exposure path left: the {len(then)} recorded path(s) are gone" if then
                            else "no exposure path in the graph")
    if verdict == "fixed":
        return "disputed", (f"recorded as fixed, but the graph still shows {len(now)} exposure path(s): "
                            + "; ".join(_chain(x) for x in sorted(now)[:3]))
    new = sorted(set(now) - then)
    if new:
        return "stale", f"{len(new)} new exposure path(s) since the decision: " + "; ".join(_chain(x) for x in new[:3])
    return "current", None


def _write_decision(params: dict) -> list:
    started = time.perf_counter()
    res = graph().query(cypher("record_decision"), params)
    trace("cypher", "record_decision", cypher("record_decision"), params, (time.perf_counter() - started) * 1000,
          len(res.result_set))
    return res.result_set


def record_decision(vuln_id: str, service: str, verdict: str, reason: str, person: str) -> dict:
    """Store a decision with the exposure it was made against. It supersedes any earlier decision on the
    same advisory and service, and starts with the status the graph gives it (a `fixed` decision while
    paths remain is disputed straight away)."""
    if verdict not in VERDICTS:
        raise ValueError(f"verdict must be one of {VERDICTS}")
    sigs = _signatures(vuln_id, service)
    status, why = _status(verdict, sigs, sigs)
    decision_id = f"DEC-{uuid.uuid4().hex[:8]}"
    at = _now()
    rows = _write_decision({"id": vuln_id, "service": service, "person": person, "decision_id": decision_id,
                            "verdict": verdict, "reason": reason, "at": at, "signatures": sigs, "via": _via(sigs),
                            "status": status, "status_reason": why, "status_at": at if why else None,
                            "superseded_by": None})
    if not rows:
        raise ValueError(f"unknown advisory {vuln_id!r} or service {service!r}")
    return {"decision": decision_id, "verdict": verdict, "service": service, "vulnerability": vuln_id,
            "at": at, "exposure_paths_recorded": len(sigs), "status": status, "status_reason": why,
            "supersedes": rows[0][1]}


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


def exposure_change(vuln_id: str, service: str, recorded: list[str] | None) -> dict:
    """Has the exposure a decision was made against changed? Compares the chains stored with the
    decision to the ones the graph gives today (D-047)."""
    then, now = set(recorded or []), set(_signatures(vuln_id, service))
    new, gone = sorted(_chain(x) for x in now - then), sorted(_chain(x) for x in then - now)
    if not new and not gone:
        summary = f"unchanged: the same {len(now)} exposure path(s) as when decided"
    else:
        summary = ", ".join(x for x in (f"{len(new)} new path(s)" if new else "",
                                        f"{len(gone)} path(s) gone" if gone else "") if x) + " since the decision"
    return {"changed": bool(new or gone), "paths_then": len(then), "paths_now": len(now),
            "new_paths": new, "removed_paths": gone, "summary": summary}


def _covers(rows: list[dict]) -> dict[str, list[str]]:
    """Every service one sign-off covers: decisions in force with the same advisory, verdict, reason and
    person (record_not_affected writes one per service)."""
    groups: dict[tuple, list[str]] = {}
    for d in _rows("current_decisions"):
        if d["status"] == "superseded":
            continue
        groups.setdefault((d["vuln"], d["verdict"], d["reason"], d["person"]), []).append(d["service"])
    return {r["decision"]: sorted(groups.get((r["about"], r["verdict"], r["reason"], r["by"]), [r["service"]]))
            for r in rows}


def recall_precedent(vuln_id: str) -> list[dict]:
    """Decisions on this advisory, then on the same package, then on advisories reached through the
    same dependency chain (`match` says which, `via` names the shared packages). Each one says who
    decided, why, when, which advisory and services it covers, whether its exposure has changed, what
    the graph says about it now (`status`), and which earlier decisions it replaced (`replaces`).
    Superseded decisions only appear under `replaces`."""
    rows = [{**r, "match": "advisory" if r["same_advisory"] else "package", "via": []}
            for r in _rows("recall_precedent", id=vuln_id)]
    via = sorted({_name(n) for r in _rows("exposure_paths", id=vuln_id, include_dev=True) for n in r["chain"] or []})
    seen = {r["decision"] for r in rows}
    if via:
        rows += [{**r, "match": "path", "package": None} for r in _rows("path_precedent", id=vuln_id, via=via)
                 if r["decision"] not in seen]
    covers = _covers(rows) if rows else {}
    for r in rows:
        r["covers"] = {"advisory": r["about"], "severity": r["severity"], "summary": r["summary"],
                       "services": covers[r["decision"]]}
        r["exposure"] = exposure_change(r["about"], r["service"], r.pop("signatures"))
    return rows


def recheck() -> list[dict]:
    """Re-derive every decision in force from today's graph and record each status that changed:
    stale (new path), disputed (says fixed, paths remain), verified (planned or claimed fix, no path
    left) or current again (e.g. a deploy was rolled back). Returns the changes."""
    changes = []
    for d in _rows("current_decisions"):
        if d["status"] == "superseded":
            continue
        now = _signatures(d["vuln"], d["service"])
        status, why = _status(d["verdict"], d["signatures"], now)
        if status == d["status"]:
            continue
        graph().query("MATCH (d:Decision {id: $id}) SET d.status = $status, d.stale_reason = $why, d.stale_at = $at",
                      {"id": d["id"], "status": status, "why": why, "at": _now() if why else None})
        changes.append({"decision": d["id"], "vulnerability": d["vuln"], "service": d["service"],
                        "verdict": d["verdict"], "made_by": d["person"], "was": d["status"], "status": status,
                        "why": why, "new_paths": sorted(_chain(x) for x in set(now) - set(d["signatures"] or []))})
    return changes


def check_drift() -> list[dict]:
    """Decisions the graph no longer supports (now stale or disputed), after re-checking all of them."""
    return [c for c in recheck() if c["status"] in ("stale", "disputed")]


def split_changes(changes: list[dict]) -> tuple[list[dict], list[dict]]:
    """(needs attention again, back in line with the graph): how a deploy reports its rechecks."""
    bad = [c for c in changes if c["status"] in ("stale", "disputed")]
    return bad, [c for c in changes if c not in bad]


def backfill_via() -> int:
    """Give decisions recorded before VIA edges existed their path packages (path precedent)."""
    rows = graph().ro_query("MATCH (d:Decision) WHERE NOT (d)-[:VIA]->() RETURN d.id, d.signatures").result_set
    for decision_id, sigs in rows:
        graph().query("MATCH (d:Decision {id: $id}), (p:Package) WHERE p.name IN $via CREATE (d)-[:VIA]->(p)",
                      {"id": decision_id, "via": _via(sigs or [])})
    return len(rows)


# ------------------------------------------------ what changed since the last investigation (D-050)

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def what_changed(vuln_id: str, record: bool = True) -> dict:
    """Compare this advisory's production exposure with the snapshot taken the last time anyone
    investigated it: services newly exposed or no longer exposed, paths added or removed, chains whose
    versions changed, lockfiles swapped, and decisions that went stale, were disputed or were verified
    in between. Then save today's
    exposure as the new snapshot."""
    now = {(r["service"], r["path"]): r["chain"] for r in _rows("advisory_signatures", id=vuln_id)}
    lockfiles = {r["repo"]: r["lockfile"] for r in _rows("repo_lockfiles")}
    last = _rows("investigations", id=vuln_id)
    out = {"vulnerability": vuln_id, "first_look": not last, "last_look": None,
           "services_now": sorted({s for s, _ in now}), "paths_now": len(now)}
    if last:
        last = last[0]
        then = {(s, p): c for s, p, c in (json.loads(x) for x in last["signatures"] or [])}
        old_locks = json.loads(last["lockfiles"] or "{}")
        chain = lambda svc, c: " → ".join([svc, *c])
        before, after = {s for s, _ in then}, {s for s, _ in now}
        changed = sorted(k for k in then.keys() & now.keys() if then[k] != now[k])
        moved = [d for d in _rows("current_decisions")
                 if d["vuln"] == vuln_id and (d.get("stale_at") or "") >= last["at"]]
        stale = [d for d in moved if d["status"] in ("stale", "disputed")]
        verified = [d for d in moved if d["status"] == "verified"]
        out.update({
            "last_look": last["at"],
            "newly_exposed_services": sorted(after - before),
            "no_longer_exposed_services": sorted(before - after),
            "new_paths": sorted(chain(k[0], now[k]) for k in now.keys() - then.keys()),
            "removed_paths": sorted(chain(k[0], then[k]) for k in then.keys() - now.keys()),
            "changed_versions": [{"service": k[0], "install_path": k[1], "before": " → ".join(then[k]),
                                  "after": " → ".join(now[k])} for k in changed],
            "lockfiles_changed": [{"service": svc, "before": old_locks.get(svc), "after": f}
                                  for svc, f in sorted(lockfiles.items()) if svc in old_locks and old_locks[svc] != f],
            "decisions_gone_stale": [{"decision": d["id"], "service": d["service"], "verdict": d["verdict"],
                                      "made_by": d["person"], "status": d["status"], "stale_at": d["stale_at"],
                                      "why": d["stale_reason"]} for d in stale],
            "decisions_verified": [{"decision": d["id"], "service": d["service"], "verdict": d["verdict"],
                                    "made_by": d["person"], "verified_at": d["stale_at"], "why": d["stale_reason"]}
                                   for d in verified],
        })
        out["changed"] = any(out[k] for k in ("newly_exposed_services", "no_longer_exposed_services", "new_paths",
                                              "removed_paths", "changed_versions", "lockfiles_changed",
                                              "decisions_gone_stale", "decisions_verified"))
    if record:
        _save_investigation(vuln_id, _now(), sorted(json.dumps([s, p, c]) for (s, p), c in now.items()),
                            json.dumps(lockfiles, sort_keys=True))
    return out


def _save_investigation(vuln_id: str, at: str, signatures: list[str], lockfiles: str) -> None:
    params = {"id": vuln_id, "at": at, "signatures": signatures, "lockfiles": lockfiles}
    started = time.perf_counter()
    res = graph().query(cypher("save_investigation"), params)
    trace("cypher", "save_investigation", cypher("save_investigation"), params,
          (time.perf_counter() - started) * 1000, len(res.result_set))


# ------------------------------------------------ keep memory across graph rebuilds

def export_memory() -> list[dict]:
    try:
        return _rows("current_decisions")
    except Exception:
        return []  # graph does not exist yet


def import_memory(decisions: list[dict]) -> int:
    """Write exported decisions back, oldest first, with the status they had. Older exports may hold
    several decisions in force on one advisory and service; the newest then supersedes the rest."""
    restored = 0
    for d in sorted(decisions, key=lambda d: (d["at"] or "", d["id"])):
        restored += len(_write_decision({
            "id": d["vuln"], "service": d["service"], "person": d["person"], "decision_id": d["id"],
            "verdict": d["verdict"], "reason": d["reason"], "at": d["at"], "signatures": d["signatures"] or [],
            "via": _via(d["signatures"] or []), "status": d["status"], "status_reason": d["stale_reason"],
            "status_at": d.get("stale_at"), "superseded_by": d.get("superseded_by")}))
    # superseded decisions come back before the decision that replaced them; link them by id
    graph().query("""MATCH (old:Decision) WHERE old.superseded_by IS NOT NULL
                     MATCH (new:Decision {id: old.superseded_by})
                     SET old.status = 'superseded' MERGE (new)-[:SUPERSEDES]->(old)""")
    return restored


def export_investigations() -> list[dict]:
    try:
        return _rows("investigations", id=None)
    except Exception:
        return []  # graph does not exist yet


def import_investigations(rows: list[dict]) -> int:
    for r in rows:
        _save_investigation(r["vuln"], r["at"], r["signatures"] or [], r["lockfiles"] or "{}")
    return len(rows)


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
