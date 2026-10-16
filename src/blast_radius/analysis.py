"""Graph questions the agent can ask. Each function runs Cypher from queries/ and returns
plain dicts that include the nodes and paths used, so every answer can show its evidence."""
import re
import time
import uuid
from contextvars import ContextVar
from collections import defaultdict, deque
from functools import cache
from pathlib import Path

import nodesemver
import semver

from blast_radius.db import connect, graph

QUERIES = Path(__file__).resolve().parents[2] / "queries"

# Effort weights for the upgrade cut (F3, D-013). Lower = easier for a developer.
EFFORT_REFRESH = 1      # a fixed version already satisfies the parent's range: refresh the lockfile
EFFORT_DIRECT = 2       # bump one of the repo's own direct dependencies
EFFORT_OVERRIDE = 4     # parent's range excludes every fix: needs an npm override
EFFORT_TRANSITIVE = 6   # change a link deep in the tree: needs an upstream package release


# Every graph query a tool runs is recorded here, so the UI can stream exactly what ran (query, params,
# time, row count). The MCP server resets it per tool call and returns it alongside the result.
TRACE: ContextVar[list | None] = ContextVar("TRACE", default=None)


def trace(kind: str, name: str, text: str, params: dict, ms: float, rows: int) -> None:
    log = TRACE.get()
    if log is not None:
        shown = {k: (v if len(str(v)) < 200 else f"<{len(v)} items>" if isinstance(v, list) else str(v)[:200])
                 for k, v in params.items()}
        log.append({"kind": kind, "name": name, "query": text.strip(), "params": shown,
                    "ms": round(ms, 1), "rows": rows})


@cache
def cypher(name: str) -> str:
    return (QUERIES / f"{name}.cypher").read_text()


def _rows(name: str, **params) -> list[dict]:
    started = time.perf_counter()
    result = graph().ro_query(cypher(name), params)
    trace("cypher", name, cypher(name), params, (time.perf_counter() - started) * 1000, len(result.result_set))
    cols = [c[1] if isinstance(c, (list, tuple)) else c for c in result.header]
    return [dict(zip(cols, row)) for row in result.result_set]


# ---------------------------------------------------------------- lookups

def find_vulnerability(text: str, limit: int = 5) -> list[dict]:
    exact = _rows("vulnerability_by_id", id=text.strip())
    if exact:
        return exact
    # RediSearch syntax treats '-', '@', '|' etc. as operators; search plain words instead
    words = re.sub(r"[^\w]+", " ", text).strip()
    return _rows("find_vulnerability", text=words, limit=limit) if words else []


# ---------------------------------------------------------------- F1 / F4

def exposure(vuln_id: str, include_dev: bool = False) -> dict:
    rows = _rows("exposure_paths", id=vuln_id, include_dev=include_dev)
    services: dict[str, dict] = {}
    for r in rows:
        svc = services.setdefault(r["service"], {"service": r["service"], "team": r["team"], "tier": r["tier"],
                                                 "paths": []})
        svc["paths"].append({"package": f"{r['package']}@{r['version']}", "depth": r["depth"],
                             "chain": r["chain"], "dev_only": r["dev_only"], "fixed": r["fixed"]})
    result = {"vulnerability": vuln_id, "include_dev": include_dev, "exposed": bool(services),
              "services": list(services.values())}
    if not services:
        result["safety_proof"] = safety_proof(vuln_id, include_dev)
    return result


def safety_proof(vuln_id: str, include_dev: bool = False) -> dict:
    """Evidence for "not affected": what is installed versus what the advisory affects."""
    packages = _rows("safety_proof", id=vuln_id)
    dev_hits = [] if include_dev else _rows("exposure_paths", id=vuln_id, include_dev=True)
    return {
        "searched": "every install of every concerned package, in all services, at any depth",
        "packages": [{"package": p["package"], "affected_ranges": p["affected_ranges"],
                      "installed": [x for x in p["installed"] if x]} for p in packages],
        "dev_only_exposure": sorted({h["service"] for h in dev_hits}),
    }


# ---------------------------------------------------------------- F2

def customer_impact(vuln_id: str, include_dev: bool = False) -> dict:
    rows = _rows("customer_impact", id=vuln_id, include_dev=include_dev)
    return {"vulnerability": vuln_id, "customers": rows,
            "by_tier": {t: sum(1 for r in rows if r["tier"] == t) for t in ("enterprise", "business", "startup")}}


# ---------------------------------------------------------------- F3

def _version(v: str):
    try:
        return semver.Version.parse(v)
    except ValueError:
        return None


def _best_fix(installed: str, fixed: list[str]) -> str | None:
    """Smallest fixed version above the installed one, preferring the same major."""
    cur = _version(installed)
    cands = sorted(v for v in (_version(f) for f in fixed) if v and (cur is None or v > cur))
    if not cands:
        return None
    same_major = [v for v in cands if cur and v.major == cur.major]
    return str((same_major or cands)[0])


def _satisfies(version: str | None, rng: str | None) -> bool:
    if not version or not rng:
        return False
    try:
        return bool(nodesemver.satisfies(version, rng, loose=True))
    except Exception:
        return False


def _repo_cut(repo: str, targets: dict[str, dict], include_dev: bool) -> dict:
    edges = _rows("repo_requires_subgraph", repo=repo)
    parents = defaultdict(list)
    for e in edges:
        parents[e["dst"]].append(e)
    # keep only the part of the tree that leads to an affected install
    keep, queue = set(targets), deque(targets)
    while queue:
        for e in parents[queue.popleft()]:
            if e["src"] not in keep:
                keep.add(e["src"])
                queue.append(e["src"])
    sub = [e for e in edges if e["src"] in keep and e["dst"] in keep]

    def capacity(e: dict) -> int:
        if e["dst"] in targets:
            fix = targets[e["dst"]]["fix"]
            if _satisfies(fix, e["range"]):
                return EFFORT_REFRESH
            return EFFORT_DIRECT if e["src"] == "ROOT" else EFFORT_OVERRIDE
        return EFFORT_DIRECT if e["src"] == "ROOT" else EFFORT_TRANSITIVE

    for e in sub:
        e["capacity"] = capacity(e)

    flow_cut, max_flow, solver = _min_cut(sub, list(targets))
    cut = [e for e in sub if (e["src"], e["dst"]) in flow_cut]
    out_edges, in_edges = defaultdict(list), defaultdict(list)
    for e in sub:
        out_edges[e["src"]].append(e)
        in_edges[e["dst"]].append(e)

    actions = []
    for e in cut:
        child = f"{e['dst_name']}@{e['dst_version']}"
        parent = repo if e["src"] == "ROOT" else f"{e['src_name']}@{e['src_version']}"
        fix = targets.get(e["dst"], {}).get("fix")
        if e["capacity"] == EFFORT_REFRESH:
            text = f"Refresh lockfile so {parent} picks up {e['dst_name']}@{fix} (its range {e['range']} already allows it)"
            kind = "refresh"
        elif e["src"] == "ROOT":
            target = f" to {fix}" if fix else " to a version that no longer pulls the vulnerable package"
            text = f"Bump direct dependency {child}{target}"
            kind = "bump_direct"
        elif e["dst"] in targets:
            text = f"Add an npm override forcing {e['dst_name']}@{fix} under {parent} (range {e['range']} excludes the fix)"
            kind = "override"
        else:
            text = f"Upgrade {parent} to a release that doesn't require {child}"
            kind = "upstream"
        actions.append({"kind": kind, "effort": e["capacity"], "parent": parent, "child": child,
                        "range": e["range"], "fix": fix, "action": text})
    return {"repo": repo, "total_effort": max_flow, "solver": solver, "exposure_paths": _count_paths(out_edges, targets),
            "vulnerable_links": sum(len(in_edges[t]) for t in targets),
            "affected_installs": len(targets), "subgraph_edges": len(sub), "actions": actions}


def _min_cut(sub: list[dict], targets: list[str]) -> tuple[set, float, str]:
    """Weighted min cut between the repo root and the affected installs.

    FalkorDB's algo.maxFlow hung on some graphs with mixed capacities but is reliable with
    unit capacities (D-024), so each edge of effort k becomes k parallel unit paths through
    helper nodes. The cut is then read from the residual graph and mapped back.
    """
    unit: list[tuple[str, str, tuple[str, str]]] = []
    for e in sub:
        orig = (e["src"], e["dst"])
        if e["capacity"] == 1:
            unit.append((e["src"], e["dst"], orig))
        else:
            for i in range(e["capacity"]):
                mid = f"{e['src']}>{e['dst']}#{i}"
                unit += [(e["src"], mid, orig), (mid, e["dst"], orig)]
    nodes = sorted({u for u, _, _ in unit} | {v for _, v, _ in unit})
    scratch = connect().select_graph(f"cut_{uuid.uuid4().hex[:12]}")
    try:
        scratch.query("UNWIND $rows AS k CREATE (:Node {key: k})", {"rows": nodes})
        scratch.query("CREATE INDEX FOR (n:Node) ON (n.key)")
        scratch.query("""UNWIND $rows AS e MATCH (a:Node {key: e[0]}), (b:Node {key: e[1]})
                         CREATE (a)-[:REQ {capacity: 1}]->(b)""", {"rows": [[u, v] for u, v, _ in unit]})
        try:
            started = time.perf_counter()
            res = scratch.query(cypher("max_flow_cut"), {"targets": targets}, timeout=10_000).result_set
            trace("algorithm", f"max_flow_cut on scratch graph {scratch.name} ({len(nodes)} nodes, {len(unit)} edges)",
                  cypher("max_flow_cut"), {"targets": targets}, (time.perf_counter() - started) * 1000, len(res))
            max_flow, flow_edges, flows = res[0]
            flow = {tuple(fe): f for fe, f in zip(flow_edges, flows)}
            solver = "falkordb algo.maxFlow"
        except Exception:
            flow, max_flow = _python_max_flow(unit, targets)
            solver = "python fallback (algo.maxFlow timed out)"
    finally:
        scratch.delete()

    out_e, in_e = defaultdict(list), defaultdict(list)
    for u, v, _ in unit:
        out_e[u].append(v)
        in_e[v].append(u)
    seen, queue = {"ROOT"}, deque(["ROOT"])
    while queue:
        u = queue.popleft()
        for v in out_e[u]:
            if flow.get((u, v), 0) < 1 and v not in seen:
                seen.add(v); queue.append(v)
        for w in in_e[u]:
            if flow.get((w, u), 0) > 0 and w not in seen:
                seen.add(w); queue.append(w)
    cut = {orig for u, v, orig in unit if u in seen and v not in seen}
    return cut, max_flow, solver


def _python_max_flow(unit: list, targets: list[str]) -> tuple[dict, float]:
    """Edmonds-Karp on unit edges; only used if FalkorDB's algorithm times out."""
    sink = "__SINK__"
    cap = defaultdict(int)
    adj = defaultdict(set)
    for u, v, _ in unit + [(t, sink, None) for t in targets]:
        cap[(u, v)] += 1 if v != sink else 10**6
        adj[u].add(v); adj[v].add(u)
    flow = defaultdict(int)
    total = 0
    while True:
        prev, queue = {"ROOT": None}, deque(["ROOT"])
        while queue and sink not in prev:
            u = queue.popleft()
            for v in adj[u]:
                if v not in prev and cap[(u, v)] - flow[(u, v)] > 0:
                    prev[v] = u; queue.append(v)
        if sink not in prev:
            break
        v = sink
        while prev[v] is not None:
            u = prev[v]; flow[(u, v)] += 1; flow[(v, u)] -= 1; v = u
        total += 1
    return {k: f for k, f in flow.items() if f > 0 and k[1] != sink}, float(total)


def _count_paths(out_edges: dict, targets: dict) -> int:
    """Distinct dependency chains from the repo root to any affected install (DAG; cycles cut)."""
    memo: dict[str, int] = {}

    def walk(node: str, stack: frozenset) -> int:
        if node in memo:
            return memo[node]
        total = 1 if node in targets else 0
        for e in out_edges[node]:
            if e["dst"] not in stack:
                total += walk(e["dst"], stack | {e["dst"]})
        memo[node] = total
        return total

    return walk("ROOT", frozenset({"ROOT"}))


def upgrade_plan(vuln_id: str, include_dev: bool = False) -> dict:
    """F3: per service, the cheapest set of dependency changes that removes every exposure path."""
    by_repo: dict[str, dict] = defaultdict(dict)
    for r in _rows("affected_installs", id=vuln_id, include_dev=include_dev):
        by_repo[r["repo"]][r["key"]] = {"name": r["name"], "version": r["version"],
                                        "fix": _best_fix(r["version"], r["fixed"] or [])}
    plans = [_repo_cut(repo, targets, include_dev) for repo, targets in sorted(by_repo.items())]
    return {"vulnerability": vuln_id, "include_dev": include_dev,
            "effort_scale": {"refresh": EFFORT_REFRESH, "bump_direct": EFFORT_DIRECT,
                             "override": EFFORT_OVERRIDE, "upstream": EFFORT_TRANSITIVE},
            "services": plans,
            "total_actions": sum(len(p["actions"]) for p in plans),
            "exposure_paths": sum(p["exposure_paths"] for p in plans),
            "vulnerable_links": sum(p["vulnerable_links"] for p in plans)}


def estate_plan(severities: tuple[str, ...] = ("CRITICAL", "HIGH"), include_dev: bool = False) -> dict:
    """One plan for many advisories at once: per service, a single min cut that separates the repo
    from every install any of these advisories affects, then the same change grouped across services.
    Fixing advisories together is cheaper than one by one when they share a chain (bump express once)."""
    by_repo: dict[str, dict] = defaultdict(dict)
    vulns_at: dict[tuple[str, str], set] = defaultdict(set)
    fixes: dict[tuple[str, str], list] = defaultdict(list)
    severity: dict[str, str] = {}
    for r in _rows("estate_affected_installs", severities=list(severities), include_dev=include_dev):
        k = (r["repo"], r["key"])
        vulns_at[k].add(r["vuln"])
        fixes[k].append(_best_fix(r["version"], r["fixed"] or []))
        severity[r["vuln"]] = r["severity"]
        by_repo[r["repo"]][r["key"]] = {"name": r["name"], "version": r["version"]}
    for (repo, key), fs in fixes.items():
        # one version that fixes every advisory on this install, if each advisory has a fix
        by_repo[repo][key]["fix"] = None if None in fs else max(fs, key=_version)

    # baseline: triaging one advisory at a time means one remediation per advisory per service
    one_by_one = len({(repo, v) for (repo, _), vs in vulns_at.items() for v in vs})
    changes: dict[tuple, dict] = {}
    plans = []
    for repo, targets in sorted(by_repo.items()):
        plan = _repo_cut(repo, targets, include_dev)
        edges = _rows("repo_requires_subgraph", repo=repo)
        down = defaultdict(list)
        for e in edges:
            down[e["src"]].append(e["dst"])
        for a in plan["actions"]:
            # advisories whose affected installs sit at or below the changed link
            start = next((e["dst"] for e in edges if f"{e['dst_name']}@{e['dst_version']}" == a["child"]
                         and (e["src"] == "ROOT" if a["parent"] == repo else f"{e['src_name']}@{e['src_version']}" == a["parent"])), None)
            seen, queue = ({start}, deque([start])) if start else (set(), deque())
            while queue:
                for n in down[queue.popleft()]:
                    if n not in seen:
                        seen.add(n); queue.append(n)
            closes = sorted({v for t in seen if t in targets for v in vulns_at[(repo, t)]})
            key = (a["kind"], a["parent"] if a["parent"] != repo else "", a["child"], a["fix"])
            c = changes.setdefault(key, {**{k: a[k] for k in ("kind", "effort", "child", "fix", "range")},
                                         "parent": a["parent"] if a["parent"] != repo else None,
                                         "action": a["action"].replace(repo, "the service") if a["parent"] == repo else a["action"],
                                         "services": [], "advisories": set()})
            c["services"].append(repo)
            c["advisories"].update(closes)
        plans.append({"repo": repo, "total_effort": plan["total_effort"], "actions": len(plan["actions"]),
                      "advisories": sorted({v for t in targets for v in vulns_at[(repo, t)]})})
    grouped = sorted(changes.values(), key=lambda c: (-len(c["advisories"]), -len(c["services"]), c["effort"]))
    for c in grouped:
        c["advisories"] = sorted(c["advisories"])
    return {"severities": list(severities), "include_dev": include_dev,
            "advisories": len(severity), "by_severity": {s: sum(1 for v in severity.values() if v == s) for s in severities},
            "services": plans,
            "changes": grouped,
            "total_changes": sum(len(c["services"]) for c in grouped),
            "distinct_changes": len(grouped),
            "one_by_one_fixes": one_by_one,
            "total_effort": sum(p["total_effort"] for p in plans)}


# ---------------------------------------------------------------- F8

def risk_board(limit: int = 10, include_dev: bool = False) -> list[dict]:
    """Advisories reaching production, ranked by business impact, those still needing a decision first."""
    return _rows("risk_board", include_dev=include_dev, limit=limit)


def chokepoints(limit: int = 10) -> list[dict]:
    return _rows("chokepoints", limit=limit)
