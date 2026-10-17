"""Blast Radius MCP server: the graph tools, served over MCP (D-011, D-016).

The agent reaches every tool through this server, and so can any MCP client
(e.g. Claude Desktop): `uv run python -m blast_radius.mcp_server`.
"""
import functools
import json
import time

from mcp.server.mcpserver import MCPServer

from blast_radius import analysis, memory

server = MCPServer(
    name="blast-radius",
    instructions=(
        "Tools over a FalkorDB graph of Acme Cloud's services, their full npm dependency trees, "
        "known advisories (OSV), customers, and past triage decisions. Every answer should cite "
        "the dependency chains or installed versions the tools return."
    ),
)

MAX_PATHS_PER_SERVICE = 3


def _json(data) -> str:
    return json.dumps(data, indent=1, default=str)


def traced(fn):
    """Attach the graph queries a tool ran (`_trace`) to its JSON result. The agent strips it before
    the model sees the result and streams it to the UI instead."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        token = analysis.TRACE.set([])
        started = time.perf_counter()
        try:
            out = json.loads(fn(*args, **kwargs))
        finally:
            log = analysis.TRACE.get()
            analysis.TRACE.reset(token)
        return _json({"result": out, "_trace": log, "_ms": round((time.perf_counter() - started) * 1000, 1)})
    return wrapper


@server.tool()
@traced
def find_vulnerability(query: str) -> str:
    """Resolve an advisory reference to graph ids. Accepts a GHSA id, a CVE id, or words from the
    advisory summary (e.g. "lodash prototype pollution"). Returns up to 5 matches with severity."""
    return _json(analysis.find_vulnerability(query))


@server.tool()
@traced
def find_exposure(vulnerability_id: str, include_dev: bool = False) -> str:
    """Which services are exposed to an advisory, and through which dependency chain.
    Production dependencies only unless include_dev is true. If nothing is exposed, returns a
    safety proof: every installed version of the concerned packages next to the affected ranges."""
    result = analysis.exposure(vulnerability_id, include_dev)
    for svc in result["services"]:
        total = len(svc["paths"])
        svc["paths"] = svc["paths"][:MAX_PATHS_PER_SERVICE]
        if total > MAX_PATHS_PER_SERVICE:
            svc["more_paths"] = total - MAX_PATHS_PER_SERVICE
    return _json(result)


@server.tool()
@traced
def customer_impact(vulnerability_id: str, include_dev: bool = False) -> str:
    """Customers affected by an advisory: those using an exposed service directly or through
    service-to-service calls (up to 3 hops), grouped by customer tier."""
    return _json(analysis.customer_impact(vulnerability_id, include_dev))


@server.tool()
@traced
def upgrade_plan(vulnerability_id: str, include_dev: bool = False) -> str:
    """The least-effort set of dependency changes, per service, that removes every exposure path
    (a min cut computed with FalkorDB's max-flow). Also reports how many distinct exposure chains
    the plan removes."""
    return _json(analysis.upgrade_plan(vulnerability_id, include_dev))


@server.tool()
@traced
def estate_plan(include_dev: bool = False) -> str:
    """One fix plan for every CRITICAL and HIGH advisory at once: per service, a single min cut
    (FalkorDB max-flow) that removes every path to any of them, then identical changes grouped
    across services and ranked by how many advisories each addresses. Compare total_changes with
    one_by_one_fixes to show what fixing together saves. Slow (several seconds)."""
    return _json(analysis.estate_plan(include_dev=include_dev))


@server.tool()
@traced
def risk_board(limit: int = 10, include_dev: bool = False) -> str:
    """What to look at first: advisories that reach production, ranked by severity times the
    customers they reach (enterprise customers weigh most) and services, with each one's triage
    status from decision memory (untriaged, partly triaged, triaged, stale). Untriaged first."""
    return _json(analysis.risk_board(limit, include_dev))


@server.tool()
@traced
def risk_breakdown(vulnerability_id: str, include_dev: bool = False) -> str:
    """Why one advisory is urgent: its risk score and every factor behind it (severity, customers
    reached by tier, services exposed), plus context that is shown but not scored (critical services,
    affected installs and direct dependencies, reachability, whether a fixed version exists).
    Cite these factors rather than giving an unexplained priority."""
    return _json(analysis.risk_breakdown(vulnerability_id, include_dev))


@server.tool()
@traced
def what_changed(vulnerability_id: str) -> str:
    """What changed in this advisory's production exposure since the last time anyone investigated it:
    services newly exposed or no longer exposed, paths added or removed, changed versions on a path,
    lockfiles swapped by deploys, and decisions that went stale in between. Saves today's exposure as
    the new baseline, so call it once per investigation, after find_exposure."""
    return _json(memory.what_changed(vulnerability_id))


@server.tool()
@traced
def chokepoints(limit: int = 10) -> str:
    """Packages the whole estate depends on most (PageRank over the package graph), with how many
    services install each and how many advisories affect it."""
    return _json(analysis.chokepoints(limit))


@server.tool()
@traced
def record_decision(vulnerability_id: str, service: str, verdict: str, reason: str, person: str) -> str:
    """Store a triage decision in the graph so it is reused later. verdict is one of
    not_affected, risk_accepted, fix_planned, fixed. The decision remembers the exact exposure
    paths it was made against, so it can be reopened if new paths appear, and it supersedes any
    earlier decision on the same advisory and service. A `fixed` decision while exposure paths remain
    is recorded as disputed; a fix is verified once the graph shows no path."""
    return _json(memory.record_decision(vulnerability_id, service, verdict, reason, person))


@server.tool()
@traced
def recall_precedent(vulnerability_id: str) -> str:
    """Past decisions about this advisory, about other advisories on the same package, or about
    advisories reached through the same dependency chain (`match`, `via`), with who made them, why,
    the earlier decisions each one replaced, and what the graph says about them now: current, stale
    (new path since), disputed (says fixed, still exposed) or verified (fix confirmed, no path left)."""
    return _json(memory.recall_precedent(vulnerability_id))


@server.tool()
@traced
def check_drift() -> str:
    """Re-check every decision in force against today's dependency graph and return each one whose
    status changed: `stale` (a new exposure path appeared), `disputed` (recorded as fixed but paths
    remain), `verified` (a planned or claimed fix left no exposure path) or `current` again."""
    return _json(memory.recheck())


@server.tool()
@traced
def draft_issue(vulnerability_id: str, service: str) -> str:
    """Draft a GitHub issue (title and markdown body) with the exposure paths and upgrade plan for
    one service. This only drafts: opening the issue needs a human's approval in the app."""
    exposure = analysis.exposure(vulnerability_id, include_dev=True)
    plan = analysis.upgrade_plan(vulnerability_id, include_dev=True)
    svc = next((s for s in exposure["services"] if s["service"] == service), None)
    cut = next((p for p in plan["services"] if p["repo"] == service), None)
    if not svc or not cut:
        return _json({"error": f"{service} is not exposed to {vulnerability_id}"})
    src, repo = exposure["advisory_source"], svc["repo"]
    lines = [f"**{vulnerability_id}** reaches `{service}` (team {svc['team']}).", "",
             f"Evidence: lockfile `{repo['lockfile']}` from [{repo['source']}@{repo['ref']}]({repo['url']}), "
             f"loaded {repo['last_seen'] or 'at an unrecorded time'}; advisory from [{src['source']}]({src['url']}), "
             f"snapshot {src['snapshot']}.", "", "### Exposure paths"]
    lines += [f"- `{service}` → " + " → ".join(f"`{c}`" for c in p["chain"]) + (" _(dev only)_" if p["dev_only"] else "")
              + f" (at `{p['install_path']}`, affected `{' | '.join(p['affected_ranges'])}`)"
              for p in svc["paths"][:5]]
    lines += ["", f"### Plan ({cut['exposure_paths']} exposure chains removed)"]
    for a in cut["actions"]:
        lines.append(f"- [ ] {a['action']} _({a['verification']['status']})_")
        lines += [f"  - {'✓' if c['ok'] else '✗' if c['ok'] is False else '? unverified:'} {c['detail']}"
                  for c in a["verification"]["checks"]]
    lines += ["", "_Generated by Blast Radius from the dependency graph._"]
    return _json({"title": f"[{service}] Remediate {vulnerability_id}", "body": "\n".join(lines)})


if __name__ == "__main__":
    server.run("stdio")
