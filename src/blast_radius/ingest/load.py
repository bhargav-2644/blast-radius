"""Build the Blast Radius graph: company layer + dependency trees + OSV advisories.

Run: uv run python -m blast_radius.ingest.load
The load is idempotent: it drops and rebuilds the graph from the committed data files.
"""
import gzip
import json
import time
from pathlib import Path

from blast_radius import config
from blast_radius.db import graph
from blast_radius.ingest import lockfile, osv

ROOT = Path(__file__).resolve().parents[3]
DATA = ROOT / "data"
BATCH = 2000


def _batched(rows: list[dict], size: int = BATCH):
    for i in range(0, len(rows), size):
        yield rows[i : i + size]


def _run(g, query: str, rows: list[dict]):
    for chunk in _batched(rows):
        g.query(query, {"rows": chunk})


def build(osv_zip: Path = DATA / "raw/npm-osv.zip") -> dict:
    started = time.time()
    company = json.loads((DATA / "company.json").read_text())
    g = graph()
    try:
        g.delete()
    except Exception:
        pass  # graph did not exist yet
    g = graph()

    for q in [
        "CREATE INDEX FOR (n:PackageVersion) ON (n.purl)",
        "CREATE INDEX FOR (n:Package) ON (n.name)",
        "CREATE INDEX FOR (n:Vulnerability) ON (n.id)",
        "CREATE INDEX FOR (n:Service) ON (n.name)",
        "CREATE INDEX FOR (n:Repo) ON (n.name)",
        "CREATE INDEX FOR (n:Customer) ON (n.name)",
        "CREATE INDEX FOR (n:Install) ON (n.key)",
    ]:
        g.query(q)
    g.query("CALL db.idx.fulltext.createNodeIndex('Vulnerability', 'summary', 'id')")

    # --- company layer (synthetic, D-006)
    _run(g, """UNWIND $rows AS t
               CREATE (team:Team {name: t.name, synthetic: true})
               WITH team, t UNWIND t.people AS p
               CREATE (:Person {name: p, synthetic: true})-[:MEMBER_OF]->(team)""", company["teams"])
    _run(g, """UNWIND $rows AS s
               MATCH (team:Team {name: s.team})
               CREATE (team)-[:OWNS]->(svc:Service {name: s.name, tier: s.tier})
                      -[:BUILT_FROM]->(:Repo {name: s.name, source: s.repo, ref: s.ref,
                                              url: 'https://github.com/' + s.repo + '/tree/' + s.ref})""",
         company["services"])
    _run(g, """UNWIND $rows AS c
               MATCH (a:Service {name: c[0]}), (b:Service {name: c[1]})
               CREATE (a)-[:CALLS]->(b)""", company["calls"])
    _run(g, """UNWIND $rows AS c
               CREATE (cust:Customer {name: c.name, tier: c.tier, synthetic: true})
               WITH cust, c UNWIND c.uses AS s
               MATCH (svc:Service {name: s}) CREATE (cust)-[:USES]->(svc)""", company["customers"])

    # --- dependency trees (real, D-004).
    # Two layers (D-022):
    #   Install: one node per node_modules path in one repo. REQUIRES edges are exact per repo,
    #            so exposure paths and the max-flow cut never mix up two repos' resolutions.
    #   PackageVersion: one node per name@version across the estate. DEPENDS_ON edges merge all
    #            repos, which is what chokepoint analysis (PageRank / betweenness) needs.
    pkgs: dict[str, dict] = {}
    edges: dict[tuple[str, str], dict] = {}
    installs, root_reqs, install_reqs = [], [], []
    for svc in company["services"]:
        lock = json.loads(gzip.decompress((DATA / "lockfiles" / f"{svc['name']}.json.gz").read_bytes()))
        tree = lockfile.parse(lock)
        for p in tree.packages:
            pkgs[p.purl] = {"purl": p.purl, "name": p.name, "version": p.version}
        for parent, child, rng in tree.edges:
            edges.setdefault((parent.purl, child.purl), {"src": parent.purl, "dst": child.purl, "range": rng})
        key = lambda path: f"{svc['name']}|{path}"
        for path, p in tree.installs.items():
            installs.append({"key": key(path), "repo": svc["name"], "path": path, "name": p.name,
                             "version": p.version, "purl": p.purl, "dev": tree.install_dev[path]})
        # one REQUIRES edge per (parent, child): algo.maxFlow rejects parallel edges
        direct: dict[str, dict] = {}
        for path, rng, dev in tree.root_installs:
            row = direct.setdefault(path, {"repo": svc["name"], "key": key(path), "range": rng, "dev": dev})
            row["dev"] = row["dev"] and dev
        root_reqs.extend(direct.values())
        seen = set()
        for a, b, rng in sorted(tree.install_edges):
            if (a, b) not in seen:
                seen.add((a, b))
                install_reqs.append({"src": key(a), "dst": key(b), "range": rng})

    _run(g, """UNWIND $rows AS p
               MERGE (pkg:Package {name: p.name})
               CREATE (pkg)-[:HAS_VERSION]->(:PackageVersion {purl: p.purl, name: p.name, version: p.version})""",
         list(pkgs.values()))
    _run(g, """UNWIND $rows AS e
               MATCH (a:PackageVersion {purl: e.src}), (b:PackageVersion {purl: e.dst})
               CREATE (a)-[:DEPENDS_ON {range: e.range}]->(b)""", list(edges.values()))
    _run(g, """UNWIND $rows AS i
               MATCH (pv:PackageVersion {purl: i.purl})
               CREATE (:Install {key: i.key, repo: i.repo, path: i.path, name: i.name,
                                 version: i.version, dev: i.dev})-[:IS]->(pv)""", installs)
    _run(g, """UNWIND $rows AS r
               MATCH (repo:Repo {name: r.repo}), (i:Install {key: r.key})
               CREATE (repo)-[:REQUIRES {range: r.range, dev: r.dev, direct: true, capacity: 1}]->(i)""", root_reqs)
    _run(g, """UNWIND $rows AS e
               MATCH (a:Install {key: e.src}), (b:Install {key: e.dst})
               CREATE (a)-[:REQUIRES {range: e.range, direct: false, capacity: 1}]->(b)""", install_reqs)

    # --- advisories matched at ingest (D-005)
    names = {p["name"] for p in pkgs.values()}
    index = osv.load_index(osv_zip, names)
    # Every advisory that concerns a package we install becomes a node with CONCERNS -> Package,
    # even when no installed version is affected: that is what lets "no path" be proven (F4).
    vulns: dict[str, dict] = {}
    concerns: dict[tuple[str, str], dict] = {}
    affects = []
    for name in sorted(names):
        for adv in index.get(name, []):
            vulns[adv.id] = {"id": adv.id, "aliases": adv.aliases, "summary": adv.summary,
                             "severity": adv.severity or "UNKNOWN", "published": adv.published}
            concerns[(adv.id, name)] = {"id": adv.id, "name": name, "ranges": adv.describe_ranges(name)}
    for p in pkgs.values():
        for adv in index.get(p["name"], []):
            if adv.affects(p["name"], p["version"]):
                affects.append({"id": adv.id, "purl": p["purl"], "fixed": adv.fixed_versions(p["name"])})
    _run(g, """UNWIND $rows AS v
               CREATE (:Vulnerability {id: v.id, aliases: v.aliases, summary: v.summary,
                                       severity: v.severity, published: v.published})""", list(vulns.values()))
    _run(g, """UNWIND $rows AS c
               MATCH (v:Vulnerability {id: c.id}), (pkg:Package {name: c.name})
               CREATE (v)-[:CONCERNS {ranges: c.ranges}]->(pkg)""", list(concerns.values()))
    _run(g, """UNWIND $rows AS a
               MATCH (v:Vulnerability {id: a.id}), (pv:PackageVersion {purl: a.purl})
               CREATE (v)-[:AFFECTS {fixed: a.fixed}]->(pv)""", affects)

    stats = {
        "graph": config.GRAPH_NAME,
        "services": len(company["services"]),
        "package_versions": len(pkgs),
        "installs": len(installs),
        "requires_edges": len(root_reqs) + len(install_reqs),
        "package_dependency_edges": len(edges),
        "vulnerabilities": len(vulns),
        "vulnerabilities_affecting_installed": len({a["id"] for a in affects}),
        "affects_edges": len(affects),
        "seconds": round(time.time() - started, 1),
    }
    return stats


if __name__ == "__main__":
    print(json.dumps(build(), indent=1))
