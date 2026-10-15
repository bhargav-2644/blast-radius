"""Integration tests against the loaded demo graph (run `python -m blast_radius.ingest.load` first)."""
from collections import defaultdict, deque

import pytest

from blast_radius import analysis as A
from blast_radius.db import graph

PATH_TO_REGEXP = "GHSA-9wv6-86v2-598j"   # express -> path-to-regexp, 5 services in production
PICOMATCH = "GHSA-c2c7-rcm5-vvqj"        # thousands of chains, mostly dev tooling


def _loaded() -> bool:
    try:
        return bool(graph().ro_query("MATCH (v:Vulnerability {id: $id}) RETURN v", {"id": PATH_TO_REGEXP}).result_set)
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _loaded(), reason="demo graph not loaded")


def test_exposure_paths_end_at_the_vulnerable_package():
    result = A.exposure(PATH_TO_REGEXP)
    assert result["exposed"]
    assert len(result["services"]) >= 3
    for svc in result["services"]:
        for path in svc["paths"]:
            assert path["chain"][-1] == path["package"]
            assert path["depth"] == len(path["chain"])


def test_lookup_by_alias_and_text():
    assert A.find_vulnerability(PATH_TO_REGEXP)[0]["id"] == PATH_TO_REGEXP
    hits = A.find_vulnerability("path-to-regexp backtracking")
    assert any(h["id"] == PATH_TO_REGEXP for h in hits)


def test_no_path_returns_a_safety_proof():
    vid = graph().ro_query("MATCH (v:Vulnerability) WHERE NOT (v)-[:AFFECTS]->() "
                           "AND (v)-[:CONCERNS]->(:Package)-[:HAS_VERSION]->() RETURN v.id LIMIT 1").result_set[0][0]
    result = A.exposure(vid, include_dev=True)
    assert not result["exposed"]
    proof = result["safety_proof"]
    assert proof["packages"] and all(p["installed"] for p in proof["packages"])


def test_customer_impact_reaches_through_service_calls():
    impact = A.customer_impact(PATH_TO_REGEXP)
    assert impact["by_tier"]["enterprise"] >= 1
    assert all(c["exposed_through"] for c in impact["customers"])


@pytest.mark.parametrize("vid,dev", [(PATH_TO_REGEXP, False), (PICOMATCH, True)])
def test_upgrade_cut_removes_every_exposure_path(vid, dev):
    plan = A.upgrade_plan(vid, include_dev=dev)
    affected = defaultdict(set)
    for r in A._rows("affected_installs", id=vid, include_dev=dev):
        affected[r["repo"]].add(r["key"])
    for svc in plan["services"]:
        assert svc["actions"], svc["repo"]
        edges = A._rows("repo_requires_subgraph", repo=svc["repo"])
        cut = {(a["parent"], a["child"]) for a in svc["actions"]}
        label = lambda e: (svc["repo"] if e["src"] == "ROOT" else f"{e['src_name']}@{e['src_version']}",
                           f"{e['dst_name']}@{e['dst_version']}")
        out = defaultdict(list)
        for e in edges:
            if label(e) not in cut:
                out[e["src"]].append(e["dst"])
        seen, queue = {"ROOT"}, deque(["ROOT"])
        while queue:
            for nxt in out[queue.popleft()]:
                if nxt not in seen:
                    seen.add(nxt); queue.append(nxt)
        assert not (seen & affected[svc["repo"]]), f"{svc['repo']} still exposed after the plan"
