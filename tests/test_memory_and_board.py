"""Risk board, estate-wide plan, path precedent and not-affected records, against the demo graph."""
import pytest

from blast_radius import analysis as A
from blast_radius import memory
from blast_radius.db import graph

from test_analysis import PATH_TO_REGEXP, _loaded

pytestmark = pytest.mark.skipif(not _loaded(), reason="demo graph not loaded")
PROXY_ADDR = "GHSA-jqcg-44mw-7w3h"   # reaches storefront through express, like path-to-regexp
MS = "GHSA-3fx5-fwvr-xrjg"           # ms ReDoS: installed everywhere, never an affected version


@pytest.fixture
def decisions():
    made = []
    yield made
    graph().query("MATCH (d:Decision) WHERE d.id IN $ids DETACH DELETE d", {"ids": made})


def test_risk_board_ranks_untriaged_by_business_impact():
    rows = A.risk_board(limit=50)
    assert rows and all(r["services"] >= 1 for r in rows)
    untriaged = [r for r in rows if r["triage"] != "triaged"]
    assert [r["score"] for r in untriaged] == sorted((r["score"] for r in untriaged), reverse=True)


def test_precedent_through_a_shared_dependency_chain(decisions):
    decisions.append(memory.record_decision(PATH_TO_REGEXP, "storefront", "risk_accepted", "t", "Priya")["decision"])
    hits = [p for p in memory.recall_precedent(PROXY_ADDR) if p["decision"] == decisions[0]]
    assert hits and hits[0]["match"] == "path" and "express" in hits[0]["via"]


def test_not_affected_records_the_proof_and_refuses_when_exposed(decisions):
    r = memory.record_not_affected(MS, "Priya")
    decisions.extend(r["decisions"])
    assert r["services"] and "Proof of safety" in r["reason"]
    with pytest.raises(ValueError):
        memory.record_not_affected(PATH_TO_REGEXP, "Priya")


def test_estate_plan_covers_every_critical_and_high_advisory():
    plan = A.estate_plan()
    covered = {v for c in plan["changes"] for v in c["advisories"]}
    assert plan["advisories"] == len(covered)
    assert plan["total_changes"] <= plan["one_by_one_fixes"]
