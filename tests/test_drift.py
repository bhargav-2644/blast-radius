"""Simulated deploy (F6): swapping one service's lockfile in place makes a decision drift, and a
rollback brings it back. Runs against the loaded demo graph."""
import pytest

from blast_radius import analysis as A
from blast_radius import memory
from blast_radius.db import graph
from blast_radius.ingest.load import DATA, redeploy

from test_analysis import PATH_TO_REGEXP, _loaded

pytestmark = pytest.mark.skipif(not _loaded(), reason="demo graph not loaded")
SCENARIO = DATA / "scenarios/storefront-adds-koa-router.json.gz"
ORIGINAL = DATA / "lockfiles/storefront.json.gz"


def _counts():
    return graph().ro_query("MATCH (n) WHERE NOT n:Decision RETURN labels(n)[0], count(n) ORDER BY 1").result_set


def _status(decision_id):
    return graph().ro_query("MATCH (d:Decision {id: $id}) RETURN d.status", {"id": decision_id}).result_set[0][0]


def test_deploy_makes_a_decision_stale_and_rollback_restores_it():
    before = _counts()
    d = memory.record_decision(PATH_TO_REGEXP, "storefront", "risk_accepted", "test", "Priya")["decision"]
    try:
        r = redeploy("storefront", SCENARIO)
        drifted = {x["decision"]: x for x in r["drift"]}
        assert d in drifted
        assert any("@koa/router" in p for p in drifted[d]["new_paths"])
        assert _status(d) == "stale"
        chains = [p["chain"] for s in A.exposure(PATH_TO_REGEXP)["services"] if s["service"] == "storefront"
                  for p in s["paths"]]
        assert any(c[0].startswith("@koa/router") for c in chains)

        r = redeploy("storefront", ORIGINAL)
        assert d in [x["decision"] for x in r["recovered"]]
        assert _status(d) == "current"
        assert _counts() == before
    finally:
        graph().query("MATCH (d:Decision {id: $id}) DETACH DELETE d", {"id": d})
        redeploy("storefront", ORIGINAL)
