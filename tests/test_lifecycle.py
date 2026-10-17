"""Decision lifecycle (D-051): a newer decision supersedes the older one, a fixed claim the graph
contradicts is disputed, a fix is verified once a deploy removes every path, and all of it survives a
rebuild. Runs against the loaded demo graph."""
import pytest

from blast_radius import analysis as A
from blast_radius import memory
from blast_radius.db import graph
from blast_radius.ingest.load import DATA, build, redeploy

from test_analysis import _loaded

pytestmark = pytest.mark.skipif(not _loaded(), reason="demo graph not loaded")
PROXY_ADDR = "GHSA-jqcg-44mw-7w3h"   # CRITICAL; storefront reaches it only through express → proxy-addr@2.0.7
FIXED = DATA / "scenarios/storefront-fixes-proxy-addr.json.gz"
ORIGINAL = DATA / "lockfiles/storefront.json.gz"


@pytest.fixture
def decisions():
    made = []
    yield made
    graph().query("MATCH (d:Decision) WHERE d.id IN $ids DETACH DELETE d", {"ids": made})


def _decide(made, verdict, person="Priya"):
    d = memory.record_decision(PROXY_ADDR, "storefront", verdict, f"test {verdict}", person)
    made.append(d["decision"])
    return d


def _state(decision_id):
    return graph().ro_query("""MATCH (d:Decision {id: $id}) OPTIONAL MATCH (n:Decision)-[:SUPERSEDES]->(d)
                               RETURN d.status, d.superseded_by, n.id""", {"id": decision_id}).result_set[0]


def test_a_newer_decision_supersedes_the_older_one(decisions):
    old = _decide(decisions, "risk_accepted")
    new = _decide(decisions, "fix_planned", "Arjun")
    assert new["supersedes"] == [old["decision"]]
    assert _state(old["decision"]) == ["superseded", new["decision"], new["decision"]]
    recalled = [p for p in memory.recall_precedent(PROXY_ADDR) if p["service"] == "storefront"]
    assert [p["decision"] for p in recalled] == [new["decision"]]
    assert [(o["verdict"], o["by"]) for o in recalled[0]["replaces"]] == [("risk_accepted", "Priya")]


def test_fixed_while_still_exposed_is_disputed(decisions):
    d = _decide(decisions, "fixed")
    assert d["status"] == "disputed" and "proxy-addr@2.0.7" in d["status_reason"]
    assert A.risk_breakdown(PROXY_ADDR)["triage"] == "disputed"


def test_a_deploy_that_removes_every_path_verifies_the_fix(decisions):
    planned = _decide(decisions, "fix_planned")
    assert planned["status"] == "current"
    try:
        r = redeploy("storefront", FIXED)
        assert {"decision": planned["decision"], "status": "verified"}.items() <= \
            next(x for x in r["recovered"] if x["decision"] == planned["decision"]).items()
        assert "storefront" not in {s["service"] for s in A.exposure(PROXY_ADDR)["services"]}
        r = redeploy("storefront", ORIGINAL)  # the fix is rolled back: the plan is open again
        assert _state(planned["decision"])[0] == "current"
        claimed = _decide(decisions, "fixed")  # claimed before the deploy lands: disputed until it does
        assert claimed["status"] == "disputed"
        r = redeploy("storefront", FIXED)
        assert ("disputed", "verified") in {(x["was"], x["status"]) for x in r["recovered"]}
    finally:
        redeploy("storefront", ORIGINAL)
    assert _state(claimed["decision"])[0] == "disputed"


def test_lifecycle_survives_a_rebuild(decisions):
    old = _decide(decisions, "risk_accepted")
    new = _decide(decisions, "fixed", "Arjun")
    build()
    assert _state(old["decision"]) == ["superseded", new["decision"], new["decision"]]
    assert _state(new["decision"])[0] == "disputed"
