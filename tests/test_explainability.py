"""Evidence on exposure paths (D-046), explained precedent (D-047), verified plan steps (D-048),
the risk breakdown (D-049) and what changed since the last investigation (D-050)."""
import pytest

from blast_radius import analysis as A
from blast_radius import memory
from blast_radius.db import graph
from blast_radius.ingest.load import DATA, build, redeploy

from test_analysis import PATH_TO_REGEXP, _loaded

pytestmark = pytest.mark.skipif(not _loaded(), reason="demo graph not loaded")
FORM_DATA = "GHSA-fjxv-7rqg-78g4"   # demo CVE-2025-7783; its fix 4.0.4 is still hit by GHSA-hmw2-7cc7-3qxx
SCENARIO = DATA / "scenarios/storefront-adds-koa-router.json.gz"
ORIGINAL = DATA / "lockfiles/storefront.json.gz"


@pytest.fixture
def clean():
    made = []
    graph().query("MATCH (n:Investigation {vuln: $id}) DETACH DELETE n", {"id": PATH_TO_REGEXP})
    yield made
    graph().query("MATCH (d:Decision) WHERE d.id IN $ids DETACH DELETE d", {"ids": made})
    graph().query("MATCH (n:Investigation {vuln: $id}) DETACH DELETE n", {"id": PATH_TO_REGEXP})
    redeploy("storefront", ORIGINAL)


def test_every_exposure_path_carries_its_evidence():
    ex = A.exposure(FORM_DATA)
    assert ex["advisory_source"]["url"].endswith(FORM_DATA) and ex["advisory_source"]["snapshot"]
    for s in ex["services"]:
        assert s["repo"]["lockfile"] == f"{s['service']}.json.gz" and s["repo"]["source"] and s["repo"]["last_seen"]
        for p in s["paths"]:
            assert p["install_path"].endswith("node_modules/" + p["package"].rsplit("@", 1)[0])
            assert p["affected_ranges"]


def test_plan_steps_are_verified_and_a_fix_hit_by_another_advisory_is_raised():
    plan = A.upgrade_plan(FORM_DATA)
    actions = [a for s in plan["services"] for a in s["actions"]]
    assert sum(plan["verification"].values()) == len(actions)
    for a in actions:
        if a["fix"] is None:
            assert a["verification"]["status"] == "unverified"
        if a["child"].startswith("form-data@4."):
            assert a["fix"] == "4.0.6" and a["verification"]["status"] == "verified"
            assert any("GHSA-hmw2-7cc7-3qxx" in c["detail"] for c in a["verification"]["checks"])


def test_risk_breakdown_adds_up_to_the_board_score():
    r = A.risk_breakdown(FORM_DATA)
    assert r["score"] == r["severity_weight"] * (r["customer_weight"] + r["services"])
    assert r["breakdown"]["formula"].endswith(f"= {r['score']}")
    scored = [f["factor"] for f in r["breakdown"]["factors"] if f["in_score"]]
    assert scored == ["Severity", "Customers reached", "Services exposed"]
    board = {x["id"]: x["score"] for x in A.risk_board(limit=200)}
    assert board[FORM_DATA] == r["score"]


def test_precedent_explains_coverage_and_exposure_change(clean):
    clean.append(memory.record_decision(PATH_TO_REGEXP, "storefront", "risk_accepted", "internal routes", "Priya")["decision"])
    p = next(x for x in memory.recall_precedent(PATH_TO_REGEXP) if x["decision"] == clean[0])
    assert p["by"] == "Priya" and p["covers"]["services"] == ["storefront"] and not p["exposure"]["changed"]
    redeploy("storefront", SCENARIO)
    p = next(x for x in memory.recall_precedent(PATH_TO_REGEXP) if x["decision"] == clean[0])
    assert p["exposure"]["changed"] and any("@koa/router" in c for c in p["exposure"]["new_paths"])


def test_what_changed_since_the_last_investigation(clean):
    first = memory.what_changed(PATH_TO_REGEXP)
    assert first["first_look"] and first["paths_now"] >= 1
    clean.append(memory.record_decision(PATH_TO_REGEXP, "storefront", "risk_accepted", "internal routes", "Priya")["decision"])
    assert not memory.what_changed(PATH_TO_REGEXP)["changed"]

    redeploy("storefront", SCENARIO)
    c = memory.what_changed(PATH_TO_REGEXP)
    assert c["changed"] and any("@koa/router" in p for p in c["new_paths"])
    assert c["lockfiles_changed"] == [{"service": "storefront", "before": "storefront.json.gz",
                                       "after": SCENARIO.name}]
    assert set(clean) <= {d["decision"] for d in c["decisions_gone_stale"]}

    redeploy("storefront", ORIGINAL)
    back = memory.what_changed(PATH_TO_REGEXP)
    assert any("@koa/router" in p for p in back["removed_paths"])

    build()  # the snapshot outlives a full rebuild, like decisions do
    assert not memory.what_changed(PATH_TO_REGEXP)["first_look"]
