"""Public-demo guards on writes to the shared graph (D-052): length caps and a per-IP hourly limit.
No graph needed: every request here is rejected before anything is written."""
from fastapi.testclient import TestClient

from blast_radius import web

client = TestClient(web.app)
DECISION = {"vulnerability_id": "GHSA-jqcg-44mw-7w3h", "service": "storefront", "verdict": "bogus",
            "reason": "test", "person": "Priya"}


def test_oversized_fields_are_rejected():
    assert client.post("/api/decisions", json={**DECISION, "reason": "x" * 1001}).status_code == 422
    assert client.post("/api/decisions", json={**DECISION, "person": ""}).status_code == 422
    assert client.post("/api/advisory/X/not_affected", json={"person": "p" * 81}).status_code == 422
    assert client.post("/api/run", json={"message": "q" * 4001}).status_code == 422


def test_writes_are_limited_per_ip(monkeypatch):
    monkeypatch.setattr(web, "WRITES_PER_HOUR_PER_IP", 2)
    monkeypatch.setattr(web, "writes", [])
    me, other = {"X-Forwarded-For": "203.0.113.7"}, {"X-Forwarded-For": "203.0.113.8"}
    codes = [client.post("/api/decisions", json=DECISION, headers=me).status_code for _ in range(3)]
    assert codes == [400, 400, 429]  # the first two reach validation (bad verdict), the third is refused
    assert client.post("/api/decisions", json=DECISION, headers=other).status_code == 400
