"""Episodic memory (D-029) survives a full graph rebuild, with its links to cited nodes (D-044)."""
import uuid

import pytest

from blast_radius import memory
from blast_radius.db import graph
from blast_radius.ingest.load import build

from test_analysis import PATH_TO_REGEXP, _loaded

pytestmark = pytest.mark.skipif(not _loaded(), reason="demo graph not loaded")


def _cited(session_id):
    return graph().ro_query("""MATCH (:Session {id: $id})-[:ASKED]->(q:Question)
                               OPTIONAL MATCH (q)-[:CITED]->(n)
                               RETURN q.text, q.at, collect(coalesce(n.id, n.name))""", {"id": session_id}).result_set


def test_sessions_and_questions_survive_a_rebuild():
    sid = f"S-test-{uuid.uuid4().hex[:6]}"
    memory.log_turn(sid, "Are we affected?", "Yes, storefront.", [
        {"tool": "exposure", "input": {"vulnerability_id": PATH_TO_REGEXP}},
        {"tool": "customers", "input": {"service": "storefront"}},
    ])
    before = _cited(sid)
    try:
        stats = build()
        assert stats["questions_restored"] >= 1
        after = _cited(sid)
        assert [(t, a, sorted(c)) for t, a, c in after] == [(t, a, sorted(c)) for t, a, c in before]
        assert sorted(after[0][2]) == sorted([PATH_TO_REGEXP, "storefront"])
    finally:
        graph().query("MATCH (s:Session {id: $id}) OPTIONAL MATCH (s)-[:ASKED]->(q) DETACH DELETE s, q", {"id": sid})
