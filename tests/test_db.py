from blast_radius.db import graph


def test_falkordb_roundtrip():
    g = graph("smoke_test")
    try:
        g.query("CREATE (:Ping {ok: true})")
        result = g.query("MATCH (p:Ping) RETURN p.ok")
        assert result.result_set == [[True]]
    finally:
        g.delete()
