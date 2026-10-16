// Remember what an advisory's exposure looked like at this look, one snapshot per advisory, so the
// next investigation can say what changed (D-050). Survives rebuilds like decisions do.
MATCH (v:Vulnerability {id: $id})
MERGE (n:Investigation {vuln: $id})
SET n.at = $at, n.signatures = $signatures, n.lockfiles = $lockfiles
MERGE (n)-[:OF]->(v)
RETURN n.vuln AS vuln
