// F8: packages the estate leans on most (PageRank over the merged package layer),
// with how many services install them and how many advisories hit them.
CALL algo.pageRank('PackageVersion', 'DEPENDS_ON') YIELD node, score
WITH node, score ORDER BY score DESC LIMIT $limit
OPTIONAL MATCH (node)<-[:IS]-(i:Install)
OPTIONAL MATCH (node)<-[:AFFECTS]-(v:Vulnerability)
RETURN node.name AS package, node.version AS version, score,
       count(DISTINCT i.repo) AS services, count(DISTINCT v) AS advisories
ORDER BY score DESC
