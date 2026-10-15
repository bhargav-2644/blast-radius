// F1: every service exposed to an advisory, with the shortest dependency chain
// from the service's repo to the affected install. Install nodes are per repo (D-022),
// so each chain is exactly how that repo resolves its dependencies.
MATCH (v:Vulnerability {id: $id})-[a:AFFECTS]->(:PackageVersion)<-[:IS]-(i:Install)
WHERE $include_dev OR NOT i.dev
MATCH (r:Repo {name: i.repo})<-[:BUILT_FROM]-(s:Service)<-[:OWNS]-(t:Team)
WITH s, t, r, i, a, shortestPath((r)-[:REQUIRES*]->(i)) AS p
RETURN s.name AS service, s.tier AS tier, t.name AS team,
       i.name AS package, i.version AS version, i.dev AS dev_only, a.fixed AS fixed,
       length(p) AS depth,
       [n IN nodes(p)[1..] | n.name + '@' + n.version] AS chain
ORDER BY service, depth
