// F1: every service exposed to an advisory, with the shortest dependency chain
// from the service's repo to the affected install. Install nodes are per repo (D-022),
// so each chain is exactly how that repo resolves its dependencies.
// Evidence (D-046): the repo and lockfile the chain was read from, when that lockfile was loaded,
// the node_modules path of the affected install and the advisory's affected ranges for the package.
MATCH (v:Vulnerability {id: $id})-[a:AFFECTS]->(:PackageVersion)<-[:IS]-(i:Install)
WHERE $include_dev OR NOT i.dev
MATCH (r:Repo {name: i.repo})<-[:BUILT_FROM]-(s:Service)<-[:OWNS]-(t:Team)
OPTIONAL MATCH (v)-[c:CONCERNS]->(:Package {name: i.name})
WITH s, t, r, i, a, c, shortestPath((r)-[:REQUIRES*]->(i)) AS p
RETURN s.name AS service, s.tier AS tier, t.name AS team,
       i.name AS package, i.version AS version, i.dev AS dev_only, a.fixed AS fixed,
       length(p) AS depth,
       [n IN nodes(p)[1..] | n.name + '@' + n.version] AS chain,
       i.path AS install_path, c.ranges AS affected_ranges,
       r.source AS repo_source, r.ref AS repo_ref, r.url AS repo_url, r.lockfile AS lockfile,
       r.loaded_at AS loaded_at
ORDER BY service, depth
