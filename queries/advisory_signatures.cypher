// The production exposure of one advisory across every service, as (service, install path, chain).
// Stored as an Investigation snapshot and compared on the next look (what changed, D-050).
MATCH (v:Vulnerability {id: $id})-[:AFFECTS]->(:PackageVersion)<-[:IS]-(i:Install)
WHERE NOT i.dev
MATCH (r:Repo {name: i.repo})
WITH i, shortestPath((r)-[:REQUIRES*]->(i)) AS p
RETURN i.repo AS service, i.path AS path, [n IN nodes(p)[1..] | n.name + '@' + n.version] AS chain
