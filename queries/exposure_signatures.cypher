// The exposure a decision relies on: one signature per affected install in the service
// (install path + shortest chain), production and dev alike.
MATCH (v:Vulnerability {id: $id})-[:AFFECTS]->(:PackageVersion)<-[:IS]-(i:Install {repo: $service})
MATCH (r:Repo {name: $service})
WITH i, shortestPath((r)-[:REQUIRES*]->(i)) AS p
RETURN i.path AS path, i.dev AS dev, [n IN nodes(p)[1..] | n.name + '@' + n.version] AS chain
