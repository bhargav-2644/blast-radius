// Affected installs per repo for one advisory, with fixed versions.
MATCH (v:Vulnerability {id: $id})-[a:AFFECTS]->(:PackageVersion)<-[:IS]-(i:Install)
WHERE $include_dev OR NOT i.dev
RETURN i.repo AS repo, i.key AS key, i.name AS name, i.version AS version, a.fixed AS fixed
