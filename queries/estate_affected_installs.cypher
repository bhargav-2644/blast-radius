// Input to the estate-wide cut: every production install hit by any advisory of the given
// severities, with the advisory and its fixed versions (one row per install × advisory).
MATCH (v:Vulnerability)-[a:AFFECTS]->(:PackageVersion)<-[:IS]-(i:Install)
WHERE v.severity IN $severities AND ($include_dev OR NOT i.dev)
RETURN i.repo AS repo, i.key AS key, i.name AS name, i.version AS version,
       v.id AS vuln, v.severity AS severity, a.fixed AS fixed
