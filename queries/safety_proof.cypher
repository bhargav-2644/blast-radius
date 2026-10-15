// F4: when no path exists, show what was searched: every installed version of the
// packages the advisory concerns, and in which services, next to the affected ranges.
MATCH (v:Vulnerability {id: $id})-[c:CONCERNS]->(pkg:Package)
OPTIONAL MATCH (pkg)-[:HAS_VERSION]->(pv:PackageVersion)<-[:IS]-(i:Install)
WITH pkg, c, pv, collect(DISTINCT i.repo) AS repos
RETURN pkg.name AS package, c.ranges AS affected_ranges,
       collect(CASE WHEN pv IS NULL THEN NULL ELSE {version: pv.version, services: repos} END) AS installed
