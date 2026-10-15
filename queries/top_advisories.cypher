// Landing view: advisories reaching the most services (production dependencies unless $include_dev).
MATCH (v:Vulnerability)-[:AFFECTS]->(:PackageVersion)<-[:IS]-(i:Install)
WHERE $include_dev OR NOT i.dev
WITH v, count(DISTINCT i.repo) AS services
RETURN v.id AS id, v.severity AS severity, v.summary AS summary, v.aliases AS aliases, services
ORDER BY CASE v.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MODERATE' THEN 2 ELSE 3 END, services DESC
LIMIT $limit
