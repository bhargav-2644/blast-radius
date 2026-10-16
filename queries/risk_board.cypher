// Risk board: every advisory that reaches production, ranked by what it means for the business
// rather than by severity alone. Score = severity weight × (tier-weighted customers reached + services),
// where customers are reached directly or through up to 3 service calls (as in customer_impact).
// Triage status comes from decision memory: which exposed services already have a decision, and
// whether any of those decisions has gone stale.
MATCH (v:Vulnerability)-[:AFFECTS]->(:PackageVersion)<-[:IS]-(i:Install)
WHERE $include_dev OR NOT i.dev
WITH v, collect(DISTINCT i.repo) AS repos
MATCH (r:Repo)<-[:BUILT_FROM]-(exposed:Service) WHERE r.name IN repos
WITH v, collect(DISTINCT exposed) AS services
UNWIND services AS exposed
OPTIONAL MATCH (c:Customer)-[:USES]->(:Service)-[:CALLS*0..3]->(exposed)
WITH v, services, collect(DISTINCT c) AS customers
OPTIONAL MATCH (d:Decision)-[:ABOUT]->(v), (d)-[:FOR]->(ds:Service) WHERE ds IN services
WITH v, services, customers, collect(DISTINCT ds.name) AS decided,
     toInteger(sum(CASE WHEN d.status = 'stale' THEN 1 ELSE 0 END)) AS stale
WITH v, services, customers, decided, stale,
     CASE v.severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MODERATE' THEN 2 ELSE 1 END AS sev,
     reduce(w = 0, c IN customers | w + CASE c.tier WHEN 'enterprise' THEN 5 WHEN 'business' THEN 3 ELSE 1 END) AS weight
RETURN v.id AS id, v.severity AS severity, v.summary AS summary, v.aliases AS aliases,
       size(services) AS services, size(customers) AS customers,
       size([c IN customers WHERE c.tier = 'enterprise']) AS enterprise,
       size(decided) AS decided, stale,
       CASE WHEN stale > 0 THEN 'stale' WHEN size(decided) = 0 THEN 'untriaged'
            WHEN size(decided) < size(services) THEN 'partly triaged' ELSE 'triaged' END AS triage,
       sev * (weight + size(services)) AS score
ORDER BY CASE triage WHEN 'triaged' THEN 1 ELSE 0 END, score DESC, id
LIMIT $limit
