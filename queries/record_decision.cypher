// F5: store a triage decision as part of the graph, linked to what it is about and to the
// packages its exposure ran through ($via), so later advisories on the same chain find it.
// It supersedes every earlier decision in force on the same advisory and service (D-051): those
// keep their history but get status 'superseded' and a SUPERSEDES edge from the new one. A decision
// restored as superseded after a rebuild supersedes nothing (its own successor relinks it).
// stale_reason / stale_at hold why and when the status was set, for any status but 'current'.
MATCH (v:Vulnerability {id: $id}), (s:Service {name: $service})
MERGE (p:Person {name: $person})
CREATE (p)-[:MADE]->(d:Decision {id: $decision_id, verdict: $verdict, reason: $reason, at: $at,
                                 signatures: $signatures, status: $status,
                                 stale_reason: $status_reason, stale_at: $status_at,
                                 superseded_by: $superseded_by})
CREATE (d)-[:ABOUT]->(v), (d)-[:FOR]->(s)
WITH d, v, s
OPTIONAL MATCH (pkg:Package) WHERE pkg.name IN $via
FOREACH (x IN CASE WHEN pkg IS NULL THEN [] ELSE [pkg] END | CREATE (d)-[:VIA]->(x))
WITH DISTINCT d, v, s
OPTIONAL MATCH (old:Decision)-[:ABOUT]->(v), (old)-[:FOR]->(s)
WHERE d.status <> 'superseded' AND old.id <> d.id AND old.status <> 'superseded' AND old.at <= d.at
FOREACH (o IN CASE WHEN old IS NULL THEN [] ELSE [old] END |
  SET o.status = 'superseded', o.superseded_by = d.id
  CREATE (d)-[:SUPERSEDES]->(o))
RETURN d.id AS id, [o IN collect(old) WHERE o IS NOT NULL | o.id] AS supersedes
