// F5: store a triage decision as part of the graph, linked to what it is about and to the
// packages its exposure ran through ($via), so later advisories on the same chain find it.
MATCH (v:Vulnerability {id: $id}), (s:Service {name: $service})
MERGE (p:Person {name: $person})
CREATE (p)-[:MADE]->(d:Decision {id: $decision_id, verdict: $verdict, reason: $reason, at: $at,
                                 signatures: $signatures, status: 'current'})
CREATE (d)-[:ABOUT]->(v), (d)-[:FOR]->(s)
WITH d
OPTIONAL MATCH (pkg:Package) WHERE pkg.name IN $via
FOREACH (x IN CASE WHEN pkg IS NULL THEN [] ELSE [pkg] END | CREATE (d)-[:VIA]->(x))
RETURN DISTINCT d.id AS id
