// F5: store a triage decision as part of the graph, linked to what it is about.
MATCH (v:Vulnerability {id: $id}), (s:Service {name: $service})
MERGE (p:Person {name: $person})
CREATE (p)-[:MADE]->(d:Decision {id: $decision_id, verdict: $verdict, reason: $reason, at: $at,
                                 signatures: $signatures, status: 'current'})
CREATE (d)-[:ABOUT]->(v), (d)-[:FOR]->(s)
RETURN d.id AS id
