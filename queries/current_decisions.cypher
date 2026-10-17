// Every decision with its status, oldest first: re-checked for drift (F6), listed in the app and
// exported before a rebuild. Superseded ones (D-051) are kept and name the decision that replaced them.
MATCH (who:Person)-[:MADE]->(d:Decision)-[:ABOUT]->(v:Vulnerability), (d)-[:FOR]->(s:Service)
RETURN d.id AS id, v.id AS vuln, s.name AS service, d.verdict AS verdict, d.reason AS reason,
       d.at AS at, d.signatures AS signatures, d.status AS status, who.name AS person,
       d.stale_reason AS stale_reason, d.stale_at AS stale_at, d.superseded_by AS superseded_by
ORDER BY at, id
