// Episodic memory (D-029) as rows, so it can be carried across a graph rebuild like decisions are.
MATCH (s:Session)-[:ASKED]->(q:Question)
OPTIONAL MATCH (q)-[:CITED]->(v:Vulnerability)
OPTIONAL MATCH (q)-[:CITED]->(svc:Service)
RETURN s.id AS session, q.text AS question, q.answer AS answer, q.tools AS tools, q.at AS at,
       collect(DISTINCT v.id) AS vulns, collect(DISTINCT svc.name) AS services
ORDER BY at
