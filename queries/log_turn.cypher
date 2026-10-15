// Episodic memory (Track 2): each question, its answer, the tools used, and what it cited.
MERGE (s:Session {id: $session})
CREATE (s)-[:ASKED]->(q:Question {text: $question, answer: $answer, tools: $tools, at: $at})
WITH q
OPTIONAL MATCH (v:Vulnerability) WHERE v.id IN $vulns
OPTIONAL MATCH (svc:Service) WHERE svc.name IN $services
WITH q, collect(DISTINCT v) + collect(DISTINCT svc) AS cited
FOREACH (n IN cited | CREATE (q)-[:CITED]->(n))
