// F5: precedent through a shared path = decisions on other advisories whose exposure ran through
// a package this advisory's exposure also runs through (e.g. both reach their bug via express).
MATCH (d:Decision)-[:VIA]->(pkg:Package) WHERE pkg.name IN $via
MATCH (d)-[:ABOUT]->(other:Vulnerability) WHERE other.id <> $id
MATCH (d)-[:FOR]->(s:Service), (who:Person)-[:MADE]->(d) WHERE d.status <> 'superseded'
WITH d, other, s, who, collect(pkg.name) AS via
OPTIONAL MATCH (d)-[:SUPERSEDES*1..]->(old:Decision)<-[:MADE]-(oldwho:Person)
WITH d, other, s, who, via,
     collect(CASE WHEN old IS NULL THEN NULL
                  ELSE {decision: old.id, verdict: old.verdict, by: oldwho.name, at: old.at, reason: old.reason} END) AS replaces
RETURN d.id AS decision, other.id AS about, false AS same_advisory, s.name AS service,
       d.verdict AS verdict, d.reason AS reason, who.name AS by, d.at AS at, d.status AS status,
       d.stale_reason AS stale_reason, d.stale_at AS stale_at, d.signatures AS signatures,
       other.severity AS severity, other.summary AS summary, via, replaces
ORDER BY at DESC
