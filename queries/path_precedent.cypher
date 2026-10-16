// F5: precedent through a shared path = decisions on other advisories whose exposure ran through
// a package this advisory's exposure also runs through (e.g. both reach their bug via express).
MATCH (d:Decision)-[:VIA]->(pkg:Package) WHERE pkg.name IN $via
MATCH (d)-[:ABOUT]->(other:Vulnerability) WHERE other.id <> $id
MATCH (d)-[:FOR]->(s:Service), (who:Person)-[:MADE]->(d)
RETURN d.id AS decision, other.id AS about, false AS same_advisory, s.name AS service,
       d.verdict AS verdict, d.reason AS reason, who.name AS by, d.at AS at, d.status AS status,
       d.stale_reason AS stale_reason, d.stale_at AS stale_at, d.signatures AS signatures,
       other.severity AS severity, other.summary AS summary, collect(pkg.name) AS via
ORDER BY at DESC
