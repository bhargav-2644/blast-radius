// F5: precedent = decisions about this advisory, or about any advisory on the same package
// (e.g. "last time lodash was hit, we accepted the risk in storefront because ...").
// Only decisions in force; the ones they superseded come back as `replaces` (D-051).
MATCH (v:Vulnerability {id: $id})-[:CONCERNS]->(pkg:Package)<-[:CONCERNS]-(other:Vulnerability)
      <-[:ABOUT]-(d:Decision)-[:FOR]->(s:Service)
MATCH (who:Person)-[:MADE]->(d) WHERE d.status <> 'superseded'
OPTIONAL MATCH (d)-[:SUPERSEDES*1..]->(old:Decision)<-[:MADE]-(oldwho:Person)
WITH d, v, pkg, other, s, who,
     collect(CASE WHEN old IS NULL THEN NULL
                  ELSE {decision: old.id, verdict: old.verdict, by: oldwho.name, at: old.at, reason: old.reason} END) AS replaces
RETURN d.id AS decision, other.id AS about, other.id = v.id AS same_advisory, pkg.name AS package,
       s.name AS service, d.verdict AS verdict, d.reason AS reason, who.name AS by, d.at AS at,
       d.status AS status, d.stale_reason AS stale_reason,
       d.stale_at AS stale_at, d.signatures AS signatures, other.severity AS severity, other.summary AS summary,
       replaces
ORDER BY same_advisory DESC, at DESC
