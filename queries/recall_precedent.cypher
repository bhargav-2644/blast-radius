// F5: precedent = decisions about this advisory, or about any advisory on the same package
// (e.g. "last time lodash was hit, we accepted the risk in storefront because ...").
MATCH (v:Vulnerability {id: $id})-[:CONCERNS]->(pkg:Package)<-[:CONCERNS]-(other:Vulnerability)
      <-[:ABOUT]-(d:Decision)-[:FOR]->(s:Service)
MATCH (who:Person)-[:MADE]->(d)
RETURN d.id AS decision, other.id AS about, other.id = v.id AS same_advisory, pkg.name AS package,
       s.name AS service, d.verdict AS verdict, d.reason AS reason, who.name AS by, d.at AS at,
       d.status AS status, d.stale_reason AS stale_reason
ORDER BY same_advisory DESC, at DESC
