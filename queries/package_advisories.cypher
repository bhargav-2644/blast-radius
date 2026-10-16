// Every advisory on the given packages with its affected ranges, used to check that a proposed
// fix version is not itself affected by another known advisory (plan verification, D-048).
MATCH (v:Vulnerability)-[c:CONCERNS]->(pkg:Package)
WHERE pkg.name IN $names
RETURN pkg.name AS package, v.id AS id, v.severity AS severity, c.ranges AS ranges
