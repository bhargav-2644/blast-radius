// F2: customers who use an exposed service directly, or a service that calls one (up to 3 hops).
MATCH (v:Vulnerability {id: $id})-[:AFFECTS]->(:PackageVersion)<-[:IS]-(i:Install)
WHERE $include_dev OR NOT i.dev
WITH DISTINCT i.repo AS repo
MATCH (:Repo {name: repo})<-[:BUILT_FROM]-(exposed:Service)
MATCH path = (c:Customer)-[:USES]->(entry:Service)-[:CALLS*0..3]->(exposed)
WITH c, exposed, min(length(path)) AS hops,
     collect([n IN nodes(path)[1..] | n.name])[0] AS via
RETURN c.name AS customer, c.tier AS tier,
       collect({service: exposed.name, hops: hops, via: via}) AS exposed_through
ORDER BY CASE c.tier WHEN 'enterprise' THEN 0 WHEN 'business' THEN 1 ELSE 2 END, customer
