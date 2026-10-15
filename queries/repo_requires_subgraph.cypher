// Input to the upgrade cut (F3): one repo's whole install graph, as edges.
MATCH (a)-[e:REQUIRES]->(b:Install {repo: $repo})
RETURN CASE WHEN a:Repo THEN 'ROOT' ELSE a.key END AS src, b.key AS dst,
       e.range AS range, e.direct AS direct,
       CASE WHEN a:Repo THEN a.name ELSE a.name END AS src_name,
       a.version AS src_version, b.name AS dst_name, b.version AS dst_version
