// Which lockfile each service's repo was last loaded from (a simulated deploy swaps it).
MATCH (r:Repo)
RETURN r.name AS repo, r.lockfile AS lockfile
