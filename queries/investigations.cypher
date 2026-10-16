// The last investigation snapshot of each advisory ($id = null for all of them, for export before a rebuild).
MATCH (n:Investigation) WHERE $id IS NULL OR n.vuln = $id
RETURN n.vuln AS vuln, n.at AS at, n.signatures AS signatures, n.lockfiles AS lockfiles
