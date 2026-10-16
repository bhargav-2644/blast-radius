# Cypher queries

Every Cypher query and graph algorithm the product depends on lives in this folder, one `.cypher` file per query, so judges can read them directly (submission Rule 10).

Added on 2026-10-16:
- `risk_board.cypher`: advisories ranked by severity × tier-weighted customers reached, untriaged first (D-041).
- `estate_affected_installs.cypher`: input to the estate-wide min cut across all critical and high advisories (D-042).
- `path_precedent.cypher`: decisions reached through a shared dependency path via `VIA` edges (D-039).
- `repo_lockfiles.cypher`: which lockfile each service runs, for simulated deploys (D-038).
