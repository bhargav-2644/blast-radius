# Cypher queries

Every Cypher query and graph algorithm the product depends on lives in this folder, one `.cypher` file per query, so judges can read them directly (submission Rule 10).

Added on 2026-10-16:
- `risk_board.cypher`: advisories ranked by severity × tier-weighted customers reached, untriaged first (D-041).
- `estate_affected_installs.cypher`: input to the estate-wide min cut across all critical and high advisories (D-042).
- `path_precedent.cypher`: decisions reached through a shared dependency path via `VIA` edges (D-039).
- `repo_lockfiles.cypher`: which lockfile each service runs, for simulated deploys (D-038).
- `session_history.cypher`: every asked question with its session and cited nodes, exported before a rebuild and written back through `log_turn.cypher` (D-044).

Added later on 2026-10-16 (explainability, D-046 to D-050):
- `exposure_paths.cypher` now also returns the evidence for each chain: repo, ref, lockfile, when it was loaded (`Repo.loaded_at`), the install's `node_modules` path and the advisory's affected ranges (D-046).
- `package_advisories.cypher`: every advisory on the packages a plan touches, used to check that a proposed fix version is not itself affected (D-048).
- `risk_board.cypher` now takes `$id` and returns the factors behind each score (D-049).
- `advisory_signatures.cypher`, `save_investigation.cypher`, `investigations.cypher`: one `Investigation` snapshot per advisory, compared on the next look to say what changed (D-050).
