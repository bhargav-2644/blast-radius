# Decision log

Every project decision goes here, with its reason. Add new entries at the bottom and never rewrite old ones: if a decision changes, add a new entry that **supersedes** the old one and mark the old one `Superseded by D-xxx`.

This log also serves as evidence for the hackathon's Rule 13 that the team made the design decisions, not just the AI.

**Statuses:** `Accepted` (in force) · `Proposed` (default we're working with until confirmed) · `Superseded` · `Rejected`

## Index

| ID | Date | Decision | Status | By |
|---|---|---|---|---|
| D-001 | 2026-10-15 | Build "Blast Radius" (dependency/CVE exposure agent) | Accepted | Bobby |
| D-002 | 2026-10-15 | Enter Tracks 1 and 2 | Accepted | Bobby (via D-001) |
| D-003 | 2026-10-15 | Position as packages → services → customers → decisions | Accepted | Bobby |
| D-004 | 2026-10-15 | npm ecosystem only, dependency trees from `package-lock.json` | Proposed | Claude |
| D-005 | 2026-10-15 | Vulnerabilities from OSV bulk dump; precompute `AFFECTS` edges with semver | Proposed | Claude |
| D-006 | 2026-10-15 | Real repos plus a labelled synthetic company layer | Proposed | Claude |
| D-007 | 2026-10-15 | Headline features: minimum upgrade cut and decision drift | Proposed | Claude |
| D-008 | 2026-10-15 | Python 3.12 for everything | Accepted | Bobby |
| D-009 | 2026-10-15 | Claude API for the agent | Accepted | Bobby |
| D-010 | 2026-10-15 | FalkorDB in Docker locally, FalkorDB Cloud for the live demo | Proposed | Claude |
| D-011 | 2026-10-15 | One tool layer exposed both to the agent loop and via MCP | Proposed | Claude |
| D-012 | 2026-10-15 | Human approval before any outward action | Proposed | Claude |
| D-013 | 2026-10-15 | Upgrade cut via `algo.maxFlow` + residual min cut, greedy fallback | Proposed | Claude |
| D-014 | 2026-10-15 | Submit by Sat 8 PM IST (4 h buffer) with a fixed cut line | Proposed | Claude |
| D-015 | 2026-10-15 | Solo build; scope sized for one person | Accepted | Bobby |
| D-016 | 2026-10-15 | Agent framework: Anthropic SDK tool runner over our own MCP server, no LangChain/LangGraph | Proposed | Claude |
| D-017 | 2026-10-15 | Model `claude-opus-5-5` with server-side refusal fallback | Superseded by D-019 | Claude |
| D-018 | 2026-10-15 | Public GitHub repo `bhargav-2644/blast-radius`, created by Bobby | Accepted | Bobby |
| D-019 | 2026-10-15 | Agent model is `claude-sonnet-5` | Superseded by D-020 | Bobby |
| D-020 | 2026-10-15 | Agent model is `claude-sonnet-5-5` | Accepted | Bobby |
| D-021 | 2026-10-15 | 14 demo services from real repos at pinned tags; lockfiles committed | Accepted | Claude |
| D-022 | 2026-10-15 | Two dependency layers: per-repo `Install` nodes + estate-wide `PackageVersion` nodes | Accepted | Claude |
| D-023 | 2026-10-15 | Fixed versions stored on `AFFECTS` edges, not as nodes | Accepted | Claude |
| D-024 | 2026-10-15 | Upgrade cut: effort-weighted, run as unit-capacity max flow on a scratch graph | Accepted | Claude |
| D-025 | 2026-10-15 | Store every advisory that concerns an installed package, to prove safety | Accepted | Claude |
| D-026 | 2026-10-15 | Production dependencies by default, dev dependencies on request | Accepted | Claude |
| D-027 | 2026-10-15 | Issues are only ever opened in our own repo, never in the upstream projects | Accepted | Claude |
| D-028 | 2026-10-15 | Decisions store their exposure signatures and survive graph rebuilds; drift is checked on every rebuild | Accepted | Claude |
| D-029 | 2026-10-15 | Episodic memory: each question, answer and cited nodes stored as `Session`/`Question` | Accepted | Claude |
| D-030 | 2026-10-15 | Web UI: one static page served by FastAPI, JS libraries vendored | Accepted | Claude |
| D-031 | 2026-10-15 | Every agent step streams to the UI as an event, including each Cypher query with params, timing and row count | Accepted | Bobby (ask), Claude |
| D-032 | 2026-10-15 | Biomni-inspired three-pane UI: sessions and tool toggles, live executor, plan plus growing graph | Accepted | Bobby (ask), Claude |

## Entries

### D-001: Build "Blast Radius"
- **Date:** 2026-10-15 · **Status:** Accepted · **By:** Bobby (decision card)
- **Decision:** Build an agent that traces a vulnerability through transitive dependencies to the company's services, customers and owners, proposes the fix and remembers triage decisions.
- **Reason:** The graph is essential (without traversal the core question can't be answered), the data is real, public and needs no login, it covers every Track 1 focus item, and it is less crowded than fraud detection or a GitHub "company brain".
- **Alternatives:** OSS Company Brain (Track 3, crowded, fragile decision extraction), fraud ring investigator (textbook demo, crowded), attack-path triage (too much modelling for 3 days), standalone memory layer (crowded, weak graph story). See ideas.md.

### D-002: Enter Tracks 1 and 2
- **Date:** 2026-10-15 · **Status:** Accepted · **By:** Bobby (part of D-001)
- **Decision:** Submit to Track 01 (Agents That Act on Connected Data) and Track 02 (Agent Memory and Coordination).
- **Reason:** Track 1 is the natural fit. Decision memory (F5/F6) is a genuine Track 2 capability, which gives a second shot at a prize from one project. Several public entries already build pure memory layers, so we enter Track 2 through memory used inside a real product.

### D-003: Position as packages → services → customers → decisions
- **Date:** 2026-10-15 · **Status:** Accepted · **By:** Bobby (agreed to the selling point in the thread)
- **Decision:** Pitch the product as joining vulnerability, dependency path, service, customer, owner and past decision, not as "chat with your dependency graph".
- **Reason:** Each piece exists already (GUAC, DepsRAG, Dependabot, OSV-Scanner), and a similar advisory → customer triage project was praised at FalkorDB's previous hackathon. What nobody does is join the pieces, compute the single fix across the estate and keep decisions current. Tagline: *Dependabot tells a repo it has a problem. Blast Radius tells the company what it means, the one fix that ends it, and remembers what you decided.*

### D-004: npm only, trees from `package-lock.json`
- **Date:** 2026-10-15 · **Status:** Proposed · **By:** Claude
- **Decision:** Support only npm. Build each repo's full resolved tree from its committed `package-lock.json`.
- **Reason:** A lockfile already contains the exact resolved transitive tree, so no resolver or external API is needed. Supporting one ecosystem keeps version matching simple. deps.dev was blocked from our cloud build environment, so avoiding it removes a dependency.
- **Alternatives:** deps.dev resolved graphs (extra API, blocked in our sandbox), multi-ecosystem support (scope risk).

### D-005: OSV bulk dump with precomputed `AFFECTS` edges
- **Date:** 2026-10-15 · **Status:** Proposed · **By:** Claude
- **Decision:** Load advisories from the OSV npm bulk dump. At ingest time, evaluate each advisory's ranges against exact versions in the graph with a semver library and write `AFFECTS` and `FIXED_IN` edges.
- **Reason:** The dump was confirmed reachable and needs no login. Precomputing keeps every runtime query a pure graph traversal (fast, and explainable), instead of version arithmetic inside the agent.
- **Alternatives:** live OSV API per query (slower, and blocked in our sandbox; it can still be used later for "refresh").

### D-006: Real repos plus a labelled synthetic company layer
- **Date:** 2026-10-15 · **Status:** Proposed · **By:** Claude
- **Decision:** Use 15–25 real public Node repos as "services". Generate teams, people, customers and service-to-service `CALLS` edges synthetically, flagged `synthetic:true` and disclosed.
- **Reason:** Dependencies and vulnerabilities stay real and credible. Business context has to be invented because no public company data exists, and the rules allow synthetic data.

### D-007: Headline features are the minimum upgrade cut and decision drift
- **Date:** 2026-10-15 · **Status:** Proposed · **By:** Claude
- **Decision:** The demo leads with F3 (minimum upgrade cut) and F6 (decision drift). Must-ship scope is F1–F5 plus F7.
- **Reason:** These are the parts no existing tool offers and that only a graph can do, so they carry the "graph is essential" argument and the differentiation.

### D-008: Python 3.12 for everything
- **Date:** 2026-10-15 · **Status:** Accepted (Bobby confirmed 2026-10-15) · **By:** Claude, confirmed by Bobby
- **Decision:** Python 3.12 for ingestion, the agent, the MCP server and a FastAPI backend. A small static page with Cytoscape.js serves as the UI.
- **Reason:** It has a mature FalkorDB client, an Anthropic SDK and an MCP SDK, and one language means fewer moving parts in 3 days. A static page avoids a frontend build chain.

### D-009: Claude API for the agent
- **Date:** 2026-10-15 · **Status:** Accepted (Bobby confirmed 2026-10-15) · **By:** Claude, confirmed by Bobby
- **Decision:** Use the Claude API with native tool use for the agent loop.
- **Reason:** Reliable tool selection, and it works with the MCP server we expose anyway.
- **Alternatives:** any LLM with tool calling; the tool layer is model-agnostic.

### D-010: FalkorDB in Docker locally, FalkorDB Cloud live
- **Date:** 2026-10-15 · **Status:** Proposed · **By:** Claude
- **Decision:** Use `docker compose` with `falkordb/falkordb` for development, and FalkorDB Cloud for the public demo. App hosting is to be decided at deploy time.
- **Reason:** Both are allowed by the rules. Cloud avoids running a database on the app host and gives judges a stable live URL.

### D-011: One tool layer, exposed to the agent and via MCP
- **Date:** 2026-10-15 · **Status:** Proposed · **By:** Claude
- **Decision:** Implement tools once (`find_exposure`, `explain_path`, `customer_impact`, `upgrade_plan`, `chokepoints`, `record_decision`, `recall_precedent`, `open_issue`). Register them with the Claude tool loop and serve the same set from an MCP server.
- **Reason:** Track 1 explicitly lists "tool selection through MCP". A single implementation keeps behaviour identical in both places. Every tool returns the nodes and edges it used, so answers can show their path.

### D-012: Human approval before outward actions
- **Date:** 2026-10-15 · **Status:** Proposed · **By:** Claude
- **Decision:** `open_issue` and any other action outside the app run only after an explicit approve click.
- **Reason:** It keeps the agent safe to demo against real GitHub, and FalkorDB's previous judges praised approval gates.

### D-013: Upgrade cut via MaxFlow
- **Date:** 2026-10-15 · **Status:** Proposed · **By:** Claude
- **Decision:** Build the exposure subgraph with capacity 1 on fixable `DEPENDS_ON` edges and a very high capacity on unfixable ones. Run `algo.maxFlow` from repos to the vulnerable version, then derive the min cut from the residual graph in Python. Keep a greedy "edge on most paths" fallback.
- **Reason:** Max flow equals min cut, so FalkorDB's own algorithm computes the "fewest fixes" answer. That is a real graph algorithm doing the product's key job. `algo.maxFlow` returns per-edge flows but not the cut itself, so the residual step is ours, and the fallback covers surprises.
- **Check (2026-10-15):** `algo.maxFlow` ran on `falkordb/falkordb:latest` with the config above and returned the correct value on a test graph.

### D-014: Submit by Sat 8 PM IST with a fixed cut line
- **Date:** 2026-10-15 · **Status:** Proposed · **By:** Claude
- **Decision:** Target submission at 8 PM IST on Oct 18, four hours before the deadline. If we're behind on Friday night, cut F8 first, then F6; never F3 or F5.
- **Reason:** Deployment and video always take longer than expected. The cut order protects the pitch.

### D-015: Solo build
- **Date:** 2026-10-15 · **Status:** Accepted · **By:** Bobby
- **Decision:** Bobby builds alone. The plan's must-ship scope (F1–F5, F7) and the Friday-night cut line stay as they are; nothing is parallelised across people.
- **Reason:** Team size is one. The schedule was already sized for one person with Claude's help, and the cut order (F8, then F6) protects the pitch if time runs short.

### D-016: Agent framework is the Anthropic SDK tool runner over our own MCP server
- **Date:** 2026-10-15 · **Status:** Proposed · **By:** Claude
- **Decision:** No agent framework (no LangChain, LangGraph, CrewAI). Graph tools are written once as an MCP server using the official `mcp` Python SDK (FastMCP). The agent connects to that server as an MCP client and runs Anthropic's tool runner (`client.beta.messages.tool_runner`) with the MCP tools converted by `anthropic.lib.tools.mcp`. The approve-before-action gate (D-012) sits in the loop.
- **Reason:** Tools reach the agent through MCP for real, which is exactly what Track 1 lists ("tool selection through MCP"). It also gives the fewest layers between the agent and the Cypher, so judges can read every query and we can explain the whole stack (Rule 13), and it avoids debugging a framework in a 3-day solo build. The same MCP server also works from Claude Desktop, which makes a nice extra demo.
- **Alternatives:** LangGraph (state machines and checkpoints we don't need; graph-memory there would compete with FalkorDB's role); LangChain FalkorDB integration (hides the Cypher we must show); Claude Agent SDK (built for coding/filesystem agents, overkill here); Managed Agents (hosted sandbox not needed; our tools must reach our FalkorDB).

### D-017: Model `claude-opus-5-5` with refusal fallback
- **Date:** 2026-10-15 · **Status:** Superseded by D-019 · **By:** Claude
- **Decision:** Use `claude-opus-5-5` with adaptive thinking and an explicit effort setting, plus the server-side `fallbacks: "default"` option so a safety-classifier refusal (more likely on security topics like CVEs) retries on another model instead of failing the demo.
- **Reason:** It is the current default and the strongest model at tool selection. The CVE domain sits near the "cyber" safety category, so the fallback protects the live demo. If API cost matters, `claude-sonnet-5-5` is a one-line switch; that is Bobby's call.

### D-018: Public repo `bhargav-2644/blast-radius`
- **Date:** 2026-10-15 · **Status:** Accepted · **By:** Bobby
- **Decision:** Code lives in a new public GitHub repo, `blast-radius`, under Bobby's account. Bobby creates the empty repo; Claude pushes the scaffold. `docs/decisions.md` in the repo becomes the copy of this log.
- **Reason:** A public repo is a submission requirement (Rule 10). This cloud session isn't allowed to create repositories itself, so Bobby makes it with one click.

### D-019: Agent model is `claude-sonnet-5`
- **Date:** 2026-10-15 · **Status:** Superseded by D-020 · **By:** Bobby
- **Decision:** The agent uses `claude-sonnet-5`, with adaptive thinking. It replaces D-017. The model ID is kept in one config value (`CLAUDE_MODEL`) so it's a one-line change later.
- **Reason:** Bobby's choice. Sonnet costs about half as much per token as Opus 5.5 ($2/$10 vs $4/$20 per million tokens), which matters for a demo that judges will run live, and it is strong at tool selection.
- **Notes:** The server-side refusal fallback isn't offered for Sonnet 5, so the agent handles a `refusal` stop reason itself by telling the user, rather than failing silently. `claude-sonnet-5-5` is the newer Sonnet at the same price, if we ever want to switch.

### D-020: Agent model is `claude-sonnet-5-5`
- **Date:** 2026-10-15 · **Status:** Accepted · **By:** Bobby
- **Decision:** The agent uses `claude-sonnet-5-5`, the current Sonnet, with adaptive thinking and effort set explicitly. It replaces D-019. The model is still the single `CLAUDE_MODEL` setting.
- **Reason:** Bobby's choice after hearing that Sonnet 5.5 is newer at the same price as Sonnet 5 ($2/$10 per million tokens).
- **Notes:** Sonnet 5.5 supports the server-side refusal fallback (`fallbacks: "default"`), so we turn it on: CVE questions sit near the security safety category, and a fallback keeps the live demo from failing. Forced `tool_choice` isn't supported on this model, so tools are chosen with `auto` and steered by the prompt.

### D-021: Demo services are 14 real repos at pinned refs, lockfiles committed
- **Date:** 2026-10-15 · **Status:** Accepted · **By:** Claude
- **Decision:** The demo company "Acme Cloud" has 14 services, each a real public Node repo at a fixed tag (for example `uptime-kuma@1.18.0`, `mattermost-webapp@v7.5.0`, `bitwarden/clients@web-v2022.12.0`). Their `package-lock.json` files are committed gzipped in `data/lockfiles/` (3.5 MB). Teams, people, customers and calls are synthetic in `data/company.json`.
- **Reason:** Pinned late-2022 versions contain many real, known vulnerabilities (532 advisories across 7,643 package versions), which makes the demo realistic. Committing the lockfiles makes the graph rebuild offline and identically, and the cloud sandbox can't use the GitHub API for repos outside the project anyway. Four services use a branch (`main`/`master`) because no suitable tag had a v2+ lockfile; their snapshot is frozen by the committed file.
- **Alternatives:** parse-server, nest, video.js and etherpad were dropped because their lockfiles at that time were v1 format (supporting v1 adds parser work for little gain).

### D-022: Two dependency layers in the graph
- **Date:** 2026-10-15 · **Status:** Accepted · **By:** Claude
- **Decision:** Model dependencies twice. **Install layer:** one `Install` node per `node_modules` path per repo, linked by `REQUIRES` edges (capacity 1) and to its `PackageVersion` by `IS`. **Package layer:** one `PackageVersion` per name@version across the whole estate, linked by merged `DEPENDS_ON` edges.
- **Reason:** The same package version can resolve to different children in different repos. With a single merged layer, a traversal from repo X could follow repo Y's resolution and report a false exposure path, and enumerating all paths timed out. The Install layer is exact per repo, so `shortestPath` returns true paths in ~40 ms, and the repos' install graphs are disjoint, so `algo.maxFlow` works over all repos at once without filtering. The merged package layer is what estate-wide chokepoint analysis (PageRank, betweenness) needs.
- **Check (2026-10-15):** On the top advisory (braces, 13 services), exposure ran in 10 ms, paths up to 8 hops in 40 ms, and `algo.maxFlow` for team-chat-web returned a cut of 3 in 60 ms. `algo.maxFlow` needs one edge per node pair and an explicit `capacityProperty`, so the loader dedupes edges and sets `capacity: 1`.

### D-023: Fixed versions live on `AFFECTS` edges
- **Date:** 2026-10-15 · **Status:** Accepted · **By:** Claude
- **Decision:** Store the advisory's fixed versions as a `fixed` list on each `(:Vulnerability)-[:AFFECTS]->(:PackageVersion)` edge instead of `FIXED_IN` edges to `PackageVersion` nodes.
- **Reason:** Fixed versions usually aren't installed anywhere in the estate, so `FIXED_IN` would need placeholder nodes that pollute chokepoint analysis. The upgrade planner only needs the version strings. This replaces the `FIXED_IN` edge in the plan's v1 model.

### D-024: Effort-weighted upgrade cut on a scratch graph, with unit capacities
- **Date:** 2026-10-15 · **Status:** Accepted · **By:** Claude (refines D-013)
- **Decision:** Each dependency link in a service's exposure subgraph gets an effort weight: 1 = refresh the lockfile (a fixed version already fits the parent's range), 2 = bump a direct dependency, 4 = npm override (the parent's range excludes every fix), 6 = needs an upstream release. The minimum-effort cut is computed by copying the subgraph into a temporary FalkorDB graph and running `algo.maxFlow`. Each weight-k link becomes k parallel unit-capacity paths, and the cut is read from the residual graph in Python. If `algo.maxFlow` exceeds 10 s, a Python Edmonds-Karp fallback runs and the result says so.
- **Reason:** Plain unit weights give "fewest links" rather than "least work", and that picks fixes developers can't actually make. On real subgraphs, `algo.maxFlow` hung on some graphs with mixed capacities (a 14-node, 24-edge graph timed out), while the same graph with unit capacities solved in 60 ms. The expansion keeps FalkorDB doing the flow computation: 698 of 700 cuts in a full sweep used `algo.maxFlow`, and 2 used the fallback. A temporary graph per request is cheap (FalkorDB hosts many graphs) and leaves the main graph untouched.
- **Check:** A test removes each plan's cut links and confirms that no affected install stays reachable. Example: picomatch ReDoS GHSA-c2c7-rcm5-vvqj reaches 3 services in production through 5,854 distinct dependency chains, which 13 changes remove.
- **Follow-up:** Worth reporting the mixed-capacity hang to FalkorDB with a minimal repro.

### D-025: Keep every advisory that concerns an installed package
- **Date:** 2026-10-15 · **Status:** Accepted · **By:** Claude
- **Decision:** Load all 1,125 advisories for packages present in the estate as `Vulnerability` nodes with `CONCERNS {ranges}` edges to `Package`, not only the 532 that affect an installed version. `AFFECTS` edges exist only for real matches.
- **Reason:** "No path found" (F4) must be provable: the safety answer shows which versions of the package are installed and where, next to the affected ranges. An advisory that isn't in the graph would give no evidence.

### D-026: Production dependencies by default
- **Date:** 2026-10-15 · **Status:** Accepted · **By:** Claude
- **Decision:** Exposure, customer impact and upgrade plans count only packages that ship (`dev: false` in the lockfile) unless `include_dev` is set. When there's no production exposure, the safety answer still lists services exposed through dev tooling.
- **Reason:** Most advisory hits in these repos are in build and test tooling. Counting them as customer-facing exposure would cry wolf and bury the real paths, while hiding them entirely would be dishonest.

### D-027: Issues only go to our own repo
- **Date:** 2026-10-15 · **Status:** Accepted · **By:** Claude
- **Decision:** The `draft_issue` tool only drafts. When a person approves in the app, the issue is opened in `bhargav-2644/blast-radius` (labelled with the service name), never in the real upstream projects that back the demo services (Mattermost, Bitwarden, etc.).
- **Reason:** The services are real open-source repos standing in for a fictional company. Opening issues on them would spam real maintainers with demo output. Keeping the action in our own repo still shows the agent acting end to end.

### D-028: Decisions remember their exposure and survive rebuilds
- **Date:** 2026-10-15 · **Status:** Accepted · **By:** Claude
- **Decision:** A `Decision` stores one signature per affected install it was made against (install path + shortest chain). The loader exports decisions before rebuilding the graph, re-attaches them afterwards, and runs `check_drift`, which marks a decision `stale` (with the new chains as the reason) when its exposure gained a path. `--deploy SERVICE=lockfile` swaps one service's lockfile to simulate a deploy. `data/scenarios/storefront-adds-koa-router.json.gz` is a labelled synthetic change that adds `@koa/router → path-to-regexp@6.2.1`.
- **Reason:** This is F6, the most distinctive feature. The graph is rebuilt from source data, so memory must live through rebuilds. Comparing signatures is exact and cheap. **Check (2026-10-15):** a `risk_accepted` decision on GHSA-9wv6 for storefront survived a rebuild unchanged, and after the simulated deploy it went stale with reason "1 new exposure path: @koa/router@10.1.1 → path-to-regexp@6.2.1".

### D-029: Episodic memory of conversations
- **Date:** 2026-10-15 · **Status:** Accepted · **By:** Claude
- **Decision:** After each answer, the agent writes `(:Session)-[:ASKED]->(:Question {text, answer, tools, at})-[:CITED]->(:Vulnerability|:Service)`.
- **Reason:** Track 2 asks for persistent conversation history. Linking questions to the nodes they cited makes history queryable through the graph ("what have we asked about storefront?") rather than kept as a flat log. Unlike decisions, sessions are not yet carried across graph rebuilds; that's a possible follow-up.

### D-030: Web UI is one static page with vendored libraries
- **Date:** 2026-10-15 · **Status:** Accepted · **By:** Claude
- **Decision:** FastAPI serves JSON endpoints and a single `index.html` (vanilla JS, Cytoscape.js 3.28.1 for the path graph, marked 12.0.2 for agent answers). The two libraries are committed in `static/vendor/` instead of loaded from a CDN. The graph, plan, decision and drift views call the graph directly, so they work without a Claude API key; only the chat needs one.
- **Reason:** No frontend build chain to maintain in a solo 3-day build. Vendoring avoids depending on a CDN during the live demo, and the CDN was blocked from our build environment anyway. Keeping the graph views usable without the LLM means the demo still shows the graph's work if the API has a problem.

### D-031: Stream every step, down to the Cypher
- **Date:** 2026-10-15 · **Status:** Accepted · **By:** Bobby (ask), Claude
- **Decision:** `Agent.stream()` yields one event per step: `start`, `plan`, `thinking`, `text`, `tool_pending`, `tool_start`, `tool_end`, `usage`, `done`, `error`. Each MCP tool wraps its work in a trace, so `tool_end` carries every graph query it ran (Cypher text, parameters, milliseconds, rows; the max-flow call is marked as an algorithm). The trace travels inside the MCP result and is stripped before the model sees it. `POST /api/run` sends the events as server-sent events, keeps each session's transcript for replay, and adds `graph` events that grow the path view as exposure and customer results arrive. Without an API key, a fixed pipeline runs the same MCP tools and emits the same events.
- **Reason:** Bobby asked for a UI that shows whatever is happening in the backend, because the users are developers. Showing the exact queries is also the strongest evidence for judges that the answers come from graph traversals, not the model. Keeping the trace in the tool result means any MCP client gets it, and the model's context stays small.
- **Alternatives:** WebSockets (two-way traffic isn't needed; SSE over a POST is simpler). Logging queries server-side only (a developer couldn't see them while the agent works).

### D-032: Biomni-inspired three-pane layout
- **Date:** 2026-10-15 · **Status:** Accepted · **By:** Bobby (ask), Claude
- **Decision:** The page is rebuilt around the live run, following Stanford's Biomni agent UI, which Bobby pointed to. The left pane holds sessions, the MCP tools with on/off toggles (a disabled tool is withheld from the model), and the Agent/Pipeline mode. The centre is the executor: each tool call is a collapsible card with Input, Cypher and Output tabs; thinking streams in its own card; the answer streams as markdown; meters show tool calls, graph queries, time in FalkorDB and tokens. The right pane shows the live plan checklist above tabs for the growing graph, findings (exposure, customers, least-effort fix with the approve-to-open-issue button), decisions with drift re-check, and the raw event log.
- **Reason:** Biomni shows its reasoning, code and results as the agent works, which is what Bobby wants for a developer audience. Its site is blocked from our build environment, so the layout follows Biomni's public documentation rather than its live page. It stays one static page (D-030).

<!-- Template for new entries:
### D-0NN: <short title>
- **Date:** YYYY-MM-DD · **Status:** Proposed | Accepted | Superseded by D-0NN | Rejected · **By:** <name>
- **Decision:** <what we will do>
- **Reason:** <why — the facts and trade-offs>
- **Alternatives:** <what we didn't pick and why> (optional)
-->
