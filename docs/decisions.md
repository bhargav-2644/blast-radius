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
| D-017 | 2026-10-15 | Model `claude-opus-5-5` with server-side refusal fallback | Proposed | Claude |
| D-018 | 2026-10-15 | Public GitHub repo `bhargav-2644/blast-radius`, created by Bobby | Accepted | Bobby |

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
- **Date:** 2026-10-15 · **Status:** Proposed · **By:** Claude
- **Decision:** Use `claude-opus-5-5` with adaptive thinking and an explicit effort setting, plus the server-side `fallbacks: "default"` option so a safety-classifier refusal (more likely on security topics like CVEs) retries on another model instead of failing the demo.
- **Reason:** It is the current default and the strongest model at tool selection. The CVE domain sits near the "cyber" safety category, so the fallback protects the live demo. If API cost matters, `claude-sonnet-5-5` is a one-line switch; that is Bobby's call.

### D-018: Public repo `bhargav-2644/blast-radius`
- **Date:** 2026-10-15 · **Status:** Accepted · **By:** Bobby
- **Decision:** Code lives in a new public GitHub repo, `blast-radius`, under Bobby's account. Bobby creates the empty repo; Claude pushes the scaffold. `docs/decisions.md` in the repo becomes the copy of this log.
- **Reason:** A public repo is a submission requirement (Rule 10). This cloud session isn't allowed to create repositories itself, so Bobby makes it with one click.

<!-- Template for new entries:
### D-0NN: <short title>
- **Date:** YYYY-MM-DD · **Status:** Proposed | Accepted | Superseded by D-0NN | Rejected · **By:** <name>
- **Decision:** <what we will do>
- **Reason:** <why — the facts and trade-offs>
- **Alternatives:** <what we didn't pick and why> (optional)
-->
