# Blast Radius: project plan

Graph Hacks 2026 (FalkorDB × WeMakeDevs). Tracks 1 and 2. Deadline **Sat Oct 18, 11:59 PM IST** (18:29 UTC).
Written 2026-10-15 at 5 PM IST, when roughly 79 hours remained. Every choice in this plan is logged with its reason in [decisions.md](decisions.md); research is in [ideas.md](ideas.md) and [ideas-deep-dive.md](ideas-deep-dive.md).

## 1. What we're building

An agent that answers "a CVE dropped, what does it mean for us?" over a FalkorDB graph of a company's services, their full dependency trees, known vulnerabilities, customers and past triage decisions.

**Pitch line:** *Dependabot tells a repo it has a problem. Blast Radius tells the company what it means, the one fix that ends it, and remembers what you decided.*

### Headline features (in demo order)
| # | Feature | Graph work | Track |
|---|---|---|---|
| F1 | **Exposure paths**: which services are affected and through which dependency chain | variable-length `DEPENDS_ON*` traversal | 1 |
| F2 | **Business impact**: customers and owning team | traversal through `CALLS*` and `USES` | 1 |
| F3 | **Minimum upgrade cut**: the fewest dependency edges to fix so that every path is broken | `algo.maxFlow`, then a min cut from the residual graph | 1 |
| F4 | **Proof of safety**: "no path" returned as evidence | an empty traversal with the search bounds shown | 1 |
| F5 | **Decision memory**: record and recall triage decisions as precedent | `Decision` nodes linked to the vulnerability, service and path | 2 |
| F6 | **Decision drift**: reopen a decision when a new path appears that it didn't cover | path signatures compared on ingest | 2 |
| F7 | **Action**: draft a GitHub issue with the plan, after human approval | agent tool | 1 |
| F8 | **Chokepoints**: packages the whole estate leans on | `algo.pageRank`, `algo.betweenness` | 1 |

**Must ship:** F1–F5 and F7. **Should ship:** F6, which is our most distinctive feature, so it is next in line once the must-ships work. **Nice to have:** F8, multi-agent handoff, live CVE feed.

## 2. Architecture

```
            ┌───────────── Web UI (FastAPI + static page, Cytoscape.js path view) ─────────────┐
            │  chat box · highlighted path graph · impact table · decision log · approve button │
            └───────────────────────────────┬──────────────────────────────────────────────────┘
                                            │
                              Agent (Claude API, tool use)
                                            │  tools
                     ┌──────────────────────┼───────────────────────┐
              MCP server (same tool set, for Claude Desktop/other clients)    GitHub API (issue drafts)
                                            │
                                   FalkorDB (Docker locally, FalkorDB Cloud live)
                                            ▲
                     Ingestion (Python): lockfiles from GitHub + OSV npm dump + synthetic company layer
```

- **Language:** Python 3.12 throughout (D-008).
- **Agent tools** are plain Python functions wrapping Cypher. They are registered with the Claude tool-use loop *and* exposed through an MCP server, so judges see "tool selection through MCP" (D-011).
- **Every tool returns the nodes and edges it used**, which the UI highlights. That is the "show the path behind the answer" requirement.

## 3. Graph model (v1)

```
(:Team {name})-[:OWNS]->(:Service {name, tier})-[:BUILT_FROM]->(:Repo {name, url, commit})
(:Service)-[:CALLS]->(:Service)
(:Customer {name, tier, synthetic:true})-[:USES]->(:Service)
(:Repo)-[:DEPENDS_ON {direct:true, range, dev}]->(:PackageVersion {purl, name, version})
(:PackageVersion)-[:DEPENDS_ON {range}]->(:PackageVersion)
(:Package {name, ecosystem})-[:HAS_VERSION]->(:PackageVersion)
(:Vulnerability {id, aliases, summary, severity, published})-[:AFFECTS]->(:PackageVersion)
(:Vulnerability)-[:FIXED_IN]->(:PackageVersion)
(:Person {name})-[:MEMBER_OF]->(:Team)
(:Decision {id, verdict, reason, at, path_signatures, status})-[:ABOUT]->(:Vulnerability)
(:Decision)-[:FOR]->(:Service) ; (:Person)-[:MADE]->(:Decision)
(:Session {id, at})-[:ASKED]->(:Question {text})-[:CITED]->(nodes used in the answer)
```
Indexes: `PackageVersion(purl)`, `Vulnerability(id)`, `Service(name)`, and a full-text index on `Vulnerability.summary`.

## 4. Key algorithms

- **Exposure (F1):** `MATCH p=(v:Vulnerability{id:$id})-[:AFFECTS]->(:PackageVersion)<-[:DEPENDS_ON*1..10]-(:Repo)<-[:BUILT_FROM]-(s:Service) RETURN p`. The 10-hop bound is reported, so "no path" (F4) states what was searched.
- **Upgrade cut (F3):** build the exposure subgraph, give every `DEPENDS_ON` edge capacity 1 (edges with no fixed version get a very high capacity), then run `CALL algo.maxFlow({sourceNodes: repos, targetNodes: [vulnerable versions], relationshipTypes: ['DEPENDS_ON'], capacityProperty: 'cap'})`. In Python, compute the min cut from the residual graph and translate each cut edge into "upgrade X to ≥ fixed version" or "bump the parent that pulls it". A greedy fallback is kept in case MaxFlow misbehaves (D-013).
- **Drift (F6):** a decision stores a hash per exposure path that existed when it was made. After each ingest, exposure is recomputed for every vulnerability that has a decision; any path hash not in the stored set marks that decision `STALE` and the agent raises it.
- **Version matching:** OSV ranges are evaluated against exact lockfile versions with a semver library at ingest time and stored as `AFFECTS` edges, so queries stay pure graph traversal (D-005).

## 5. Data

- **Services:** 15–25 real public Node.js repos with a committed `package-lock.json`, chosen so at least 2–3 share a real historical vulnerable package (D-004, D-006).
- **Vulnerabilities:** the OSV npm bulk dump (`osv-vulnerabilities/npm/all.zip`), filtered to packages present in the graph (D-005).
- **Company layer:** synthetic teams, people, customers and `CALLS` edges, all marked `synthetic:true` and disclosed in the README (D-006).
- **Demo scenario:** one advisory hits several services through transitive paths, and a second advisory shows a clean "no path".

## 6. Schedule

Times are IST. Buffers are deliberate.

| Block | When | Deliverable | Exit check |
|---|---|---|---|
| **0. Setup** | Wed Oct 15, evening | Repo, Docker Compose with FalkorDB, project skeleton, README stub, decisions.md copied into the repo | `docker compose up` gives a reachable FalkorDB |
| **1. Ingestion** | Wed night → Thu midday | Lockfile parser, OSV loader, semver matching, synthetic company generator, idempotent loader | Graph loaded; F1 query returns real paths in Browser |
| **2. Core queries** | Thu afternoon | F1, F2, F4, F8 queries plus the MaxFlow cut (F3), each with a test | Each query returns expected results on the demo scenario |
| **3. Agent + MCP** | Thu evening → Fri midday | Tool layer, Claude tool loop, MCP server, decision write/recall (F5) | Agent answers the 5 demo questions end to end in the CLI |
| **4. UI + action** | Fri afternoon → night | Web page with chat and path graph, approve-to-open-issue (F7), drift (F6) | Full demo flow works in the browser |
| **5. Deploy** | Sat morning | FalkorDB Cloud plus app hosting, seeded demo data | Public URL works from a clean browser |
| **6. Submission** | Sat afternoon | README (setup, data model, Cypher list, AI disclosure), demo video, blog post (optional), submit on WeMakeDevs panel | Submitted **by 8 PM IST**, leaving a 4-hour buffer |

**Cut line if we're behind on Friday night:** drop F8, then F6. Never drop F3 or F5, since they are the pitch.

## 7. Submission checklist (Rule 10)
- [ ] Public repo
- [ ] README with setup instructions and the graph data model (diagram)
- [ ] The Cypher queries and algorithms listed (`queries/` folder plus a README section)
- [ ] Demo video (about 3 min, following the script in ideas-deep-dive.md)
- [ ] Live deployment URL (or full local setup)
- [ ] Tracks named: 01 and 02
- [ ] AI-assistant use disclosed; decisions.md shows our own reasoning (Rule 13)
- [ ] Registered on the WeMakeDevs panel, team members added

## 8. Open questions for Bobby
1. Team size: solo or with teammates? This affects the schedule.
2. Stack: is Python OK (D-008, proposed)?
3. LLM: is the Claude API OK, and do we have an API key (D-009, proposed)?
4. Hosting preference for the live demo (D-010, proposed)?
5. GitHub repo name and whether I should create it (proposed name: `blast-radius`).
