# Blast Radius

> Dependabot tells a repo it has a problem. Blast Radius tells the company what it means, the one fix that ends it, and remembers what you decided.

An agent that answers "a CVE dropped, what does it mean for us?" over a [FalkorDB](https://falkordb.com) graph of a company's services, their full dependency trees, known vulnerabilities, customers and past triage decisions.

Built for **Graph Hacks 2026** (WeMakeDevs × FalkorDB). Tracks: **01 Agents That Act on Connected Data** and **02 Agent Memory and Coordination**.

🚧 Work in progress. See [docs/plan.md](docs/plan.md) for the plan and [docs/decisions.md](docs/decisions.md) for every design decision and its reason.

## Quick start (local)

```bash
docker compose up -d          # FalkorDB on :6379, Browser on http://localhost:3000
uv sync                       # install dependencies
cp .env.example .env          # add your ANTHROPIC_API_KEY
uv run python -m blast_radius.ingest.load   # build the graph (~3 s, from the committed advisory snapshot)
uv run pytest                 # tests (need the graph loaded)
```

To refresh advisories from the full OSV npm dump (~220 MB): `./scripts/fetch_osv.sh && uv run python scripts/snapshot_osv.py`.

Then:

```bash
uv run uvicorn blast_radius.web:app      # web app on http://localhost:8000; streams every agent step and Cypher query live
                                         # (without an API key it runs a fixed pipeline over the same tools)
uv run python -m blast_radius.agent "Are we affected by CVE-2025-7783?"   # agent in the terminal
uv run python -m blast_radius.mcp_server # the graph tools as an MCP server (stdio), e.g. for Claude Desktop
```

Simulate a deploy and watch past decisions drift:

```bash
uv run python -m blast_radius.ingest.load --deploy storefront=data/scenarios/storefront-adds-koa-router.json.gz
```

The demo company's 14 services are real public repos at pinned versions (lockfiles committed in `data/lockfiles/`); teams, customers and service calls are synthetic (`data/company.json`).

## Deploy (FalkorDB Cloud + Render)

1. Create a free FalkorDB Cloud instance and note its host, port, username and password.
2. In Render, choose **New > Blueprint** and pick this repo. `render.yaml` defines one Docker web service.
3. Fill in `FALKORDB_HOST`, `FALKORDB_PORT`, `FALKORDB_USERNAME`, `FALKORDB_PASSWORD` (set `FALKORDB_SSL=true` if your instance requires TLS) and, optionally, `ANTHROPIC_API_KEY`.
4. On first start the container builds the graph in a few seconds from the committed data (`data/lockfiles`, `data/osv/npm-snapshot.zip`). An existing graph is left alone, so recorded decisions survive restarts.

Public-demo guards: agent runs are limited per IP per hour and per day (`AGENT_RUNS_PER_HOUR_PER_IP`, `AGENT_RUNS_PER_DAY`), after which runs fall back to the fixed pipeline. Idle sessions beyond `MAX_LIVE_SESSIONS` release their tool process. Leave `GITHUB_TOKEN` unset on a public deploy: the "Open issue" button then shows the draft instead of filing it.

Run the same container locally: `docker compose --profile app up --build`.

## Graph data model

_Coming soon (see docs/plan.md §3 for the draft)._

## Queries and algorithms

See [queries/](queries/).

## AI assistance disclosure

This project is built with help from Claude (Anthropic) as a coding assistant. Design decisions and their reasons are recorded in [docs/decisions.md](docs/decisions.md).
