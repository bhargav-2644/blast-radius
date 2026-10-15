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
uv run pytest                 # smoke test: connects to FalkorDB
```

## Graph data model

_Coming soon (see docs/plan.md §3 for the draft)._

## Queries and algorithms

See [queries/](queries/).

## AI assistance disclosure

This project is built with help from Claude (Anthropic) as a coding assistant. Design decisions and their reasons are recorded in [docs/decisions.md](docs/decisions.md).
