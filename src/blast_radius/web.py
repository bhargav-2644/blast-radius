"""Web app: one page with the agent chat, the exposure graph, the plan and the decision log.

Run: uv run uvicorn blast_radius.web:app --reload
"""
import os
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from blast_radius import analysis, memory
from blast_radius.mcp_server import draft_issue

STATIC = Path(__file__).parent / "static"
ISSUE_REPO = os.getenv("ISSUE_REPO", "bhargav-2644/blast-radius")  # never upstream projects (D-027)
agents: dict = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    for agent in agents.values():
        await agent.__aexit__(None, None, None)


app = FastAPI(title="Blast Radius", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/overview")
def overview(include_dev: bool = False):
    return {
        "stats": analysis._rows("graph_stats"),
        "top": analysis._rows("top_advisories", include_dev=include_dev, limit=12),
        "agent_available": bool(os.getenv("ANTHROPIC_API_KEY")),
        "issues_enabled": bool(os.getenv("GITHUB_TOKEN")),
        "issue_repo": ISSUE_REPO,
    }


@app.get("/api/search")
def search(q: str):
    return analysis.find_vulnerability(q, limit=8)


def _graph_view(vuln_id: str, exposure: dict, customers: dict) -> dict:
    """Nodes and edges for the path view: advisory → packages → services → customers."""
    nodes, edges = {}, set()
    nodes[vuln_id] = {"id": vuln_id, "label": vuln_id, "kind": "vulnerability"}
    for svc in exposure["services"]:
        sid = f"svc:{svc['service']}"
        nodes[sid] = {"id": sid, "label": svc["service"], "kind": "service", "tier": svc["tier"]}
        for path in svc["paths"][:3]:
            prev = sid
            for i, pkg in enumerate(path["chain"]):
                last = i == len(path["chain"]) - 1
                pid = f"pkg:{pkg}"
                nodes.setdefault(pid, {"id": pid, "label": pkg, "kind": "vulnerable" if last else "package"})
                edges.add((prev, pid, "requires"))
                prev = pid
            edges.add((f"pkg:{path['chain'][-1]}", vuln_id, "affected by"))
    for c in customers["customers"]:
        cid = f"cust:{c['customer']}"
        nodes[cid] = {"id": cid, "label": c["customer"], "kind": "customer", "tier": c["tier"]}
        for x in c["exposed_through"]:
            via = x["via"] or [x["service"]]
            nodes.setdefault(f"svc:{via[0]}", {"id": f"svc:{via[0]}", "label": via[0], "kind": "service"})
            edges.add((cid, f"svc:{via[0]}", "uses"))
            for a, b in zip(via, via[1:]):
                nodes.setdefault(f"svc:{b}", {"id": f"svc:{b}", "label": b, "kind": "service"})
                edges.add((f"svc:{a}", f"svc:{b}", "calls"))
    return {"nodes": list(nodes.values()),
            "edges": [{"source": a, "target": b, "label": l} for a, b, l in edges]}


@app.get("/api/advisory/{vuln_id}")
def advisory(vuln_id: str, include_dev: bool = False):
    found = analysis.find_vulnerability(vuln_id)
    if not found or found[0]["id"] != vuln_id:
        raise HTTPException(404, f"unknown advisory {vuln_id}")
    exposure = analysis.exposure(vuln_id, include_dev)
    customers = analysis.customer_impact(vuln_id, include_dev)
    plan = analysis.upgrade_plan(vuln_id, include_dev) if exposure["exposed"] else None
    return {"advisory": found[0], "exposure": exposure, "customers": customers, "plan": plan,
            "precedent": memory.recall_precedent(vuln_id), "graph": _graph_view(vuln_id, exposure, customers)}


class DecisionIn(BaseModel):
    vulnerability_id: str
    service: str
    verdict: str
    reason: str
    person: str


@app.post("/api/decisions")
def record(d: DecisionIn):
    try:
        return memory.record_decision(d.vulnerability_id, d.service, d.verdict, d.reason, d.person)
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.get("/api/decisions")
def decisions():
    return [{k: v for k, v in d.items() if k != "signatures"} for d in analysis._rows("current_decisions")]


@app.post("/api/drift")
def drift():
    return memory.check_drift()


class IssueIn(BaseModel):
    vulnerability_id: str
    service: str


@app.post("/api/issues")
def open_issue(i: IssueIn):
    """Opens the drafted issue in our own repo. Called only from the approve button (D-012, D-027)."""
    import json
    draft = json.loads(draft_issue(i.vulnerability_id, i.service))
    if "error" in draft:
        raise HTTPException(400, draft["error"])
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        return {"opened": False, "reason": "GITHUB_TOKEN is not set", "draft": draft}
    r = httpx.post(f"https://api.github.com/repos/{ISSUE_REPO}/issues",
                   headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
                   json={"title": draft["title"], "body": draft["body"], "labels": ["blast-radius", i.service]},
                   timeout=30)
    if r.status_code >= 300:
        raise HTTPException(502, f"GitHub said {r.status_code}: {r.text[:200]}")
    return {"opened": True, "url": r.json()["html_url"], "draft": draft}


class ChatIn(BaseModel):
    session_id: str
    message: str


@app.post("/api/chat")
async def chat(c: ChatIn):
    if not os.getenv("ANTHROPIC_API_KEY"):
        raise HTTPException(503, "The agent needs ANTHROPIC_API_KEY. The graph views work without it.")
    from blast_radius.agent import Agent

    agent = agents.get(c.session_id)
    if agent is None:
        agent = await Agent(session_id=c.session_id).__aenter__()
        agents[c.session_id] = agent
    turn = await agent.ask(c.message)
    return {"answer": turn.answer, "tool_calls": turn.tool_calls, "refused": turn.refused, "model": turn.model}
