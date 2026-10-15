"""Web app: one page with the agent chat, the exposure graph, the plan and the decision log.

Run: uv run uvicorn blast_radius.web:app --reload
"""
import asyncio
import json
import os
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from blast_radius import analysis, config, memory
from blast_radius.agent import agent_available
from blast_radius.mcp_server import draft_issue

STATIC = Path(__file__).parent / "static"
ISSUE_REPO = os.getenv("ISSUE_REPO", "bhargav-2644/blast-radius")  # never upstream projects (D-027)
sessions: dict = {}  # session id -> agent, transcript of events, graph state


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    for s in sessions.values():
        await s["agent"].__aexit__(None, None, None)


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
        "agent_available": agent_available(),
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
    draft = json.loads(draft_issue(i.vulnerability_id, i.service))
    draft = draft.get("result", draft)
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


class RunIn(BaseModel):
    session_id: str | None = None
    message: str
    mode: str = "auto"            # auto | agent | pipeline
    disabled_tools: list[str] = []


def _sse(event: dict) -> str:
    return f"data: {json.dumps(event, default=str)}\n\n"


@app.get("/api/capabilities")
async def capabilities():
    """The MCP tools the agent can choose from, for the tools drawer."""
    from blast_radius.mcp_server import server
    tools = await server.list_tools()
    return {"tools": [{"name": t.name, "description": " ".join((t.description or "").split()).split(". ")[0]} for t in tools],
            "agent_available": agent_available(), "model": config.CLAUDE_MODEL}


@app.get("/api/sessions")
def list_sessions():
    return [{"id": sid, "title": s["title"], "created": s["created"], "turns": s["turns"]}
            for sid, s in sorted(sessions.items(), key=lambda kv: kv[1]["created"], reverse=True)]


@app.get("/api/sessions/{sid}")
def get_session(sid: str):
    if sid not in sessions:
        raise HTTPException(404, "unknown session")
    return {"id": sid, "title": sessions[sid]["title"], "events": sessions[sid]["events"]}


@app.post("/api/run")
async def run(r: RunIn):
    """Stream one agent turn as server-sent events: plan, thinking, text, every tool call with the
    Cypher it ran, graph updates and token usage (D-031). Each event is also kept so the session
    can be replayed."""
    from blast_radius.agent import Agent

    sid = r.session_id or f"S-{uuid.uuid4().hex[:8]}"
    s = sessions.get(sid)
    if s is None:
        agent = await Agent(session_id=sid).__aenter__()
        s = sessions[sid] = {"agent": agent, "title": r.message[:60], "created": time.time(), "turns": 0,
                             "events": [], "lock": asyncio.Lock(), "graph": {}}
    mode = r.mode if r.mode != "auto" else ("agent" if agent_available() else "pipeline")

    async def events():
        async with s["lock"]:
            s["turns"] += 1
            user = {"type": "user", "text": r.message, "session_id": sid, "mode": mode, "at": time.time()}
            s["events"].append(user)
            yield _sse(user)
            async for ev in s["agent"].stream(r.message, mode=mode, disabled=set(r.disabled_tools)):
                ev["at"] = time.time()
                s["events"].append(ev)
                yield _sse(ev)
                graph = _graph_update(s["graph"], ev)
                if graph:
                    s["events"].append(graph)
                    yield _sse(graph)

    return StreamingResponse(events(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "X-Session": sid})


def _graph_update(state: dict, ev: dict) -> dict | None:
    """Grow the session's path graph as exposure and customer results arrive."""
    if ev.get("type") != "tool_end" or ev.get("is_error") or not isinstance(ev.get("result"), dict):
        return None
    if ev["tool"] not in ("find_exposure", "customer_impact"):
        return None
    vid = ev["input"].get("vulnerability_id")
    view = state.setdefault(vid, {"exposure": {"services": []}, "customers": {"customers": []}})
    view["exposure" if ev["tool"] == "find_exposure" else "customers"] = ev["result"]
    return {"type": "graph", "vulnerability_id": vid, "at": time.time(),
            **_graph_view(vid, view["exposure"], view["customers"])}
