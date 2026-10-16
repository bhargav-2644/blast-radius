"""The plan panel advances even when the model writes its plan once and never updates it (D-045).
No graph or API key needed: the MCP session is faked."""
import asyncio
import json
from types import SimpleNamespace

from blast_radius.agent import Agent


class FakeSession:
    async def call_tool(self, name, arguments):
        return SimpleNamespace(content=[SimpleNamespace(text=json.dumps({"result": {"ok": True}}))], is_error=False)


def _agent():
    a = Agent()
    a._session, events = FakeSession(), []

    async def emit(ev):
        events.append(ev)
    a._emit = emit
    return a, events


def _progress(events):
    return [[s["status"] for s in e["steps"]] for e in events if e["type"] == "plan"]


def test_plan_written_once_still_reaches_all_done():
    async def go():
        a, events = _agent()
        await a._set_plan([{"title": t, "status": "pending"} for t in ("Resolve", "Check", "Summarize")])
        await a.call("find_vulnerability", {"query": "x"})
        await a.call("find_exposure", {"vulnerability_id": "x"})
        await a._finish_plan()
        return _progress(events)

    assert asyncio.run(go()) == [["pending", "pending", "pending"],
                                 ["in_progress", "pending", "pending"],
                                 ["done", "done", "done"]]


def test_model_updates_are_kept_and_next_step_starts_on_next_tool():
    async def go():
        a, events = _agent()
        await a._set_plan([{"title": "A", "status": "done"}, {"title": "B", "status": "pending"}])
        await a.call("customer_impact", {"vulnerability_id": "x"})
        await a.call("upgrade_plan", {"vulnerability_id": "x"})  # B already in progress: no new event
        await a._finish_plan()
        await a._finish_plan()  # already done: no new event
        return _progress(events)

    assert asyncio.run(go()) == [["done", "pending"], ["done", "in_progress"], ["done", "done"]]


def test_no_plan_means_no_plan_events():
    async def go():
        a, events = _agent()
        await a.call("find_vulnerability", {"query": "x"})
        await a._finish_plan()
        return _progress(events)

    assert asyncio.run(go()) == []
