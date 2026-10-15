"""The Blast Radius agent: Claude (Sonnet 5.5, D-020) choosing graph tools over MCP (D-016).

`Agent.stream()` yields every step as an event (plan, thinking, text, tool call, the Cypher each
tool ran, results, token usage) so the UI can show the work live (D-031). Without an API key,
`mode="pipeline"` runs a fixed tool sequence through the same MCP tools and emits the same events.

CLI: uv run python -m blast_radius.agent "Are we affected by CVE-2025-7783?"
"""
import asyncio
import json
import os
import re
import sys
import time
import uuid
from contextlib import AsyncExitStack
from typing import AsyncIterator

from anthropic import AsyncAnthropic, beta_async_tool
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from blast_radius import config
from blast_radius.memory import log_turn

SYSTEM = """You are Blast Radius, a security triage agent for Acme Cloud.
You answer questions about vulnerabilities using tools over a graph of Acme's services, their full
npm dependency trees, known advisories, customers, and past triage decisions.

How to work:
- For any question needing more than one tool, first call update_plan with 3-6 short steps, then keep it
  current (mark steps in_progress / done) as you go.
- Resolve any advisory the user mentions with find_vulnerability before other tools.
- Before giving advice on an advisory, call recall_precedent: if the team decided something before
  (about this advisory or the same package), say so and say whether that decision is still current.
- Ground every claim in tool output. Show exposure as dependency chains (service → a → b → vulnerable)
  and cite numbers the tools return. Never invent paths, versions, customers or decisions.
- When find_exposure says nothing is exposed, present its safety proof (what is installed versus the
  affected ranges) rather than just saying "safe". Mention dev-only exposure if it lists any.
- Production dependencies are the default. Include dev dependencies only if the user asks.
- Only call record_decision when the user explicitly states a decision and who made it.
- draft_issue only drafts. Never claim an issue was opened; the user approves that in the app.
- Be concise: lead with the answer (exposed or not, how many services and customers), then evidence."""

PLAN_SCHEMA = {
    "type": "object",
    "properties": {"steps": {"type": "array", "items": {
        "type": "object",
        "properties": {"title": {"type": "string"},
                       "status": {"type": "string", "enum": ["pending", "in_progress", "done"]}},
        "required": ["title", "status"]}}},
    "required": ["steps"],
}


def agent_available() -> bool:
    return bool(os.getenv("ANTHROPIC_API_KEY"))


class Agent:
    """One chat session: an MCP connection to the graph tools plus the conversation history."""

    def __init__(self, session_id: str | None = None):
        self.session_id = session_id or f"S-{uuid.uuid4().hex[:8]}"
        self.messages: list[dict] = []
        self.mcp_tools = []
        self._stack = AsyncExitStack()
        self._session: ClientSession | None = None
        self._emit = None  # set per run: where tool events go

    async def __aenter__(self):
        params = StdioServerParameters(command=sys.executable, args=["-m", "blast_radius.mcp_server"])
        read, write = await self._stack.enter_async_context(stdio_client(params))
        self._session = await self._stack.enter_async_context(ClientSession(read, write))
        await self._session.initialize()
        self.mcp_tools = (await self._session.list_tools()).tools
        return self

    async def __aexit__(self, *exc):
        await self._stack.aclose()

    # ------------------------------------------------------------- tools

    async def call(self, name: str, args: dict, call_id: str | None = None) -> dict:
        """Call one MCP tool, streaming its start, the queries it ran, and its result."""
        call_id = call_id or f"t-{uuid.uuid4().hex[:6]}"
        await self._emit({"type": "tool_start", "id": call_id, "tool": name, "input": args})
        started = time.perf_counter()
        res = await self._session.call_tool(name=name, arguments=args)
        text = "".join(getattr(c, "text", "") for c in res.content)
        try:
            data = json.loads(text)
            result, queries = data.get("result", data), data.get("_trace", [])
        except json.JSONDecodeError:
            result, queries = {"error": text}, []
        await self._emit({"type": "tool_end", "id": call_id, "tool": name, "input": args, "result": result,
                          "queries": queries, "ms": round((time.perf_counter() - started) * 1000, 1),
                          "is_error": bool(getattr(res, "is_error", False))})
        return result

    def _runner_tools(self, disabled: set[str]):
        tools = []
        for t in self.mcp_tools:
            if t.name in disabled:
                continue

            async def run(_name=t.name, **kwargs):
                return json.dumps(await self.call(_name, kwargs), default=str)

            schema = getattr(t, "input_schema", None) or getattr(t, "inputSchema")
            tools.append(beta_async_tool(run, name=t.name, description=t.description, input_schema=schema))

        async def update_plan(steps: list[dict]) -> str:
            await self._emit({"type": "plan", "steps": steps})
            return "plan updated"

        tools.append(beta_async_tool(update_plan, name="update_plan", input_schema=PLAN_SCHEMA,
                                     description="Show the user your step-by-step plan and its progress."))
        return tools

    # ------------------------------------------------------------- runs

    async def stream(self, question: str, mode: str = "agent", disabled: set[str] = frozenset()
                     ) -> AsyncIterator[dict]:
        queue: asyncio.Queue = asyncio.Queue()
        self._emit = queue.put

        async def drive():
            try:
                if mode == "agent" and agent_available():
                    await self._run_agent(question, set(disabled))
                else:
                    await self._run_pipeline(question)
            except Exception as e:  # surface failures in the UI instead of hanging the stream
                await queue.put({"type": "error", "message": f"{type(e).__name__}: {e}"})
            finally:
                await queue.put(None)

        task = asyncio.create_task(drive())
        while (event := await queue.get()) is not None:
            yield event
        await task

    async def _run_agent(self, question: str, disabled: set[str]):
        client = AsyncAnthropic()
        self.messages.append({"role": "user", "content": question})
        await self._emit({"type": "start", "mode": "agent", "model": config.CLAUDE_MODEL})
        runner = client.beta.messages.tool_runner(
            model=config.CLAUDE_MODEL, max_tokens=16000, system=SYSTEM,
            tools=self._runner_tools(disabled), messages=list(self.messages), stream=True,
            thinking={"type": "adaptive", "display": "summarized"},
            output_config={"effort": "medium"},
            # retry on another model if a safety classifier declines (CVE topics sit near "cyber")
            betas=["server-side-fallback-2026-07-01"], fallbacks="default",
        )
        calls, usage, last = [], {"input_tokens": 0, "output_tokens": 0, "cache_read_input_tokens": 0}, None
        async for stream in runner:
            async for event in stream:
                if event.type == "thinking":
                    await self._emit({"type": "thinking", "delta": event.thinking})
                elif event.type == "text":
                    await self._emit({"type": "text", "delta": event.text})
                elif event.type == "content_block_start" and event.content_block.type == "tool_use":
                    await self._emit({"type": "tool_pending", "tool": event.content_block.name})
            last = await stream.get_final_message()
            for k in usage:
                usage[k] += getattr(last.usage, k, 0) or 0
            await self._emit({"type": "usage", **usage, "model": last.model})
            self.messages.append({"role": "assistant", "content": last.content})
            calls += [{"tool": b.name, "input": b.input} for b in last.content if b.type == "tool_use"]
            response = await runner.generate_tool_call_response()
            if response is not None:
                self.messages.append(response)
        if last is not None and last.stop_reason == "refusal":
            await self._emit({"type": "done", "answer": "The model declined this request. Try rephrasing it.",
                              "refused": True})
            return
        answer = "".join(b.text for b in last.content if b.type == "text").strip() if last else ""
        log_turn(self.session_id, question, answer, calls)
        await self._emit({"type": "done", "answer": answer, "refused": False})

    async def _run_pipeline(self, question: str):
        """Deterministic triage through the same MCP tools, for use without an API key."""
        emit = self._emit
        await emit({"type": "start", "mode": "pipeline", "model": None})
        steps = ["Resolve the advisory", "Check past decisions", "Trace exposure paths",
                 "Find affected customers", "Compute the least-effort fix"]
        plan = [{"title": s, "status": "pending"} for s in steps]

        async def mark(i, status):
            plan[i]["status"] = status
            await emit({"type": "plan", "steps": [dict(p) for p in plan]})

        async def say(text):
            for chunk in re.findall(r"\S+\s*", text):
                await emit({"type": "text", "delta": chunk})
                await asyncio.sleep(0.01)

        await mark(0, "in_progress")
        ref = re.search(r"(GHSA-[\w-]{14}|CVE-\d{4}-\d+)", question, re.I)
        hits = await self.call("find_vulnerability", {"query": ref.group(1).upper() if ref else question})
        if not hits:
            await mark(0, "done")
            await say("I couldn't match that to an advisory in the graph. Try a GHSA or CVE id.")
            await emit({"type": "done", "answer": "", "refused": False})
            return
        vid = hits[0]["id"]
        await mark(0, "done"); await mark(1, "in_progress")
        precedent = await self.call("recall_precedent", {"vulnerability_id": vid})
        await mark(1, "done"); await mark(2, "in_progress")
        exposure = await self.call("find_exposure", {"vulnerability_id": vid})
        await mark(2, "done")
        lines = [f"**{vid}** ({hits[0]['severity']}): {hits[0]['summary']}", ""]
        if precedent:
            p = precedent[0]
            lines.append(f"Precedent: {p['by']} marked **{p['verdict']}** for {p['service']} on {p['at'][:10]} "
                         f"({'this advisory' if p['same_advisory'] else 'same package ' + p['package']}); "
                         f"that decision is **{p['status']}**." + (f" {p['stale_reason']}" if p["stale_reason"] else ""))
            lines.append("")
        if not exposure["exposed"]:
            for i in (3, 4):
                await mark(i, "done")
            sp = exposure["safety_proof"]
            lines.append("**Not exposed in production.** No dependency path reaches an affected version:")
            for pk in sp["packages"]:
                inst = ", ".join(f"`{x['version']}` ({len(x['services'])} services)" for x in pk["installed"]) or "not installed"
                lines.append(f"- `{pk['package']}` affected `{' | '.join(pk['affected_ranges'])}`; installed: {inst}")
            if sp["dev_only_exposure"]:
                lines.append(f"\nDev tooling only: {', '.join(sp['dev_only_exposure'])}.")
        else:
            await mark(3, "in_progress")
            impact = await self.call("customer_impact", {"vulnerability_id": vid})
            await mark(3, "done"); await mark(4, "in_progress")
            plan_res = await self.call("upgrade_plan", {"vulnerability_id": vid})
            await mark(4, "done")
            svcs = exposure["services"]
            lines.append(f"**Exposed: {len(svcs)} services, {len(impact['customers'])} customers "
                         f"({impact['by_tier']['enterprise']} enterprise).**")
            for s in svcs:
                p0 = s["paths"][0]
                lines.append(f"- `{s['service']}` ({s['team']}): {s['service']} → " + " → ".join(p0["chain"]))
            lines += ["", f"**Fix:** {plan_res['total_actions']} changes remove all "
                          f"{plan_res['exposure_paths']:,} exposure chains:"]
            for s in plan_res["services"]:
                for a in s["actions"]:
                    lines.append(f"- {s['repo']}: {a['action']}")
        answer = "\n".join(lines)
        await say(answer)
        log_turn(self.session_id, question, answer,
                 [{"tool": "pipeline", "input": {"vulnerability_id": vid}}])
        await emit({"type": "done", "answer": answer, "refused": False})


async def _main(question: str):
    async with Agent() as agent:
        async for ev in agent.stream(question):
            if ev["type"] in ("text", "thinking"):
                print(ev["delta"], end="", flush=True)
            elif ev["type"] == "tool_end":
                print(f"\n  · {ev['tool']}({json.dumps(ev['input'])}) {ev['ms']} ms, "
                      f"{len(ev['queries'])} graph queries")
            elif ev["type"] == "error":
                print("\nerror:", ev["message"])
        print()


if __name__ == "__main__":
    asyncio.run(_main(" ".join(sys.argv[1:]) or "Are we affected by CVE-2025-7783?"))
