"""The Blast Radius agent: Claude (Sonnet 5.5, D-020) choosing graph tools over MCP (D-016).

CLI: uv run python -m blast_radius.agent "Are we affected by CVE-2024-45296?"
"""
import asyncio
import json
import sys
import uuid
from contextlib import AsyncExitStack
from dataclasses import dataclass, field

from anthropic import AsyncAnthropic
from anthropic.lib.tools.mcp import async_mcp_tool
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from blast_radius import config
from blast_radius.memory import log_turn

SYSTEM = """You are Blast Radius, a security triage agent for Acme Cloud.
You answer questions about vulnerabilities using tools over a graph of Acme's services, their full
npm dependency trees, known advisories, customers, and past triage decisions.

How to work:
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


@dataclass
class Turn:
    answer: str
    tool_calls: list[dict] = field(default_factory=list)
    refused: bool = False
    model: str | None = None


class Agent:
    """Keeps one MCP connection and the conversation history for a chat session."""

    def __init__(self, session_id: str | None = None):
        self.session_id = session_id or f"S-{uuid.uuid4().hex[:8]}"
        self.messages: list[dict] = []
        self._stack = AsyncExitStack()
        self._tools = None
        self._client = AsyncAnthropic()

    async def __aenter__(self):
        params = StdioServerParameters(command=sys.executable, args=["-m", "blast_radius.mcp_server"])
        read, write = await self._stack.enter_async_context(stdio_client(params))
        session = await self._stack.enter_async_context(ClientSession(read, write))
        await session.initialize()
        listed = await session.list_tools()
        self._tools = [async_mcp_tool(t, session) for t in listed.tools]
        return self

    async def __aexit__(self, *exc):
        await self._stack.aclose()

    async def ask(self, question: str) -> Turn:
        self.messages.append({"role": "user", "content": question})
        runner = self._client.beta.messages.tool_runner(
            model=config.CLAUDE_MODEL,
            max_tokens=16000,
            system=SYSTEM,
            tools=self._tools,
            messages=list(self.messages),
            thinking={"type": "adaptive"},
            output_config={"effort": "medium"},
            # retry on another model if a safety classifier declines (CVE topics sit near "cyber")
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        )
        calls: list[dict] = []
        last = None
        async for message in runner:
            last = message
            self.messages.append({"role": "assistant", "content": message.content})
            for block in message.content:
                if block.type == "tool_use":
                    calls.append({"tool": block.name, "input": block.input})
            response = await runner.generate_tool_call_response()
            if response is not None:
                self.messages.append(response)
                results = [c for c in response["content"] if c.get("type") == "tool_result"]
                for call, result in zip(calls[-len(results):], results):
                    call["result"] = _text(result.get("content"))
        if last is None:
            return Turn(answer="(no response)")
        if last.stop_reason == "refusal":
            return Turn(answer="The model declined to answer this request. Try rephrasing it.",
                        tool_calls=calls, refused=True, model=last.model)
        answer = "".join(b.text for b in last.content if b.type == "text").strip()
        log_turn(self.session_id, question, answer, calls)
        return Turn(answer=answer, tool_calls=calls, model=last.model)


def _text(content) -> str:
    if isinstance(content, str):
        return content
    return "".join(c.get("text", "") for c in content or [] if isinstance(c, dict))


async def _main(question: str):
    async with Agent() as agent:
        turn = await agent.ask(question)
        for c in turn.tool_calls:
            print(f"  · {c['tool']}({json.dumps(c['input'])})")
        print(turn.answer)


if __name__ == "__main__":
    asyncio.run(_main(" ".join(sys.argv[1:]) or "Which advisories hit the most services?"))
