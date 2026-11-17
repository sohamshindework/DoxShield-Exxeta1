"""The agent's only path to DoxShield tools: an MCP client session.

Calls go over the Model Context Protocol (JSON-RPC, official SDK) to the existing
DoxShield MCP server, so the server's own input validation, per-tool timeout and
approval gate always apply. The agent duplicates none of that business logic.

The client adds what the agent needs on top:

* a **scope check** — investigation code can only call read-only tools; action
  tools are reachable only through ``call_action`` with an ``approval_id``;
* a client-side timeout, so a hung or unreachable server cannot stall the graph;
* strict parsing: anything that is not the expected JSON shape is reported as
  ``malformed_response`` instead of being passed on.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from mcp.shared.memory import create_connected_server_and_client_session
from mcp_server.tools import ACTION_TOOLS, READ_ONLY_TOOLS

# Tools whose result is a JSON list (FastMCP sends one content item per element).
LIST_TOOLS = {"list_apps", "get_connections", "search_knowledge", "find_eu_alternatives",
              "get_incidents", "get_evidence"}

_ERROR_RE = re.compile(r"^(?:Error executing tool [\w-]+: )?([a-z_]+): (.*)$", re.S)


@dataclass
class ToolResult:
    tool: str
    ok: bool
    data: Any = None
    error_code: str | None = None
    error: str | None = None
    duration_ms: int = 0


class ToolScopeError(Exception):
    """Raised when code asks for a tool outside its allowed scope. A bug, not data."""


ServerFactory = Callable[[], Any]


class MCPToolClient:
    def __init__(self, server_factory: ServerFactory, timeout_s: float = 20.0) -> None:
        self._server_factory = server_factory
        self._timeout_s = timeout_s

    async def call_read(self, tool: str, args: dict[str, Any]) -> ToolResult:
        if tool not in READ_ONLY_TOOLS:
            raise ToolScopeError(f"{tool!r} is not a read-only tool")
        return await self._call(tool, args)

    async def call_action(self, tool: str, args: dict[str, Any], approval_id: str) -> ToolResult:
        if tool not in ACTION_TOOLS:
            raise ToolScopeError(f"{tool!r} is not an action tool")
        if not approval_id:
            raise ToolScopeError("Action tools need an approval_id")
        return await self._call(tool, {**args, "approval_id": approval_id})

    async def _call(self, tool: str, args: dict[str, Any]) -> ToolResult:
        started = time.monotonic()
        try:
            result = await asyncio.wait_for(self._roundtrip(tool, args), self._timeout_s)
        except TimeoutError:
            return self._fail(tool, "timeout", f"No response within {self._timeout_s}s", started)
        except Exception as exc:  # server could not be built or the session broke
            return self._fail(tool, "unavailable",
                              f"MCP server unavailable ({type(exc).__name__})", started)
        return self._parse(tool, result, started)

    async def _roundtrip(self, tool: str, args: dict[str, Any]):
        server = self._server_factory()
        if server is None:
            raise ConnectionError("no MCP server")
        async with create_connected_server_and_client_session(server) as session:
            return await session.call_tool(tool, args)

    def _parse(self, tool: str, result: Any, started: float) -> ToolResult:
        content = list(getattr(result, "content", None) or [])
        raw_texts = [getattr(c, "text", None) for c in content]
        if any(not isinstance(t, str) for t in raw_texts):
            return self._fail(tool, "malformed_response", "Non-text content", started)
        texts: list[str] = [str(t) for t in raw_texts]
        if getattr(result, "isError", False):
            raw = " ".join(texts).strip()
            m = _ERROR_RE.match(raw)
            code, msg = (m.group(1), m.group(2)) if m else ("tool_error", raw)
            return self._fail(tool, code, msg[:300], started)
        try:
            items = [json.loads(t) for t in texts]
        except (TypeError, ValueError):
            return self._fail(tool, "malformed_response", "Response is not JSON", started)
        if tool in LIST_TOOLS:
            data: Any = items
        elif len(items) == 1 and isinstance(items[0], dict):
            data = items[0]
        else:
            return self._fail(tool, "malformed_response", "Expected one JSON object", started)
        return ToolResult(tool=tool, ok=True, data=data,
                          duration_ms=int((time.monotonic() - started) * 1000))

    @staticmethod
    def _fail(tool: str, code: str, msg: str, started: float) -> ToolResult:
        return ToolResult(tool=tool, ok=False, error_code=code, error=msg,
                          duration_ms=int((time.monotonic() - started) * 1000))
