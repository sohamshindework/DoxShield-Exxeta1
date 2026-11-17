"""Shared fixtures for the M4 agent tests: synthetic data, real MCP server,
injectable faults. No network, no model, no API keys."""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sidecar"))
os.environ["DOXSHIELD_BACKEND"] = "fixture"

from agent.config import AgentConfig  # noqa: E402
from agent.mcp_client import MCPToolClient  # noqa: E402
from agent.service import InvestigationService, Principal  # noqa: E402
from incidents.db import init_db, make_engine, make_session_factory  # noqa: E402
from incidents.detection import detect_incidents  # noqa: E402
from incidents.store import save_incident  # noqa: E402
from mcp_server.server import build_server  # noqa: E402
from mcp_server.tools import DoxShieldTools  # noqa: E402
from scanner import backend as backend_mod  # noqa: E402

ANALYST = Principal("analyst@example.invalid", frozenset({"viewer", "analyst"}))
APPROVER = Principal("dpo@example.invalid", frozenset({"viewer", "approver"}))
VIEWER = Principal("viewer@example.invalid", frozenset({"viewer"}))
BOTH = Principal("both@example.invalid", frozenset({"viewer", "analyst", "approver"}))


class Env:
    """A temp database seeded with the fixture scan's incidents, plus a real
    DoxShield MCP server over that database."""

    def __init__(self, tmp_path: Path, server_timeout: float = 15.0, tools_cls=DoxShieldTools):
        backend_mod.reset_backend()
        self.backend = backend_mod.get_backend()
        self.engine = make_engine(f"sqlite:///{tmp_path / 'agent.db'}")
        init_db(self.engine)
        self.sf = make_session_factory(self.engine)
        self.rules_dir = tmp_path / "rules"
        self.tool_impl = tools_cls(backend=self.backend, session_factory=self.sf,
                                   block_rules_dir=self.rules_dir)
        self.server = build_server(self.tool_impl, timeout=server_timeout)
        scan = {"connections": asyncio.run(self.backend.get_connections()),
                "permissions": self.backend.get_permissions(),
                "cookies": self.backend.scan_cookies()}
        self.incidents = detect_incidents(scan)
        with self.sf() as s:
            for inc in self.incidents:
                save_incident(s, inc)

    def incident(self, app: str, type_: str = "non_adequate_transfer"):
        return next(i for i in self.incidents if i.app == app and i.type.value == type_)

    def client(self, cls=MCPToolClient, timeout_s: float = 20.0, **kw):
        return cls(lambda: self.server, timeout_s, **kw)

    def service(self, tools=None, config: AgentConfig | None = None, **kw):
        return InvestigationService(self.sf, tools=tools or self.client(),
                                    config=config or AgentConfig(retry_backoff_s=0.0),
                                    policy_fetcher=kw.pop("policy_fetcher", None), **kw)


class FaultyClient(MCPToolClient):
    """Injects faults per tool: 'timeout', 'unavailable', 'malformed' or 'error'."""

    def __init__(self, factory, timeout_s=20.0, faults: dict | None = None):
        super().__init__(factory, timeout_s)
        self.faults = dict(faults or {})
        self.calls: list[str] = []

    async def _roundtrip(self, tool, args):
        self.calls.append(tool)
        fault = self.faults.get(tool) or self.faults.get("*")
        if fault == "timeout":
            raise TimeoutError()
        if fault == "unavailable":
            raise ConnectionError("down")
        if fault == "malformed":
            return SimpleNamespace(isError=False,
                                   content=[SimpleNamespace(text="<html>not json</html>")])
        if fault == "error":
            return SimpleNamespace(isError=True, content=[SimpleNamespace(
                text=f"Error executing tool {tool}: internal: boom")])
        return await super()._roundtrip(tool, args)


def run(coro):
    return asyncio.run(coro)


async def start_and_wait(svc, principal, target_type, ref, objective=""):
    return await svc.start(principal, target_type, ref, objective, wait=True)


async def approve_all(svc, inv_id, principal=APPROVER, decision="approve"):
    snap = svc.get(inv_id)["snapshot"]
    for p in [p for p in snap["proposals"] if p["status"] == "proposed"]:
        await svc.decide(inv_id, p["id"], principal, decision, "reviewed", p["payload_hash"],
                         wait=True)
    return svc.get(inv_id)
