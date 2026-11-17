"""Smoke test: the FastMCP server exposes the tools with schemas and runs them."""
import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sidecar"))

os.environ["DOXSHIELD_BACKEND"] = "fixture"

from incidents.db import init_db, make_engine, make_session_factory  # noqa: E402
from mcp_server.server import build_server  # noqa: E402
from mcp_server.tools import ACTION_TOOLS, READ_ONLY_TOOLS, DoxShieldTools  # noqa: E402
from scanner import backend as backend_mod  # noqa: E402


@pytest.fixture()
def server(tmp_path):
    backend_mod.reset_backend()
    engine = make_engine(f"sqlite:///{tmp_path / 'srv.db'}")
    init_db(engine)
    sf = make_session_factory(engine)
    tools = DoxShieldTools(backend=backend_mod.get_backend(), session_factory=sf,
                           block_rules_dir=tmp_path / "rules")
    return build_server(tools)


def test_tools_registered_with_input_schemas(server):
    tools = asyncio.run(server.list_tools())
    names = {t.name for t in tools}
    assert set(READ_ONLY_TOOLS) <= names
    assert set(ACTION_TOOLS) <= names
    for t in tools:
        assert t.inputSchema.get("type") == "object"


def test_call_tool_returns_json_content(server):
    # FastMCP returns one TextContent per list element.
    result = asyncio.run(server.call_tool("list_apps", {}))
    apps = [json.loads(item.text) for item in result]
    assert any(a["name"] == "Google Chrome" for a in apps)
