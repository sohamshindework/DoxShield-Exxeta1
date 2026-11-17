"""M4 MCP integration: real protocol calls, scope, timeouts, malformed output,
tool errors and an unavailable server."""
import asyncio
from types import SimpleNamespace

import pytest
from _agent_helpers import ANALYST, Env, FaultyClient, run, start_and_wait
from agent.config import AgentConfig
from agent.mcp_client import MCPToolClient, ToolScopeError
from mcp_server.tools import DoxShieldTools


@pytest.fixture()
def env(tmp_path):
    return Env(tmp_path)


def test_read_only_call_over_mcp_protocol(env):
    res = run(env.client().call_read("list_apps", {}))
    assert res.ok and any(a["name"] == "Google Chrome" for a in res.data)
    res = run(env.client().call_read("get_app_details", {"app_id": "app-chrome"}))
    assert res.ok and res.data["bundle_id"] == "com.google.Chrome"


def test_structured_tool_errors_are_parsed(env):
    res = run(env.client().call_read("get_app_details", {"app_id": "nope"}))
    assert not res.ok and res.error_code == "not_found"
    res = run(env.client().call_read("get_app_details", {}))  # schema violation
    assert not res.ok and res.error_code == "tool_error"


def test_investigation_scope_cannot_reach_action_tools(env):
    client = env.client()
    with pytest.raises(ToolScopeError):
        run(client.call_read("create_ticket", {"title": "t", "body": "b", "approval_id": "x"}))
    with pytest.raises(ToolScopeError):
        run(client.call_action("list_apps", {}, "approval"))
    with pytest.raises(ToolScopeError):
        run(client.call_action("create_ticket", {"title": "t", "body": "b"}, ""))


def test_action_tool_without_valid_approval_is_rejected_by_server(env):
    res = run(env.client().call_action("create_ticket", {"title": "t", "body": "b"}, "forged"))
    assert not res.ok and res.error_code == "approval_not_found"


class SlowTools(DoxShieldTools):
    def check_tracker(self, domain):
        import time
        time.sleep(0.5)
        return super().check_tracker(domain)


def test_server_side_tool_timeout(tmp_path):
    env = Env(tmp_path, server_timeout=0.1, tools_cls=SlowTools)
    res = run(env.client().call_read("check_tracker", {"domain": "example.com"}))
    assert not res.ok and res.error_code == "timeout"


def test_client_side_timeout_when_server_hangs(tmp_path):
    env = Env(tmp_path, server_timeout=5.0, tools_cls=SlowTools)
    res = run(env.client(timeout_s=0.1).call_read("check_tracker", {"domain": "example.com"}))
    assert not res.ok and res.error_code == "timeout"


def test_unavailable_server(env):
    def broken():
        raise ConnectionError("no server")
    res = run(MCPToolClient(broken, 1.0).call_read("list_apps", {}))
    assert not res.ok and res.error_code == "unavailable"


def test_malformed_responses_are_rejected(env):
    client = env.client()
    started = 0.0
    bad_json = SimpleNamespace(isError=False, content=[SimpleNamespace(text="{oops")])
    assert client._parse("get_app_details", bad_json, started).error_code == "malformed_response"
    two_objects = SimpleNamespace(isError=False, content=[SimpleNamespace(text="{}"),
                                                          SimpleNamespace(text="{}")])
    assert client._parse("get_app_details", two_objects, started).error_code == \
        "malformed_response"
    image = SimpleNamespace(isError=False, content=[SimpleNamespace(data=b"x")])
    assert client._parse("list_apps", image, started).error_code == "malformed_response"
    empty_list = SimpleNamespace(isError=False, content=[])
    assert client._parse("list_apps", empty_list, started).data == []


def test_tool_timeout_is_retried_once_and_budgeted(env):
    client = env.client(FaultyClient, faults={"get_connections": "timeout"})
    svc = env.service(tools=client, config=AgentConfig(retry_backoff_s=0.0))
    snap = svc.get(run(start_and_wait(svc, ANALYST, "app", "app-chrome")))["snapshot"]
    attempts = [t for t in snap["tool_calls"] if t["tool"] == "get_connections"]
    assert [a["attempt"] for a in attempts] == [1, 2]
    assert snap["budget"]["used"] == len(snap["tool_calls"])
    assert "evidence_unavailable:get_connections" in snap["flags"]
    assert snap["assessment"] is not None  # the run still finished with what it had


def test_malformed_tool_output_is_not_retried_or_used(env):
    client = env.client(FaultyClient, faults={"get_permissions": "malformed"})
    svc = env.service(tools=client)
    snap = svc.get(run(start_and_wait(svc, ANALYST, "app", "app-chrome")))["snapshot"]
    assert client.calls.count("get_permissions") == 1
    assert not any(e["source_tool"] == "get_permissions" for e in snap["evidence"])
    err = next(e for e in snap["errors"] if e["tool"] == "get_permissions")
    assert err["code"] == "malformed_response"


def test_tool_error_marks_evidence_unavailable(env):
    client = env.client(FaultyClient, faults={"search_knowledge": "error"})
    svc = env.service(tools=client)
    snap = svc.get(run(start_and_wait(svc, ANALYST, "app", "app-chrome")))["snapshot"]
    assert "evidence_unavailable:search_knowledge" in snap["flags"]
    assert any("could not be retrieved" in u["text"]
               for u in snap["assessment"]["uncertainties"])


def test_mcp_unavailable_at_triage_fails_safely(env):
    client = env.client(FaultyClient, faults={"*": "unavailable"})
    svc = env.service(tools=client)
    inv = svc.get(run(start_and_wait(svc, ANALYST, "app", "app-chrome")))
    assert inv["status"] == "failed"
    assert inv["snapshot"]["proposals"] == []
    assert inv["report"]["status"] == "failed"


def test_mcp_unavailable_mid_investigation_stops_tool_loop(env):
    client = env.client(FaultyClient, faults={"get_app_details": "unavailable"})
    svc = env.service(tools=client)
    snap = svc.get(run(start_and_wait(svc, ANALYST, "app", "app-chrome")))["snapshot"]
    assert "mcp_unavailable" in snap["flags"]
    assert snap["assessment"]["partial_evidence"] is True
    assert client.calls[-1] == "get_app_details"  # nothing called after the outage


def test_concurrent_investigations_are_isolated(env):
    svc = env.service()

    async def both():
        return await asyncio.gather(
            svc.start(ANALYST, "app", "app-chrome", wait=True),
            svc.start(ANALYST, "app", "app-weather", wait=True))

    a, b = run(both())
    labels = {svc.get(a)["label"], svc.get(b)["label"]}
    assert labels == {"Google Chrome", "WeatherApp"}
    ev_b = svc.get(b)["snapshot"]["evidence"]
    assert not any("Chrome" in e["summary"] for e in ev_b)
