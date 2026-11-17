"""M4 HTTP API: identity, roles, origin guard and the flow the UI drives
(start → progress → review → approve → report)."""
import time

import jwt
import pytest
from _agent_helpers import Env
from agent import api as agent_api
from fastapi import FastAPI
from fastapi.testclient import TestClient

AN = {"X-DoxShield-Demo-User": "analyst"}
AP = {"X-DoxShield-Demo-User": "approver"}
VW = {"X-DoxShield-Demo-User": "viewer"}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DOXSHIELD_DEMO_IDENTITIES", "1")
    env = Env(tmp_path)
    agent_api.set_service(env.service())
    app = FastAPI()
    app.include_router(agent_api.router)
    with TestClient(app) as c:
        c.env = env
        yield c
    agent_api.set_service(None)


def wait_for(c, inv_id, statuses, timeout=15):
    deadline = time.time() + timeout
    seen = []
    while time.time() < deadline:
        inv = c.get(f"/api/investigations/{inv_id}", headers=VW).json()
        seen.append(inv["status"])
        if inv["status"] in statuses:
            return inv, seen
        time.sleep(0.05)
    raise AssertionError(f"stuck in {seen[-1]}")


def test_requests_need_an_identity(client):
    assert client.get("/api/investigations").status_code == 401
    assert client.post("/api/investigations", json={"target_type": "app",
                                                    "target_ref": "app-chrome"}).status_code == 401


def test_demo_identities_off_by_default(client, monkeypatch):
    monkeypatch.delenv("DOXSHIELD_DEMO_IDENTITIES")
    assert client.get("/api/investigations", headers=AN).status_code == 401


def test_viewer_cannot_start(client):
    r = client.post("/api/investigations", headers=VW,
                    json={"target_type": "app", "target_ref": "app-chrome"})
    assert r.status_code == 403


def test_foreign_origin_is_refused_for_mutations(client):
    r = client.post("/api/investigations", headers={**AN, "Origin": "https://evil.example"},
                    json={"target_type": "app", "target_ref": "app-chrome"})
    assert r.status_code == 403
    r = client.post("/api/investigations", headers={**AN, "Origin": "http://localhost:5173"},
                    json={"target_type": "app", "target_ref": "app-chrome"})
    assert r.status_code == 202


def test_full_flow_over_http(client):
    # The fixture incidents are already stored, so detection deduplicates them.
    r = client.post("/api/incidents/detect", headers=AN)
    assert r.status_code == 200 and r.json() == {"created": 0, "backend": "fixture",
                                                 "synthetic": True}
    assert client.post("/api/incidents/detect", headers=VW).status_code == 403
    incidents = client.get("/api/incidents", headers=VW).json()
    weather = next(i for i in incidents if i["app"] == "WeatherApp"
                   and i["type"] == "non_adequate_transfer")
    r = client.post("/api/investigations", headers=AN,
                    json={"target_type": "incident", "target_ref": weather["id"],
                          "objective": "Check the CN flow"})
    assert r.status_code == 202
    inv_id = r.json()["id"]
    inv, seen = wait_for(client, inv_id, {"awaiting_approval"})
    assert inv["snapshot"]["evidence"] and inv["snapshot"]["assessment"]
    assert inv["label"] == "WeatherApp" and inv["review_priority"] == "high"
    proposals = inv["snapshot"]["proposals"]

    # The analyst who started it cannot approve.
    p0 = proposals[0]
    r = client.post(f"/api/investigations/{inv_id}/actions/{p0['id']}/decision", headers=AN,
                    json={"decision": "approve", "reason": "ok",
                          "payload_hash": p0["payload_hash"]})
    assert r.status_code == 403
    # Missing reason is refused by validation.
    r = client.post(f"/api/investigations/{inv_id}/actions/{p0['id']}/decision", headers=AP,
                    json={"decision": "approve", "reason": "",
                          "payload_hash": p0["payload_hash"]})
    assert r.status_code == 422
    for p in proposals:
        r = client.post(f"/api/investigations/{inv_id}/actions/{p['id']}/decision",
                        headers=AP, json={"decision": "approve", "reason": "Reviewed",
                                          "payload_hash": p["payload_hash"]})
        assert r.status_code == 200, r.text
    inv, _ = wait_for(client, inv_id, {"completed", "failed"})
    assert inv["status"] == "completed"
    assert all(e["ok"] for e in inv["snapshot"]["executions"])
    report = client.get(f"/api/investigations/{inv_id}/report", headers=VW).json()
    assert "## Assessment" in report["markdown"] and "not a legal" in report["markdown"]
    assert client.get("/api/audit/verify", headers=VW).json() == {"ok": True, "broken_seq": None}
    listed = client.get("/api/investigations", headers=VW).json()
    assert listed[0]["id"] == inv_id and "snapshot" not in listed[0]


def test_cancel_and_revise_over_http(client):
    inv_id = client.post("/api/investigations", headers=AN,
                         json={"target_type": "app", "target_ref": "app-chrome"}).json()["id"]
    inv, _ = wait_for(client, inv_id, {"awaiting_approval"})
    ticket = next(p for p in inv["snapshot"]["proposals"] if p["kind"] == "create_ticket")
    r = client.post(f"/api/investigations/{inv_id}/actions/{ticket['id']}/revise", headers=AN,
                    json={"args": {"title": "New title", "body": "New body"}, "note": "edit"})
    assert r.status_code == 200 and r.json()["version"] == 2
    r = client.post(f"/api/investigations/{inv_id}/actions/{ticket['id']}/revise", headers=AN,
                    json={"args": {"title": "x"}, "note": "edit"})
    assert r.status_code == 409  # old version is superseded
    assert client.post(f"/api/investigations/{inv_id}/cancel", headers=VW).status_code == 403
    assert client.post(f"/api/investigations/{inv_id}/cancel", headers=AN).status_code == 200
    inv, _ = wait_for(client, inv_id, {"cancelled"})
    assert inv["snapshot"]["executions"] == []


def test_config_reports_unavailable_model_and_non_durable_checkpoints(client):
    cfg = client.get("/api/investigations/config").json()
    assert cfg["llm"]["available"] is False and cfg["llm"]["data_leaves_machine"] is False
    assert cfg["durable_checkpoints"] is False and cfg["demo_identities"] is True
    assert cfg["budget"]["max_tool_calls"] > 0


def test_token_identity_and_role_map(client, monkeypatch):
    secret = "s" * 40
    monkeypatch.setenv("JWT_SECRET", secret)
    monkeypatch.setenv("DOXSHIELD_ROLES", '{"dpo@corp.example": ["approver"]}')
    token = jwt.encode({"email": "dpo@corp.example"}, secret, algorithm="HS256")
    who = client.get("/api/investigations/whoami",
                     headers={"Authorization": f"Bearer {token}"}).json()
    assert who["roles"] == ["approver", "viewer"] and who["source"] == "token"
    unknown = jwt.encode({"email": "someone@corp.example"}, secret, algorithm="HS256")
    who = client.get("/api/investigations/whoami",
                     headers={"Authorization": f"Bearer {unknown}"}).json()
    assert who["roles"] == ["viewer"]
    forged = jwt.encode({"email": "dpo@corp.example"}, "x" * 40, algorithm="HS256")
    r = client.get("/api/investigations/whoami", headers={"Authorization": f"Bearer {forged}"})
    assert r.status_code == 401


def test_demo_identities_refused_on_real_backend(client, monkeypatch):
    from scanner import backend as backend_mod
    monkeypatch.setattr(type(backend_mod.get_backend()), "is_synthetic",
                        property(lambda self: False))
    from agent.identity import demo_enabled
    assert demo_enabled() is False
