"""M4 graph behaviour: transitions, routing, budgets, termination, recovery."""
import pytest
from _agent_helpers import ANALYST, APPROVER, VIEWER, Env, approve_all, run, start_and_wait
from agent.config import AgentConfig
from agent.service import ServiceError
from incidents.db import ActionRow, ApprovalRow, InvestigationEvidenceRow
from sqlalchemy import select

EXPECTED_NODES = {"triage", "investigate", "assess", "propose_actions", "await_approval",
                  "execute", "report"}


@pytest.fixture()
def env(tmp_path):
    return Env(tmp_path)


def stages(inv):
    return [t["stage"] for t in inv["snapshot"]["timeline"]]


def test_graph_has_exactly_the_documented_nodes(env):
    graph = env.service().graph.get_graph()
    assert set(graph.nodes) - {"__start__", "__end__"} == EXPECTED_NODES
    mermaid = graph.draw_mermaid()
    for node in EXPECTED_NODES:
        assert node in mermaid


def test_incident_investigation_pauses_before_any_action(env):
    svc = env.service()
    inv_id = run(start_and_wait(svc, ANALYST, "incident", env.incident("WeatherApp").id))
    inv = svc.get(inv_id)
    assert inv["status"] == "awaiting_approval"
    assert stages(inv)[0] == "triage" and stages(inv)[-1] == "propose_actions"
    assert "investigate" in stages(inv) and "assess" in stages(inv)
    snap = inv["snapshot"]
    assert snap["assessment"]["review_priority"] == "high"
    kinds = {p["kind"] for p in snap["proposals"]}
    assert {"create_ticket", "draft_dpo_notification"} <= kinds
    # Nothing ran: every action is only proposed, no approval exists, no rule file.
    with env.sf() as s:
        assert all(a.status == "proposed" for a in s.scalars(select(ActionRow)
                   .where(ActionRow.investigation_id == inv_id)))
        assert not s.scalars(select(ApprovalRow).where(
            ApprovalRow.investigation_id == inv_id)).all()
    assert not env.rules_dir.exists()
    assert snap["executions"] == []


def test_approval_resumes_and_executes_then_reports(env):
    svc = env.service()
    inv_id = run(start_and_wait(svc, ANALYST, "incident", env.incident("WeatherApp").id))
    inv = run(approve_all(svc, inv_id))
    assert inv["status"] == "completed"
    assert stages(inv)[-3:] == ["await_approval", "execute", "report"]
    execs = inv["snapshot"]["executions"]
    assert execs and all(e["ok"] for e in execs)
    dpo = next(e for e in execs if e["kind"] == "draft_dpo_notification")
    assert dpo["result"]["sent"] is False
    assert inv["report"]["markdown"].startswith("# DoxShield investigation")
    assert all(p["status"] == "executed" for p in inv["snapshot"]["proposals"])


def test_rejection_executes_nothing(env):
    svc = env.service()
    inv_id = run(start_and_wait(svc, ANALYST, "incident", env.incident("WeatherApp").id))
    inv = run(approve_all(svc, inv_id, decision="reject"))
    assert inv["status"] == "completed"
    assert inv["snapshot"]["executions"] == []
    assert "execute" not in stages(inv)
    assert all(p["status"] == "rejected" for p in inv["snapshot"]["proposals"])


def test_app_target_with_tracker_proposes_dry_run_block_rule(env):
    svc = env.service()
    inv_id = run(start_and_wait(svc, ANALYST, "app", "app-chrome"))
    snap = svc.get(inv_id)["snapshot"]
    cats = {c["category"] for c in snap["assessment"]["concerns"]}
    assert "third_party_tracker" in cats
    rule = next(p for p in snap["proposals"] if p["kind"] == "propose_block_rule")
    assert rule["args"] == {"target": "www.google-analytics.com"}
    assert "NOT changed" in rule["expected_effect"]
    inv = run(approve_all(svc, inv_id))
    res = next(e for e in inv["snapshot"]["executions"] if e["kind"] == "propose_block_rule")
    assert res["ok"] and res["result"]["dry_run"] is True and res["result"]["applied"] is False


def test_benign_app_completes_without_proposals_or_pause(env):
    svc = env.service()
    inv_id = run(start_and_wait(svc, ANALYST, "app", "app-mail"))
    inv = svc.get(inv_id)
    assert inv["status"] == "completed"
    assert inv["snapshot"]["proposals"] == []
    assert "await_approval" not in stages(inv)
    assert inv["snapshot"]["assessment"]["concerns"] == [] or \
        inv["snapshot"]["assessment"]["review_priority"] == "low"


def test_unknown_incident_is_rejected_safely(env):
    svc = env.service()
    inv_id = run(start_and_wait(svc, ANALYST, "incident", "does-not-exist"))
    inv = svc.get(inv_id)
    assert inv["status"] == "rejected_target"
    assert inv["snapshot"]["proposals"] == [] and inv["snapshot"]["evidence"] == []
    assert inv["report"]["status"] == "rejected_target"


def test_unknown_app_is_rejected_safely(env):
    svc = env.service()
    inv = svc.get(run(start_and_wait(svc, ANALYST, "app", "com.unknown.app")))
    assert inv["status"] == "rejected_target"


@pytest.mark.parametrize("ref", ["../../etc/passwd", "a;rm -rf /", "x" * 200, ""])
def test_malformed_target_refused_before_running(env, ref):
    with pytest.raises(ServiceError) as exc:
        run(env.service().start(ANALYST, "incident", ref, wait=True))
    assert exc.value.status == 422


def test_only_analysts_can_start(env):
    for who in (VIEWER, APPROVER):
        with pytest.raises(ServiceError) as exc:
            run(env.service().start(who, "app", "app-chrome", wait=True))
        assert exc.value.status == 403


def test_dismissed_incident_is_closed_by_rules(env):
    inc = env.incident("WeatherApp")
    from incidents.db import IncidentRow
    with env.sf() as s:
        s.get(IncidentRow, inc.id).status = "dismissed"
        s.commit()
    svc = env.service()
    inv = svc.get(run(start_and_wait(svc, ANALYST, "incident", inc.id)))
    assert inv["status"] == "closed_by_rules"
    assert inv["snapshot"]["proposals"] == []


def test_budget_exhaustion_terminates_with_partial_evidence(env):
    svc = env.service(config=AgentConfig(max_tool_calls=4, retry_backoff_s=0.0))
    inv_id = run(start_and_wait(svc, ANALYST, "incident", env.incident("WeatherApp").id))
    snap = svc.get(inv_id)["snapshot"]
    assert snap["budget"]["used"] == 4
    assert len(snap["tool_calls"]) == 4
    assert "budget_exhausted" in snap["flags"]
    assert snap["assessment"]["partial_evidence"] is True
    assert any("budget ran out" in u["text"] for u in snap["assessment"]["uncertainties"])


def test_zero_budget_still_terminates(env):
    svc = env.service(config=AgentConfig(max_tool_calls=0))
    inv = svc.get(run(start_and_wait(svc, ANALYST, "app", "app-chrome")))
    assert inv["status"] == "failed"
    assert inv["snapshot"]["tool_calls"] == []


def test_step_limit_fails_closed(env):
    svc = env.service(config=AgentConfig(max_graph_steps=3, retry_backoff_s=0.0))
    inv = svc.get(run(start_and_wait(svc, ANALYST, "incident", env.incident("WeatherApp").id)))
    assert inv["status"] == "failed"
    assert "step_limit" in inv["snapshot"]["flags"]
    assert all(p["status"] != "approved" for p in inv["snapshot"]["proposals"])


def test_evidence_volume_is_capped(env):
    svc = env.service(config=AgentConfig(max_evidence_items=3, retry_backoff_s=0.0))
    snap = svc.get(run(start_and_wait(svc, ANALYST, "app", "app-chrome")))["snapshot"]
    assert len(snap["evidence"]) == 3
    assert "evidence_cap_reached" in snap["flags"]


def test_cancellation_during_investigation(env):
    svc = env.service()

    async def scenario():
        inv_id = await svc.start(ANALYST, "app", "app-chrome")  # runs in the background
        task = svc._tasks[inv_id]
        assert await svc.cancel(inv_id, ANALYST) == {"cancel_requested": True}
        await task
        return inv_id

    inv = svc.get(run(scenario()))
    assert inv["status"] == "cancelled"
    assert inv["snapshot"]["proposals"] == []
    assert "cancelled" in inv["snapshot"]["flags"]
    assert inv["report"]["status"] == "cancelled"


def test_cancellation_while_awaiting_approval(env):
    svc = env.service()
    inv_id = run(start_and_wait(svc, ANALYST, "incident", env.incident("WeatherApp").id))
    run(svc.cancel(inv_id, ANALYST, wait=True))
    inv = svc.get(inv_id)
    assert inv["status"] == "cancelled"
    assert all(p["status"] == "cancelled" for p in inv["snapshot"]["proposals"])
    assert inv["snapshot"]["executions"] == []
    with pytest.raises(ServiceError):
        run(svc.cancel(inv_id, ANALYST, wait=True))


def test_restart_marks_paused_investigation_interrupted(env):
    svc = env.service()
    inv_id = run(start_and_wait(svc, ANALYST, "incident", env.incident("WeatherApp").id))
    action = svc.get(inv_id)["snapshot"]["proposals"][0]
    # Simulated restart: a new service has no in-memory checkpoint for this run.
    restarted = env.service()
    inv = restarted.get(inv_id)
    assert inv["status"] == "interrupted"
    with pytest.raises(ServiceError) as exc:
        run(restarted.decide(inv_id, action["id"], APPROVER, "approve", "ok",
                             action["payload_hash"], wait=True))
    assert exc.value.status == 409
    with env.sf() as s:
        assert s.get(ActionRow, action["id"]).status == "cancelled"


def test_investigations_do_not_share_state(env):
    svc = env.service()
    a = run(start_and_wait(svc, ANALYST, "app", "app-chrome"))
    b = run(start_and_wait(svc, ANALYST, "incident", env.incident("WeatherApp").id))
    ev_a = svc.get(a)["snapshot"]["evidence"]
    ev_b = svc.get(b)["snapshot"]["evidence"]
    assert all(e["id"].startswith(f"EV-{a[:8]}") for e in ev_a)
    assert all(e["id"].startswith(f"EV-{b[:8]}") for e in ev_b)
    assert not {e["id"] for e in ev_a} & {e["id"] for e in ev_b}
    with env.sf() as s:
        rows_b = s.scalars(select(InvestigationEvidenceRow).where(
            InvestigationEvidenceRow.investigation_id == b)).all()
    assert {r.id for r in rows_b} == {e["id"] for e in ev_b}
    # Each investigation only cites its own evidence.
    for inv_id, own in ((a, ev_a), (b, ev_b)):
        own_ids = {e["id"] for e in own}
        for claim in svc.get(inv_id)["snapshot"]["assessment"]["claims"]:
            assert set(claim["evidence_ids"]) <= own_ids
