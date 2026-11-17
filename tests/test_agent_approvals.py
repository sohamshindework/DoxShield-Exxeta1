"""M4 approval security: the interrupt, binding, single use and failure paths.
A failure must never turn into an approval or a successful execution."""
import pytest
from _agent_helpers import ANALYST, APPROVER, BOTH, VIEWER, Env, approve_all, run, start_and_wait
from agent.service import Principal, ServiceError
from incidents import approvals
from incidents.db import ActionRow, ApprovalRow
from incidents.store import verify_audit_chain
from langgraph.types import Command
from mcp_server.errors import ToolError
from sqlalchemy import select


@pytest.fixture()
def env(tmp_path):
    return Env(tmp_path)


@pytest.fixture()
def paused(env):
    svc = env.service()
    inv_id = run(start_and_wait(svc, ANALYST, "app", "app-chrome"))
    assert svc.get(inv_id)["status"] == "awaiting_approval"
    return svc, inv_id


def _proposal(svc, inv_id, kind):
    return next(p for p in svc.get(inv_id)["snapshot"]["proposals"] if p["kind"] == kind)


def _approve_one(svc, inv_id, kind, who=APPROVER):
    """Approve one action without resuming (others stay pending)."""
    p = _proposal(svc, inv_id, kind)
    run(svc.decide(inv_id, p["id"], who, "approve", "ok", p["payload_hash"], wait=True))
    with svc._sf() as s:
        return p, approvals.approval_for_action(s, p["id"]).id


def test_graph_interrupt_is_a_real_langgraph_pause(paused):
    svc, inv_id = paused
    state = svc.graph.get_state(svc._cfg(inv_id))
    assert state.next == ("await_approval",)
    assert state.tasks[0].interrupts[0].value["type"] == "approval_required"


def test_approved_action_runs_exactly_once(env, paused):
    svc, inv_id = paused
    inv = run(approve_all(svc, inv_id))
    ticket = next(e for e in inv["snapshot"]["executions"] if e["kind"] == "create_ticket")
    assert ticket["ok"]
    p = _proposal(svc, inv_id, "create_ticket")
    with env.sf() as s:
        appr = approvals.approval_for_action(s, p["id"])
        assert appr.consumed_at is not None
    # Duplicate execution request with the same approval is refused by the tool.
    with pytest.raises(ToolError) as exc:
        env.tool_impl.create_ticket(p["args"]["title"], p["args"]["body"], appr.id)
    assert exc.value.code == "approval_already_used"
    # ...and over MCP.
    res = run(env.client().call_action("create_ticket", p["args"], appr.id))
    assert not res.ok and res.error_code == "approval_already_used"
    # A second decision on a finished investigation is refused.
    with pytest.raises(ServiceError) as exc2:
        run(svc.decide(inv_id, p["id"], APPROVER, "approve", "again", p["payload_hash"]))
    assert exc2.value.status == 409


def test_text_resume_value_is_not_authorisation(env, paused):
    svc, inv_id = paused
    run(svc._run(inv_id, Command(resume="approved")))
    inv = svc.get(inv_id)
    assert inv["snapshot"]["executions"] == []
    assert "invalid_resume_ignored" in inv["snapshot"]["flags"]
    assert all(p["status"] == "cancelled" for p in inv["snapshot"]["proposals"])


def test_forged_approval_ids_in_resume_are_ignored(env, paused):
    svc, inv_id = paused
    run(svc._run(inv_id, Command(resume={"type": "decided", "approval_ids": ["forged"]})))
    assert svc.get(inv_id)["snapshot"]["executions"] == []


def test_requester_cannot_approve_a_version_revised_by_someone_else(env):
    svc = env.service()
    inv_id = run(start_and_wait(svc, BOTH, "app", "app-chrome"))
    old = _proposal(svc, inv_id, "create_ticket")
    other_analyst = Principal("analyst2@example.invalid", frozenset({"analyst"}))
    new = svc.revise(inv_id, old["id"], other_analyst,
                     {"title": "t2", "body": "b2"}, "edit")
    with pytest.raises(ServiceError) as exc:
        run(svc.decide(inv_id, new["id"], BOTH, "approve", "ok", new["payload_hash"]))
    assert exc.value.code == "self_approval"


def test_self_approval_is_refused(env):
    svc = env.service()
    inv_id = run(start_and_wait(svc, BOTH, "app", "app-chrome"))
    p = _proposal(svc, inv_id, "create_ticket")
    with pytest.raises(ServiceError) as exc:
        run(svc.decide(inv_id, p["id"], BOTH, "approve", "mine", p["payload_hash"]))
    assert exc.value.status == 403 and exc.value.code == "self_approval"


@pytest.mark.parametrize("who", [VIEWER, ANALYST])
def test_non_approvers_cannot_decide(paused, who):
    svc, inv_id = paused
    p = _proposal(svc, inv_id, "create_ticket")
    with pytest.raises(ServiceError) as exc:
        run(svc.decide(inv_id, p["id"], who, "approve", "ok", p["payload_hash"]))
    assert exc.value.code == "forbidden"


def test_reason_is_mandatory(paused):
    svc, inv_id = paused
    p = _proposal(svc, inv_id, "create_ticket")
    with pytest.raises(ServiceError) as exc:
        run(svc.decide(inv_id, p["id"], APPROVER, "approve", "  ", p["payload_hash"]))
    assert exc.value.code == "reason_required"


def test_decision_on_stale_payload_view_is_refused(paused):
    svc, inv_id = paused
    p = _proposal(svc, inv_id, "create_ticket")
    with pytest.raises(ServiceError) as exc:
        run(svc.decide(inv_id, p["id"], APPROVER, "approve", "ok", "0" * 64))
    assert exc.value.code == "approval_payload_mismatch"


def test_modified_payload_is_rejected_by_the_tool(env, paused):
    svc, inv_id = paused
    p, approval_id = _approve_one(svc, inv_id, "propose_block_rule")
    with pytest.raises(ToolError) as exc:
        env.tool_impl.propose_block_rule("evil.example", approval_id)
    assert exc.value.code == "approval_payload_mismatch"
    with pytest.raises(ToolError) as exc:
        env.tool_impl.create_ticket("t", "b", approval_id)
    assert exc.value.code == "approval_mismatch"  # wrong kind
    assert not env.rules_dir.exists()


def test_revision_invalidates_old_version(env, paused):
    svc, inv_id = paused
    old = _proposal(svc, inv_id, "create_ticket")
    new = svc.revise(inv_id, old["id"], ANALYST,
                     {"title": old["args"]["title"], "body": "Edited body"}, "shorter")
    assert new["version"] == 2 and new["supersedes"] == old["id"]
    assert new["payload_hash"] != old["payload_hash"]
    with pytest.raises(ServiceError) as exc:
        run(svc.decide(inv_id, old["id"], APPROVER, "approve", "ok", old["payload_hash"]))
    assert exc.value.code == "action_not_pending"
    # The editor (an analyst) proposed v2 and still cannot approve it.
    with pytest.raises(ServiceError):
        run(svc.decide(inv_id, new["id"], ANALYST, "approve", "ok", new["payload_hash"]))
    inv = run(approve_all(svc, inv_id))
    ticket = next(e for e in inv["snapshot"]["executions"] if e["kind"] == "create_ticket")
    assert ticket["result"]["body"] == "Edited body"


def test_approval_cannot_be_used_after_revision(env, paused):
    svc, inv_id = paused
    p, approval_id = _approve_one(svc, inv_id, "create_ticket")
    with env.sf() as s:  # simulate a later edit/state change of the approved action
        s.get(ActionRow, p["id"]).status = approvals.ActionStatus.SUPERSEDED
        s.commit()
    with pytest.raises(ToolError) as exc:
        env.tool_impl.create_ticket(p["args"]["title"], p["args"]["body"], approval_id)
    assert exc.value.code == "approval_stale"


def test_expired_approval_is_not_executed(env, paused, monkeypatch):
    svc, inv_id = paused
    monkeypatch.setenv("DOXSHIELD_APPROVAL_MAX_AGE_SECONDS", "-1")
    inv = run(approve_all(svc, inv_id))
    assert inv["snapshot"]["executions"] == []
    assert {d["error"] for d in inv["snapshot"]["decisions"] if d["status"] == "approved"} == \
        {"approval_expired"}


def test_approval_from_another_investigation_is_refused(env):
    svc = env.service()
    a = run(start_and_wait(svc, ANALYST, "app", "app-chrome"))
    b = run(start_and_wait(svc, ANALYST, "app", "app-chrome"))
    pa, approval_a = _approve_one(svc, a, "create_ticket")
    pb = _proposal(svc, b, "create_ticket")
    with env.sf() as s:
        with pytest.raises(approvals.ApprovalError) as exc:
            approvals.validate_for_execution(s, approval_a, "create_ticket", pa["args"],
                                             investigation_id=b)
    assert exc.value.code == "approval_mismatch"
    # Deciding on investigation B's action through investigation A is refused.
    with pytest.raises(ServiceError) as exc2:
        run(svc.decide(a, pb["id"], APPROVER, "approve", "ok", pb["payload_hash"]))
    assert exc2.value.code == "action_not_found"


def test_forged_rows_cannot_authorise(env, paused):
    """An approval row inserted without the proper role/binding is refused."""
    svc, inv_id = paused
    p = _proposal(svc, inv_id, "create_ticket")
    with env.sf() as s:
        s.add(ApprovalRow(id="forged-1", incident_id=None, action_id=p["id"],
                          decided_by="attacker", decision="approved", reason="x",
                          timestamp="2026-11-17T00:00:00+00:00", investigation_id=inv_id,
                          payload_hash=p["payload_hash"], approver_role=None))
        s.commit()
    with pytest.raises(ToolError) as exc:
        env.tool_impl.create_ticket(p["args"]["title"], p["args"]["body"], "forged-1")
    assert exc.value.code == "approval_stale"  # action itself is still only proposed


def test_concurrent_consumption_only_succeeds_once(env, paused):
    svc, inv_id = paused
    p, approval_id = _approve_one(svc, inv_id, "create_ticket")
    with env.sf() as s1, env.sf() as s2:
        approvals.validate_for_execution(s2, approval_id, "create_ticket", p["args"])
        approvals.consume_approval(s1, approval_id, "create_ticket", p["args"])
        with pytest.raises(approvals.ApprovalError):
            approvals.consume_approval(s2, approval_id, "create_ticket", p["args"])


def test_failed_action_is_recorded_not_retried(env):
    svc = env.service()
    inv_id = run(start_and_wait(svc, ANALYST, "incident", env.incident("WeatherApp").id))
    calls = []

    def failing_draft(*_args):  # the tool fails after the approval was given
        calls.append(1)
        raise ToolError("internal", "boom")

    env.tool_impl.draft_dpo_notification = failing_draft
    inv = run(approve_all(svc, inv_id))
    dpo = next(e for e in inv["snapshot"]["executions"] if e["kind"] == "draft_dpo_notification")
    assert dpo["ok"] is False and dpo["error_code"] == "internal"
    assert len(calls) == 1  # non-idempotent action: never retried
    assert next(p for p in inv["snapshot"]["proposals"]
                if p["kind"] == "draft_dpo_notification")["status"] == "failed"
    assert inv["status"] == "completed"


def test_audit_trail_is_complete_and_verifies(env, paused):
    svc, inv_id = paused
    run(approve_all(svc, inv_id))
    from incidents.db import AuditRow
    with env.sf() as s:
        actions = [r.action for r in s.scalars(select(AuditRow).where(
            AuditRow.target_id == inv_id).order_by(AuditRow.seq))]
        ok, broken = verify_audit_chain(s)
    assert ok and broken is None
    for expected in ("investigation.started", "investigation.triaged",
                     "investigation.tool_call", "investigation.assessed", "action.proposed",
                     "investigation.awaiting_approval", "action.approved", "action.executed",
                     "investigation.reported"):
        assert expected in actions, expected
    assert actions.index("action.approved") < actions.index("action.executed")


def test_unknown_principal_roles_cannot_do_anything(paused):
    svc, inv_id = paused
    nobody = Principal("x@example.invalid", frozenset())
    with pytest.raises(ServiceError):
        run(svc.cancel(inv_id, nobody))
    with pytest.raises(ServiceError):
        run(svc.start(nobody, "app", "app-chrome"))
