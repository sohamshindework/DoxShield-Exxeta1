"""DoxShield tool logic: read-only tools and gated action tools."""
import asyncio
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sidecar"))

os.environ["DOXSHIELD_BACKEND"] = "fixture"

from incidents import approvals  # noqa: E402
from incidents.db import init_db, make_engine, make_session_factory  # noqa: E402
from incidents.models import (  # noqa: E402
    Decision,
    Evidence,
    EvidenceClass,
    Incident,
    IncidentType,
    Severity,
)
from incidents.store import save_incident  # noqa: E402
from mcp_server.errors import ToolError  # noqa: E402
from mcp_server.tools import DoxShieldTools  # noqa: E402
from scanner import backend as backend_mod  # noqa: E402


@pytest.fixture()
def env(tmp_path):
    backend_mod.reset_backend()
    engine = make_engine(f"sqlite:///{tmp_path / 'tools.db'}")
    init_db(engine)
    sf = make_session_factory(engine)
    tools = DoxShieldTools(backend=backend_mod.get_backend(), session_factory=sf,
                           block_rules_dir=tmp_path / "rules")
    return tools, sf


# Arguments each test later passes to the tool. Since M4 an approval is bound to
# the exact payload, so the helper proposes exactly these arguments.
_DEFAULT_ARGS = {
    "draft_dpo_notification": None,  # filled with the incident id
    "create_ticket": {"title": "t", "body": "b"},
    "send_alert_email": {"to": "dpo@example.invalid", "subject": "subj", "body": "body"},
    "propose_block_rule": {"target": "tracker.example"},
}


def _approved(sf, kind, decision=Decision.APPROVED):
    """Create an incident with one proposed action and a human decision on it,
    using the same approval store the API uses (proposer != approver)."""
    inc = Incident(
        type=IncidentType.KNOWN_TRACKER, severity=Severity.MEDIUM,
        title="t", source_scanner="x",
        evidence=[Evidence(source_tool="network",
                           evidence_class=EvidenceClass.OBSERVED, summary="s")],
    )
    args = _DEFAULT_ARGS[kind] or {"incident_id": inc.id}
    with sf() as s:
        save_incident(s, inc)
        action = approvals.create_proposal(
            s, kind=kind, args=args, proposed_by="analyst@example.invalid",
            description="d", expected_effect="e", investigation_id="inv-test",
            incident_id=inc.id)
        approval = approvals.record_decision(
            s, action_id=action.id, investigation_id="inv-test",
            decided_by="dpo@example.invalid", roles={"approver"}, decision=decision,
            reason="r", seen_payload_hash=action.payload_hash)
    return inc.id, approval.id


# ── Read-only tools ───────────────────────────────────────────────────────────

def test_list_apps(env):
    tools, _ = env
    assert any(a["name"] == "Google Chrome" for a in tools.list_apps())


def test_get_connections_filter(env):
    tools, _ = env
    conns = asyncio.run(tools.get_connections("WeatherApp"))
    assert conns and all("weather" in c["app_name"].lower() for c in conns)


def test_lookup_ip_is_offline(env):
    tools, _ = env
    assert asyncio.run(tools.lookup_ip_jurisdiction("192.168.1.1"))["jurisdiction"] == "LOCAL"


def test_check_tracker_shape(env):
    tools, _ = env
    r = tools.check_tracker("www.google-analytics.com")
    assert r["domain"] == "www.google-analytics.com" and "is_known_tracker" in r


def test_search_knowledge_has_sources(env):
    tools, _ = env
    res = tools.search_knowledge("adequacy transfer")
    assert res and all("source" in n and "retrieved" in n for n in res)


def test_find_eu_alternatives(env):
    tools, _ = env
    res = tools.find_eu_alternatives("Email")
    assert any(a["country"] in ("CH", "DE") for a in res)


def test_incident_history_and_evidence(env):
    tools, sf = env
    inc_id, _ = _approved(sf, "create_ticket")
    assert any(i["id"] == inc_id for i in tools.get_incidents())
    assert tools.get_evidence(inc_id)


def test_local_risk_indicators(env):
    tools, _ = env
    r = asyncio.run(tools.local_risk_indicators())
    assert r["connections"] >= 1 and r["basis"] == "heuristic"


# ── Gated action tools ────────────────────────────────────────────────────────

def test_action_runs_with_valid_approval(env):
    tools, sf = env
    inc_id, approval_id = _approved(sf, "draft_dpo_notification")
    out = tools.draft_dpo_notification(inc_id, approval_id)
    assert out["sent"] is False and "draft" in out


def test_missing_approval_rejected(env):
    tools, sf = env
    inc_id, _ = _approved(sf, "draft_dpo_notification")
    with pytest.raises(ToolError) as exc:
        tools.draft_dpo_notification(inc_id, "")
    assert exc.value.code == "approval_required"


def test_forged_approval_rejected(env):
    tools, sf = env
    inc_id, _ = _approved(sf, "draft_dpo_notification")
    with pytest.raises(ToolError) as exc:
        tools.draft_dpo_notification(inc_id, "forged-approval-id")
    assert exc.value.code == "approval_not_found"


def test_wrong_kind_approval_rejected(env):
    tools, sf = env
    inc_id, approval_id = _approved(sf, "create_ticket")  # not a dpo-notification approval
    with pytest.raises(ToolError) as exc:
        tools.draft_dpo_notification(inc_id, approval_id)
    assert exc.value.code == "approval_mismatch"


def test_rejected_approval_rejected(env):
    tools, sf = env
    _, approval_id = _approved(sf, "propose_block_rule", decision=Decision.REJECTED)
    with pytest.raises(ToolError) as exc:
        tools.propose_block_rule("tracker.example", approval_id)
    assert exc.value.code == "approval_not_granted"


def test_propose_block_rule_is_dry_run(env):
    tools, sf = env
    _, approval_id = _approved(sf, "propose_block_rule")
    out = tools.propose_block_rule("tracker.example", approval_id)
    assert out["applied"] is False and out["dry_run"] is True
    rule_file = Path(out["rule_file"])
    assert rule_file.exists() and "DRY-RUN" in rule_file.read_text()


def test_send_alert_email_never_sends(env):
    tools, sf = env
    _, approval_id = _approved(sf, "send_alert_email")
    out = tools.send_alert_email("dpo@example.invalid", "subj", "body", approval_id)
    assert out["sent"] is False
