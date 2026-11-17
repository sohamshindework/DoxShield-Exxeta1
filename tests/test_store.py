"""Incident persistence round-trips through SQLAlchemy (SQLite)."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sidecar"))

from incidents.db import init_db, make_engine, make_session_factory  # noqa: E402
from incidents.models import (  # noqa: E402
    Approval,
    Decision,
    Evidence,
    EvidenceClass,
    Incident,
    IncidentType,
    ProposedAction,
    Severity,
)
from incidents.store import get_incident, list_incidents, save_incident  # noqa: E402


@pytest.fixture()
def session(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'test.db'}")
    init_db(engine)
    factory = make_session_factory(engine)
    with factory() as s:
        yield s


def _sample_incident() -> Incident:
    action = ProposedAction(kind="draft_dpo_notification", description="Draft a note",
                            expected_effect="Creates a draft for review")
    return Incident(
        type=IncidentType.NON_ADEQUATE_TRANSFER, severity=Severity.HIGH,
        title="Weather app -> CN", source_scanner="network+permissions",
        app="WeatherApp", destination="api.telemetry.example", country_code="CN",
        jurisdiction="CN", recommended_follow_up="DPO review",
        evidence=[Evidence(source_tool="network", evidence_class=EvidenceClass.OBSERVED,
                           summary="flow to CN", payload={"ip": "203.0.113.44"})],
        proposed_actions=[action],
        approvals=[Approval(action_id=action.id, decided_by="dpo@example.invalid",
                            decision=Decision.APPROVED, reason="expected telemetry")],
    )


def test_save_and_reload_incident(session):
    inc = _sample_incident()
    save_incident(session, inc)

    loaded = get_incident(session, inc.id)
    assert loaded is not None
    assert loaded.title == inc.title
    assert loaded.country_code == "CN"
    assert len(loaded.evidence) == 1 and loaded.evidence[0].hash
    assert loaded.proposed_actions[0].kind == "draft_dpo_notification"
    assert loaded.approvals[0].decision == Decision.APPROVED


def test_list_incidents(session):
    save_incident(session, _sample_incident())
    save_incident(session, _sample_incident())
    assert len(list_incidents(session)) == 2
