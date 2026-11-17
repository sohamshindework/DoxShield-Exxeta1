"""The audit log is append-only and tamper-evident."""
import sys
from pathlib import Path

import pytest
from sqlalchemy import update

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sidecar"))

from incidents.db import AuditRow, init_db, make_engine, make_session_factory  # noqa: E402
from incidents.store import append_audit, verify_audit_chain  # noqa: E402


@pytest.fixture()
def session(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'audit.db'}")
    init_db(engine)
    factory = make_session_factory(engine)
    with factory() as s:
        yield s


def test_chain_verifies_when_intact(session):
    append_audit(session, "analyst", "create_incident", "incident", "i1", {"n": 1})
    append_audit(session, "analyst", "investigate", "incident", "i1", {"n": 2})
    append_audit(session, "approver", "approve", "action", "a1", {"n": 3})
    ok, broken = verify_audit_chain(session)
    assert ok and broken is None


def test_sequence_and_linkage(session):
    e1 = append_audit(session, "analyst", "create", "incident", "i1")
    e2 = append_audit(session, "analyst", "update", "incident", "i1")
    assert e1.seq == 1 and e2.seq == 2
    assert e2.prev_hash == e1.hash


def test_tampering_breaks_the_chain(session):
    append_audit(session, "analyst", "create", "incident", "i1", {"amount": 1})
    append_audit(session, "approver", "approve", "action", "a1", {"amount": 2})

    # Tamper with a stored row's data, bypassing append_audit.
    session.execute(update(AuditRow).where(AuditRow.seq == 1)
                    .values(data={"amount": 999}))
    session.commit()

    ok, broken = verify_audit_chain(session)
    assert ok is False
    assert broken == 1
