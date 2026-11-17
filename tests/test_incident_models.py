"""Incident model basics: deterministic hashing and evidence classification."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sidecar"))

from incidents.models import (  # noqa: E402
    GENESIS_HASH,
    AuditEvent,
    Evidence,
    EvidenceClass,
    Incident,
    IncidentType,
    Severity,
    canonical_hash,
)


def test_evidence_hash_is_deterministic_and_content_bound():
    e1 = Evidence(source_tool="network", evidence_class=EvidenceClass.OBSERVED,
                  summary="x", payload={"a": 1}, timestamp="2026-01-01T00:00:00").finalize()
    e2 = Evidence(source_tool="network", evidence_class=EvidenceClass.OBSERVED,
                  summary="x", payload={"a": 1}, timestamp="2026-01-01T00:00:00").finalize()
    assert e1.hash == e2.hash and len(e1.hash) == 64
    e2.payload = {"a": 2}
    assert e2.finalize().hash != e1.hash


def test_canonical_hash_key_order_independent():
    assert canonical_hash({"a": 1, "b": 2}) == canonical_hash({"b": 2, "a": 1})


def test_audit_event_finalize():
    ev = AuditEvent(seq=1, actor="analyst", action="create", target_type="incident",
                    target_id="i1", data={}, prev_hash=GENESIS_HASH).finalize()
    assert ev.hash and len(ev.hash) == 64


def test_incident_confidence_is_heuristic_not_probability():
    inc = Incident(type=IncidentType.KNOWN_TRACKER, severity=Severity.MEDIUM,
                   title="t", source_scanner="network")
    assert 0.0 <= inc.confidence <= 1.0
    assert inc.confidence_basis in {"observed", "heuristic", "ai"}
