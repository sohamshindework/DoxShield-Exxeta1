"""Persistence and the append-only, tamper-evident audit log."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import (
    ActionRow,
    ApprovalRow,
    AuditRow,
    EvidenceRow,
    IncidentRow,
)
from .models import (
    GENESIS_HASH,
    Approval,
    AuditEvent,
    Evidence,
    EvidenceClass,
    Incident,
    IncidentType,
    ProposedAction,
    Severity,
    Status,
    canonical_hash,
)

# ─── Incidents ────────────────────────────────────────────────────────────────

def save_incident(session: Session, incident: Incident) -> str:
    row = IncidentRow(
        id=incident.id,
        type=incident.type.value,
        severity=incident.severity.value,
        status=incident.status.value,
        title=incident.title,
        source_scanner=incident.source_scanner,
        app=incident.app,
        destination=incident.destination,
        country_code=incident.country_code,
        jurisdiction=incident.jurisdiction,
        confidence=incident.confidence,
        confidence_basis=incident.confidence_basis,
        uncertainty=incident.uncertainty,
        recommended_follow_up=incident.recommended_follow_up,
        detected_at=incident.detected_at,
    )
    for ev in incident.evidence:
        if ev.hash is None:
            ev.finalize()
        row.evidence.append(EvidenceRow(
            id=ev.id, source_tool=ev.source_tool,
            evidence_class=ev.evidence_class.value, summary=ev.summary,
            payload=ev.payload, timestamp=ev.timestamp, hash=ev.hash,
        ))
    for ac in incident.proposed_actions:
        row.actions.append(ActionRow(
            id=ac.id, kind=ac.kind, description=ac.description,
            expected_effect=ac.expected_effect, reversible=ac.reversible,
            requires_approval=ac.requires_approval,
        ))
    for ap in incident.approvals:
        row.approvals.append(ApprovalRow(
            id=ap.id, action_id=ap.action_id, decided_by=ap.decided_by,
            decision=ap.decision.value, reason=ap.reason, timestamp=ap.timestamp,
        ))
    session.add(row)
    session.commit()
    return incident.id


def _row_to_incident(row: IncidentRow) -> Incident:
    return Incident(
        id=row.id,
        type=IncidentType(row.type),
        severity=Severity(row.severity),
        status=Status(row.status),
        title=row.title,
        source_scanner=row.source_scanner,
        app=row.app,
        destination=row.destination,
        country_code=row.country_code,
        jurisdiction=row.jurisdiction,
        confidence=row.confidence,
        confidence_basis=row.confidence_basis,
        uncertainty=row.uncertainty,
        recommended_follow_up=row.recommended_follow_up,
        detected_at=row.detected_at,
        evidence=[
            Evidence(
                id=e.id, source_tool=e.source_tool,
                evidence_class=EvidenceClass(e.evidence_class), summary=e.summary,
                payload=e.payload, timestamp=e.timestamp, hash=e.hash,
            ) for e in row.evidence
        ],
        proposed_actions=[
            ProposedAction(
                id=a.id, kind=a.kind, description=a.description,
                expected_effect=a.expected_effect, reversible=a.reversible,
                requires_approval=a.requires_approval,
            ) for a in row.actions
        ],
        approvals=[
            Approval(
                id=p.id, action_id=p.action_id, decided_by=p.decided_by,
                decision=p.decision, reason=p.reason, timestamp=p.timestamp,
            ) for p in row.approvals
        ],
    )


def get_incident(session: Session, incident_id: str) -> Incident | None:
    row = session.get(IncidentRow, incident_id)
    return _row_to_incident(row) if row else None


def list_incidents(session: Session) -> list[Incident]:
    rows = session.scalars(select(IncidentRow)).all()
    return [_row_to_incident(r) for r in rows]


# ─── Audit log (append-only, hash-chained) ────────────────────────────────────

def append_audit(
    session: Session,
    actor: str,
    action: str,
    target_type: str,
    target_id: str,
    data: dict | None = None,
) -> AuditEvent:
    last = session.scalars(
        select(AuditRow).order_by(AuditRow.seq.desc()).limit(1)
    ).first()
    seq = (last.seq + 1) if last else 1
    prev_hash = last.hash if last else GENESIS_HASH

    event = AuditEvent(
        seq=seq, actor=actor, action=action, target_type=target_type,
        target_id=target_id, data=data or {}, prev_hash=prev_hash,
    ).finalize()

    session.add(AuditRow(
        seq=event.seq, id=event.id, timestamp=event.timestamp, actor=event.actor,
        action=event.action, target_type=event.target_type,
        target_id=event.target_id, data=event.data, prev_hash=event.prev_hash,
        hash=event.hash,
    ))
    session.commit()
    return event


def verify_audit_chain(session: Session) -> tuple[bool, int | None]:
    """Recompute every event's hash and check the chain links.

    Returns ``(ok, broken_seq)``. ``broken_seq`` is the first sequence number
    whose stored hash does not match its content or whose link to the previous
    event is broken; ``None`` when the chain is intact.
    """
    rows = session.scalars(select(AuditRow).order_by(AuditRow.seq.asc())).all()
    expected_prev = GENESIS_HASH
    for row in rows:
        recomputed = canonical_hash({
            "seq": row.seq,
            "timestamp": row.timestamp,
            "actor": row.actor,
            "action": row.action,
            "target_type": row.target_type,
            "target_id": row.target_id,
            "data": row.data,
            "prev_hash": row.prev_hash,
        })
        if recomputed != row.hash or row.prev_hash != expected_prev:
            return False, row.seq
        expected_prev = row.hash
    return True, None
