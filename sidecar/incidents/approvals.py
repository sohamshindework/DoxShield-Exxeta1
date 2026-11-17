"""The single approval system for gated actions (M3 gate, strengthened in M4).

An approval authorises exactly one execution of exactly one action version:

* **kind** — the action tool it was granted for;
* **payload** — a hash of the exact tool arguments the approver saw;
* **investigation / incident** — the run that proposed it;
* **identity** — decided by a principal with the ``approver`` role who is not
  the person who proposed the action ("nobody approves their own proposal");
* **state** — the action must still be ``approved`` (not superseded by a
  revision, cancelled, or already executed), the approval must be unused, and it
  must be younger than ``APPROVAL_MAX_AGE_SECONDS``.

Both the MCP action tools (``mcp_server/tools.py``) and the LangGraph agent call
``validate_for_execution``; only the tool calls ``consume_approval``, which marks
the approval used in one conditional UPDATE so a duplicate request cannot run the
action twice.
"""
from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from .db import ActionRow, ApprovalRow
from .models import Decision, canonical_hash, new_id, now_iso

# The exact argument names each gated tool accepts (``approval_id`` excluded).
ACTION_ARG_KEYS: dict[str, tuple[str, ...]] = {
    "draft_dpo_notification": ("incident_id",),
    "create_ticket": ("title", "body"),
    "send_alert_email": ("to", "subject", "body"),
    "propose_block_rule": ("target",),
}

APPROVER_ROLE = "approver"
DEFAULT_MAX_AGE_SECONDS = 24 * 3600


class ActionStatus:
    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    SUPERSEDED = "superseded"
    CANCELLED = "cancelled"
    EXECUTED = "executed"
    FAILED = "failed"


class ApprovalError(Exception):
    """An approval check failed. ``code`` is machine-readable and stable."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def approval_max_age_seconds() -> int:
    try:
        return int(os.getenv("DOXSHIELD_APPROVAL_MAX_AGE_SECONDS", DEFAULT_MAX_AGE_SECONDS))
    except ValueError:
        return DEFAULT_MAX_AGE_SECONDS


def normalise_args(kind: str, args: dict[str, Any]) -> dict[str, Any]:
    """Return exactly the arguments the tool accepts, or raise."""
    keys = ACTION_ARG_KEYS.get(kind)
    if keys is None:
        raise ApprovalError("unknown_action", f"{kind!r} is not a gated action")
    if set(args) != set(keys):
        raise ApprovalError("bad_payload", f"{kind} takes exactly {list(keys)}")
    for k in keys:
        if not isinstance(args[k], str):
            raise ApprovalError("bad_payload", f"{kind}.{k} must be a string")
    return {k: args[k] for k in keys}


def payload_hash(kind: str, args: dict[str, Any]) -> str:
    return canonical_hash({"kind": kind, "args": normalise_args(kind, args)})


# ─── Proposals ────────────────────────────────────────────────────────────────

def create_proposal(
    session: Session,
    *,
    kind: str,
    args: dict[str, Any],
    proposed_by: str,
    description: str,
    expected_effect: str,
    investigation_id: str | None = None,
    incident_id: str | None = None,
    reason: str = "",
    evidence_ids: list[str] | None = None,
    limitations: str = "",
    reversible: bool = True,
    version: int = 1,
    supersedes: str | None = None,
    commit: bool = True,
) -> ActionRow:
    clean = normalise_args(kind, args)
    row = ActionRow(
        id=new_id(), incident_id=incident_id, kind=kind, description=description,
        expected_effect=expected_effect, reversible=reversible, requires_approval=True,
        investigation_id=investigation_id, args=clean, payload_hash=payload_hash(kind, clean),
        proposed_by=proposed_by, status=ActionStatus.PROPOSED, version=version,
        supersedes=supersedes, reason=reason, evidence_ids=list(evidence_ids or []),
        limitations=limitations, created_at=now_iso(),
    )
    session.add(row)
    if commit:
        session.commit()
    return row


def current_actions(session: Session, investigation_id: str) -> list[ActionRow]:
    """Actions of an investigation that are not superseded by a revision."""
    rows = session.scalars(
        select(ActionRow).where(ActionRow.investigation_id == investigation_id)
    ).all()
    return [r for r in rows if r.status != ActionStatus.SUPERSEDED]


def revise_proposal(
    session: Session,
    *,
    action_id: str,
    investigation_id: str,
    revised_by: str,
    new_args: dict[str, Any],
    note: str,
) -> ActionRow:
    """Replace a still-pending proposal with a new version.

    The new version gets a new id and payload hash, so no earlier approval can
    authorise it. The editor becomes the proposer of the new version.
    """
    old = session.get(ActionRow, action_id)
    if old is None or old.investigation_id != investigation_id:
        raise ApprovalError("action_not_found", "No such action in this investigation")
    if old.status != ActionStatus.PROPOSED:
        raise ApprovalError("action_not_pending", f"Action is {old.status!r}")
    old.status = ActionStatus.SUPERSEDED
    new = create_proposal(
        session, kind=old.kind, args=new_args, proposed_by=revised_by,
        description=old.description, expected_effect=old.expected_effect,
        investigation_id=old.investigation_id, incident_id=old.incident_id,
        reason=f"{old.reason} [revised: {note.strip()[:300]}]",
        evidence_ids=list(old.evidence_ids or []), limitations=old.limitations or "",
        reversible=old.reversible, version=(old.version or 1) + 1, supersedes=old.id,
        commit=False,
    )
    session.commit()
    return new


def cancel_pending(session: Session, investigation_id: str) -> int:
    """Cancel every not-yet-executed action of an investigation."""
    n = 0
    for row in current_actions(session, investigation_id):
        if row.status in (ActionStatus.PROPOSED, ActionStatus.APPROVED):
            row.status = ActionStatus.CANCELLED
            n += 1
    session.commit()
    return n


# ─── Decisions ────────────────────────────────────────────────────────────────

def record_decision(
    session: Session,
    *,
    action_id: str,
    investigation_id: str,
    decided_by: str,
    roles: set[str] | frozenset[str],
    decision: Decision,
    reason: str,
    seen_payload_hash: str,
) -> ApprovalRow:
    """Record a human approve/reject decision for one pending action version."""
    if APPROVER_ROLE not in roles:
        raise ApprovalError("forbidden", "Only an approver can decide on actions")
    if not reason or not reason.strip():
        raise ApprovalError("reason_required", "A decision needs a reason")
    action = session.get(ActionRow, action_id)
    if action is None or action.investigation_id != investigation_id:
        raise ApprovalError("action_not_found", "No such action in this investigation")
    if action.status != ActionStatus.PROPOSED:
        raise ApprovalError("action_not_pending", f"Action is {action.status!r}")
    if not action.payload_hash or seen_payload_hash != action.payload_hash:
        raise ApprovalError("approval_payload_mismatch",
                            "The payload changed since it was reviewed; review it again")
    if decided_by == action.proposed_by:
        raise ApprovalError("self_approval", "Nobody can approve an action they proposed")

    row = ApprovalRow(
        id=new_id(), incident_id=action.incident_id, action_id=action.id,
        decided_by=decided_by, decision=decision.value, reason=reason.strip()[:1000],
        timestamp=now_iso(), investigation_id=investigation_id,
        payload_hash=action.payload_hash, approver_role=APPROVER_ROLE,
    )
    action.status = (ActionStatus.APPROVED if decision == Decision.APPROVED
                     else ActionStatus.REJECTED)
    session.add(row)
    session.commit()
    return row


def approval_for_action(session: Session, action_id: str) -> ApprovalRow | None:
    return session.scalars(
        select(ApprovalRow).where(ApprovalRow.action_id == action_id)
        .order_by(ApprovalRow.timestamp.desc())
    ).first()


# ─── Execution gate ───────────────────────────────────────────────────────────

def _age_seconds(ts: str, now: datetime) -> float:
    try:
        then = datetime.fromisoformat(ts)
    except (TypeError, ValueError):
        return float("inf")
    if then.tzinfo is None:
        then = then.replace(tzinfo=UTC)
    return (now - then).total_seconds()


def validate_for_execution(
    session: Session,
    approval_id: str,
    kind: str,
    args: dict[str, Any],
    *,
    investigation_id: str | None = None,
    now: datetime | None = None,
) -> tuple[ApprovalRow, ActionRow]:
    """Check that ``approval_id`` authorises running ``kind`` with ``args`` now.

    Order matters only for which error code is reported; every check must pass.
    """
    if not approval_id:
        raise ApprovalError("approval_required", "This action requires an approval_id")
    approval = session.get(ApprovalRow, approval_id)
    if approval is None:
        raise ApprovalError("approval_not_found", "Unknown approval_id")
    if approval.decision != Decision.APPROVED.value:
        raise ApprovalError("approval_not_granted", f"Approval decision is {approval.decision!r}")
    action = session.get(ActionRow, approval.action_id)
    if action is None or action.kind != kind:
        raise ApprovalError("approval_mismatch", f"Approval does not authorise {kind!r}")
    try:
        requested_hash = payload_hash(kind, args)
    except ApprovalError as exc:
        raise ApprovalError("approval_payload_mismatch", exc.message) from exc
    if not action.payload_hash or approval.payload_hash != action.payload_hash \
            or requested_hash != action.payload_hash:
        raise ApprovalError("approval_payload_mismatch",
                            "Arguments differ from the approved payload")
    if approval.investigation_id != action.investigation_id \
            or approval.incident_id != action.incident_id:
        raise ApprovalError("approval_mismatch", "Approval belongs to a different investigation")
    if investigation_id is not None and action.investigation_id != investigation_id:
        raise ApprovalError("approval_mismatch", "Approval belongs to a different investigation")
    if approval.consumed_at or action.status == ActionStatus.EXECUTED:
        raise ApprovalError("approval_already_used", "This approval was already used")
    if action.status != ActionStatus.APPROVED:
        raise ApprovalError("approval_stale", f"Action is {action.status!r}, not approved")
    if approval.approver_role != APPROVER_ROLE:
        raise ApprovalError("approval_role_invalid", "Approval was not given by an approver")
    if not action.proposed_by or approval.decided_by == action.proposed_by:
        raise ApprovalError("self_approval", "Nobody can approve an action they proposed")
    if _age_seconds(approval.timestamp, now or datetime.now(UTC)) > approval_max_age_seconds():
        raise ApprovalError("approval_expired", "Approval is older than the allowed age")
    return approval, action


def consume_approval(
    session: Session, approval_id: str, kind: str, args: dict[str, Any],
) -> tuple[ApprovalRow, ActionRow]:
    """Validate, then mark the approval used with a single conditional UPDATE.

    If two requests race, only one UPDATE matches ``consumed_at IS NULL``; the
    other gets ``approval_already_used``.
    """
    approval, action = validate_for_execution(session, approval_id, kind, args)
    stamp = now_iso()
    res = session.execute(
        update(ApprovalRow)
        .where(ApprovalRow.id == approval_id, ApprovalRow.consumed_at.is_(None))
        .values(consumed_at=stamp)
    )
    if getattr(res, "rowcount", 0) != 1:
        session.rollback()
        raise ApprovalError("approval_already_used", "This approval was already used")
    session.execute(
        update(ActionRow).where(ActionRow.id == action.id)
        .values(status=ActionStatus.EXECUTED, executed_at=stamp)
    )
    session.commit()
    return approval, action


def record_action_result(session: Session, action_id: str, *, ok: bool,
                         result: dict[str, Any]) -> None:
    row = session.get(ActionRow, action_id)
    if row is None:
        return
    row.status = ActionStatus.EXECUTED if ok else ActionStatus.FAILED
    row.result = result
    session.commit()
