"""Pydantic models for privacy incidents, evidence, actions, approvals and audit.

Design notes:
- Evidence is tagged by class — ``observed`` (a scanner fact), ``heuristic`` (a
  rule-based indicator) or ``ai`` (a language-model interpretation) — so facts are
  never conflated with inference.
- ``Incident.confidence`` is a heuristic score in [0, 1], NOT a calibrated
  probability. ``confidence_basis`` records how it was derived.
- ``Evidence`` and ``AuditEvent`` carry a SHA-256 ``hash`` of their canonical
  content. The audit log is append-only and each event also stores the previous
  event's hash, forming a tamper-evident chain.
"""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def new_id() -> str:
    return str(uuid4())


def canonical_hash(obj: Any) -> str:
    """Deterministic SHA-256 over a JSON-canonicalised object."""
    encoded = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    SEVERE = "SEVERE"


class IncidentType(str, Enum):
    NON_ADEQUATE_TRANSFER = "non_adequate_transfer"
    KNOWN_TRACKER = "known_tracker"
    NEW_DESTINATION_COUNTRY = "new_destination_country"
    POLICY_RED_FLAG = "policy_red_flag"


class Status(str, Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    AWAITING_APPROVAL = "awaiting_approval"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


class EvidenceClass(str, Enum):
    OBSERVED = "observed"      # a direct scanner observation / fact
    HEURISTIC = "heuristic"    # a rule-based indicator
    AI = "ai"                  # a language-model interpretation


class Decision(str, Enum):
    APPROVED = "approved"
    REJECTED = "rejected"


class Evidence(BaseModel):
    id: str = Field(default_factory=new_id)
    source_tool: str
    evidence_class: EvidenceClass
    summary: str
    payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=now_iso)
    hash: str | None = None

    def finalize(self) -> Evidence:
        """Compute and store the content hash. Idempotent."""
        self.hash = canonical_hash({
            "source_tool": self.source_tool,
            "evidence_class": self.evidence_class.value,
            "summary": self.summary,
            "payload": self.payload,
            "timestamp": self.timestamp,
        })
        return self


class ProposedAction(BaseModel):
    id: str = Field(default_factory=new_id)
    kind: str                     # draft_dpo_notification, create_ticket, propose_block_rule, ...
    description: str
    expected_effect: str
    reversible: bool = True
    requires_approval: bool = True


class Approval(BaseModel):
    id: str = Field(default_factory=new_id)
    action_id: str
    decided_by: str
    decision: Decision
    reason: str
    timestamp: str = Field(default_factory=now_iso)


class Incident(BaseModel):
    id: str = Field(default_factory=new_id)
    type: IncidentType
    severity: Severity
    status: Status = Status.NEW
    title: str
    source_scanner: str
    app: str | None = None
    destination: str | None = None
    country_code: str | None = None
    jurisdiction: str | None = None
    # Heuristic score in [0, 1]. NOT a calibrated probability.
    confidence: float = 0.5
    confidence_basis: str = "heuristic"
    uncertainty: str | None = None
    recommended_follow_up: str | None = None
    evidence: list[Evidence] = Field(default_factory=list)
    proposed_actions: list[ProposedAction] = Field(default_factory=list)
    approvals: list[Approval] = Field(default_factory=list)
    detected_at: str = Field(default_factory=now_iso)


class AuditEvent(BaseModel):
    id: str = Field(default_factory=new_id)
    seq: int
    timestamp: str = Field(default_factory=now_iso)
    actor: str
    action: str
    target_type: str
    target_id: str
    data: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str
    hash: str | None = None

    def finalize(self) -> AuditEvent:
        self.hash = canonical_hash({
            "seq": self.seq,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "action": self.action,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "data": self.data,
            "prev_hash": self.prev_hash,
        })
        return self


GENESIS_HASH = "0" * 64
