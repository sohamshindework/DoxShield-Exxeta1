"""SQLAlchemy engine, session and ORM tables for the incident store.

The database is chosen by ``DATABASE_URL``. It defaults to a local SQLite file so
development and CI need no running server; docker-compose provides PostgreSQL for
a production-like setup (``postgresql+psycopg://...``). The ORM is backend-neutral.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Float,
    ForeignKey,
    Integer,
    String,
    create_engine,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
    sessionmaker,
)


def _default_sqlite_url() -> str:
    data_dir = Path(os.path.expanduser("~/.doxshield"))
    data_dir.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{data_dir / 'doxshield.db'}"


def get_database_url() -> str:
    return os.getenv("DATABASE_URL", "").strip() or _default_sqlite_url()


class Base(DeclarativeBase):
    pass


class IncidentRow(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    type: Mapped[str] = mapped_column(String)
    severity: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String)
    title: Mapped[str] = mapped_column(String)
    source_scanner: Mapped[str] = mapped_column(String)
    app: Mapped[str | None] = mapped_column(String, nullable=True)
    destination: Mapped[str | None] = mapped_column(String, nullable=True)
    country_code: Mapped[str | None] = mapped_column(String, nullable=True)
    jurisdiction: Mapped[str | None] = mapped_column(String, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    confidence_basis: Mapped[str] = mapped_column(String, default="heuristic")
    uncertainty: Mapped[str | None] = mapped_column(String, nullable=True)
    recommended_follow_up: Mapped[str | None] = mapped_column(String, nullable=True)
    detected_at: Mapped[str] = mapped_column(String)

    evidence: Mapped[list[EvidenceRow]] = relationship(
        back_populates="incident", cascade="all, delete-orphan")
    actions: Mapped[list[ActionRow]] = relationship(
        back_populates="incident", cascade="all, delete-orphan")
    approvals: Mapped[list[ApprovalRow]] = relationship(
        back_populates="incident", cascade="all, delete-orphan")


class EvidenceRow(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"))
    source_tool: Mapped[str] = mapped_column(String)
    evidence_class: Mapped[str] = mapped_column(String)
    summary: Mapped[str] = mapped_column(String)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    timestamp: Mapped[str] = mapped_column(String)
    hash: Mapped[str] = mapped_column(String)

    incident: Mapped[IncidentRow] = relationship(back_populates="evidence")


class ActionRow(Base):
    __tablename__ = "proposed_actions"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    # Nullable since M4: an app-scoped investigation may propose actions without
    # a stored incident.
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id"), nullable=True)
    kind: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(String)
    expected_effect: Mapped[str] = mapped_column(String)
    reversible: Mapped[bool] = mapped_column(Boolean, default=True)
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=True)
    # ── M4: approval binding (see incidents/approvals.py) ──
    investigation_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    args: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    payload_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    proposed_by: Mapped[str | None] = mapped_column(String, nullable=True)
    status: Mapped[str] = mapped_column(String, default="proposed")
    version: Mapped[int] = mapped_column(Integer, default=1)
    supersedes: Mapped[str | None] = mapped_column(String, nullable=True)
    reason: Mapped[str | None] = mapped_column(String, nullable=True)
    evidence_ids: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    limitations: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[str | None] = mapped_column(String, nullable=True)
    executed_at: Mapped[str | None] = mapped_column(String, nullable=True)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    incident: Mapped[IncidentRow | None] = relationship(back_populates="actions")


class ApprovalRow(Base):
    __tablename__ = "approvals"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id"), nullable=True)
    action_id: Mapped[str] = mapped_column(String)
    decided_by: Mapped[str] = mapped_column(String)
    decision: Mapped[str] = mapped_column(String)
    reason: Mapped[str] = mapped_column(String)
    timestamp: Mapped[str] = mapped_column(String)
    # ── M4: binding to the exact investigation, payload and approver role ──
    investigation_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    payload_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    approver_role: Mapped[str | None] = mapped_column(String, nullable=True)
    consumed_at: Mapped[str | None] = mapped_column(String, nullable=True)

    incident: Mapped[IncidentRow | None] = relationship(back_populates="approvals")


class AuditRow(Base):
    __tablename__ = "audit_events"

    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    id: Mapped[str] = mapped_column(String, unique=True)
    timestamp: Mapped[str] = mapped_column(String)
    actor: Mapped[str] = mapped_column(String)
    action: Mapped[str] = mapped_column(String)
    target_type: Mapped[str] = mapped_column(String)
    target_id: Mapped[str] = mapped_column(String)
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String)
    hash: Mapped[str] = mapped_column(String)


class InvestigationRow(Base):
    """One LangGraph investigation run (M4). ``snapshot`` holds the minimal,
    user-facing state (stage, evidence summaries, assessment, proposals)."""
    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    target_type: Mapped[str] = mapped_column(String)
    target_ref: Mapped[str] = mapped_column(String)
    incident_id: Mapped[str | None] = mapped_column(String, nullable=True)
    objective: Mapped[str] = mapped_column(String, default="")
    requested_by: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String)
    stage: Mapped[str] = mapped_column(String)
    created_at: Mapped[str] = mapped_column(String)
    updated_at: Mapped[str] = mapped_column(String)
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    report: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)


class InvestigationEvidenceRow(Base):
    """Evidence retrieved by an investigation. Claims must cite these ids."""
    __tablename__ = "investigation_evidence"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    investigation_id: Mapped[str] = mapped_column(String, index=True)
    source_tool: Mapped[str] = mapped_column(String)
    source_ref: Mapped[str] = mapped_column(String)
    trust: Mapped[str] = mapped_column(String)
    summary: Mapped[str] = mapped_column(String)
    content: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    limitations: Mapped[str] = mapped_column(String, default="")
    retrieved_at: Mapped[str] = mapped_column(String)
    hash: Mapped[str] = mapped_column(String)


def make_engine(url: str | None = None):
    return create_engine(url or get_database_url(), future=True)


def make_session_factory(engine=None):
    return sessionmaker(bind=engine or make_engine(), expire_on_commit=False, future=True)


def init_db(engine=None) -> None:
    """Create tables if absent. Alembic owns schema changes for PostgreSQL."""
    Base.metadata.create_all(engine or make_engine())
