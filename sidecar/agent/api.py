"""FastAPI routes for incidents and investigations (mounted by ``main.py``)."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from incidents.db import ActionRow, init_db, make_engine, make_session_factory
from incidents.detection import detect_incidents
from incidents.store import append_audit, list_incidents, save_incident, verify_audit_chain
from pydantic import BaseModel, Field
from sqlalchemy import inspect

from .identity import check_origin, demo_enabled, resolve_principal
from .service import InvestigationService, Principal, ServiceError

router = APIRouter(tags=["investigations"])
_service: InvestigationService | None = None
SETTINGS_FILE = Path(os.path.expanduser("~/.doxshield")) / "settings.json"


def _alert_recipient() -> str | None:
    try:
        settings = json.loads(SETTINGS_FILE.read_text())
    except (OSError, ValueError):
        return None
    if not settings.get("email_alerts_enabled"):
        return None
    return str(settings.get("alert_email") or "").strip() or None


def get_service() -> InvestigationService:
    global _service
    if _service is None:
        engine = make_engine()
        init_db(engine)
        cols = {c["name"] for c in inspect(engine).get_columns(ActionRow.__tablename__)}
        if "payload_hash" not in cols:
            raise HTTPException(503, "The incident database predates M4. Run "
                                     "`alembic upgrade head` (see docs/M4_AGENT.md).")
        _service = InvestigationService(make_session_factory(engine),
                                        alert_recipient=_alert_recipient)
    return _service


def set_service(service: InvestigationService | None) -> None:
    """Used by tests to inject a service with fixtures."""
    global _service
    _service = service


def principal(request: Request) -> Principal:
    return resolve_principal(request)


def mutating(request: Request) -> Principal:
    check_origin(request)
    return resolve_principal(request)


# A signed-in caller; Mutator also passes the Origin check (state-changing calls).
Caller = Annotated[Principal, Depends(principal)]
Mutator = Annotated[Principal, Depends(mutating)]


def _need(p: Principal, role: str) -> None:
    if role not in p.roles:
        raise HTTPException(403, f"Requires the {role} role")


def _call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except ServiceError as exc:
        raise HTTPException(exc.status, {"code": exc.code, "message": exc.message}) from exc


async def _acall(fn, *args, **kwargs):
    try:
        return await fn(*args, **kwargs)
    except ServiceError as exc:
        raise HTTPException(exc.status, {"code": exc.code, "message": exc.message}) from exc


# ── session / config ──────────────────────────────────────────────────────────

@router.get("/api/investigations/config")
async def investigation_config():
    svc = get_service()
    return {"demo_identities": demo_enabled(), "llm": svc.gateway.status(),
            "policy_fetch_enabled": os.getenv("DOXSHIELD_AGENT_FETCH_POLICIES", "") == "1",
            "budget": {"max_tool_calls": svc.config.max_tool_calls,
                       "max_graph_steps": svc.config.max_graph_steps,
                       "max_evidence_items": svc.config.max_evidence_items},
            "durable_checkpoints": False}


@router.get("/api/investigations/whoami")
async def whoami(p: Caller):
    return {"id": p.id, "roles": sorted(p.roles), "source": p.source}


# ── incidents ─────────────────────────────────────────────────────────────────

@router.get("/api/incidents")
async def get_incidents(p: Caller):
    _need(p, "viewer")
    svc = get_service()
    with svc._sf() as s:
        return [{"id": i.id, "type": i.type.value, "severity": i.severity.value,
                 "status": i.status.value, "title": i.title, "app": i.app,
                 "destination": i.destination, "country_code": i.country_code,
                 "detected_at": i.detected_at, "evidence_count": len(i.evidence)}
                for i in list_incidents(s)]


@router.post("/api/incidents/detect")
async def run_detection(p: Mutator):
    """Run the M2 detection rules on the active backend and store new incidents
    (deduplicated by title)."""
    _need(p, "analyst")
    from scanner.backend import get_backend
    backend = get_backend()
    scan = {"connections": await backend.get_connections(),
            "permissions": backend.get_permissions(), "cookies": backend.scan_cookies()}
    svc = get_service()
    created = 0
    with svc._sf() as s:
        existing = {i.title for i in list_incidents(s)}
        for inc in detect_incidents(scan):
            if inc.title in existing:
                continue
            save_incident(s, inc)
            existing.add(inc.title)
            created += 1
        append_audit(s, actor=p.id, action="incidents.detected", target_type="scan",
                     target_id=backend.name, data={"created": created})
    return {"created": created, "backend": backend.name, "synthetic": backend.is_synthetic}


@router.get("/api/audit/verify")
async def audit_verify(p: Caller):
    _need(p, "viewer")
    with get_service()._sf() as s:
        ok, broken = verify_audit_chain(s)
    return {"ok": ok, "broken_seq": broken}


# ── investigations ────────────────────────────────────────────────────────────

class StartRequest(BaseModel):
    target_type: Literal["incident", "app"]
    target_ref: str = Field(min_length=1, max_length=120)
    objective: str = Field(default="", max_length=500)


class DecisionRequest(BaseModel):
    decision: Literal["approve", "reject"]
    reason: str = Field(min_length=1, max_length=1000)
    payload_hash: str = Field(min_length=64, max_length=64)


class ReviseRequest(BaseModel):
    args: dict[str, str]
    note: str = Field(min_length=1, max_length=300)


@router.get("/api/investigations")
async def list_investigations(p: Caller):
    _need(p, "viewer")
    return get_service().list()


@router.post("/api/investigations", status_code=202)
async def start_investigation(body: StartRequest, p: Mutator):
    inv_id = await _acall(get_service().start, p, body.target_type, body.target_ref,
                          body.objective)
    return {"id": inv_id, "status": "queued"}


@router.get("/api/investigations/{inv_id}")
async def get_investigation(inv_id: str, p: Caller):
    _need(p, "viewer")
    return _call(get_service().get, inv_id)


@router.get("/api/investigations/{inv_id}/report")
async def get_report(inv_id: str, p: Caller):
    _need(p, "viewer")
    inv = _call(get_service().get, inv_id)
    if not inv.get("report"):
        raise HTTPException(404, "No report yet")
    return inv["report"]


@router.post("/api/investigations/{inv_id}/actions/{action_id}/decision")
async def decide(inv_id: str, action_id: str, body: DecisionRequest,
                 p: Mutator):
    return await _acall(get_service().decide, inv_id, action_id, p, body.decision,
                        body.reason, body.payload_hash)


@router.post("/api/investigations/{inv_id}/actions/{action_id}/revise")
async def revise(inv_id: str, action_id: str, body: ReviseRequest,
                 p: Mutator):
    return _call(get_service().revise, inv_id, action_id, p, body.args, body.note)


@router.post("/api/investigations/{inv_id}/cancel")
async def cancel(inv_id: str, p: Mutator):
    return await _acall(get_service().cancel, inv_id, p)
