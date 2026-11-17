"""Runs investigations: start, progress, human decisions, cancel, recovery.

Checkpointing: the graph uses LangGraph's in-memory checkpointer. A pause for
approval survives as long as the sidecar process runs, **not across restarts**.
On start-up, any investigation that was running or awaiting approval is marked
``interrupted`` and its pending actions are cancelled, so a stale approval can
never execute later. (A durable Postgres checkpointer is planned with the cloud
milestones; see docs/M4_AGENT.md.)
"""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Any

from ai.llm_gateway import LLMGateway, get_gateway
from incidents import approvals as approvals_store
from incidents.db import InvestigationRow
from incidents.models import Decision, new_id, now_iso
from incidents.store import append_audit
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.errors import GraphRecursionError
from langgraph.types import Command
from sqlalchemy import select

from .config import AgentConfig
from .evidence import clean_text
from .graph import AgentDeps, InvestigationState, build_graph, build_report
from .mcp_client import MCPToolClient
from .policy import default_fetcher

ACTIVE = ("queued", "running", "awaiting_approval", "resuming")
_REF = re.compile(r"^[\w.\-:@ ]{1,120}$")


@dataclass(frozen=True)
class Principal:
    id: str
    roles: frozenset[str]
    source: str = "token"


class ServiceError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def default_server_factory(session_factory):
    from mcp_server.server import build_server
    from mcp_server.tools import DoxShieldTools
    server = build_server(DoxShieldTools(session_factory=session_factory))
    return lambda: server


class InvestigationService:
    def __init__(self, session_factory, *, tools: MCPToolClient | None = None,
                 gateway: LLMGateway | None = None, config: AgentConfig | None = None,
                 policy_fetcher: Any = "default", alert_recipient=None) -> None:
        self._sf = session_factory
        self.config = config or AgentConfig.from_env()
        self.gateway = gateway or get_gateway()
        self.tools = tools or MCPToolClient(default_server_factory(session_factory),
                                            self.config.tool_timeout_s)
        self._cancel: set[str] = set()
        self._resuming: set[str] = set()
        self._tasks: dict[str, asyncio.Task] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self.checkpointer = InMemorySaver()
        deps = AgentDeps(
            tools=self.tools, session_factory=session_factory, gateway=self.gateway,
            config=self.config, is_cancelled=lambda i: i in self._cancel,
            policy_fetcher=default_fetcher() if policy_fetcher == "default" else policy_fetcher,
            alert_recipient=alert_recipient or (lambda: None))
        self.graph = build_graph(deps).compile(checkpointer=self.checkpointer)
        self.recover_interrupted()

    # ── helpers ───────────────────────────────────────────────────────────────

    def _cfg(self, inv_id: str) -> dict:
        return {"configurable": {"thread_id": inv_id},
                "recursion_limit": self.config.max_graph_steps}

    def _audit(self, actor: str, action: str, inv_id: str, data: dict) -> None:
        with self._sf() as s:
            append_audit(s, actor=actor, action=action, target_type="investigation",
                         target_id=inv_id, data=data)

    def _row(self, s, inv_id: str) -> InvestigationRow:
        row = s.get(InvestigationRow, inv_id)
        if row is None:
            raise ServiceError(404, "not_found", "No such investigation")
        return row

    def _is_paused(self, inv_id: str) -> bool:
        snap = self.graph.get_state(self._cfg(inv_id))
        return bool(snap and snap.next and "await_approval" in snap.next)

    def _persist(self, inv_id: str, status: str | None = None, extra_flag: str | None = None,
                 error: dict | None = None) -> None:
        values: dict = dict(self.graph.get_state(self._cfg(inv_id)).values or {})
        with self._sf() as s:
            row = self._row(s, inv_id)
            proposals = [_view(r) for r in approvals_store.current_actions(s, inv_id)]
            flags = list(values.get("flags", []))
            if extra_flag and extra_flag not in flags:
                flags.append(extra_flag)
            errors = list(values.get("errors", [])) + ([error] if error else [])
            row.status = status or values.get("status") or row.status
            row.stage = values.get("stage", row.stage)
            row.snapshot = {
                "stage": row.stage, "context": values.get("context", {}),
                "budget": values.get("budget", {}), "tool_calls": values.get("tool_calls", []),
                "evidence": values.get("evidence", []),
                "assessment": values.get("assessment"), "proposals": proposals,
                "decisions": values.get("decisions", []),
                "executions": values.get("executions", []), "errors": errors,
                "flags": flags, "timeline": values.get("timeline", []),
            }
            if values.get("report"):
                row.report = values["report"]
            elif row.status in ("failed", "interrupted", "cancelled") and values:
                row.report = build_report({**values, "status": row.status, "flags": flags,
                                           "errors": errors, "proposals": proposals})
            row.updated_at = now_iso()
            s.commit()

    async def _run(self, inv_id: str, graph_input: Any) -> None:
        lock = self._locks.setdefault(inv_id, asyncio.Lock())
        async with lock:
            cfg = self._cfg(inv_id)
            try:
                async for _ in self.graph.astream(graph_input, cfg, stream_mode="updates"):
                    self._persist(inv_id, status="running"
                                  if not self._is_paused(inv_id) else "awaiting_approval")
            except GraphRecursionError:
                self._fail(inv_id, "step_limit", "The workflow step limit was reached.")
                return
            except Exception as exc:  # any failure must fail closed, never approve
                self._fail(inv_id, "internal_error", f"{type(exc).__name__}")
                return
            finally:
                self._resuming.discard(inv_id)
            if self._is_paused(inv_id):
                self._persist(inv_id, status="awaiting_approval")
                self._audit("agent", "investigation.awaiting_approval", inv_id, {})
            else:
                self._persist(inv_id)
                self._cancel.discard(inv_id)

    def _fail(self, inv_id: str, code: str, message: str) -> None:
        with self._sf() as s:
            approvals_store.cancel_pending(s, inv_id)
        self._persist(inv_id, status="failed", extra_flag=code,
                      error={"stage": "service", "code": code, "message": message})
        self._audit("agent", "investigation.failed", inv_id, {"code": code})

    def _launch(self, inv_id: str, graph_input: Any, wait: bool):
        if wait:
            return self._run(inv_id, graph_input)
        task = asyncio.create_task(self._run(inv_id, graph_input))
        self._tasks[inv_id] = task
        task.add_done_callback(lambda _t: self._tasks.pop(inv_id, None))
        return None

    # ── public API ────────────────────────────────────────────────────────────

    async def start(self, principal: Principal, target_type: str, target_ref: str,
                    objective: str = "", wait: bool = False) -> str:
        if "analyst" not in principal.roles:
            raise ServiceError(403, "forbidden", "Only an analyst can start an investigation")
        if target_type not in ("incident", "app") or not _REF.match(target_ref or ""):
            raise ServiceError(422, "bad_target", "Target must be an incident id or app id")
        inv_id = new_id()
        stamp = now_iso()
        with self._sf() as s:
            s.add(InvestigationRow(
                id=inv_id, target_type=target_type, target_ref=target_ref,
                incident_id=target_ref if target_type == "incident" else None,
                objective=clean_text(objective, 500), requested_by=principal.id,
                status="queued", stage="queued", created_at=stamp, updated_at=stamp,
                snapshot={}))
            s.commit()
        self._audit(principal.id, "investigation.started", inv_id,
                    {"target_type": target_type, "target_ref": target_ref})
        state: InvestigationState = {
            "investigation_id": inv_id, "target": {"type": target_type, "ref": target_ref},
            "objective": clean_text(objective, 500), "requested_by": principal.id,
            "requested_roles": sorted(principal.roles), "status": "running",
            "stage": "queued", "timeline": []}
        coro = self._launch(inv_id, state, wait)
        if coro is not None:
            await coro
        return inv_id

    def get(self, inv_id: str) -> dict:
        with self._sf() as s:
            return _row_dict(self._row(s, inv_id))

    def list(self, limit: int = 50) -> list[dict]:
        with self._sf() as s:
            rows = s.scalars(select(InvestigationRow)
                             .order_by(InvestigationRow.created_at.desc()).limit(limit)).all()
            return [_row_dict(r, brief=True) for r in rows]

    def _require_paused(self, s, inv_id: str) -> InvestigationRow:
        row = self._row(s, inv_id)
        if row.status != "awaiting_approval" or not self._is_paused(inv_id):
            raise ServiceError(409, "not_awaiting_approval",
                               f"Investigation is {row.status}; it is not waiting for approval")
        return row

    async def decide(self, inv_id: str, action_id: str, principal: Principal, decision: str,
                     reason: str, payload_hash: str, wait: bool = False) -> dict:
        if decision not in ("approve", "reject"):
            raise ServiceError(422, "bad_decision", "decision must be approve or reject")
        with self._sf() as s:
            row = self._require_paused(s, inv_id)
            if "approver" not in principal.roles:
                raise ServiceError(403, "forbidden", "Only an approver can decide on actions")
            if principal.id == row.requested_by:
                # Separation of duties covers every version of every action in a
                # run the principal started, including versions revised by others.
                raise ServiceError(403, "self_approval",
                                   "The person who started the investigation cannot approve")
            try:
                appr = approvals_store.record_decision(
                    s, action_id=action_id, investigation_id=inv_id, decided_by=principal.id,
                    roles=principal.roles,
                    decision=Decision.APPROVED if decision == "approve" else Decision.REJECTED,
                    reason=reason, seen_payload_hash=payload_hash)
            except approvals_store.ApprovalError as exc:
                status = 403 if exc.code in ("forbidden", "self_approval") else 409
                raise ServiceError(status, exc.code, exc.message) from exc
            pending = [r for r in approvals_store.current_actions(s, inv_id)
                       if r.status == approvals_store.ActionStatus.PROPOSED]
            result = {"approval_id": appr.id, "decision": appr.decision,
                      "pending_actions": len(pending)}
        self._audit(principal.id, f"action.{appr.decision}", inv_id,
                    {"action_id": action_id, "approval_id": appr.id})
        self._persist(inv_id, status="awaiting_approval")
        if not pending and inv_id not in self._resuming:
            self._resuming.add(inv_id)
            self._persist(inv_id, status="resuming")
            coro = self._launch(inv_id, Command(resume={"type": "decided"}), wait)
            if coro is not None:
                await coro
            result["resumed"] = True
        return result

    def revise(self, inv_id: str, action_id: str, principal: Principal,
               new_args: dict, note: str) -> dict:
        if "analyst" not in principal.roles:
            raise ServiceError(403, "forbidden", "Only an analyst can edit proposals")
        with self._sf() as s:
            self._require_paused(s, inv_id)
            try:
                new = approvals_store.revise_proposal(
                    s, action_id=action_id, investigation_id=inv_id, revised_by=principal.id,
                    new_args={k: clean_text(v, 4000) if k == "body" else clean_text(v, 200)
                              for k, v in new_args.items()},
                    note=note)
            except approvals_store.ApprovalError as exc:
                raise ServiceError(409 if exc.code != "bad_payload" else 422,
                                   exc.code, exc.message) from exc
            out = _view(new)
        self._audit(principal.id, "action.revised", inv_id,
                    {"old_action_id": action_id, "new_action_id": out["id"],
                     "payload_hash": out["payload_hash"]})
        self._persist(inv_id, status="awaiting_approval")
        return out

    async def cancel(self, inv_id: str, principal: Principal, wait: bool = False) -> dict:
        if not principal.roles & {"analyst", "approver"}:
            raise ServiceError(403, "forbidden", "Only an analyst or approver can cancel")
        with self._sf() as s:
            row = self._row(s, inv_id)
            status = row.status
        self._audit(principal.id, "investigation.cancel_requested", inv_id, {"status": status})
        if status == "awaiting_approval" and self._is_paused(inv_id) \
                and inv_id not in self._resuming:
            self._resuming.add(inv_id)
            coro = self._launch(inv_id, Command(resume={"type": "cancel"}), wait)
            if coro is not None:
                await coro
            return {"cancelled": True}
        if status in ("queued", "running"):
            self._cancel.add(inv_id)
            return {"cancel_requested": True}
        raise ServiceError(409, "not_cancellable", f"Investigation is {status}")

    def recover_interrupted(self) -> int:
        """After a restart, paused/running investigations cannot resume (in-memory
        checkpoints). Mark them interrupted and cancel their pending actions."""
        n = 0
        with self._sf() as s:
            rows = s.scalars(select(InvestigationRow)
                             .where(InvestigationRow.status.in_(ACTIVE))).all()
            for row in rows:
                if self.graph.get_state(self._cfg(row.id)).values:
                    continue  # this process owns it
                approvals_store.cancel_pending(s, row.id)
                row.status = "interrupted"
                row.snapshot = {**(row.snapshot or {}),
                                "flags": [*(row.snapshot or {}).get("flags", []), "interrupted"]}
                row.updated_at = now_iso()
                n += 1
            s.commit()
        return n


def _view(row) -> dict:
    from .graph import _proposal_view
    view = _proposal_view(row)
    if row.result:
        view["result"] = row.result
    return view


def _row_dict(row: InvestigationRow, brief: bool = False) -> dict:
    out: dict[str, Any] = {"id": row.id, "target_type": row.target_type, "target_ref": row.target_ref,
           "objective": row.objective, "requested_by": row.requested_by, "status": row.status,
           "stage": row.stage, "created_at": row.created_at, "updated_at": row.updated_at}
    snap = row.snapshot or {}
    out["label"] = (snap.get("context") or {}).get("label")
    out["review_priority"] = (snap.get("assessment") or {}).get("review_priority")
    if not brief:
        out["snapshot"] = snap
        out["report"] = row.report
    return out
