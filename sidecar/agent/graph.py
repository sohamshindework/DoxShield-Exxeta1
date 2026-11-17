"""The DoxShield investigation graph (LangGraph).

    START → triage ─┬─→ investigate ⟲ (one MCP call per step, bounded) ─→ assess
                    └─→ report (invalid / out-of-scope / closed target)
    assess → propose_actions ─┬─→ await_approval (interrupt) ─┬─→ execute → report
                              └─→ report (nothing to propose)  └─→ report (rejected/cancelled)
    report → END

Design rules:
* The investigation plan is deterministic. The model never chooses tools, so
  injected text cannot trigger a tool call.
* Only read-only tools are reachable before approval (``MCPToolClient.call_read``).
* ``await_approval`` uses ``langgraph.types.interrupt``. The resume value carries
  no authority: approvals are re-read from the store and re-validated.
* ``execute`` calls each approved action once, through MCP, where the tool
  validates and consumes the approval again. Action tools are never retried.
"""
from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal, TypedDict

from ai.llm_gateway import LLMGateway
from incidents import approvals as approvals_store
from incidents.store import append_audit
from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from .actions import build_proposals
from .assessment import EXPLAIN_SYSTEM, explanation_prompt, parse_explanation, rules_assessment
from .config import AgentConfig
from .evidence import (
    EvidenceLog,
    clean_text,
    record_incident,
    record_tool_result,
    stored_evidence_ids,
    validate_claims,
)
from .mcp_client import MCPToolClient
from .policy import PolicyFetcher, analyze_policy

SAFE_REF = re.compile(r"^[\w.\-:@ ]{1,120}$")
RETRYABLE = {"timeout", "unavailable"}
TERMINAL = {"cancelled", "rejected_target", "closed_by_rules", "failed"}


class InvestigationState(TypedDict, total=False):
    investigation_id: str
    target: dict            # {"type": "incident" | "app", "ref": str}
    objective: str          # untrusted user text; stored and shown, never executed
    requested_by: str
    requested_roles: list[str]
    stage: str
    status: str             # running | awaiting_approval | completed | cancelled | ...
    context: dict           # resolved incident / app identifiers (minimal)
    plan: list[dict]        # pending read-only tool calls
    budget: dict            # {"max_tool_calls", "used", "llm_calls"}
    tool_calls: list[dict]  # history (tool, args, ok, error_code, ms)
    evidence: list[dict]
    assessment: dict | None
    proposals: list[dict]
    decisions: list[dict]
    executions: list[dict]
    errors: list[dict]
    flags: list[str]
    timeline: list[dict]
    report: dict | None


@dataclass
class AgentDeps:
    tools: MCPToolClient
    session_factory: Any
    gateway: LLMGateway = field(default_factory=LLMGateway)
    config: AgentConfig = field(default_factory=AgentConfig)
    is_cancelled: Callable[[str], bool] = lambda _id: False
    policy_fetcher: PolicyFetcher | None = None
    alert_recipient: Callable[[], str | None] = lambda: None


def _now() -> str:
    from incidents.models import now_iso
    return now_iso()


def _tl(state: InvestigationState, stage: str, note: str) -> list[dict]:
    return [*state.get("timeline", []), {"stage": stage, "at": _now(), "note": note}]


def _add_flag(flags: list[str], flag: str) -> list[str]:
    return flags if flag in flags else [*flags, flag]


def build_graph(deps: AgentDeps):
    cfg = deps.config

    def audit(state: InvestigationState, action: str, data: dict) -> None:
        with deps.session_factory() as s:
            append_audit(s, actor=f"agent(on behalf of {state['requested_by']})",
                         action=action, target_type="investigation",
                         target_id=state["investigation_id"], data=data)

    def evidence_log(state: InvestigationState) -> EvidenceLog:
        return EvidenceLog(state["investigation_id"], deps.session_factory,
                           state.get("evidence", []), cfg.max_evidence_items)

    async def call_tool(state: InvestigationState, budget: dict, history: list[dict],
                        tool: str, args: dict) -> tuple[Any, dict | None]:
        """One bounded read-only call with bounded retries. Every attempt is budgeted."""
        result = None
        for attempt in range(1 + cfg.read_retries):
            if budget["used"] >= budget["max_tool_calls"]:
                break
            budget["used"] += 1
            result = await deps.tools.call_read(tool, args)
            history.append({"tool": tool, "args": {k: clean_text(v, 80) for k, v in args.items()},
                            "ok": result.ok, "error_code": result.error_code,
                            "ms": result.duration_ms, "attempt": attempt + 1})
            audit(state, "investigation.tool_call",
                  {"tool": tool, "ok": result.ok, "error_code": result.error_code})
            if result.ok or result.error_code not in RETRYABLE:
                break
            await asyncio.sleep(cfg.retry_backoff_s * (attempt + 1))
        if result is None:
            return None, {"tool": tool, "code": "budget_exhausted",
                          "message": "Tool budget exhausted"}
        if not result.ok:
            return None, {"tool": tool, "code": result.error_code,
                          "message": clean_text(result.error, 200)}
        return result.data, None

    # ── triage ────────────────────────────────────────────────────────────────

    async def triage(state: InvestigationState) -> dict:
        target = state["target"]
        budget = {"max_tool_calls": cfg.max_tool_calls, "used": 0, "llm_calls": 0}
        history: list[dict] = []
        base = {"stage": "triage", "budget": budget, "tool_calls": history, "flags": [],
                "errors": [], "evidence": [], "plan": [], "proposals": [], "decisions": [],
                "executions": [], "assessment": None, "report": None}

        def stop(status: str, note: str, code: str) -> dict:
            return {**base, "status": status, "tool_calls": history,
                    "errors": [{"stage": "triage", "code": code, "message": note}],
                    "timeline": _tl(state, "triage", note)}

        if "analyst" not in state.get("requested_roles", []):
            return stop("rejected_target", "Requester lacks the analyst role.", "forbidden")
        if target.get("type") not in ("incident", "app") or not SAFE_REF.match(
                str(target.get("ref", ""))):
            return stop("rejected_target", "Unsupported or malformed target.", "bad_target")

        log = evidence_log({**state, "evidence": []})
        context: dict = {}
        if target["type"] == "incident":
            data, err = await call_tool(state, budget, history, "get_incidents", {})
            if err:
                return stop("failed", f"Could not read incidents: {err['code']}", err["code"])
            inc = next((i for i in data if isinstance(i, dict) and i.get("id") == target["ref"]),
                       None)
            if inc is None:
                return stop("rejected_target", "Incident not found.", "not_found")
            if inc.get("status") in ("resolved", "dismissed"):
                return stop("closed_by_rules", f"Incident is already {inc.get('status')}.",
                            "closed")
            record_incident(log, inc)
            context = {"incident_id": inc["id"], "incident_type": inc.get("type"),
                       "app_name": clean_text(inc.get("app"), 80), "label":
                       clean_text(inc.get("app") or inc.get("destination") or inc["id"], 80)}
            plan = [{"tool": "list_apps", "args": {}, "purpose": "Resolve the app"}]
            if context["app_name"]:
                plan.append({"tool": "get_connections", "args": {"app": context["app_name"]},
                             "purpose": "Current network destinations"})
        else:
            data, err = await call_tool(state, budget, history, "list_apps", {})
            if err:
                return stop("failed", f"Could not list apps: {err['code']}", err["code"])
            ref = target["ref"].lower()
            app = next((a for a in data if isinstance(a, dict) and ref in (
                str(a.get("id", "")).lower(), str(a.get("bundle_id", "")).lower(),
                str(a.get("name", "")).lower())), None)
            if app is None:
                return stop("rejected_target", "App not found in the inventory.", "not_found")
            context = {"incident_id": None, "app_id": app["id"], "bundle_id": app.get("bundle_id"),
                       "app_name": clean_text(app.get("name"), 80),
                       "label": clean_text(app.get("name"), 80)}
            plan = [{"tool": "get_app_details", "args": {"app_id": app["id"]},
                     "purpose": "App metadata"},
                    {"tool": "get_connections", "args": {"app": context["app_name"]},
                     "purpose": "Current network destinations"}]
            if app.get("bundle_id"):
                plan.append({"tool": "get_permissions", "args": {"app": app["bundle_id"]},
                             "purpose": "Granted permissions"})
        plan.append({"tool": "search_knowledge", "args": {"query": "transfer adequacy tracker"},
                     "purpose": "Reference notes for the reviewer"})
        audit(state, "investigation.triaged", {"target": target["type"], "plan": len(plan)})
        return {**base, "status": "running", "context": context, "plan": plan,
                "evidence": log.items, "tool_calls": history,
                "timeline": _tl(state, "triage", f"Target validated; {len(plan)} steps planned.")}

    def route_after_triage(state: InvestigationState) -> Literal["investigate", "report"]:
        return "report" if state["status"] in TERMINAL else "investigate"

    # ── investigate (one tool call per step) ─────────────────────────────────

    async def investigate(state: InvestigationState) -> dict:
        inv = state["investigation_id"]
        flags = list(state.get("flags", []))
        if deps.is_cancelled(inv):
            return {"stage": "investigate", "status": "cancelled",
                    "flags": _add_flag(flags, "cancelled"),
                    "timeline": _tl(state, "investigate", "Cancelled by user.")}
        plan = list(state.get("plan", []))
        budget = dict(state["budget"])
        history = list(state.get("tool_calls", []))
        errors = list(state.get("errors", []))
        context = dict(state.get("context", {}))
        if not plan:
            return {"stage": "investigate"}
        if budget["used"] >= budget["max_tool_calls"]:
            return {"stage": "investigate", "plan": [],
                    "flags": _add_flag(flags, "budget_exhausted"),
                    "timeline": _tl(state, "investigate",
                                    f"Tool budget exhausted; {len(plan)} step(s) skipped.")}

        step, plan = plan[0], plan[1:]
        log = evidence_log(state)
        data, err = await call_tool(state, budget, history, step["tool"], step["args"])
        note = f"{step['tool']}: "
        if err:
            errors.append({"stage": "investigate", **err})
            flags = _add_flag(flags, f"evidence_unavailable:{step['tool']}")
            note += f"evidence unavailable ({err['code']})"
            recent = [h for h in history[-2:] if h.get("error_code") == "unavailable"]
            if err["code"] == "unavailable" and len(recent) >= 2:
                flags = _add_flag(flags, "mcp_unavailable")
                plan = []
                note += "; MCP server unavailable, stopping the tool loop"
            if err["code"] == "budget_exhausted":
                flags = _add_flag(flags, "budget_exhausted")
                plan = []
        else:
            before = len(log.items)
            record_tool_result(log, step["tool"], step["args"], data)
            note += f"{len(log.items) - before} evidence item(s)"
            plan = _expand(step["tool"], data, plan, context)
            if step["tool"] == "analyze_privacy_policy" and data.get("policy_url") \
                    and budget["llm_calls"] < cfg.max_llm_calls:
                if deps.policy_fetcher is not None and deps.gateway.available:
                    budget["llm_calls"] += 1
                pol = await analyze_policy(deps.gateway, deps.policy_fetcher,
                                           context.get("app_name") or "", data["policy_url"], log)
                for f in pol["flags"]:
                    flags = _add_flag(flags, f)
                note += f"; policy text: {pol['status']}"
        if log.dropped:
            flags = _add_flag(flags, "evidence_cap_reached")
        return {"stage": "investigate", "plan": plan, "budget": budget, "tool_calls": history,
                "errors": errors, "flags": flags, "evidence": log.items, "context": context,
                "timeline": _tl(state, "investigate", note)}

    def _expand(tool: str, data: Any, plan: list[dict], context: dict) -> list[dict]:
        """Add follow-up steps based on what a tool returned (bounded)."""
        if tool == "list_apps":
            name = (context.get("app_name") or "").lower()
            app = next((a for a in data if isinstance(a, dict)
                        and str(a.get("name", "")).lower() == name), None)
            if app:
                context.update(app_id=app["id"], bundle_id=app.get("bundle_id"))
                extra = [{"tool": "get_app_details", "args": {"app_id": app["id"]},
                          "purpose": "App metadata"}]
                if app.get("bundle_id"):
                    extra.append({"tool": "get_permissions", "args": {"app": app["bundle_id"]},
                                  "purpose": "Granted permissions"})
                return extra + plan
        if tool == "get_app_details" and isinstance(data, dict):
            extra = [{"tool": "analyze_privacy_policy", "args": {"app": data["id"]},
                      "purpose": "Privacy policy reference"}]
            tail = []
            if data.get("category"):
                tail = [{"tool": "find_eu_alternatives",
                         "args": {"category": clean_text(data["category"], 40)},
                         "purpose": "EU-based alternatives"}]
            return extra + plan + tail
        if tool == "get_connections":
            lookups: list[dict] = []
            seen: set[str] = set()
            for c in data:
                if len(seen) >= cfg.max_destinations or not isinstance(c, dict):
                    break
                dest = c.get("remote_domain") or c.get("remote_ip")
                if not dest or dest in seen:
                    continue
                seen.add(dest)
                if c.get("remote_domain"):
                    lookups.append({"tool": "check_tracker",
                                  "args": {"domain": clean_text(c["remote_domain"], 200)},
                                  "purpose": "Tracker check"})
                if c.get("remote_ip"):
                    lookups.append({"tool": "lookup_ip_jurisdiction",
                                  "args": {"ip": clean_text(c["remote_ip"], 45)},
                                  "purpose": "Independent jurisdiction check"})
            return lookups + plan
        return plan

    def route_after_investigate(state: InvestigationState) -> Literal[
            "investigate", "assess", "report"]:
        if state.get("status") == "cancelled":
            return "report"
        budget = state["budget"]
        if state.get("plan") and budget["used"] < budget["max_tool_calls"]:
            return "investigate"
        if state.get("plan"):
            return "investigate"  # records budget exhaustion, then routes to assess
        return "assess"

    # ── assess ────────────────────────────────────────────────────────────────

    async def assess(state: InvestigationState) -> dict:
        flags = list(state.get("flags", []))
        evidence = state.get("evidence", [])
        budget = dict(state["budget"])
        assessment = rules_assessment(evidence, flags)
        stored = stored_evidence_ids(deps.session_factory, state["investigation_id"])
        problems = validate_claims(assessment["claims"], stored)
        if problems:  # a bug in the rules must never ship ungrounded claims
            assessment["claims"] = [c for c in assessment["claims"]
                                    if not validate_claims([c], stored)]
            flags = _add_flag(flags, "rules_claims_dropped")
        if deps.gateway.available and evidence and budget["llm_calls"] < cfg.max_llm_calls:
            user = explanation_prompt(evidence, assessment)
            explanation, problems = None, []
            for attempt in range(2):  # first try + one repair attempt
                if budget["llm_calls"] >= cfg.max_llm_calls:
                    break
                budget["llm_calls"] += 1
                prompt = user if attempt == 0 else (
                    user + "\nYour previous answer was rejected: " + "; ".join(problems[:5])
                    + ". Fix it and reply with JSON only.")
                res = await deps.gateway.complete("assessment_explanation", EXPLAIN_SYSTEM,
                                                  prompt)
                if not res.ok:
                    problems = [f"model unavailable: {res.error}"]
                    break
                explanation, problems = parse_explanation(res.text, stored)
                if explanation:
                    break
            if explanation:
                assessment["ai_explanation"] = explanation
            else:
                flags = _add_flag(flags, "llm_fallback")
                assessment["ai_explanation_error"] = "; ".join(problems[:3])
        elif not deps.gateway.available:
            assessment["ai_explanation_error"] = "No approved model is configured; the " \
                                                 "assessment is rules-only."
        audit(state, "investigation.assessed",
              {"priority": assessment["review_priority"], "concerns": len(assessment["concerns"]),
               "claims": len(assessment["claims"]),
               "ai_explanation": bool(assessment["ai_explanation"])})
        return {"stage": "assess", "assessment": assessment, "flags": flags, "budget": budget,
                "timeline": _tl(state, "assess",
                                f"Review priority {assessment['review_priority']} "
                                f"({len(assessment['concerns'])} concern(s)).")}

    # ── propose_actions ───────────────────────────────────────────────────────

    async def propose_actions(state: InvestigationState) -> dict:
        ctx = state["context"]
        assessment = state.get("assessment") or {"concerns": [], "review_priority": "undetermined"}
        specs = build_proposals(
            investigation_id=state["investigation_id"], target_label=ctx.get("label", ""),
            incident_id=ctx.get("incident_id"), assessment=assessment,
            evidence=state.get("evidence", []), alert_recipient=deps.alert_recipient())
        proposals: list[dict] = []
        with deps.session_factory() as s:
            for p in specs:
                row = approvals_store.create_proposal(
                    s, kind=p["kind"], args=p["args"], proposed_by=state["requested_by"],
                    description=p["description"], expected_effect=p["expected_effect"],
                    investigation_id=state["investigation_id"],
                    incident_id=ctx.get("incident_id"), reason=p["reason"],
                    evidence_ids=p["evidence_ids"], limitations=p["limitations"])
                proposals.append(_proposal_view(row, p["approval_requirements"]))
        for p in proposals:
            audit(state, "action.proposed", {"action_id": p["id"], "kind": p["kind"],
                                             "payload_hash": p["payload_hash"]})
        return {"stage": "propose_actions", "proposals": proposals,
                "timeline": _tl(state, "propose_actions",
                                f"{len(proposals)} action(s) proposed; none executed.")}

    def route_after_proposals(state: InvestigationState) -> Literal["await_approval", "report"]:
        return "await_approval" if state.get("proposals") else "report"

    # ── await_approval (human interrupt) ──────────────────────────────────────

    async def await_approval(state: InvestigationState) -> dict:
        inv = state["investigation_id"]
        # Everything before interrupt() must be side-effect free: LangGraph re-runs
        # this node from the top when the graph is resumed.
        resume = interrupt({"type": "approval_required", "investigation_id": inv,
                            "actions": [{"id": p["id"], "kind": p["kind"],
                                         "payload_hash": p["payload_hash"]}
                                        for p in state["proposals"]]})
        flags = list(state.get("flags", []))
        kind = resume.get("type") if isinstance(resume, dict) else None
        if kind == "cancel":
            with deps.session_factory() as s:
                approvals_store.cancel_pending(s, inv)
                rows = approvals_store.current_actions(s, inv)
                proposals = [_proposal_view(r) for r in rows]
            audit(state, "investigation.cancelled", {"stage": "await_approval"})
            return {"stage": "await_approval", "status": "cancelled", "proposals": proposals,
                    "flags": _add_flag(flags, "cancelled"),
                    "timeline": _tl(state, "await_approval", "Cancelled by user.")}
        if kind != "decided":
            flags = _add_flag(flags, "invalid_resume_ignored")

        decisions: list[dict] = []
        with deps.session_factory() as s:
            for row in approvals_store.current_actions(s, inv):
                entry = {"action_id": row.id, "kind": row.kind, "status": row.status,
                         "approval_id": None, "valid": False}
                if row.status == approvals_store.ActionStatus.APPROVED and kind == "decided":
                    appr = approvals_store.approval_for_action(s, row.id)
                    entry["approval_id"] = appr.id if appr else None
                    entry["decided_by"] = appr.decided_by if appr else None
                    try:
                        approvals_store.validate_for_execution(
                            s, appr.id if appr else "", row.kind, row.args or {},
                            investigation_id=inv)
                        entry["valid"] = True
                    except approvals_store.ApprovalError as exc:
                        entry["error"] = exc.code
                elif row.status == approvals_store.ActionStatus.REJECTED:
                    appr = approvals_store.approval_for_action(s, row.id)
                    entry["decided_by"] = appr.decided_by if appr else None
                    entry["reason"] = appr.reason if appr else None
                decisions.append(entry)
            # A malformed resume authorises nothing: close out every action.
            if kind != "decided":
                approvals_store.cancel_pending(s, inv)
            # Anything still undecided is not executed and is closed out.
            for row in approvals_store.current_actions(s, inv):
                if row.status == approvals_store.ActionStatus.PROPOSED:
                    row.status = approvals_store.ActionStatus.CANCELLED
            s.commit()
            proposals = [_proposal_view(r) for r in approvals_store.current_actions(s, inv)]
        approved = sum(1 for d in decisions if d["valid"])
        return {"stage": "await_approval", "decisions": decisions, "proposals": proposals,
                "flags": flags, "status": "running",
                "timeline": _tl(state, "await_approval",
                                f"{approved} action(s) approved and validated.")}

    def route_after_approval(state: InvestigationState) -> Literal["execute", "report"]:
        if state.get("status") == "cancelled":
            return "report"
        return "execute" if any(d["valid"] for d in state.get("decisions", [])) else "report"

    # ── execute (approved actions only, via MCP) ──────────────────────────────

    async def execute(state: InvestigationState) -> dict:
        inv = state["investigation_id"]
        executions = list(state.get("executions", []))
        done = {e["action_id"] for e in executions}
        args_by_id = {p["id"]: p for p in state.get("proposals", [])}
        for d in state.get("decisions", []):
            if not d["valid"] or d["action_id"] in done:
                continue
            p = args_by_id.get(d["action_id"])
            if p is None:
                continue
            res = await deps.tools.call_action(p["kind"], p["args"], d["approval_id"])
            outcome = {"action_id": p["id"], "kind": p["kind"], "ok": res.ok,
                       "error_code": res.error_code,
                       "error": clean_text(res.error, 200) if res.error else None,
                       "result": _bounded_result(res.data) if res.ok else None, "at": _now()}
            executions.append(outcome)
            with deps.session_factory() as s:
                approvals_store.record_action_result(
                    s, p["id"], ok=res.ok,
                    result=outcome["result"] or {"error_code": res.error_code})
            audit(state, "action.executed" if res.ok else "action.failed",
                  {"action_id": p["id"], "kind": p["kind"], "error_code": res.error_code})
        with deps.session_factory() as s:
            proposals = [_proposal_view(r) for r in approvals_store.current_actions(s, inv)]
        ok = sum(1 for e in executions if e["ok"])
        return {"stage": "execute", "executions": executions, "proposals": proposals,
                "timeline": _tl(state, "execute",
                                f"{ok} of {len(executions)} approved action(s) completed.")}

    # ── report ────────────────────────────────────────────────────────────────

    async def report(state: InvestigationState) -> dict:
        status = state.get("status", "running")
        if status in ("running", "awaiting_approval"):
            status = "completed"
        rep = build_report({**state, "status": status})
        audit(state, "investigation.reported", {"status": status, "flags": rep["flags"]})
        return {"stage": "report", "status": status, "report": rep,
                "timeline": _tl(state, "report", f"Investigation {status}.")}

    g = StateGraph(InvestigationState)
    g.add_node("triage", triage)
    g.add_node("investigate", investigate)
    g.add_node("assess", assess)
    g.add_node("propose_actions", propose_actions)
    g.add_node("await_approval", await_approval)
    g.add_node("execute", execute)
    g.add_node("report", report)
    g.add_edge(START, "triage")
    g.add_conditional_edges("triage", route_after_triage)
    g.add_conditional_edges("investigate", route_after_investigate)
    g.add_edge("assess", "propose_actions")
    g.add_conditional_edges("propose_actions", route_after_proposals)
    g.add_conditional_edges("await_approval", route_after_approval)
    g.add_edge("execute", "report")
    g.add_edge("report", END)
    return g


def _bounded_result(data: Any) -> dict:
    if not isinstance(data, dict):
        return {"value": clean_text(data, 500)}
    out = {}
    for k, v in list(data.items())[:12]:
        out[k] = clean_text(v, 2000) if isinstance(v, str) else v
    return out


def _proposal_view(row, approval_requirements: str | None = None) -> dict:
    from .actions import APPROVAL_TEXT
    return {"id": row.id, "kind": row.kind, "args": dict(row.args or {}),
            "payload_hash": row.payload_hash, "status": row.status, "version": row.version,
            "supersedes": row.supersedes, "description": row.description,
            "reason": row.reason, "expected_effect": row.expected_effect,
            "limitations": row.limitations, "evidence_ids": list(row.evidence_ids or []),
            "proposed_by": row.proposed_by,
            "approval_requirements": approval_requirements or APPROVAL_TEXT}


def build_report(state: dict) -> dict:
    a = state.get("assessment") or {}
    lines = [f"# DoxShield investigation {state['investigation_id']}",
             f"Target: {state['target']['type']} {clean_text(state['target']['ref'], 120)}",
             f"Status: {state['status']}"]
    if state.get("flags"):
        lines.append("Flags: " + ", ".join(state["flags"]))
    if a:
        lines += ["", "## Assessment", f"Review priority: {a.get('review_priority')} "
                  f"({a.get('priority_rule')})", a.get("summary", "")]
        for c in a.get("concerns", []):
            lines += [f"### {c['title']}", f"- Observed: {c['observed']} "
                      f"[{', '.join(c['evidence_ids'])}]",
                      f"- Why it may matter: {c['why_it_matters']}",
                      f"- Unknown: {c['unknowns']}", f"- To verify: {c['verify']}"]
        if a.get("uncertainties"):
            lines += ["", "## Uncertainties"] + [
                f"- {u['text']}" + (f" [{', '.join(u['evidence_ids'])}]"
                                    if u["evidence_ids"] else "")
                for u in a["uncertainties"]]
    if state.get("evidence"):
        lines += ["", "## Evidence"] + [f"- {e['id']} ({e['source_tool']}, {e['trust']}): "
                                        f"{e['summary']}" for e in state["evidence"]]
    if state.get("proposals"):
        lines += ["", "## Actions"] + [f"- {p['kind']} — {p['status']}"
                                       for p in state["proposals"]]
    if state.get("executions"):
        lines += ["", "## Execution results"] + [
            f"- {e['kind']}: {'done' if e['ok'] else 'failed (' + str(e['error_code']) + ')'}"
            for e in state["executions"]]
    lines += ["", "_" + (a.get("disclaimer") or
                         "Decision support for human review; not a legal assessment.") + "_"]
    return {
        "investigation_id": state["investigation_id"],
        "target": state["target"],
        "status": state["status"],
        "flags": state.get("flags", []),
        "review_priority": a.get("review_priority"),
        "summary": a.get("summary"),
        "evidence_count": len(state.get("evidence", [])),
        "tool_calls": len(state.get("tool_calls", [])),
        "actions": [{"id": p["id"], "kind": p["kind"], "status": p["status"]}
                    for p in state.get("proposals", [])],
        "executions": state.get("executions", []),
        "errors": state.get("errors", []),
        "markdown": "\n".join(lines),
        "generated_at": _now(),
    }
