"""DoxShield tool implementations.

Kept as plain, deterministic methods so they can be tested without the MCP
runtime; ``server.py`` is a thin adapter. Read-only tools investigate; action
tools change state and require a valid ``approval_id`` before doing anything.

Safety:
- No tool reads secrets, credentials or `.env`; only scan/incident/knowledge data
  is returned.
- ``propose_block_rule`` is dry-run: it writes a rule file and never touches the
  firewall. ``send_alert_email`` never sends from here; it returns a draft.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from incidents.approvals import ApprovalError, consume_approval
from incidents.db import ApprovalRow, make_session_factory
from incidents.models import now_iso
from incidents.store import get_incident, list_incidents
from scanner import ip_geo
from scanner.backend import get_backend

from .errors import ToolError
from .knowledge import find_eu_alternatives, search_knowledge

MAX_ITEMS = 500
# A hostname or an IPv4/IPv6 literal; nothing that could inject rule syntax.
_SAFE_TARGET = re.compile(r"[A-Za-z0-9.\-:]{1,253}")


def _default_block_rules_dir() -> Path:
    return Path(os.path.expanduser("~/.doxshield")) / "block_rules"


class DoxShieldTools:
    def __init__(self, backend=None, session_factory=None, block_rules_dir: Path | None = None):
        self._backend = backend or get_backend()
        self._session_factory = session_factory or make_session_factory()
        self._block_rules_dir = Path(block_rules_dir) if block_rules_dir else _default_block_rules_dir()

    # ── Read-only investigation tools ─────────────────────────────────────────

    def list_apps(self) -> list[dict]:
        apps = self._backend.scan_apps()[:MAX_ITEMS]
        return [{"id": a.id, "name": a.name, "bundle_id": a.bundle_id,
                 "jurisdiction": a.jurisdiction, "risk_level": a.risk_level} for a in apps]

    def get_app_details(self, app_id: str) -> dict:
        for a in self._backend.scan_apps():
            if a.id == app_id or a.bundle_id == app_id:
                return a.model_dump()
        raise ToolError("not_found", f"No app matching {app_id!r}")

    async def get_connections(self, app: str | None = None) -> list[dict]:
        conns = await self._backend.get_connections()
        if app:
            needle = app.lower()
            conns = [c for c in conns
                     if needle in (c.get("app_name") or "").lower()
                     or needle == (c.get("bundle_id") or "").lower()]
        return conns[:MAX_ITEMS]

    async def lookup_ip_jurisdiction(self, ip: str) -> dict:
        if not ip or len(ip) > 45:
            raise ToolError("bad_input", "Provide a single IP address")
        return await ip_geo.geolocate_ip(ip)

    def check_tracker(self, domain: str) -> dict:
        if not domain:
            raise ToolError("bad_input", "Provide a domain")
        match = ip_geo.check_domain_tracker(domain)
        return {"domain": domain, "is_known_tracker": match is not None, "match": match}

    def get_permissions(self, app: str | None = None) -> dict:
        perms = self._backend.get_permissions()
        if app:
            only = perms.get("permissions", {}).get(app, [])
            return {"bundle_id": app, "permissions": only}
        return perms

    def analyze_privacy_policy(self, app: str) -> dict:
        """Read-only: returns the known policy URL. Model-based analysis is M4 and
        runs through the LLM gateway, not from this offline tool."""
        for a in self._backend.scan_apps():
            if a.id == app or a.bundle_id == app:
                url = (a.tools_db_entry or {}).get("privacy_policy_url")
                return {"app": a.name, "policy_url": url,
                        "analysis_available": False,
                        "note": "Policy analysis runs in the agent (M4), not in this tool."}
        raise ToolError("not_found", f"No app matching {app!r}")

    def search_knowledge(self, query: str, limit: int = 5) -> list[dict]:
        return search_knowledge(query, min(limit, 50))

    def find_eu_alternatives(self, category: str) -> list[dict]:
        return find_eu_alternatives(category)

    def get_incidents(self) -> list[dict]:
        with self._session_factory() as s:
            return [i.model_dump() for i in list_incidents(s)][:MAX_ITEMS]

    def get_evidence(self, incident_id: str) -> list[dict]:
        with self._session_factory() as s:
            inc = get_incident(s, incident_id)
        if inc is None:
            raise ToolError("not_found", f"No incident {incident_id!r}")
        return [e.model_dump() for e in inc.evidence]

    async def local_risk_indicators(self) -> dict:
        """Heuristic summary of the current (synthetic or real) scan — not a
        calibrated probability."""
        conns = await self._backend.get_connections()
        by_jurisdiction: dict[str, int] = {}
        trackers = 0
        for c in conns:
            j = c.get("jurisdiction", "Unknown")
            by_jurisdiction[j] = by_jurisdiction.get(j, 0) + 1
            if c.get("is_known_tracker"):
                trackers += 1
        return {"connections": len(conns), "by_jurisdiction": by_jurisdiction,
                "known_trackers": trackers, "basis": "heuristic"}

    # ── Gated action tools (require a valid approval_id) ──────────────────────

    def _require_approval(self, approval_id: str, action_kind: str,
                          args: dict) -> ApprovalRow:
        """Validate and consume the approval (single use, payload-bound).

        See ``incidents/approvals.py`` for every check. Any failure raises a
        ``ToolError`` and the action does not run.
        """
        with self._session_factory() as s:
            try:
                approval, _ = consume_approval(s, approval_id, action_kind, args)
            except ApprovalError as exc:
                raise ToolError(exc.code, exc.message) from exc
            return approval

    def draft_dpo_notification(self, incident_id: str, approval_id: str) -> dict:
        self._require_approval(approval_id, "draft_dpo_notification",
                               {"incident_id": incident_id})
        with self._session_factory() as s:
            inc = get_incident(s, incident_id)
        if inc is None:
            raise ToolError("not_found", f"No incident {incident_id!r}")
        body = (f"Subject: Privacy review — {inc.title}\n\n"
                f"Incident {inc.id} ({inc.type.value}, severity {inc.severity.value}).\n"
                f"App: {inc.app}; destination: {inc.destination} ({inc.country_code}).\n"
                f"Evidence items: {len(inc.evidence)}. Recommended follow-up: "
                f"{inc.recommended_follow_up}\n\n"
                f"This is a decision-support draft for DPO review, not a legal determination.")
        return {"kind": "dpo_notification", "incident_id": inc.id, "draft": body,
                "sent": False}

    def create_ticket(self, title: str, body: str, approval_id: str) -> dict:
        self._require_approval(approval_id, "create_ticket", {"title": title, "body": body})
        return {"kind": "ticket", "title": title, "body": body,
                "status": "drafted", "created_at": now_iso(), "external_system": None}

    def send_alert_email(self, to: str, subject: str, body: str, approval_id: str) -> dict:
        self._require_approval(approval_id, "send_alert_email",
                               {"to": to, "subject": subject, "body": body})
        # M3 never sends from the tool layer: return a draft. Real delivery is a
        # separately configured, human-approved path.
        return {"kind": "alert_email", "to": to, "subject": subject, "body": body,
                "sent": False, "note": "Draft only; delivery is not performed by this tool."}

    def propose_block_rule(self, target: str, approval_id: str) -> dict:
        """Dry-run: write a rule file. Never modifies the firewall."""
        if not target or not _SAFE_TARGET.fullmatch(target):
            raise ToolError("bad_input", "Provide a single domain or IP to block")
        self._require_approval(approval_id, "propose_block_rule", {"target": target})
        self._block_rules_dir.mkdir(parents=True, exist_ok=True)
        safe = target.replace("/", "_").replace(":", "_")
        path = self._block_rules_dir / f"block_{safe}.rule"
        content = (f"# DoxShield proposed block rule (DRY-RUN — not applied)\n"
                   f"# Generated: {now_iso()}\n"
                   f"# Review before applying manually.\n"
                   f"block drop out quick to {target}\n")
        path.write_text(content)
        return {"kind": "block_rule", "target": target, "applied": False,
                "dry_run": True, "rule_file": str(path), "rule": content}


READ_ONLY_TOOLS = [
    "list_apps", "get_app_details", "get_connections", "lookup_ip_jurisdiction",
    "check_tracker", "get_permissions", "analyze_privacy_policy",
    "search_knowledge", "find_eu_alternatives", "get_incidents", "get_evidence",
    "local_risk_indicators",
]
ACTION_TOOLS = [
    "draft_dpo_notification", "create_ticket", "send_alert_email",
    "propose_block_rule",
]
