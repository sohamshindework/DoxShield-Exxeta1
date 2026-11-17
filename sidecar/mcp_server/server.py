"""FastMCP adapter exposing DoxShield tools over the Model Context Protocol.

Each tool runs under a timeout. Read-only tools are the default; action tools
require an ``approval_id`` and are gated inside the tool implementation.
"""
from __future__ import annotations

import asyncio

from mcp.server.fastmcp import FastMCP

from .errors import ToolError
from .tools import DoxShieldTools

TOOL_TIMEOUT = 15.0


def build_server(tools: DoxShieldTools | None = None,
                 timeout: float = TOOL_TIMEOUT) -> FastMCP:
    t = tools or DoxShieldTools()
    mcp = FastMCP("doxshield")

    async def _guard_sync(fn, *args):
        try:
            return await asyncio.wait_for(asyncio.to_thread(fn, *args), timeout)
        except TimeoutError as exc:
            raise ToolError("timeout", f"{fn.__name__} exceeded {timeout}s") from exc

    async def _guard_async(coro, name: str):
        try:
            return await asyncio.wait_for(coro, timeout)
        except TimeoutError as exc:
            raise ToolError("timeout", f"{name} exceeded {timeout}s") from exc

    # ── Read-only investigation tools ─────────────────────────────────────────

    @mcp.tool()
    async def list_apps() -> list:
        """List installed applications (id, name, bundle, jurisdiction, risk)."""
        return await _guard_sync(t.list_apps)

    @mcp.tool()
    async def get_app_details(app_id: str) -> dict:
        """Full details for one app, by id or bundle id."""
        return await _guard_sync(t.get_app_details, app_id)

    @mcp.tool()
    async def get_connections(app: str = "") -> list:
        """Active network connections, optionally filtered by app name or bundle."""
        return await _guard_async(t.get_connections(app or None), "get_connections")

    @mcp.tool()
    async def lookup_ip_jurisdiction(ip: str) -> dict:
        """Offline jurisdiction lookup for one IP address (no network)."""
        return await _guard_async(t.lookup_ip_jurisdiction(ip), "lookup_ip_jurisdiction")

    @mcp.tool()
    async def check_tracker(domain: str) -> dict:
        """Check whether a domain matches a known tracker pattern."""
        return await _guard_sync(t.check_tracker, domain)

    @mcp.tool()
    async def get_permissions(app: str = "") -> dict:
        """TCC permissions, optionally narrowed to one bundle id."""
        return await _guard_sync(t.get_permissions, app or None)

    @mcp.tool()
    async def analyze_privacy_policy(app: str) -> dict:
        """Return the known privacy-policy URL for an app (read-only)."""
        return await _guard_sync(t.analyze_privacy_policy, app)

    @mcp.tool()
    async def search_knowledge(query: str, limit: int = 5) -> list:
        """Search the GDPR reference notes."""
        return await _guard_sync(t.search_knowledge, query, limit)

    @mcp.tool()
    async def find_eu_alternatives(category: str) -> list:
        """Find EU-based software alternatives by category."""
        return await _guard_sync(t.find_eu_alternatives, category)

    @mcp.tool()
    async def get_incidents() -> list:
        """Incident history from the store."""
        return await _guard_sync(t.get_incidents)

    @mcp.tool()
    async def get_evidence(incident_id: str) -> list:
        """Evidence items supporting one incident."""
        return await _guard_sync(t.get_evidence, incident_id)

    @mcp.tool()
    async def local_risk_indicators() -> dict:
        """Heuristic summary of the current scan (not a calibrated probability)."""
        return await _guard_async(t.local_risk_indicators(), "local_risk_indicators")

    # ── Gated action tools (require approval_id) ──────────────────────────────

    @mcp.tool()
    async def draft_dpo_notification(incident_id: str, approval_id: str) -> dict:
        """Draft a DPO notification for an incident. Requires approval_id."""
        return await _guard_sync(t.draft_dpo_notification, incident_id, approval_id)

    @mcp.tool()
    async def create_ticket(title: str, body: str, approval_id: str) -> dict:
        """Create a ticket draft. Requires approval_id."""
        return await _guard_sync(t.create_ticket, title, body, approval_id)

    @mcp.tool()
    async def send_alert_email(to: str, subject: str, body: str, approval_id: str) -> dict:
        """Draft an alert email (never sends). Requires approval_id."""
        return await _guard_sync(t.send_alert_email, to, subject, body, approval_id)

    @mcp.tool()
    async def propose_block_rule(target: str, approval_id: str) -> dict:
        """Generate a dry-run block-rule file (never changes the firewall). Requires approval_id."""
        return await _guard_sync(t.propose_block_rule, target, approval_id)

    return mcp


def main() -> None:
    build_server().run()


if __name__ == "__main__":
    main()
