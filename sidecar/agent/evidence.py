"""Evidence records and citation checks.

Every tool result the agent keeps becomes a structured evidence record:

    id, source_tool, source_ref, trust, summary, content, limitations,
    retrieved_at, hash

* ``content`` keeps only the fields the assessment needs (data minimisation) and
  is size-bounded. Free text from tools (app names, policy text, incident titles)
  is untrusted data: it is cleaned of control characters and truncated, and it is
  never interpreted as an instruction.
* Records are written to ``investigation_evidence`` as they are retrieved. Claims
  are later checked against that table (``validate_claims``), so a claim can only
  cite evidence that was actually retrieved by this investigation.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

from incidents.db import InvestigationEvidenceRow
from incidents.models import canonical_hash, now_iso
from sqlalchemy import select

TRUST_LEVELS = ("observed", "heuristic", "reference", "stored", "ai", "external_untrusted")
CLAIM_KINDS = ("observed", "inference", "uncertainty", "recommendation")

MAX_TEXT = 400
MAX_LIST = 20

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f​-‏ -‮]")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Candidate IPv6 literals (incl. "::" compression); confirmed with ipaddress.
_IPV6 = re.compile(r"(?<![\w:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:])")

# Phrases that would state a legal conclusion. DoxShield never does that.
LEGAL_CONCLUSION = re.compile(
    r"\b(violat\w*|illegal\w*|unlawful\w*|non-?complian\w*|in breach|breach(?:es|ed)? (?:of )?"
    r"(?:the )?gdpr|is not gdpr[- ]compliant|is gdpr[- ]compliant)\b", re.I)


def clean_text(value: Any, limit: int = MAX_TEXT) -> str:
    """Make untrusted text safe to store and display: no control characters,
    collapsed whitespace, bounded length."""
    text = _CONTROL.sub(" ", str(value if value is not None else ""))
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def redact_ips(text: str) -> str:
    """Remove IP addresses before text is shown to a model (data minimisation)."""
    text = _IPV4.sub("[ip]", text)
    return _IPV6.sub(lambda m: "[ip]" if _is_ip(m.group(0)) else m.group(0), text)


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _bounded(value: Any, depth: int = 0) -> Any:
    if depth > 3:
        return "…"
    if isinstance(value, str):
        return clean_text(value)
    if isinstance(value, bool | int | float) or value is None:
        return value
    if isinstance(value, list):
        return [_bounded(v, depth + 1) for v in value[:MAX_LIST]]
    if isinstance(value, dict):
        return {clean_text(k, 60): _bounded(v, depth + 1) for k, v in list(value.items())[:30]}
    return clean_text(value)


def _pick(d: dict, keys: tuple[str, ...]) -> dict:
    return {k: d.get(k) for k in keys if k in d}


# ─── Building records ─────────────────────────────────────────────────────────

class EvidenceLog:
    """Assigns ids, enforces the evidence cap and persists each record."""

    def __init__(self, investigation_id: str, session_factory, existing: list[dict],
                 max_items: int) -> None:
        self.investigation_id = investigation_id
        self._sf = session_factory
        self.items = list(existing)
        self.max_items = max_items
        self.dropped = 0

    def add(self, *, source_tool: str, source_ref: str, trust: str, summary: str,
            content: dict | None = None, limitations: str = "") -> dict | None:
        if trust not in TRUST_LEVELS:
            raise ValueError(f"unknown trust level {trust!r}")
        if len(self.items) >= self.max_items:
            self.dropped += 1
            return None
        seq = len(self.items) + 1
        record = {
            "id": f"EV-{self.investigation_id[:8]}-{seq:02d}",
            "source_tool": source_tool,
            "source_ref": clean_text(source_ref, 120),
            "trust": trust,
            "summary": clean_text(summary),
            "content": _bounded(content or {}),
            "limitations": clean_text(limitations),
            "retrieved_at": now_iso(),
        }
        record["hash"] = canonical_hash({k: v for k, v in record.items() if k != "hash"})
        with self._sf() as s:
            s.add(InvestigationEvidenceRow(investigation_id=self.investigation_id, **record))
            s.commit()
        self.items.append(record)
        return record


def record_tool_result(log: EvidenceLog, tool: str, args: dict, data: Any) -> list[dict]:
    """Turn one successful tool result into minimal evidence records."""
    out: list[dict | None] = []
    ref = ",".join(f"{k}={v}" for k, v in args.items()) or tool

    if tool == "get_app_details":
        app = _pick(data, ("id", "name", "bundle_id", "category", "developer",
                           "jurisdiction", "risk_level", "synthetic"))
        out.append(log.add(
            source_tool=tool, source_ref=ref, trust="observed", content=app,
            summary=f"App {clean_text(app.get('name'), 80)} ({app.get('bundle_id')}), "
                    f"developer jurisdiction {app.get('jurisdiction')}, category "
                    f"{app.get('category')}",
            limitations="Developer jurisdiction is catalogue metadata, not where data is stored."))

    elif tool == "get_connections":
        for c in data[:10]:
            conn = _pick(c, ("app_name", "bundle_id", "remote_domain", "remote_ip",
                             "remote_port", "country_code", "jurisdiction",
                             "is_known_tracker", "tracker_category", "synthetic"))
            dest = conn.get("remote_domain") or conn.get("remote_ip")
            out.append(log.add(
                source_tool=tool, source_ref=ref, trust="observed", content=conn,
                summary=f"{clean_text(conn.get('app_name'), 80)} connected to "
                        f"{clean_text(dest, 120)} (country {conn.get('country_code')}, "
                        f"jurisdiction {conn.get('jurisdiction')})",
                limitations="Connection metadata only; payload contents are not inspected. "
                            "Country is inferred from IP/domain."))
        if not data:
            out.append(log.add(source_tool=tool, source_ref=ref, trust="observed",
                               summary="No active connections observed for this app.",
                               content={"count": 0},
                               limitations="A single snapshot; absence is not proof."))

    elif tool == "get_permissions":
        perms = [clean_text(p, 40) for p in (data.get("permissions") or [])][:MAX_LIST]
        out.append(log.add(
            source_tool=tool, source_ref=ref, trust="observed",
            content={"bundle_id": data.get("bundle_id"), "permissions": perms},
            summary=f"Granted permissions: {', '.join(perms) if perms else 'none recorded'}",
            limitations="Granted permissions show capability, not actual use."))

    elif tool == "check_tracker":
        match = data.get("match") or {}
        out.append(log.add(
            source_tool=tool, source_ref=ref, trust="heuristic",
            content={"domain": data.get("domain"),
                     "is_known_tracker": bool(data.get("is_known_tracker")),
                     "category": match.get("category") if isinstance(match, dict) else None},
            summary=f"{clean_text(data.get('domain'), 120)} "
                    f"{'matches' if data.get('is_known_tracker') else 'does not match'} "
                    f"a known tracker pattern",
            limitations="Pattern match against a local tracker list; may be incomplete."))

    elif tool == "lookup_ip_jurisdiction":
        out.append(log.add(
            source_tool=tool, source_ref=ref, trust="heuristic",
            content=_pick(data, ("country_code", "jurisdiction", "source")) | {"ip": args.get("ip")},
            summary=f"Offline lookup for {args.get('ip')}: country {data.get('country_code')}, "
                    f"jurisdiction {data.get('jurisdiction')}",
            limitations="Offline range table; LOCAL/Unknown means it could not confirm a country."))

    elif tool == "analyze_privacy_policy":
        out.append(log.add(
            source_tool=tool, source_ref=ref, trust="reference",
            content={"policy_url": data.get("policy_url"), "app": data.get("app")},
            summary=(f"Published privacy policy: {clean_text(data.get('policy_url'), 200)}"
                     if data.get("policy_url") else "No privacy-policy URL is known for this app"),
            limitations="A link only; the policy text was not analysed by this tool."))

    elif tool == "search_knowledge":
        for note in data[:3]:
            out.append(log.add(
                source_tool=tool, source_ref=clean_text(note.get("id") or note.get("topic"), 80),
                trust="reference",
                content=_pick(note, ("topic", "source", "retrieved")),
                summary=f"Reference note: {clean_text(note.get('topic'), 120)} — "
                        f"{clean_text(note.get('text'), 240)}",
                limitations="Background reference for human review; not a legal assessment."))

    elif tool == "find_eu_alternatives":
        names = [clean_text(a.get("name"), 60) for a in data[:5]]
        if names:
            out.append(log.add(
                source_tool=tool, source_ref=ref, trust="reference",
                content={"alternatives": [_pick(a, ("name", "country", "category", "source"))
                                          for a in data[:5]]},
                summary=f"EU-based alternatives listed: {', '.join(names)}",
                limitations="Curated seed list; suitability is not assessed."))

    return [r for r in out if r]


def record_incident(log: EvidenceLog, incident: dict) -> list[dict]:
    """The stored incident and its own evidence become the starting evidence."""
    out = [log.add(
        source_tool="get_incidents", source_ref=f"incident={incident.get('id')}",
        trust="stored",
        content=_pick(incident, ("id", "type", "severity", "status", "app", "destination",
                                 "country_code", "jurisdiction", "confidence_basis")),
        summary=f"Stored incident ({incident.get('type')}, severity "
                f"{incident.get('severity')}): {clean_text(incident.get('title'), 200)}",
        limitations=clean_text(incident.get("uncertainty") or "Rule-based detection."))]
    for ev in (incident.get("evidence") or [])[:10]:
        out.append(log.add(
            source_tool="incident_store", source_ref=f"evidence={ev.get('id')}",
            trust="stored", content=ev.get("payload") or {},
            summary=f"Detection evidence ({ev.get('evidence_class')}): "
                    f"{clean_text(ev.get('summary'), 240)}",
            limitations=f"Recorded at detection time ({ev.get('timestamp')})."))
    return [r for r in out if r]


# ─── Claim validation ─────────────────────────────────────────────────────────

def stored_evidence_ids(session_factory, investigation_id: str) -> set[str]:
    with session_factory() as s:
        return set(s.scalars(select(InvestigationEvidenceRow.id).where(
            InvestigationEvidenceRow.investigation_id == investigation_id)).all())


def validate_claims(claims: list[dict], valid_ids: set[str]) -> list[str]:
    """Return a list of problems; empty means every claim is properly grounded.

    * kinds must be observed / inference / uncertainty / recommendation;
    * observed, inference and recommendation claims must cite ≥1 evidence id;
    * every cited id must exist in the store for this investigation;
    * no claim may state a legal conclusion.
    """
    problems: list[str] = []
    for i, c in enumerate(claims):
        kind = c.get("kind")
        ids = c.get("evidence_ids") or []
        text = str(c.get("text") or "")
        if kind not in CLAIM_KINDS:
            problems.append(f"claim {i}: unknown kind {kind!r}")
        if not text.strip():
            problems.append(f"claim {i}: empty text")
        if kind != "uncertainty" and not ids:
            problems.append(f"claim {i}: {kind} claim cites no evidence")
        unknown = [e for e in ids if e not in valid_ids]
        if unknown:
            problems.append(f"claim {i}: cites evidence that was never retrieved: {unknown}")
        if LEGAL_CONCLUSION.search(text):
            problems.append(f"claim {i}: states a legal conclusion")
    return problems
