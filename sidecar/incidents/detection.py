"""Turn a scan result into privacy incidents using explicit, auditable rules.

Rules are deliberately simple and transparent — each incident cites the exact
observations it was built from. Nothing here states a legal conclusion; incidents
carry "for DPO review" follow-ups and heuristic (not calibrated) confidence.

The adequacy list below is a minimal placeholder for M2. M5 replaces it with a
sourced, dated knowledge-base entry.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .models import (
    Evidence,
    EvidenceClass,
    Incident,
    IncidentType,
    Severity,
    Status,
    new_id,
)

# EU/EEA members (ISO-3166 alpha-2).
_EU_EEA = {
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR",
    "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK",
    "SI", "ES", "SE", "IS", "LI", "NO",
}
# Countries/territories with an EU adequacy decision (placeholder set for M2).
_ADEQUACY = {
    "AD", "AR", "CA", "FO", "GG", "IL", "IM", "JP", "JE", "NZ", "KR", "CH",
    "GB", "UY",
}
ADEQUATE_COUNTRY_CODES = _EU_EEA | _ADEQUACY

SENSITIVE_PERMISSIONS = {
    "Camera", "Microphone", "Location", "Contacts", "Photos",
    "ScreenCapture", "FullDiskAccess", "Accessibility", "Calendars",
}


def is_adequate(country_code: str | None) -> bool:
    """True when the destination has EU membership or an adequacy decision.

    Unknown/missing codes are treated as NOT adequate (fail-safe for review).
    """
    if not country_code:
        return False
    return country_code.upper() in ADEQUATE_COUNTRY_CODES


def _app_permissions(permissions: dict, bundle_id: str | None) -> list[str]:
    if not bundle_id:
        return []
    return permissions.get("permissions", {}).get(bundle_id, [])


def _severity_from_risk(risk_level: str | None, default: Severity) -> Severity:
    try:
        return Severity(risk_level) if risk_level else default
    except ValueError:
        return default


def detect_incidents(
    scan: dict[str, Any],
    known_destinations: Iterable[tuple[str, str]] | None = None,
) -> list[Incident]:
    """Build incidents from a scan dict.

    ``scan`` keys: ``connections`` (list of enriched dicts), ``permissions``
    (dict), ``cookies`` (dict with a ``cookies`` list). ``known_destinations`` is
    an optional baseline of ``(app, country_code)`` pairs for new-country
    detection.
    """
    connections = scan.get("connections", [])
    permissions = scan.get("permissions", {})
    cookies = scan.get("cookies", {}).get("cookies", [])
    baseline = {(a, c) for a, c in (known_destinations or [])}

    incidents: list[Incident] = []

    for conn in connections:
        incidents.extend(_rules_for_connection(conn, permissions, baseline))

    for cookie in cookies:
        incident = _tracker_cookie_incident(cookie)
        if incident:
            incidents.append(incident)

    return incidents


def _copy(evidence: Evidence) -> Evidence:
    """A per-incident copy: evidence rows belong to one incident, so two incidents
    built from the same observation must not share an evidence id."""
    return evidence.model_copy(update={"id": new_id()})


def _rules_for_connection(conn: dict, permissions: dict, baseline: set) -> list[Incident]:
    out: list[Incident] = []
    cc = conn.get("country_code")
    app = conn.get("app_name") or conn.get("process_name")
    bundle = conn.get("bundle_id")
    dest = conn.get("remote_domain") or conn.get("remote_ip")

    conn_evidence = Evidence(
        source_tool="network",
        evidence_class=EvidenceClass.OBSERVED,
        summary=f"{app} connected to {dest} ({cc}, {conn.get('jurisdiction')})",
        payload={k: conn.get(k) for k in
                 ("app_name", "bundle_id", "remote_ip", "remote_domain",
                  "country_code", "jurisdiction", "remote_port")},
    ).finalize()

    # Rule 1: transfer to a non-adequate destination with a sensitive permission.
    if cc and not is_adequate(cc):
        perms = _app_permissions(permissions, bundle)
        sensitive = sorted(set(perms) & SENSITIVE_PERMISSIONS)
        if sensitive:
            perm_evidence = Evidence(
                source_tool="permissions",
                evidence_class=EvidenceClass.OBSERVED,
                summary=f"{app} holds sensitive permissions: {', '.join(sensitive)}",
                payload={"bundle_id": bundle, "permissions": sensitive},
            ).finalize()
            out.append(Incident(
                type=IncidentType.NON_ADEQUATE_TRANSFER,
                severity=_severity_from_risk(conn.get("risk_level"), Severity.HIGH),
                status=Status.NEW,
                title=f"{app}: data flow to {cc} (no adequacy decision) with sensitive access",
                source_scanner="network+permissions",
                app=app,
                destination=dest,
                country_code=cc,
                jurisdiction=conn.get("jurisdiction"),
                confidence=0.7,
                confidence_basis="heuristic",
                uncertainty="Destination inferred from IP/domain; adequacy list is a "
                            "placeholder; actual payload contents are not inspected.",
                recommended_follow_up="Review transfer basis (GDPR Chapter V) with the DPO.",
                evidence=[conn_evidence, perm_evidence],
            ))

    # Rule 2: connection to a known tracker.
    if conn.get("is_known_tracker"):
        out.append(Incident(
            type=IncidentType.KNOWN_TRACKER,
            severity=_severity_from_risk(conn.get("risk_level"), Severity.MEDIUM),
            status=Status.NEW,
            title=f"{app}: connection to known tracker {dest}",
            source_scanner="network",
            app=app,
            destination=dest,
            country_code=cc,
            jurisdiction=conn.get("jurisdiction"),
            confidence=0.6,
            confidence_basis="heuristic",
            uncertainty="Tracker match is pattern-based; category may be imprecise.",
            recommended_follow_up="Confirm whether this tracker is expected for the app.",
            evidence=[_copy(conn_evidence)],
        ))

    # Rule 3: new destination country for this app (needs a baseline).
    if cc and app and baseline and (app, cc) not in baseline:
        out.append(Incident(
            type=IncidentType.NEW_DESTINATION_COUNTRY,
            severity=Severity.LOW,
            status=Status.NEW,
            title=f"{app}: new destination country {cc}",
            source_scanner="network",
            app=app,
            destination=dest,
            country_code=cc,
            jurisdiction=conn.get("jurisdiction"),
            confidence=0.5,
            confidence_basis="heuristic",
            uncertainty="Based on the supplied baseline; a first scan has no baseline.",
            recommended_follow_up="Check whether this new destination is expected.",
            evidence=[_copy(conn_evidence)],
        ))

    return out


def _tracker_cookie_incident(cookie: dict) -> Incident | None:
    if not cookie.get("is_known_tracker"):
        return None
    domain = cookie.get("domain")
    evidence = Evidence(
        source_tool="cookies",
        evidence_class=EvidenceClass.OBSERVED,
        summary=f"Tracker cookie {cookie.get('name')} on {domain} "
                f"({cookie.get('browser')})",
        payload={k: cookie.get(k) for k in
                 ("domain", "name", "browser", "jurisdiction",
                  "tracker_category", "is_third_party")},
    ).finalize()
    return Incident(
        type=IncidentType.KNOWN_TRACKER,
        severity=_severity_from_risk(cookie.get("risk_level"), Severity.MEDIUM),
        status=Status.NEW,
        title=f"Tracker cookie on {domain}",
        source_scanner="cookies",
        app=cookie.get("browser"),
        destination=domain,
        jurisdiction=cookie.get("jurisdiction"),
        confidence=0.6,
        confidence_basis="heuristic",
        uncertainty="Tracker match is pattern-based.",
        recommended_follow_up="Review cookie-consent and tracker expectations.",
        evidence=[evidence],
    )
