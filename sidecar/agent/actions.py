"""Turn an assessment into proposed actions. Proposing never executes anything.

Proposals are deterministic (rule-based), built from concerns and their evidence.
No action argument is taken from untrusted text except after cleaning, and the
alert-email recipient comes only from the user's own settings — never from tool
output, policy text or the model.
"""
from __future__ import annotations

import re

from incidents.approvals import ACTION_ARG_KEYS

from .evidence import clean_text

_HOSTNAME = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
                       r"[A-Za-z]{2,63}$")
_EMAIL = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$")

APPROVAL_TEXT = ("Requires approval by a user with the 'approver' role who did not start this "
                 "investigation. The approval is bound to this exact payload and can be used once.")


def _concern(assessment: dict, category: str) -> dict | None:
    return next((c for c in assessment["concerns"] if c["category"] == category), None)


def _tracker_domain(evidence: list[dict], ids: list[str]) -> str | None:
    for e in evidence:
        if e["id"] in ids:
            dom = e["content"].get("domain") or e["content"].get("remote_domain")
            if dom and _HOSTNAME.match(str(dom)):
                return str(dom).lower()
    return None


def build_proposals(*, investigation_id: str, target_label: str, incident_id: str | None,
                    assessment: dict, evidence: list[dict],
                    alert_recipient: str | None) -> list[dict]:
    concerns = assessment["concerns"]
    priority = assessment["review_priority"]
    # Proportionality: low/undetermined priority findings stay as recommendations
    # in the report; only medium/high priority leads to action proposals.
    if not concerns or priority not in ("medium", "high"):
        return []
    label = clean_text(target_label, 80)
    all_ids = sorted({i for c in concerns for i in c["evidence_ids"]})
    lines = [f"- {c['title']} [evidence: {', '.join(c['evidence_ids'][:6])}]" for c in concerns]
    summary_body = (f"DoxShield privacy review: {label}\nInvestigation: {investigation_id}\n"
                    f"Review priority (heuristic rule, not a score): {priority}\n\nConcerns:\n"
                    + "\n".join(lines)
                    + "\n\nOpen questions: " + " ".join(c["unknowns"] for c in concerns)
                    + "\n\nDecision support for human review; not a legal determination.")
    proposals: list[dict] = []

    proposals.append({
        "kind": "create_ticket",
        "args": {"title": clean_text(f"[DoxShield] Privacy review: {label}", 120),
                 "body": summary_body[:4000]},
        "description": "Prepare an internal ticket draft to track this review.",
        "reason": f"{len(concerns)} concern(s) need a tracked human follow-up.",
        "evidence_ids": all_ids,
        "expected_effect": "A ticket draft is produced in DoxShield. No external ticket "
                           "system is contacted.",
        "limitations": "Draft only; someone must file it in the ticketing system.",
    })

    transfer = _concern(assessment, "non_adequate_destination")
    if incident_id and transfer and priority in ("high", "medium"):
        proposals.append({
            "kind": "draft_dpo_notification",
            "args": {"incident_id": incident_id},
            "description": "Draft a notification to the Data Protection Officer.",
            "reason": "Observed flow to a destination without an adequacy decision.",
            "evidence_ids": transfer["evidence_ids"],
            "expected_effect": "A notification draft for the DPO is produced. Nothing is sent.",
            "limitations": "The DPO decides whether any transfer mechanism is missing.",
        })

    tracker = _concern(assessment, "third_party_tracker")
    domain = _tracker_domain(evidence, tracker["evidence_ids"]) if tracker else None
    if tracker and domain:
        proposals.append({
            "kind": "propose_block_rule",
            "args": {"target": domain},
            "description": f"Generate a dry-run firewall rule proposal for {domain}.",
            "reason": "Observed contact with a known tracker domain.",
            "evidence_ids": tracker["evidence_ids"],
            "expected_effect": "A rule file is written for manual review. The firewall is "
                               "NOT changed.",
            "limitations": "Blocking may break app features; an administrator must review "
                           "and apply it manually.",
        })

    if alert_recipient and _EMAIL.match(alert_recipient) and priority == "high":
        proposals.append({
            "kind": "send_alert_email",
            "args": {"to": alert_recipient,
                     "subject": clean_text(f"DoxShield alert: {label}", 120),
                     "body": summary_body[:4000]},
            "description": "Draft an alert email to the configured alert address.",
            "reason": "High review priority.",
            "evidence_ids": all_ids,
            "expected_effect": "An email draft is produced. DoxShield does not send it.",
            "limitations": "Recipient comes from DoxShield settings; delivery is manual.",
        })

    for p in proposals:
        if set(p["args"]) != set(ACTION_ARG_KEYS[p["kind"]]):
            raise ValueError(f"proposal for {p['kind']} has wrong arguments")
        p["approval_requirements"] = APPROVAL_TEXT
    return proposals
