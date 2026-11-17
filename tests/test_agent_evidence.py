"""M4 evidence integrity: provenance, hashing, minimisation, conflicts, gaps."""
import pytest
from _agent_helpers import ANALYST, Env, run, start_and_wait
from agent.assessment import rules_assessment
from agent.evidence import EvidenceLog, clean_text, record_tool_result
from incidents.db import InvestigationEvidenceRow
from incidents.models import canonical_hash


@pytest.fixture()
def env(tmp_path):
    return Env(tmp_path)


def _ev(id_, tool, trust="observed", **content):
    return {"id": id_, "source_tool": tool, "trust": trust, "summary": "s",
            "content": content, "limitations": "", "source_ref": "r", "retrieved_at": "t"}


def test_records_carry_provenance_and_a_verifiable_hash(env):
    svc = env.service()
    inv_id = run(start_and_wait(svc, ANALYST, "app", "app-chrome"))
    evidence = svc.get(inv_id)["snapshot"]["evidence"]
    with env.sf() as s:
        for e in evidence:
            row = s.get(InvestigationEvidenceRow, e["id"])
            assert row is not None and row.investigation_id == inv_id
            assert e["source_tool"] and e["source_ref"] and e["retrieved_at"] and e["trust"]
            assert e["hash"] == canonical_hash({k: v for k, v in e.items() if k != "hash"})


def test_tool_output_is_minimised_and_cleaned(env):
    log = EvidenceLog("abcdef12-x", env.sf, [], 10)
    noisy = [{"app_name": "Evil\x00App‮" + "A" * 1000, "remote_domain": "x.example",
              "remote_ip": "203.0.113.9", "country_code": "CN", "cookie_value": "SECRET",
              "pid": 4242, "process_path": "/Users/me/secret"}]
    rec = record_tool_result(log, "get_connections", {"app": "Evil"}, noisy)[0]
    assert "cookie_value" not in rec["content"] and "process_path" not in rec["content"]
    assert "pid" not in rec["content"]
    assert "\x00" not in rec["summary"] and "‮" not in rec["summary"]
    assert len(rec["content"]["app_name"]) <= 400
    assert clean_text("a\nb\tc") == "a b c"


def test_evidence_cap_drops_extra_records(env):
    log = EvidenceLog("abcdef12-y", env.sf, [], 2)
    for i in range(4):
        log.add(source_tool="t", source_ref=str(i), trust="observed", summary="s")
    assert len(log.items) == 2 and log.dropped == 2


def test_conflicting_countries_become_an_uncertainty():
    ev = [_ev("EV-1", "get_connections", remote_ip="203.0.113.9", country_code="CN"),
          _ev("EV-2", "lookup_ip_jurisdiction", "heuristic", ip="203.0.113.9",
              country_code="DE")]
    a = rules_assessment(ev, [])
    conflict = next(u for u in a["uncertainties"] if "Conflicting evidence" in u["text"])
    assert conflict["evidence_ids"] == ["EV-1", "EV-2"]


def test_no_evidence_means_undetermined_not_a_conclusion():
    a = rules_assessment([], [])
    assert a["review_priority"] == "undetermined" and a["concerns"] == []
    assert "not enough evidence" in a["summary"]


def test_adequate_destination_raises_no_transfer_concern():
    a = rules_assessment([_ev("EV-1", "get_connections", country_code="DE")], [])
    assert not any(c["category"] == "non_adequate_destination" for c in a["concerns"])
    a = rules_assessment([_ev("EV-1", "get_connections", country_code="LOCAL")], [])
    assert a["concerns"] == []


def test_every_claim_is_typed_and_grounded():
    ev = [_ev("EV-1", "get_connections", country_code="CN", is_known_tracker=True,
              remote_domain="t.example"),
          _ev("EV-2", "get_permissions", permissions=["Camera"])]
    a = rules_assessment(ev, ["budget_exhausted"])
    assert a["review_priority"] == "high" and a["partial_evidence"] is True
    for c in a["claims"]:
        assert c["kind"] in ("observed", "inference", "uncertainty", "recommendation")
        if c["kind"] != "uncertainty":
            assert set(c["evidence_ids"]) <= {"EV-1", "EV-2"} and c["evidence_ids"]
    assert "not a legal assessment" in a["disclaimer"]
