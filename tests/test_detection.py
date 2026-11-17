"""Detection rules turn a fixture scan into the expected incidents."""
import asyncio
import os
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sidecar"))

os.environ["DOXSHIELD_BACKEND"] = "fixture"

from incidents.detection import detect_incidents, is_adequate  # noqa: E402
from incidents.models import EvidenceClass, IncidentType  # noqa: E402
from scanner import backend as backend_mod  # noqa: E402


def _fixture_scan() -> dict:
    backend_mod.reset_backend()
    b = backend_mod.get_backend()
    return {
        "connections": asyncio.run(b.get_connections()),
        "permissions": b.get_permissions(),
        "cookies": b.scan_cookies(),
    }


def test_adequacy_classification():
    assert is_adequate("DE") and is_adequate("GB")
    assert not is_adequate("US") and not is_adequate("CN")
    assert not is_adequate(None)


def test_fixture_scan_produces_expected_incidents():
    incidents = detect_incidents(_fixture_scan())
    counts = Counter(i.type for i in incidents)
    assert counts[IncidentType.NON_ADEQUATE_TRANSFER] == 3
    assert counts[IncidentType.KNOWN_TRACKER] == 3
    assert len(incidents) == 6


def test_incidents_cite_evidence_and_avoid_legal_conclusions():
    for inc in detect_incidents(_fixture_scan()):
        assert inc.evidence, "every incident must cite evidence"
        for ev in inc.evidence:
            assert ev.hash and ev.evidence_class in EvidenceClass
        assert inc.recommended_follow_up
        text = f"{inc.title} {inc.recommended_follow_up}".lower()
        assert "illegal" not in text and "violat" not in text


def test_new_destination_country_rule_uses_baseline():
    baseline = [("Mail", "DE"), ("Google Chrome", "US")]
    incidents = detect_incidents(_fixture_scan(), known_destinations=baseline)
    new_country = [i for i in incidents
                   if i.type == IncidentType.NEW_DESTINATION_COUNTRY]
    assert any(i.app == "WeatherApp" and i.country_code == "CN" for i in new_country)
