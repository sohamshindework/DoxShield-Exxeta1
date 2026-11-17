"""In fixture mode the live monitor never scans the real machine and never emails."""
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sidecar"))
os.environ["DOXSHIELD_BACKEND"] = "fixture"

import alerts.resend_client as resend_client  # noqa: E402
import main  # noqa: E402
import scanner.network as network  # noqa: E402
from scanner import backend as backend_mod  # noqa: E402

ALERTS_ON = {**main.DEFAULT_SETTINGS, "alert_email": "dpo@example.invalid",
             "email_alerts_enabled": True, "alerts_enabled": True}


def _forbid(*_a, **_k):
    raise AssertionError("must not be called in fixture mode")


def test_monitor_uses_fixture_backend_and_sends_no_email(monkeypatch):
    backend_mod.reset_backend()
    monkeypatch.setattr(network, "get_active_connections", _forbid)
    monkeypatch.setattr(resend_client, "send_risk_alert", _forbid)
    monkeypatch.setattr(main, "_load_settings", lambda: ALERTS_ON)
    events = []

    async def capture(data):
        events.append(data)

    monkeypatch.setattr(main, "broadcast", capture)
    seen: set[str] = set()
    asyncio.run(main.monitor_once(seen))
    assert events and all(e["data"].get("synthetic") for e in events)
    assert all(e["data"]["risk_level"] in ("HIGH", "SEVERE") for e in events)
    events.clear()
    asyncio.run(main.monitor_once(seen))  # already-seen connections are not re-broadcast
    assert events == []


def test_scan_alerts_are_not_sent_for_synthetic_scans(monkeypatch):
    backend_mod.reset_backend()
    monkeypatch.setattr(main, "_load_settings", lambda: ALERTS_ON)
    monkeypatch.setattr(main, "_send_scan_alerts", _forbid)
    monkeypatch.setattr(asyncio, "create_task", _forbid)
    main._schedule_scan_alerts([{"app_name": "WeatherApp", "risk_level": "SEVERE"}])


def test_full_scan_uses_backend_and_skips_network_in_fixture_mode(monkeypatch, tmp_path):
    backend_mod.reset_backend()
    import ai.policy_analyzer as policy_analyzer
    monkeypatch.setattr(policy_analyzer, "analyze_policy", _forbid)
    monkeypatch.setattr(policy_analyzer, "fetch_policy_text", _forbid)
    monkeypatch.setattr(network, "get_active_connections", _forbid)
    import scanner.apps as apps_mod
    import scanner.cookies as cookies_mod
    import scanner.permissions as perms_mod
    for mod in (apps_mod, cookies_mod, perms_mod):
        for name in dir(mod):
            if name.startswith(("scan_", "get_", "check_", "find_")) and callable(getattr(mod, name)):
                monkeypatch.setattr(mod, name, _forbid)
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "LAST_SCAN_FILE", tmp_path / "last_scan.json")
    monkeypatch.setattr(main, "_schedule_scan_alerts", lambda risks: None)

    async def consume():
        resp = await main.full_scan_stream()
        return "".join([chunk async for chunk in resp.body_iterator])

    body = asyncio.run(consume())
    assert '"step": "complete"' in body and "skipped for synthetic data" in body
    assert '"synthetic": true' in body and '"step": "error"' not in body


def test_icon_endpoint_does_not_touch_the_real_machine(monkeypatch):
    backend_mod.reset_backend()
    import subprocess
    monkeypatch.setattr(subprocess, "run", _forbid)
    assert asyncio.run(main.get_app_icon("com.google.Chrome")) == {"icon": None}


def test_switching_fixture_sets_reads_only_fixture_files(monkeypatch, tmp_path):
    """Pointing the fixture backend at another data set (e.g. another company's
    synthetic scenario) reads those files only, never real machine state."""
    import json
    import shutil
    shutil.copytree(backend_mod.FIXTURE_DIR, tmp_path / "other")
    conns = json.loads((tmp_path / "other" / "connections.json").read_text())
    conns[0]["app_name"] = "OtherCompanyApp"
    (tmp_path / "other" / "connections.json").write_text(json.dumps(conns))
    monkeypatch.setattr(network, "get_active_connections", _forbid)
    other = backend_mod.FixtureBackend(fixture_dir=tmp_path / "other")
    assert other.is_synthetic
    got = asyncio.run(other.get_connections())
    assert got[0]["app_name"] == "OtherCompanyApp"
    assert other.scan_apps() and other.get_permissions()
