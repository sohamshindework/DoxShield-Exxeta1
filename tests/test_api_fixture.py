"""API endpoints serve synthetic data on the fixture backend, with no system access.

Endpoint functions are called directly (no server, no lifespan/device monitor),
so the test never starts real scanning.
"""
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sidecar"))

os.environ["DOXSHIELD_BACKEND"] = "fixture"

from scanner import backend as backend_mod  # noqa: E402

backend_mod.reset_backend()

import main  # noqa: E402


def test_health_reports_fixture_backend():
    data = asyncio.run(main.health())
    assert data["backend"] == "fixture"
    assert data["synthetic"] is True


def test_network_live_returns_synthetic_connections():
    conns = asyncio.run(main.get_live_connections())
    assert any(c["jurisdiction"] == "CN" for c in conns)
    assert all(c.get("synthetic") for c in conns)


def test_network_history_returns_list():
    hist = asyncio.run(main.get_connection_history())
    assert isinstance(hist, list) and len(hist) >= 1


def test_cookies_status_reports_browsers():
    status = asyncio.run(main.cookies_status())
    assert status["fda_granted"] is True
    assert "Google Chrome" in status["browsers_found"]
