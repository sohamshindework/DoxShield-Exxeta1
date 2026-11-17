"""Scanner backend selection and the synthetic fixture backend."""
import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sidecar"))

from scanner import backend as backend_mod  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_backend():
    backend_mod.reset_backend()
    yield
    backend_mod.reset_backend()


def test_default_backend_is_macos(monkeypatch):
    monkeypatch.delenv("DOXSHIELD_BACKEND", raising=False)
    backend_mod.reset_backend()
    assert backend_mod.get_backend().name == "macos"


def test_invalid_backend_raises(monkeypatch):
    monkeypatch.setenv("DOXSHIELD_BACKEND", "cloud")
    backend_mod.reset_backend()
    with pytest.raises(ValueError):
        backend_mod.get_backend()


def test_fixture_backend_is_synthetic(monkeypatch):
    monkeypatch.setenv("DOXSHIELD_BACKEND", "fixture")
    backend_mod.reset_backend()
    b = backend_mod.get_backend()
    assert b.name == "fixture"
    assert b.is_synthetic is True


def test_fixture_apps_shape(monkeypatch):
    monkeypatch.setenv("DOXSHIELD_BACKEND", "fixture")
    backend_mod.reset_backend()
    apps = backend_mod.get_backend().scan_apps()
    assert len(apps) >= 1
    first = apps[0]
    assert first.id and first.name and first.path
    assert hasattr(first, "dict")  # pydantic AppInfo, drop-in for the real scanner


def test_fixture_permissions_shape(monkeypatch):
    monkeypatch.setenv("DOXSHIELD_BACKEND", "fixture")
    backend_mod.reset_backend()
    perms = backend_mod.get_backend().get_permissions()
    assert isinstance(perms.get("permissions"), dict)


def test_fixture_connections_cover_jurisdictions(monkeypatch):
    monkeypatch.setenv("DOXSHIELD_BACKEND", "fixture")
    backend_mod.reset_backend()
    conns = asyncio.run(backend_mod.get_backend().get_connections())
    assert all("remote_ip" in c for c in conns)
    jurisdictions = {c["jurisdiction"] for c in conns}
    assert {"EU", "US", "CN"} <= jurisdictions


def test_fixture_cookies_shape(monkeypatch):
    monkeypatch.setenv("DOXSHIELD_BACKEND", "fixture")
    backend_mod.reset_backend()
    cookies = backend_mod.get_backend().scan_cookies()
    assert cookies["fda_granted"] is True
    assert len(cookies["cookies"]) >= 1
