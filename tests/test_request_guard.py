"""The sidecar refuses requests driven by other websites; the app's own renderers work.

Uses TestClient without the lifespan (no background monitor). Refused requests
never reach a handler, so the POSTs below cannot write settings or send email.
Header shapes mirror what Chromium/Electron 29 actually sent in the packaged-app
smoke test (file:// renderer: no Origin, ``Sec-Fetch-Site: cross-site``).
"""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sidecar"))
os.environ["DOXSHIELD_BACKEND"] = "fixture"

import main  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from request_guard import check_request  # noqa: E402

TOKEN = "t" * 64
client = TestClient(main.app, base_url="http://127.0.0.1:8765")
# What the packaged renderer sends (the main process adds the token).
PACKAGED = {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "cors"}


@pytest.fixture(autouse=True)
def token(monkeypatch):
    monkeypatch.setenv("DOXSHIELD_CLIENT_TOKEN", TOKEN)


@pytest.mark.parametrize("path,method", [
    ("/api/settings", "post"), ("/api/alerts/send", "post"), ("/api/alerts/test", "post"),
    ("/api/settings", "get"), ("/api/scan/full-stream", "get"),
    ("/api/incidents/detect", "post"), ("/api/investigations", "post"),
])
def test_foreign_website_is_refused_everywhere(path, method):
    kw = {"json": {"email": "x@evil.example"}} if method == "post" else {}
    r = getattr(client, method)(path, headers={"Origin": "https://evil.example",
                                               "Sec-Fetch-Site": "cross-site"}, **kw)
    assert r.status_code == 403


def test_packaged_renderer_with_token_is_allowed():
    r = client.get("/api/settings", headers={**PACKAGED, "X-DoxShield-Client": TOKEN})
    assert r.status_code == 200


def test_packaged_renderer_shape_without_token_is_refused():
    # Same shape as an <img>/link/navigation request from a website.
    assert client.get("/api/scan/full-stream", headers=PACKAGED).status_code == 403
    assert client.get("/api/scan/full-stream", headers={
        **PACKAGED, "X-DoxShield-Client": "wrong"}).status_code == 403
    assert client.get("/health", headers={"Sec-Fetch-Site": "none"}).status_code == 403


def test_sandboxed_iframe_null_origin_needs_token():
    sandboxed = {"Origin": "null", "Sec-Fetch-Site": "cross-site"}
    assert client.post("/api/alerts/test", json={"email": "x@evil.example"},
                       headers=sandboxed).status_code == 403
    assert client.get("/health", headers={**sandboxed, "X-DoxShield-Client": TOKEN}
                      ).status_code == 200
    assert client.get("/health", headers={"Origin": "file://", "X-DoxShield-Client": TOKEN}
                      ).status_code == 200


def test_token_required_even_when_unconfigured(monkeypatch):
    monkeypatch.delenv("DOXSHIELD_CLIENT_TOKEN")
    assert client.get("/health", headers={**PACKAGED, "X-DoxShield-Client": ""}
                      ).status_code == 403


def test_plain_html_form_post_is_refused():
    r = client.post("/api/alerts/test", content=b"email=x",
                    headers={"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site",
                             "Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 403


@pytest.mark.parametrize("origin", ["http://localhost:5173", "http://127.0.0.1:5199",
                                    "http://[::1]:3000"])
def test_local_dev_renderer_is_allowed(origin):
    r = client.get("/health", headers={"Origin": origin, "Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == origin


def test_direct_local_http_client_is_allowed():
    assert client.get("/health").status_code == 200


@pytest.mark.parametrize("host", ["evil.example:8765", "evil.example", "127.0.0.1.evil.example",
                                  "localhost.evil.example:8765", ""])
def test_dns_rebinding_hosts_are_refused(host):
    # A rebinding page makes same-origin requests: no Origin, Host = attacker name.
    r = client.get("/api/settings", headers={"Host": host, "Sec-Fetch-Site": "same-origin"})
    assert r.status_code == 403
    assert check_request({"host": host}) == "host not allowed"


def test_lookalike_origins_are_refused():
    for origin in ("http://localhost.evil.example", "http://127.0.0.1.evil.example",
                   "https://evil.example/http://localhost:5173"):
        assert check_request({"host": "127.0.0.1:8765", "origin": origin}) is not None


def test_cors_preflight_does_not_grant_foreign_origins():
    r = client.options("/api/settings", headers={
        "Origin": "https://evil.example", "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type"})
    assert "access-control-allow-origin" not in r.headers
    r = client.options("/api/settings", headers={
        "Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST"})
    assert r.headers.get("access-control-allow-origin") == "http://localhost:5173"


def test_no_websocket_endpoints_exist():
    from starlette.routing import WebSocketRoute
    from starlette.websockets import WebSocketDisconnect
    assert not [r for r in main.app.routes if isinstance(r, WebSocketRoute)]
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/api/network/stream", headers={
                "Origin": "https://evil.example"}):
            pass
