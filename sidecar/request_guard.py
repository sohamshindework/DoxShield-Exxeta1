"""Stop web pages in the user's browser from driving the local sidecar.

The sidecar listens on 127.0.0.1, but any website the user visits can still send
requests to it. CORS only controls whether a page can *read* a response, not
whether the request runs. So every HTTP request goes through ``check_request``
before any handler (and therefore before any side effect):

1. ``Host`` must be a loopback name (``127.0.0.1``, ``localhost``, ``[::1]``).
   This defeats DNS rebinding, where ``evil.example`` is re-pointed at 127.0.0.1
   and its pages make same-origin requests that carry no ``Origin`` header.
2. ``Origin`` is a local dev origin (``http://localhost:*`` etc.) → allowed (the
   Vite dev renderer).
3. Browser requests whose origin is missing or opaque → allowed **only** with
   the per-launch client token. This covers the packaged Electron renderer:
   Chromium sends its ``file://`` requests with no ``Origin`` (or ``null``) and
   ``Sec-Fetch-Site: cross-site``. It also covers what an attacker can produce
   (``<img>``/link requests, sandboxed iframes), which lack the token.
   Electron generates the token, passes it to the sidecar as
   ``DOXSHIELD_CLIENT_TOKEN`` and adds it as ``X-DoxShield-Client`` only to its
   own app window's requests; web content cannot read it.
4. Any other ``Origin`` → refused.
5. No ``Origin`` and no browser fetch metadata (curl, tests, local tools) →
   allowed: local processes are a separate trust boundary (not authenticated).
"""
from __future__ import annotations

import hmac
import os
import re

from fastapi import Request
from fastapi.responses import JSONResponse

LOCAL_ORIGIN = re.compile(r"^https?://(localhost|127\.0\.0\.1|\[::1\])(:\d{1,5})?$")
LOCAL_HOST = re.compile(r"^(localhost|127\.0\.0\.1|\[::1\])(:\d{1,5})?$")
OPAQUE_ORIGINS = {"null", "file://"}
BROWSER_SITES = {"cross-site", "same-site", "same-origin", "none"}
TOKEN_HEADER = "x-doxshield-client"


def _has_valid_token(headers) -> bool:
    expected = os.getenv("DOXSHIELD_CLIENT_TOKEN", "")
    supplied = headers.get(TOKEN_HEADER, "")
    return bool(expected) and hmac.compare_digest(expected.encode(), supplied.encode())


def check_request(headers) -> str | None:
    """Return a refusal reason, or ``None`` when the request may proceed."""
    host = (headers.get("host") or "").lower()
    if not LOCAL_HOST.match(host):
        return "host not allowed"
    origin = headers.get("origin")
    if origin is not None and LOCAL_ORIGIN.match(origin):
        return None
    if origin is not None and origin not in OPAQUE_ORIGINS:
        return "origin not allowed"
    # Missing or opaque origin. A browser marks its requests with Sec-Fetch-Site;
    # an opaque Origin header is only ever sent by a browser.
    from_browser = origin is not None or headers.get("sec-fetch-site") in BROWSER_SITES
    if not from_browser:
        return None
    if _has_valid_token(headers):
        return None
    return "browser request without a local origin or a valid client token"


async def guard_middleware(request: Request, call_next):
    # CORS preflights carry no side effects; CORSMiddleware answers them.
    if request.method != "OPTIONS":
        reason = check_request(request.headers)
        if reason:
            return JSONResponse({"detail": f"Request refused: {reason}"}, status_code=403)
    return await call_next(request)


# CORS: only the local renderers may read responses. "null" covers an opaque
# Electron origin; such requests still need the client token above.
CORS_ORIGIN_REGEX = r"^(null|https?://(localhost|127\.0\.0\.1|\[::1\])(:\d{1,5})?)$"
