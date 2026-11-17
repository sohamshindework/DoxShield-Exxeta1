"""Who is calling, and with which roles (viewer / analyst / approver).

Two ways to identify a caller:

1. **Signed token** (normal): ``Authorization: Bearer <jwt>`` issued by the
   existing OTP login (``auth.py``). Roles come from ``DOXSHIELD_ROLES`` (JSON:
   ``{"email": ["analyst"]}``) or ``~/.doxshield/roles.json``. An unknown user is a
   viewer.
2. **Demo identities** (fixture backend only): when ``DOXSHIELD_DEMO_IDENTITIES=1``
   *and* the synthetic fixture backend is active, the header
   ``X-DoxShield-Demo-User: analyst|approver|viewer`` selects a fixed demo user.
   This is for demonstrating separation of duties on synthetic data; it is
   refused with the real macOS backend.

Mutating requests also pass an Origin check, so a web page open in the user's
browser cannot drive the local sidecar (the existing CORS policy is permissive).
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import jwt
from fastapi import HTTPException, Request

from .service import Principal

DEMO_USERS: dict[str, tuple[str, frozenset[str]]] = {
    "analyst": ("demo-analyst@doxshield.invalid", frozenset({"viewer", "analyst"})),
    "approver": ("demo-approver@doxshield.invalid", frozenset({"viewer", "approver"})),
    "viewer": ("demo-viewer@doxshield.invalid", frozenset({"viewer"})),
}
VALID_ROLES = {"viewer", "analyst", "approver"}
_ALLOWED_ORIGIN = re.compile(
    r"^(null|file://.*|app://.*|https?://(localhost|127\.0\.0\.1|\[::1\])(:\d{1,5})?)$")


def demo_enabled() -> bool:
    if os.getenv("DOXSHIELD_DEMO_IDENTITIES", "") != "1":
        return False
    from scanner.backend import get_backend
    return bool(get_backend().is_synthetic)


def _role_map() -> dict[str, list[str]]:
    raw = os.getenv("DOXSHIELD_ROLES", "").strip()
    if not raw:
        path = Path(os.path.expanduser("~/.doxshield/roles.json"))
        raw = path.read_text() if path.exists() else "{}"
    try:
        data = json.loads(raw)
    except ValueError:
        return {}
    return {str(k).lower(): [r for r in v if r in VALID_ROLES]
            for k, v in data.items() if isinstance(v, list)}


def roles_for(email: str) -> frozenset[str]:
    return frozenset({"viewer", *_role_map().get(email.lower(), [])})


def check_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    if origin is not None and not _ALLOWED_ORIGIN.match(origin):
        raise HTTPException(403, "Requests from this origin are not allowed")


def resolve_principal(request: Request) -> Principal:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        secret = os.getenv("JWT_SECRET", "").strip()
        if len(secret) < 32:
            raise HTTPException(401, "Token login is not configured (JWT_SECRET)")
        try:
            payload = jwt.decode(auth[7:].strip(), secret, algorithms=["HS256"])
        except jwt.PyJWTError as exc:
            raise HTTPException(401, "Invalid or expired token") from exc
        email = str(payload.get("email") or "").strip()
        if not email:
            raise HTTPException(401, "Token has no identity")
        return Principal(id=email, roles=roles_for(email), source="token")
    demo = request.headers.get("x-doxshield-demo-user", "").strip().lower()
    if demo:
        if not demo_enabled():
            raise HTTPException(401, "Demo identities are disabled")
        if demo not in DEMO_USERS:
            raise HTTPException(401, "Unknown demo user")
        email, roles = DEMO_USERS[demo]
        return Principal(id=email, roles=roles, source="demo")
    raise HTTPException(401, "Sign in to use investigations")
