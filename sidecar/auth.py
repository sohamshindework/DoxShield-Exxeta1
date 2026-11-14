"""OTP-based authentication with JWT tokens."""
import os
import secrets
import time

import jwt
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

try:
    import resend as resend_lib
except ImportError:
    resend_lib = None  # type: ignore

router = APIRouter(prefix="/api/auth", tags=["auth"])

# In-memory OTP store: email → {code, expires_at, name, user_type}
_otp_store: dict[str, dict] = {}

JWT_SECRET = os.getenv("JWT_SECRET", "").strip()
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_DAYS = 30


def _require_jwt_secret() -> None:
    if len(JWT_SECRET) < 32 or JWT_SECRET == "doxshield-default-secret-change-in-production":
        raise HTTPException(503, "OTP login requires a unique JWT_SECRET of at least 32 characters")


class SendOTPRequest(BaseModel):
    email: str
    name: str = ""
    user_type: str = "consumer"  # "consumer" | "business"


class VerifyOTPRequest(BaseModel):
    email: str
    code: str


class VerifyTokenRequest(BaseModel):
    token: str


def _generate_otp() -> str:
    return str(secrets.randbelow(900000) + 100000)


def _send_otp_email(email: str, name: str, code: str) -> tuple[bool, str]:
    """Send OTP via Resend. Returns (success, error_msg)."""
    api_key = os.getenv("RESEND_API_KEY", "")
    if not api_key:
        return False, "OTP email is unavailable: configure RESEND_API_KEY"

    if resend_lib is None:
        return False, "resend package not installed"

    try:
        resend_lib.api_key = api_key
        resend_lib.Emails.send({
            "from": "Doxshield <onboarding@resend.dev>",
            "to": [email],
            "subject": "Your Doxshield verification code",
            "html": f"""
<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#0A0A0F;
             font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">
  <div style="max-width:400px;margin:40px auto;background:#111118;border-radius:12px;
              overflow:hidden;border:1px solid rgba(255,255,255,0.1)">
    <div style="padding:28px 28px 0">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:20px">
        <div style="width:32px;height:32px;background:#3B82F6;border-radius:8px;
                    display:flex;align-items:center;justify-content:center;
                    font-size:18px">🛡</div>
        <span style="color:#F0F0F5;font-size:16px;font-weight:600">Doxshield</span>
      </div>
      <p style="color:#A0A0B0;font-size:14px;margin:0 0 8px">
        Hi{' ' + name if name else ''},</p>
      <p style="color:#F0F0F5;font-size:15px;margin:0 0 24px">
        Your verification code:</p>
      <div style="font-size:40px;font-weight:700;letter-spacing:10px;
                  color:#3B82F6;margin:0 0 24px;text-align:center;
                  background:#0A0A0F;border-radius:8px;padding:16px">
        {code}
      </div>
      <p style="color:#606070;font-size:12px;margin:0 0 24px">
        Expires in 10 minutes. If you didn't request this, you can safely ignore it.
      </p>
    </div>
    <div style="padding:16px 28px;border-top:1px solid rgba(255,255,255,0.06);
                text-align:center;color:#404050;font-size:11px">
      Doxshield · Protecting European data sovereignty
    </div>
  </div>
</body>
</html>
""",
        })
        return True, ""
    except Exception:
        # Provider exceptions may contain request data. Never log them or OTPs.
        return False, "OTP email delivery failed"


@router.post("/send-otp")
async def send_otp(req: SendOTPRequest):
    _require_jwt_secret()
    code = _generate_otp()
    _otp_store[req.email] = {
        "code": code,
        "expires_at": time.time() + 600,  # 10 min
        "name": req.name,
        "user_type": req.user_type,
    }

    ok, err = _send_otp_email(req.email, req.name, code)
    if not ok:
        _otp_store.pop(req.email, None)
        return {"success": False, "error": err}
    return {"success": True, "message": "Code sent"}


@router.post("/verify-otp")
async def verify_otp(req: VerifyOTPRequest):
    _require_jwt_secret()
    entry = _otp_store.get(req.email)
    if not entry:
        raise HTTPException(400, "No OTP sent to this email")
    if time.time() > entry["expires_at"]:
        del _otp_store[req.email]
        raise HTTPException(400, "Code expired")
    if req.code != entry["code"]:
        raise HTTPException(400, "Invalid code")

    # Clear OTP after successful verify
    del _otp_store[req.email]

    user = {
        "email": req.email,
        "name": entry.get("name", req.email.split("@")[0]),
        "user_type": entry.get("user_type", "consumer"),
    }

    payload = {
        **user,
        "iat": int(time.time()),
        "exp": int(time.time()) + JWT_EXPIRE_DAYS * 86400,
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    return {"success": True, "token": token, "user": user}


@router.post("/verify-token")
async def verify_token(req: VerifyTokenRequest):
    _require_jwt_secret()
    try:
        payload = jwt.decode(req.token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user = {
            "email": payload.get("email", ""),
            "name": payload.get("name", ""),
            "user_type": payload.get("user_type", "consumer"),
        }
        return {"valid": True, "user": user}
    except jwt.ExpiredSignatureError:
        return {"valid": False, "reason": "expired"}
    except Exception:
        return {"valid": False, "reason": "invalid"}
