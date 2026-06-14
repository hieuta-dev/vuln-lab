# FILE: backend/security/csrf_token.py
# PURPOSE: HMAC-based CSRF token generation and verification
# SECURITY NOTE: generate_token / verify_token use the app SECRET_KEY — never expose client-side

import hashlib
import hmac
import secrets

from config import settings


def generate_token(session_id: str) -> str:
    nonce = secrets.token_hex(16)
    raw = f"{session_id}:{nonce}"
    sig = hmac.new(settings.secret_key.encode(), raw.encode(), hashlib.sha256).hexdigest()
    return f"{nonce}:{sig}"


def verify_token(token: str, session_id: str) -> bool:
    try:
        nonce, sig = token.split(":", 1)
    except ValueError:
        return False
    raw = f"{session_id}:{nonce}"
    expected = hmac.new(settings.secret_key.encode(), raw.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)
