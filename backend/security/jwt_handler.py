# FILE: backend/security/jwt_handler.py
# PURPOSE: JWT creation, decoding, and in-memory revocation for logout
# SECURITY NOTE: Uses HS256 with SECRET_KEY from env — never hardcode

from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt

from config import settings

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# In-process token blacklist (resets on restart — acceptable for demo)
_revoked: set[str] = set()


def create_access_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def decode_token(token: str) -> dict | None:
    if token in _revoked:
        return None
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
    except JWTError:
        return None


def revoke_token(token: str) -> None:
    _revoked.add(token)
