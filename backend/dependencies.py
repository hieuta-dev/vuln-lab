# FILE: backend/dependencies.py
# PURPOSE: FastAPI dependencies — current user extraction from Bearer JWT
# SECURITY NOTE: 401 raised for missing/invalid/expired/revoked tokens

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from security.jwt_handler import decode_token

bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> dict:
    if not creds:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    payload = decode_token(creds.credentials)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    return payload


async def get_current_user_optional(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> dict | None:
    if not creds:
        return None
    return decode_token(creds.credentials)
