# FILE: backend/middleware/security_mode.py
# PURPOSE: Read X-Security-Mode header and set request.state.secure_mode
# SECURITY NOTE: Defaults to False (vulnerable) when header is absent

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class SecurityModeMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        mode = request.headers.get("X-Security-Mode", "vulnerable").lower()
        request.state.secure_mode = mode == "secure"
        return await call_next(request)
