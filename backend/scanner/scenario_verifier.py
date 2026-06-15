# FILE: backend/scanner/scenario_verifier.py
# PURPOSE: Classify scanner probe responses using deterministic evidence checks
# SECURITY NOTE: Verification consumes response metadata only; it does not trigger additional requests

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from httpx import Response

from .payloads import ERROR_PATTERNS, SENSITIVE_KEYWORDS, XSS_CANARY
from .schemas import RequestCandidate, VerificationResult


class ScenarioVerifier:
    """Classifies results as confirmed, suspected, not_found, or error."""

    def verify(
        self,
        candidate: RequestCandidate,
        response: Response | None,
        baseline: Response | None = None,
        error: str = "",
    ) -> VerificationResult:
        if error or response is None:
            return VerificationResult(
                status="error",
                confirmed=False,
                evidence=error or "No response received",
                severity_num=0,
            )

        verification_type = candidate.verification.get("type", "")
        text = response.text or ""
        lower = text.lower()
        allowed_statuses = candidate.verification.get("status_codes") or [200]
        status_ok = response.status_code in allowed_statuses

        if verification_type == "response_contains_unescaped_payload":
            payload = self._first_payload(candidate)
            confirmed = bool(payload and payload in text and "&lt;" not in text)
            return self._result(confirmed, response, f"Payload reflected unescaped: {payload}", 2)

        if verification_type == "error_or_sensitive_keyword":
            error_hit = any(pattern in lower for pattern in ERROR_PATTERNS)
            sensitive_hit = any(keyword in lower for keyword in SENSITIVE_KEYWORDS)
            confirmed = status_ok and (error_hit or sensitive_hit)
            evidence = "SQL/error pattern or sensitive keyword found" if confirmed else "No SQL/error indicators found"
            return self._result(confirmed, response, evidence, 3 if confirmed else 0)

        if verification_type == "redirects_to_external_host":
            location = response.headers.get("location", "")
            host = urlparse(location).netloc
            confirmed = response.is_redirect and bool(host) and host != urlparse(candidate.url).netloc
            return self._result(confirmed, response, f"Redirect Location: {location}", 2)

        if verification_type == "sensitive_keyword_exposure":
            hits = [keyword for keyword in SENSITIVE_KEYWORDS if keyword in lower]
            confirmed = status_ok and bool(hits)
            return self._result(confirmed, response, f"Sensitive keywords exposed: {hits}", 3 if confirmed else 0)

        if verification_type == "auth_bypass_signal":
            confirmed = status_ok and self._has_auth_signal(response)
            return self._result(confirmed, response, "Authentication success signal detected", 4 if confirmed else 0)

        if verification_type == "error_message_or_length_anomaly":
            suspected = response.status_code in {200, 400, 401, 403} and len(text) > 0
            return VerificationResult(
                status="suspected" if suspected else "not_found",
                confirmed=False,
                evidence="Login error response collected for comparison" if suspected else "No enumerable error response",
                severity_num=1 if suspected else 0,
                response_status=response.status_code,
                response_length=len(response.content),
            )

        if verification_type == "unexpected_success_status":
            confirmed = status_ok
            return self._result(confirmed, response, f"Unexpected success status {response.status_code}", 2)

        if verification_type == "privilege_keyword_or_success":
            confirmed = status_ok and any(marker in lower for marker in ("admin", "role", "privilege", "permission"))
            return self._result(confirmed, response, "Privilege field accepted or echoed", 3 if confirmed else 0)

        if verification_type == "unexpected_200_without_auth":
            confirmed = response.status_code == 200 and len(text) > 50
            return self._result(confirmed, response, "Sensitive page returned content without auth", 3 if confirmed else 0)

        if verification_type == "dangerous_methods_allowed":
            allow = response.headers.get("allow", "").upper()
            confirmed = any(method in allow for method in ("PUT", "PATCH", "DELETE"))
            return self._result(confirmed, response, f"Allow header: {allow}", 1 if confirmed else 0)

        if verification_type == "response_length_anomaly" and baseline:
            diff = abs(len(response.content) - len(baseline.content))
            suspected = diff > max(500, len(baseline.content) * 0.5)
            return VerificationResult(
                status="suspected" if suspected else "not_found",
                confirmed=False,
                evidence=f"Response length delta: {diff}",
                severity_num=1 if suspected else 0,
                response_status=response.status_code,
                response_length=len(response.content),
            )

        return VerificationResult(
            status="suspected" if status_ok else "not_found",
            confirmed=False,
            evidence=f"Status {response.status_code}; no verifier-specific evidence",
            severity_num=1 if status_ok else 0,
            response_status=response.status_code,
            response_length=len(response.content),
        )

    def _result(self, confirmed: bool, response: Response, evidence: str, severity_num: int) -> VerificationResult:
        return VerificationResult(
            status="confirmed" if confirmed else "not_found",
            confirmed=confirmed,
            evidence=evidence if confirmed else "Expected signal not observed",
            severity_num=severity_num if confirmed else 0,
            response_status=response.status_code,
            response_length=len(response.content),
        )

    def _first_payload(self, candidate: RequestCandidate) -> Any:
        for container in (candidate.params, candidate.data, candidate.json):
            for value in container.values():
                if isinstance(value, str):
                    return value
        return XSS_CANARY if XSS_CANARY in str(candidate.params or candidate.data or candidate.json) else ""

    def _has_auth_signal(self, response: Response) -> bool:
        text = (response.text or "").lower()
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        return (
            "token" in text
            or "access_token" in text
            or "jwt" in text
            or "set-cookie" in headers
            or response.is_redirect
        )

