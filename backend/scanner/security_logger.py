# FILE: backend/scanner/security_logger.py
# PURPOSE: Persist scanner probe observations through the existing ELK-style logging flow
# SECURITY NOTE: Request/response bodies are truncated; secrets should not be logged in full

from __future__ import annotations

from datetime import datetime, timezone

from services.elk_logger import elk

from .schemas import RequestCandidate, VerificationResult


class SecurityLogger:
    """Thin adapter over the existing ELK logger service."""

    def log_probe(
        self,
        session_id: int,
        candidate: RequestCandidate,
        result: VerificationResult,
        request_body: dict | None = None,
    ) -> None:
        elk.log_probe_result(
            session_id=session_id,
            vuln_type=candidate.vuln_type,
            scenario_name=candidate.scenario_name,
            method=candidate.method,
            url=candidate.url,
            status_code=result.response_status,
            confirmed=result.confirmed,
            evidence=result.evidence[:500],
            duration_ms=int(result.details.get("duration_ms", 0)),
        )
        elk._send({
            "log_type": "probe_result",
            "session_id": session_id,
            "scenario_name": candidate.scenario_name,
            "vuln_type": candidate.vuln_type,
            "severity_num": result.severity_num,
            "request_method": candidate.method,
            "request_url": candidate.url,
            "request_body": request_body or candidate.json or candidate.data or candidate.params,
            "response_status": result.response_status,
            "evidence": result.evidence[:500],
            "confirmed": result.confirmed,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })

