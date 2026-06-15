# FILE: backend/services/elk_logger.py
# PURPOSE: Structured JSON logging to Logstash TCP input for ELK stack visualisation
# SECURITY NOTE: Never log secrets, API keys, or plaintext passwords — only metadata

import json
import logging
import socket
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class ELKLogger:
    """
    Sends structured JSON logs to Logstash TCP input (port 5000).
    Falls back to stdout if Logstash is unreachable — never crashes the scan.
    """

    def __init__(self, host: str = "logstash", port: int = 5000) -> None:
        self.host = host
        self.port = port

    def _send(self, payload: dict) -> None:
        payload["timestamp"] = datetime.now(timezone.utc).isoformat()
        payload["service"] = "vulnlab-backend"
        line = json.dumps(payload) + "\n"
        try:
            with socket.create_connection((self.host, self.port), timeout=2) as sock:
                sock.sendall(line.encode("utf-8"))
        except Exception:
            # Fallback — logging must never crash the application
            logger.info("[ELK-FALLBACK] %s", line.strip())

    # ── Log types ─────────────────────────────────────────────────────────────

    def log_scan_request(
        self,
        session_id: int,
        target_url: str,
        target_name: str,
        user: str,
        vuln_types: list[str],
    ) -> None:
        self._send({
            "log_type":     "scan_request",
            "session_id":   session_id,
            "target_url":   target_url,
            "target_name":  target_name,
            "requested_by": user,
            "vuln_types":   vuln_types,
            "total_checks": len(vuln_types),
        })

    def log_agent_step(
        self,
        session_id: int,
        vuln_type: str,
        step_number: int,
        tool_name: str,
        tool_input: dict,
        tool_output: dict,
        duration_ms: int,
    ) -> None:
        self._send({
            "log_type":    "agent_step",
            "session_id":  session_id,
            "vuln_type":   vuln_type,
            "step_number": step_number,
            "tool_name":   tool_name,
            "tool_input":  tool_input,
            "tool_output": tool_output,
            "duration_ms": duration_ms,
        })

    def log_probe_result(
        self,
        session_id: int,
        vuln_type: str,
        scenario_name: str,
        method: str,
        url: str,
        status_code: int,
        confirmed: bool,
        evidence: str,
        duration_ms: int,
    ) -> None:
        self._send({
            "log_type":        "probe_result",
            "session_id":      session_id,
            "vuln_type":       vuln_type,
            "scenario_name":   scenario_name,
            "request_method":  method,
            "request_url":     url,
            "response_status": status_code,
            "confirmed":       confirmed,
            "evidence":        (evidence or "")[:500],
            "duration_ms":     duration_ms,
        })

    def log_scan_result(
        self,
        session_id: int,
        vuln_type: str,
        status: str,
        severity: str | None,
        finding_summary: str,
        scenarios_tested: int,
        scenarios_confirmed: int,
        total_duration_ms: int,
    ) -> None:
        self._send({
            "log_type":            "scan_result",
            "session_id":          session_id,
            "vuln_type":           vuln_type,
            "status":              status,
            "severity":            severity,
            "finding_summary":     (finding_summary or "")[:500],
            "scenarios_tested":    scenarios_tested,
            "scenarios_confirmed": scenarios_confirmed,
            "total_duration_ms":   total_duration_ms,
        })

    def log_session_complete(
        self,
        session_id: int,
        target_url: str,
        total_checks: int,
        vulnerabilities_found: int,
        highest_severity: str | None,
        total_duration_ms: int,
    ) -> None:
        self._send({
            "log_type":             "session_complete",
            "session_id":           session_id,
            "target_url":           target_url,
            "total_checks":         total_checks,
            "vulnerabilities_found": vulnerabilities_found,
            "highest_severity":     highest_severity,
            "total_duration_ms":    total_duration_ms,
        })


# Singleton — import and use `elk` everywhere
elk = ELKLogger()
