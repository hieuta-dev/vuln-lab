# FILE: backend/scanner/request_candidate_builder.py
# PURPOSE: Convert generated attack scenarios into executable HTTP request definitions
# SECURITY NOTE: Enforces allowlist and safe-to-run policy before candidates are returned

from __future__ import annotations

from .schemas import AttackScenario, RequestCandidate, ScannerConfig


class RequestCandidateBuilder:
    """Builds executable request candidates from AttackScenario objects."""

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config

    def build_many(self, scenarios: list[AttackScenario]) -> list[RequestCandidate]:
        candidates: list[RequestCandidate] = []
        for scenario in scenarios:
            candidate = self.build(scenario)
            if not candidate:
                continue
            if self.config.is_allowed_url(candidate.url) and candidate.safe_to_run:
                candidates.append(candidate)
        return candidates

    def build(self, scenario: AttackScenario) -> RequestCandidate | None:
        target = scenario.target
        url = str(target.get("url", ""))
        method = str(target.get("method", "GET")).upper()
        if not url:
            return None

        return RequestCandidate(
            scenario_name=scenario.scenario_name,
            vuln_type=scenario.vuln_type,
            method=method,
            url=url,
            headers=dict(target.get("headers") or {}),
            params=dict(target.get("params") or {}),
            json=dict(target.get("json") or {}),
            data=dict(target.get("data") or {}),
            cookies=dict(target.get("cookies") or {}),
            auth_required=scenario.auth_required,
            safe_to_run=bool(scenario.safe_to_run),
            verification=dict(scenario.verification or {}),
        )

