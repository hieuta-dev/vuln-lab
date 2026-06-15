# FILE: backend/scanner/orchestrator.py
# PURPOSE: Coordinate page analysis, scenario generation, request execution, verification, and logging
# SECURITY NOTE: Enforces allowlist, safe_to_run, request budget, and rate limits before sending probes

from __future__ import annotations

import asyncio
import time
from collections import Counter
from typing import Any

import httpx

from .attack_scenario_generator import AttackScenarioGenerator
from .page_analyzer import PageAnalyzer
from .request_candidate_builder import RequestCandidateBuilder
from .scenario_verifier import ScenarioVerifier
from .schemas import RequestCandidate, ScannerConfig, VerificationResult
from .security_logger import SecurityLogger


class ScannerOrchestrator:
    """Runs the safe scenario generation + verification workflow for crawl items."""

    def __init__(
        self,
        config: ScannerConfig,
        session_id: int = 0,
        logger: SecurityLogger | None = None,
    ) -> None:
        self.config = config
        self.session_id = session_id
        self.analyzer = PageAnalyzer()
        self.generator = AttackScenarioGenerator()
        self.builder = RequestCandidateBuilder(config)
        self.verifier = ScenarioVerifier()
        self.logger = logger or SecurityLogger()
        self._last_request_at = 0.0

    async def run(self, crawl_items: list[dict[str, Any]]) -> dict[str, Any]:
        analyses = [self.analyzer.analyze(item) for item in crawl_items]

        scenarios = []
        for analysis in analyses:
            scenarios.extend(self.generator.generate(analysis))

        scenarios = self._dedupe_scenarios(scenarios)
        candidates = self.builder.build_many(scenarios)
        candidates = candidates[: self.config.max_requests_per_run]

        results: list[dict[str, Any]] = []
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
            for candidate in candidates:
                await self._rate_limit()
                result = await self._execute_and_verify(client, candidate)
                self.logger.log_probe(self.session_id, candidate, result)
                results.append({
                    "candidate_id": candidate.id,
                    "scenario_name": candidate.scenario_name,
                    "vuln_type": candidate.vuln_type,
                    "status": result.status,
                    "confirmed": result.confirmed,
                    "evidence": result.evidence,
                    "response_status": result.response_status,
                    "severity_num": result.severity_num,
                })

        summary_by_type = Counter(row["vuln_type"] for row in results)
        confirmed_by_type = Counter(row["vuln_type"] for row in results if row["confirmed"])

        summary = {
            "pages_analyzed": len(analyses),
            "scenarios_generated": len(scenarios),
            "requests_executed": len(results),
            "confirmed_count": sum(1 for row in results if row["confirmed"]),
            "summary_by_vuln_type": dict(summary_by_type),
            "confirmed_by_vuln_type": dict(confirmed_by_type),
            "results": results,
        }
        print(summary)
        return summary

    async def _execute_and_verify(
        self,
        client: httpx.AsyncClient,
        candidate: RequestCandidate,
    ) -> VerificationResult:
        started = time.time()
        response: httpx.Response | None = None
        error = ""
        try:
            response = await client.request(
                method=candidate.method,
                url=candidate.url,
                headers=candidate.headers,
                params=candidate.params,
                json=candidate.json or None,
                data=candidate.data or None,
                cookies=candidate.cookies,
            )
        except httpx.RequestError as exc:
            error = str(exc)

        result = self.verifier.verify(candidate, response, error=error)
        result.details["duration_ms"] = int((time.time() - started) * 1000)
        return result

    async def _rate_limit(self) -> None:
        if self.config.rate_limit_per_second <= 0:
            return
        min_interval = 1.0 / self.config.rate_limit_per_second
        now = time.time()
        elapsed = now - self._last_request_at
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        self._last_request_at = time.time()

    def _dedupe_scenarios(self, scenarios: list) -> list:
        seen: set[str] = set()
        out = []
        for scenario in scenarios:
            key = scenario.dedup_key()
            if key in seen:
                continue
            seen.add(key)
            out.append(scenario)
        return out


def config_from_dict(data: dict[str, Any]) -> ScannerConfig:
    scanner = data.get("scanner", data)
    return ScannerConfig(
        base_url=scanner["base_url"],
        max_requests_per_run=int(scanner.get("max_requests_per_run", 100)),
        rate_limit_per_second=float(scanner.get("rate_limit_per_second", 2)),
        enable_xss_tests=bool(scanner.get("enable_xss_tests", True)),
        enable_sqli_tests=bool(scanner.get("enable_sqli_tests", True)),
        enable_auth_tests=bool(scanner.get("enable_auth_tests", True)),
        enable_access_control_tests=bool(scanner.get("enable_access_control_tests", True)),
        enable_upload_tests=bool(scanner.get("enable_upload_tests", True)),
        enable_api_tests=bool(scanner.get("enable_api_tests", True)),
        lab_mode=bool(scanner.get("lab_mode", True)),
        allowed_base_urls=list(scanner.get("allowed_base_urls") or [scanner["base_url"]]),
    )

