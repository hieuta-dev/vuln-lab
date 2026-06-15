# FILE: backend/scanner/__init__.py
# PURPOSE: Safe target-allowlisted scanner package for generating and verifying lab attack scenarios
# SECURITY NOTE: Modules in this package enforce allowlist and safe-to-run checks before requests execute

from .attack_scenario_generator import AttackScenarioGenerator
from .orchestrator import ScannerOrchestrator, config_from_dict
from .page_analyzer import PageAnalyzer
from .request_candidate_builder import RequestCandidateBuilder
from .scenario_verifier import ScenarioVerifier
from .schemas import AttackScenario, PageAnalysis, RequestCandidate, ScannerConfig, VerificationResult

__all__ = [
    "AttackScenario",
    "AttackScenarioGenerator",
    "PageAnalysis",
    "PageAnalyzer",
    "RequestCandidate",
    "RequestCandidateBuilder",
    "ScannerConfig",
    "ScannerOrchestrator",
    "ScenarioVerifier",
    "VerificationResult",
    "config_from_dict",
]
