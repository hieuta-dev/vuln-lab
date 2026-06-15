# FILE: backend/scanner/schemas.py
# PURPOSE: Typed scanner models shared by analyzer, generator, request builder, verifier, and orchestrator
# SECURITY NOTE: ScannerConfig enforces explicit target allowlists before any request candidate executes

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urlparse
from uuid import uuid4


VerificationStatus = Literal["confirmed", "suspected", "not_found", "error"]


@dataclass(slots=True)
class ScannerConfig:
    base_url: str
    max_requests_per_run: int = 100
    rate_limit_per_second: float = 2.0
    enable_xss_tests: bool = True
    enable_sqli_tests: bool = True
    enable_auth_tests: bool = True
    enable_access_control_tests: bool = True
    enable_upload_tests: bool = True
    enable_api_tests: bool = True
    lab_mode: bool = True
    allowed_base_urls: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/")
        if not self.allowed_base_urls:
            self.allowed_base_urls = [self.base_url]

    def is_allowed_url(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return False
        return any(url.startswith(base.rstrip("/")) for base in self.allowed_base_urls)


@dataclass(slots=True)
class PageFeatures:
    is_login: bool = False
    is_register: bool = False
    is_search: bool = False
    is_basket: bool = False
    is_profile: bool = False
    is_admin: bool = False
    is_upload: bool = False
    is_comment: bool = False
    is_product: bool = False
    is_api: bool = False
    is_error: bool = False


@dataclass(slots=True)
class FormInput:
    name: str
    input_type: str = "text"
    value: str = ""


@dataclass(slots=True)
class FormInfo:
    action: str
    method: str = "GET"
    inputs: list[FormInput] = field(default_factory=list)
    buttons: list[str] = field(default_factory=list)


@dataclass(slots=True)
class PageAnalysis:
    url: str
    method: str
    status_code: int
    headers: dict[str, str]
    forms: list[FormInfo]
    links: list[str]
    scripts: list[str]
    api_paths: list[str]
    hidden_fields: list[FormInput]
    csrf_tokens: list[str]
    candidate_params: list[str]
    features: PageFeatures
    title: str = ""


@dataclass(slots=True)
class AttackScenario:
    scenario_name: str
    vuln_type: str
    risk: str
    target: dict[str, Any]
    payload_family: str
    reason: str
    expected_signal: str
    verification: dict[str, Any]
    auth_required: bool = False
    safe_to_run: bool = True

    def dedup_key(self) -> str:
        target_url = self.target.get("url", "")
        method = self.target.get("method", "GET")
        params = sorted((self.target.get("params") or {}).keys())
        data = sorted((self.target.get("data") or {}).keys())
        js = sorted((self.target.get("json") or {}).keys())
        return f"{self.vuln_type}:{self.scenario_name}:{method}:{target_url}:{params}:{data}:{js}"


@dataclass(slots=True)
class RequestCandidate:
    scenario_name: str
    vuln_type: str
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    params: dict[str, Any] = field(default_factory=dict)
    json: dict[str, Any] = field(default_factory=dict)
    data: dict[str, Any] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    auth_required: bool = False
    safe_to_run: bool = True
    verification: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid4()))


@dataclass(slots=True)
class VerificationResult:
    status: VerificationStatus
    confirmed: bool
    evidence: str
    severity_num: int
    response_status: int = 0
    response_length: int = 0
    details: dict[str, Any] = field(default_factory=dict)

