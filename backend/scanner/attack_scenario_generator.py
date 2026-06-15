# FILE: backend/scanner/attack_scenario_generator.py
# PURPOSE: Generate safe attack scenario candidates from normalized page analysis
# SECURITY NOTE: Generates lab-safe candidates only; destructive requests are marked unsafe and filtered later

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from .payloads import (
    COMMENT_PAYLOADS,
    JSON_TAMPER_FIELDS,
    LAB_CREDENTIALS,
    MASS_ASSIGNMENT_FIELDS,
    OPEN_REDIRECT_PAYLOADS,
    PATH_TRAVERSAL_PAYLOADS,
    SQLI_PAYLOADS,
    UPLOAD_TEST_FILES,
    XSS_PAYLOADS,
)
from .schemas import AttackScenario, FormInfo, PageAnalysis


class AttackScenarioGenerator:
    """Builds scenario candidates from page features and crawler metadata."""

    REDIRECT_PARAMS = {"redirect", "returnurl", "return_url", "next", "url", "continue", "callback"}
    FILE_PARAMS = {"file", "path", "download", "image", "img", "template", "page"}
    IDOR_PARAMS = {"id", "userid", "user_id", "accountid", "account_id", "basketid", "orderid", "order_id"}

    def generate(self, page: PageAnalysis) -> list[AttackScenario]:
        scenarios: list[AttackScenario] = []
        scenarios.extend(self._from_query_params(page))
        scenarios.extend(self._from_forms(page))
        scenarios.extend(self._from_url_features(page))
        scenarios.extend(self._from_api_paths(page))
        return self._dedupe(scenarios)

    def _from_query_params(self, page: PageAnalysis) -> list[AttackScenario]:
        scenarios: list[AttackScenario] = []
        parsed = urlparse(page.url)
        existing_params = parse_qs(parsed.query)

        for param in page.candidate_params:
            scenarios.append(AttackScenario(
                scenario_name=f"Reflected XSS candidate in {param} parameter",
                vuln_type="xss",
                risk="medium",
                target={"method": "GET", "url": self._strip_query(page.url), "params": {param: XSS_PAYLOADS[0]}},
                payload_family="html_script_injection",
                reason="The page accepts a query/form parameter and returns HTML.",
                expected_signal="Payload appears unescaped in response HTML.",
                verification={"type": "response_contains_unescaped_payload", "status_codes": [200]},
            ))
            scenarios.append(AttackScenario(
                scenario_name=f"SQL injection candidate in {param} parameter",
                vuln_type="sql_injection",
                risk="medium",
                target={"method": "GET", "url": self._strip_query(page.url), "params": {param: SQLI_PAYLOADS[0]}},
                payload_family="sql_boolean_bypass",
                reason="The endpoint accepts a user-controlled parameter.",
                expected_signal="SQL error, larger result set, or sensitive keyword exposure.",
                verification={"type": "error_or_sensitive_keyword", "status_codes": [200, 500]},
            ))

            if param.lower() in self.REDIRECT_PARAMS:
                scenarios.append(AttackScenario(
                    scenario_name=f"Open redirect candidate in {param} parameter",
                    vuln_type="open_redirect",
                    risk="medium",
                    target={"method": "GET", "url": self._strip_query(page.url), "params": {param: OPEN_REDIRECT_PAYLOADS[0]}},
                    payload_family="external_redirect",
                    reason="Redirect-like parameter name controls navigation destination.",
                    expected_signal="Location header or final URL points to attacker-controlled host.",
                    verification={"type": "redirects_to_external_host", "status_codes": [301, 302, 303, 307, 308]},
                ))

            if param.lower() in self.FILE_PARAMS:
                scenarios.append(AttackScenario(
                    scenario_name=f"Path traversal candidate in {param} parameter",
                    vuln_type="path_traversal",
                    risk="high",
                    target={"method": "GET", "url": self._strip_query(page.url), "params": {param: PATH_TRAVERSAL_PAYLOADS[0]}},
                    payload_family="relative_file_path",
                    reason="File-like parameter may read server-side paths.",
                    expected_signal="Sensitive file content or package metadata appears in response.",
                    verification={"type": "sensitive_keyword_exposure", "status_codes": [200]},
                ))

            if param.lower() in self.IDOR_PARAMS or existing_params.get(param):
                scenarios.append(self._idor_scenario(page.url, param))

        return scenarios

    def _from_forms(self, page: PageAnalysis) -> list[AttackScenario]:
        scenarios: list[AttackScenario] = []
        for form in page.forms:
            if self._is_login_form(form) and page.features.is_login:
                scenarios.extend(self._login_form_scenarios(form))
            if page.features.is_register:
                scenarios.extend(self._register_form_scenarios(form))
            if page.features.is_comment:
                scenarios.extend(self._comment_form_scenarios(form))
            if page.features.is_upload or self._has_file_input(form):
                scenarios.extend(self._upload_form_scenarios(form))
        return scenarios

    def _login_form_scenarios(self, form: FormInfo) -> list[AttackScenario]:
        user_field = self._first_matching(form, ("email", "user", "username", "login", "name"))
        pass_field = self._first_matching(form, ("pass", "password", "pwd"))
        if not user_field or not pass_field:
            return []

        scenarios = [
            AttackScenario(
                scenario_name="Authentication bypass candidate via SQL injection",
                vuln_type="broken_auth",
                risk="high",
                target={"method": form.method, "url": form.action, "data": {user_field: SQLI_PAYLOADS[0], pass_field: "x"}},
                payload_family="auth_sqli_bypass",
                reason="Login form has username/email and password fields.",
                expected_signal="Login succeeds, token is returned, or redirect goes to an authenticated area.",
                verification={"type": "auth_bypass_signal", "status_codes": [200, 302]},
            ),
            AttackScenario(
                scenario_name="Account enumeration candidate from login errors",
                vuln_type="broken_auth",
                risk="low",
                target={"method": form.method, "url": form.action, "data": {user_field: "admin", pass_field: "wrong-password"}},
                payload_family="error_message_diff",
                reason="Login errors may reveal whether an account exists.",
                expected_signal="Different response text for known-looking vs nonexistent usernames.",
                verification={"type": "error_message_or_length_anomaly", "status_codes": [200, 401, 403]},
            ),
        ]
        for username, password in LAB_CREDENTIALS:
            scenarios.append(AttackScenario(
                scenario_name=f"Weak lab credential candidate {username}:{password}",
                vuln_type="broken_auth",
                risk="medium",
                target={"method": form.method, "url": form.action, "data": {user_field: username, pass_field: password}},
                payload_family="lab_weak_credentials",
                reason="Lab apps often ship default or weak credentials for challenges.",
                expected_signal="Token, session cookie, or authenticated redirect is returned.",
                verification={"type": "auth_bypass_signal", "status_codes": [200, 302]},
            ))
        return scenarios

    def _register_form_scenarios(self, form: FormInfo) -> list[AttackScenario]:
        scenarios = [
            AttackScenario(
                scenario_name="Registration weak validation candidate",
                vuln_type="insecure_design",
                risk="medium",
                target={"method": form.method, "url": form.action, "data": {"email": "invalid", "password": "1"}},
                payload_family="weak_registration_validation",
                reason="Registration form should reject malformed email and weak password.",
                expected_signal="Account creation succeeds despite weak or invalid inputs.",
                verification={"type": "unexpected_success_status", "status_codes": [200, 201, 302]},
            )
        ]
        field_names = {inp.name.lower() for inp in form.inputs}
        if field_names & {"role", "isadmin", "admin", "privilege"}:
            scenarios.append(AttackScenario(
                scenario_name="Registration role manipulation candidate",
                vuln_type="broken_access_control",
                risk="high",
                target={"method": form.method, "url": form.action, "data": MASS_ASSIGNMENT_FIELDS},
                payload_family="mass_assignment",
                reason="Registration form exposes privilege-related fields.",
                expected_signal="Created user has elevated role or response accepts admin fields.",
                verification={"type": "privilege_keyword_or_success", "status_codes": [200, 201, 302]},
            ))
        return scenarios

    def _comment_form_scenarios(self, form: FormInfo) -> list[AttackScenario]:
        text_field = self._first_matching(form, ("comment", "review", "message", "feedback", "content", "text"))
        if not text_field:
            return []
        return [
            AttackScenario(
                scenario_name="Stored XSS candidate in comment/review form",
                vuln_type="xss",
                risk="medium",
                target={"method": form.method, "url": form.action, "data": {text_field: COMMENT_PAYLOADS[0]}},
                payload_family="stored_html_injection",
                reason="Comment/review forms often persist user-supplied HTML.",
                expected_signal="Payload appears unescaped after submission or page reload.",
                verification={"type": "response_contains_unescaped_payload", "status_codes": [200, 201, 302]},
            )
        ]

    def _upload_form_scenarios(self, form: FormInfo) -> list[AttackScenario]:
        file_field = self._first_matching(form, ("file", "upload", "avatar", "image", "document")) or "file"
        return [
            AttackScenario(
                scenario_name="File upload extension validation candidate",
                vuln_type="file_upload",
                risk="high",
                target={"method": form.method, "url": form.action, "files": {"field": file_field, "files": UPLOAD_TEST_FILES}},
                payload_family="upload_validation",
                reason="Upload form should reject dangerous extensions and mismatched MIME types.",
                expected_signal="Probe file accepted or returned as accessible resource.",
                verification={"type": "unexpected_success_status", "status_codes": [200, 201]},
            ),
            AttackScenario(
                scenario_name="Safe oversized upload validation candidate",
                vuln_type="file_upload",
                risk="medium",
                target={"method": form.method, "url": form.action, "files": {"field": file_field, "files": [("vulnlab-large.txt", b"A" * 2048, "text/plain")]}},
                payload_family="upload_size_limit",
                reason="Upload endpoints should enforce documented size limits.",
                expected_signal="Small lab-only oversized probe is accepted unexpectedly.",
                verification={"type": "unexpected_success_status", "status_codes": [200, 201]},
            ),
        ]

    def _from_url_features(self, page: PageAnalysis) -> list[AttackScenario]:
        scenarios: list[AttackScenario] = []
        if page.features.is_profile or page.features.is_admin or page.features.is_basket:
            scenarios.append(AttackScenario(
                scenario_name="Broken access control candidate on sensitive page",
                vuln_type="broken_access_control",
                risk="high" if page.features.is_admin else "medium",
                target={"method": "GET", "url": page.url},
                payload_family="unauthenticated_sensitive_page",
                reason="Sensitive profile/account/admin/cart page may require authentication or authorization.",
                expected_signal="Sensitive page returns 200 without auth or exposes user-specific content.",
                verification={"type": "unexpected_200_without_auth", "status_codes": [200]},
            ))

        path = urlparse(page.url).path
        if any(part.isdigit() for part in path.split("/")):
            scenarios.append(self._idor_scenario(page.url, "path_id"))
        return scenarios

    def _from_api_paths(self, page: PageAnalysis) -> list[AttackScenario]:
        scenarios: list[AttackScenario] = []
        paths = set(page.api_paths)
        if page.features.is_api:
            paths.add(urlparse(page.url).path)

        for path in paths:
            url = path if path.startswith("http") else self._origin(page.url) + path
            scenarios.extend([
                AttackScenario(
                    scenario_name=f"Missing authorization candidate on API {path}",
                    vuln_type="underprotected_apis",
                    risk="high",
                    target={"method": "GET", "url": url},
                    payload_family="api_without_auth",
                    reason="API-like endpoint discovered by crawler.",
                    expected_signal="Endpoint returns data without authentication.",
                    verification={"type": "sensitive_keyword_exposure", "status_codes": [200]},
                ),
                AttackScenario(
                    scenario_name=f"Mass assignment candidate on API {path}",
                    vuln_type="insecure_design",
                    risk="medium",
                    target={"method": "POST", "url": url, "json": MASS_ASSIGNMENT_FIELDS},
                    payload_family="mass_assignment",
                    reason="JSON APIs may accept unexpected privilege fields.",
                    expected_signal="Response accepts or echoes role/admin fields.",
                    verification={"type": "privilege_keyword_or_success", "status_codes": [200, 201]},
                ),
                AttackScenario(
                    scenario_name=f"JSON parameter tampering candidate on API {path}",
                    vuln_type="insecure_design",
                    risk="medium",
                    target={"method": "POST", "url": url, "json": JSON_TAMPER_FIELDS},
                    payload_family="json_business_logic_tamper",
                    reason="API endpoint may trust client-side numeric or ownership fields.",
                    expected_signal="Invalid price, quantity, or role field is accepted.",
                    verification={"type": "unexpected_success_status", "status_codes": [200, 201]},
                ),
                AttackScenario(
                    scenario_name=f"Safe method confusion candidate on API {path}",
                    vuln_type="underprotected_apis",
                    risk="low",
                    target={"method": "OPTIONS", "url": url},
                    payload_family="method_discovery",
                    reason="API method exposure can reveal unsafe operations.",
                    expected_signal="Allow header includes PUT/PATCH/DELETE.",
                    verification={"type": "dangerous_methods_allowed", "status_codes": [200, 204]},
                    safe_to_run=True,
                ),
            ])
        return scenarios

    def _idor_scenario(self, url: str, param: str) -> AttackScenario:
        return AttackScenario(
            scenario_name=f"IDOR candidate via {param}",
            vuln_type="insecure_design",
            risk="high",
            target={"method": "GET", "url": self._strip_query(url), "params": {param: "1"}},
            payload_family="object_id_tampering",
            reason="URL or parameter appears to reference an object/user identifier.",
            expected_signal="Different object or user data is returned without authorization.",
            verification={"type": "sensitive_keyword_exposure", "status_codes": [200]},
            auth_required=True,
        )

    def _first_matching(self, form: FormInfo, markers: tuple[str, ...]) -> str:
        for inp in form.inputs:
            lowered = inp.name.lower()
            if any(marker in lowered for marker in markers):
                return inp.name
        return form.inputs[0].name if form.inputs else ""

    def _has_file_input(self, form: FormInfo) -> bool:
        return any(inp.input_type == "file" for inp in form.inputs)

    def _is_login_form(self, form: FormInfo) -> bool:
        names = " ".join(inp.name.lower() for inp in form.inputs)
        has_password = any(inp.input_type == "password" or "pass" in inp.name.lower() for inp in form.inputs)
        has_user = any(marker in names for marker in ("email", "user", "login", "name"))
        return has_password and has_user

    def _strip_query(self, url: str) -> str:
        parsed = urlparse(url)
        return parsed._replace(query="", fragment="").geturl()

    def _origin(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _dedupe(self, scenarios: list[AttackScenario]) -> list[AttackScenario]:
        seen: set[str] = set()
        out: list[AttackScenario] = []
        for scenario in scenarios:
            key = scenario.dedup_key()
            if key not in seen:
                seen.add(key)
                out.append(scenario)
        return out

