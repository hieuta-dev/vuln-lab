# FILE: backend/services/scan_service.py
# PURPOSE: Background scan logic — runs AI scenario generation + HTTP probe per vuln type
# SECURITY NOTE: Probe is educational/passive simulation only — never sends destructive payloads

import logging
from datetime import datetime, timezone

import httpx
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

import time as _time

from ai_engine.scenario_agent import generate_scenario
from database import AsyncSessionLocal
from models.scan_result import ScanResult
from models.scan_session import ScanSession
from services.elk_logger import elk
from services.reproduce_service import generate_reproduce_steps

logger = logging.getLogger(__name__)

VULN_TYPES = [
    "sql_injection", "xss", "csrf", "file_upload", "broken_auth",
    "security_misconfig", "sensitive_data_exposure", "logging_monitoring",
    "supply_chain", "cryptographic_failure", "insecure_design",
    "exceptional_conditions", "underprotected_apis",
]

SECURITY_HEADERS = [
    "x-frame-options", "x-content-type-options",
    "content-security-policy", "strict-transport-security",
    "x-xss-protection", "referrer-policy",
]

SQL_ERROR_PATTERNS = [
    "sql syntax", "mysql_fetch", "ora-0", "pg::", "sqlite3",
    "unclosed quotation", "you have an error in your sql",
    "warning: mysql", "unterminated string", "syntax error",
    "microsoft ole db provider", "odbc sql server driver",
    "jdbc", "sqlexception", "pdo", "invalid query",
]

XSS_REFLECTED_PATTERNS = ["<script>", "onerror=", "onload=", "javascript:"]

BACKUP_PATHS = [
    "/.env", "/.env.bak", "/.env.old",
    "/.git/config", "/.git/HEAD",
    "/index.php.bak", "/index.html.bak",
    "/web.config.old", "/database.sql",
    "/backup.sql", "/db.sql",
]

ADMIN_PATHS = [
    "/phpmyadmin/", "/adminer.php", "/adminer/",
    "/jenkins/", "/kibana/", "/_cat/indices",
    "/admin/", "/admin/dashboard", "/wp-admin/",
    "/manager/html", "/console/",
]

LOG_PATHS = [
    "/logs", "/log", "/debug", "/trace",
    "/api/logs", "/.well-known/security.txt",
    "/actuator/logfile", "/actuator/httptrace",
]

API_DOC_PATHS = [
    "/swagger-ui.html", "/swagger-ui/", "/swagger.json",
    "/openapi.json", "/api-docs", "/v3/api-docs",
    "/api/", "/graphql",
]

SSRF_INTERNAL = [
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/",
    "http://localhost:5432",
    "http://127.0.0.1:6379",
]


def _headers_lower(resp: httpx.Response) -> dict[str, str]:
    return {k.lower(): v for k, v in resp.headers.items()}


def _body(resp: httpx.Response, chars: int = 3000) -> str:
    return resp.text[:chars].lower()


async def _get(client: httpx.AsyncClient, url: str, timeout: int = 10) -> httpx.Response | None:
    try:
        return await client.get(url, timeout=timeout, follow_redirects=True)
    except httpx.RequestError:
        return None


async def probe_target(
    client: httpx.AsyncClient,
    target_url: str,
    vuln_type: str,
    auth_info: dict | None,
) -> dict:
    """Best-effort educational HTTP probe. Returns finding dict. Never sends destructive payloads."""

    base_resp = await _get(client, target_url)
    if base_resp is None:
        return {"status": "failed", "severity": None,
                "summary": "Target URL not reachable. Check URL and try again."}

    h = _headers_lower(base_resp)
    body = _body(base_resp)
    base_url = target_url.rstrip("/")

    # ── SQL Injection ─────────────────────────────────────────────────────────
    if vuln_type == "sql_injection":
        findings = []

        # 1. Quote injection probe (passive — only checks for error patterns)
        probe_resp = await _get(client, f"{base_url}/?id=1'", timeout=10)
        if probe_resp and any(e in probe_resp.text.lower() for e in SQL_ERROR_PATTERNS):
            findings.append("SQL error message leaked via id parameter injection")

        # 2. NoSQL indicator in response content-type
        if "mongodb" in body or "mongoose" in body:
            findings.append("MongoDB/Mongoose reference in response — potential NoSQL injection surface")

        # 3. HTTP headers reflected in body (header injection risk)
        if "x-forwarded-for" in body or "user-agent" in body or "referer" in body:
            findings.append("HTTP headers reflected in response body — possible header injection to DB")

        # 4. Server header reveals DB type
        server_hdr = h.get("server", "") + h.get("x-powered-by", "")
        if any(db in server_hdr.lower() for db in ["mysql", "postgres", "mssql", "oracle"]):
            findings.append(f"DB type disclosed in server header: {server_hdr}")

        if findings:
            return {"status": "success", "severity": "critical",
                    "summary": "; ".join(findings),
                    "detail": f"Probe URL: {base_url}/?id=1'"}
        return {"status": "passed", "severity": None,
                "summary": "No obvious SQL errors detected — manual testing recommended (time-based blind, second-order, header injection)"}

    # ── XSS ──────────────────────────────────────────────────────────────────
    if vuln_type == "xss":
        findings = []
        csp = h.get("content-security-policy", "")

        if not csp:
            findings.append("No Content-Security-Policy header — XSS mitigations absent")
        else:
            if "unsafe-inline" in csp:
                findings.append("CSP present but allows 'unsafe-inline' — inline scripts permitted")
            if "unsafe-eval" in csp:
                findings.append("CSP present but allows 'unsafe-eval' — eval() permitted")

        if not h.get("x-xss-protection"):
            findings.append("X-XSS-Protection header missing (legacy protection absent)")

        # DOM XSS indicator: document.write / innerHTML in body
        if "document.write(" in base_resp.text or "innerhtml" in body:
            findings.append("document.write() or innerHTML usage detected in page source — potential DOM XSS sink")

        # Reflected input test (safe probe with benign marker)
        marker = "xsstest12345"
        reflected_resp = await _get(client, f"{base_url}/?q={marker}")
        if reflected_resp and marker in reflected_resp.text:
            findings.append("Input reflected in response without visible encoding — possible reflected XSS")

        # Check if page can be framed (clickjacking → mXSS risk)
        if not h.get("x-frame-options") and "frame-ancestors" not in csp:
            findings.append("Page frameable (no X-Frame-Options / CSP frame-ancestors) — mXSS/clickjacking risk")

        if findings:
            severity = "high" if any("absent" in f or "reflected" in f or "innerHTML" in f for f in findings) else "medium"
            return {
                "status": "success", "severity": severity,
                "summary": "; ".join(findings),
                "detail": f"CSP value: {csp[:200] if csp else 'not set'}",
            }
        return {"status": "passed", "severity": None,
                "summary": "CSP present with no obvious bypass indicators",
                "detail": f"CSP value: {csp[:200]}"}

    # ── CSRF ──────────────────────────────────────────────────────────────────
    if vuln_type == "csrf":
        findings = []

        # CSRF token indicators in page
        csrf_tokens = ["csrf", "xsrf", "_token", "authenticity_token", "csrfmiddlewaretoken"]
        has_csrf = any(t in body for t in csrf_tokens)
        if not has_csrf:
            findings.append("No CSRF token indicators found in page body")

        # SameSite cookie check
        set_cookie = h.get("set-cookie", "")
        if "samesite" not in set_cookie.lower() and set_cookie:
            findings.append("Cookie Set-Cookie header missing SameSite attribute")

        # CORS headers check
        cors = h.get("access-control-allow-origin", "")
        if cors == "*":
            findings.append("Access-Control-Allow-Origin: * — wildcard CORS enables cross-origin reads")
        elif cors and cors != "null":
            findings.append(f"CORS origin allowed: {cors}")

        # Check preflight response
        cors_creds = h.get("access-control-allow-credentials", "")
        if cors == "*" and cors_creds.lower() == "true":
            findings.append("CRITICAL: CORS wildcard + credentials=true — cross-origin requests with cookies allowed")

        if findings:
            severity = "critical" if "CRITICAL" in " ".join(findings) else "high"
            return {"status": "success", "severity": severity,
                    "summary": "; ".join(findings)}
        return {"status": "passed", "severity": None,
                "summary": "CSRF protections appear to be in place (token indicators found, SameSite set)"}

    # ── File Upload ───────────────────────────────────────────────────────────
    if vuln_type == "file_upload":
        findings = []

        upload_indicators = [
            'type="file"', "enctype=\"multipart", "enctype='multipart",
            "/upload", "/file", "multipart/form-data", "file upload",
        ]
        found_upload = any(ind in body or ind in base_resp.text.lower() for ind in upload_indicators)
        if found_upload:
            findings.append("File upload surface detected in page")

        # Check if uploads directory is listable
        uploads_resp = await _get(client, f"{base_url}/uploads/", timeout=8)
        if uploads_resp and uploads_resp.status_code == 200:
            if "index of" in uploads_resp.text.lower() or "<a href=" in uploads_resp.text.lower():
                findings.append("CRITICAL: /uploads/ directory listing enabled — all uploaded files browsable")

        # Check for SVG MIME serving (XSS via SVG)
        # Check Content-Disposition on uploaded file paths
        if not h.get("x-content-type-options"):
            findings.append("X-Content-Type-Options: nosniff missing — browser may MIME-sniff uploaded files")

        # Check for zip extraction paths (passive)
        if "zip" in body or "archive" in body or "extract" in body:
            findings.append("Archive handling detected — test for Zip Slip path traversal")

        if findings:
            severity = "critical" if "CRITICAL" in " ".join(findings) else "high"
            return {"status": "success", "severity": severity, "summary": "; ".join(findings)}
        return {"status": "passed", "severity": None,
                "summary": "No obvious file upload surface found — nosniff header present"}

    # ── Broken Authentication ─────────────────────────────────────────────────
    if vuln_type == "broken_auth":
        if not auth_info or not auth_info.get("username"):
            return {"status": "needs_info", "severity": None,
                    "summary": "Cannot fully test broken auth without credentials",
                    "missing_info": "Provide login URL, username, and password to test rate limiting, lockout, and session handling"}

        findings = []
        login_url = auth_info.get("login_url", f"{base_url}/api/auth/login")

        # Rate limiting check — send 5 rapid failed logins
        rate_limited = False
        for _ in range(5):
            try:
                r = await client.post(login_url,
                    json={"username": auth_info["username"], "password": "WRONG_PASS_PROBE"},
                    timeout=10)
                if r.status_code == 429:
                    rate_limited = True
                    break
                rate_headers = [k for k in r.headers if "rate" in k.lower() or "retry" in k.lower()]
                if rate_headers:
                    rate_limited = True
                    break
            except httpx.RequestError:
                break

        if not rate_limited:
            findings.append("No rate limiting detected after 5 rapid failed login attempts")

        # Check for lockout (distinct error messages for user-not-found vs wrong-password)
        try:
            r_nouser = await client.post(login_url,
                json={"username": "nonexistent_user_xzxz9", "password": "wrong"},
                timeout=10)
            r_wrongpw = await client.post(login_url,
                json={"username": auth_info["username"], "password": "WRONG_PASS_PROBE"},
                timeout=10)
            if r_nouser.text != r_wrongpw.text and r_nouser.status_code == r_wrongpw.status_code:
                findings.append("Username enumeration possible — different responses for invalid user vs wrong password")
        except httpx.RequestError:
            pass

        # Check password reset endpoint
        reset_paths = ["/api/auth/reset-password", "/api/password-reset", "/forgot-password"]
        for rp in reset_paths:
            rr = await _get(client, f"{base_url}{rp}", timeout=6)
            if rr and rr.status_code < 400:
                findings.append(f"Password reset endpoint found at {rp} — test for token reuse and enumeration")
                break

        if findings:
            return {"status": "success", "severity": "high",
                    "summary": "; ".join(findings),
                    "detail": f"Login endpoint tested: {login_url}"}
        return {"status": "passed", "severity": None,
                "summary": "Basic auth checks passed — rate limiting and distinct error messages detected",
                "detail": f"Login endpoint tested: {login_url}"}

    # ── Security Misconfiguration ─────────────────────────────────────────────
    if vuln_type == "security_misconfig":
        findings = []

        # Missing security headers
        missing_hdrs = [hdr for hdr in SECURITY_HEADERS if hdr not in h]
        if missing_hdrs:
            findings.append(f"Missing security headers: {', '.join(missing_hdrs)}")

        # Check HTTP methods via OPTIONS
        try:
            opts_resp = await client.request("OPTIONS", base_url, timeout=8)
            allow_hdr = opts_resp.headers.get("allow", opts_resp.headers.get("Allow", ""))
            dangerous = [m for m in ["TRACE", "PUT", "DELETE"] if m in allow_hdr.upper()]
            if dangerous:
                findings.append(f"Dangerous HTTP methods enabled: {', '.join(dangerous)}")
        except httpx.RequestError:
            pass

        # Check for backup/config files
        for bp in BACKUP_PATHS:
            r = await _get(client, f"{base_url}{bp}", timeout=5)
            if r and r.status_code == 200 and len(r.text) > 10:
                findings.append(f"Sensitive file accessible: {bp}")
                break

        # Check for admin interfaces
        for ap in ADMIN_PATHS:
            r = await _get(client, f"{base_url}{ap}", timeout=5)
            if r and r.status_code == 200:
                findings.append(f"Admin interface accessible without auth: {ap}")
                break

        # Server version disclosure
        server_val = h.get("server", "") + h.get("x-powered-by", "")
        version_patterns = ["apache/", "nginx/", "iis/", "php/", "express/", "django/", "flask/"]
        if any(p in server_val.lower() for p in version_patterns):
            findings.append(f"Server version disclosed: {server_val[:80]}")

        # Directory listing check
        dir_resp = await _get(client, f"{base_url}/static/", timeout=6)
        if dir_resp and "index of" in dir_resp.text.lower():
            findings.append("Directory listing enabled at /static/")

        if findings:
            severity = "critical" if any("accessible" in f for f in findings) else "high"
            return {"status": "success", "severity": severity,
                    "summary": "; ".join(findings),
                    "detail": f"HTTP {base_resp.status_code}"}
        return {"status": "passed", "severity": None,
                "summary": "Security headers and config appear to be present",
                "detail": f"HTTP {base_resp.status_code}"}

    # ── Sensitive Data Exposure ───────────────────────────────────────────────
    if vuln_type == "sensitive_data_exposure":
        findings = []

        if not target_url.startswith("https://"):
            findings.append("HTTP instead of HTTPS — all data transmitted in plaintext")

        hsts = h.get("strict-transport-security", "")
        if not hsts:
            findings.append("HSTS header missing — browser may use plain HTTP")

        # Sensitive data in query param pattern in page links
        if "password=" in body or "token=" in body or "secret=" in body or "api_key=" in body:
            findings.append("Possible sensitive data in URL parameters found in page source")

        # Cookie security flags
        set_cookie = h.get("set-cookie", "")
        if set_cookie:
            cookie_issues = []
            if "httponly" not in set_cookie.lower():
                cookie_issues.append("missing HttpOnly")
            if "secure" not in set_cookie.lower():
                cookie_issues.append("missing Secure flag")
            if "samesite" not in set_cookie.lower():
                cookie_issues.append("missing SameSite")
            if cookie_issues:
                findings.append(f"Cookie security issues: {', '.join(cookie_issues)}")

        # HTML comments with sensitive data
        import re as _re
        comments = _re.findall(r"<!--(.*?)-->", base_resp.text, _re.DOTALL)
        sensitive_words = ["password", "secret", "token", "key", "admin", "todo: remove"]
        for c in comments:
            if any(w in c.lower() for w in sensitive_words):
                findings.append(f"Suspicious HTML comment: <!--{c[:80].strip()}-->")
                break

        # Autocomplete on forms
        if 'autocomplete="off"' not in base_resp.text.lower() and 'type="password"' in base_resp.text.lower():
            findings.append("Password field may not have autocomplete=off")

        # PII patterns in API response
        pii_patterns = [r"\b\d{16}\b", r"\b\d{3}-\d{2}-\d{4}\b"]  # card, SSN
        for pattern in pii_patterns:
            if _re.search(pattern, base_resp.text):
                findings.append("Possible PII pattern (card number / SSN) found in response")
                break

        if findings:
            return {"status": "success", "severity": "high", "summary": "; ".join(findings)}
        return {"status": "passed", "severity": None,
                "summary": "No obvious sensitive data exposure detected"}

    # ── Logging & Monitoring ──────────────────────────────────────────────────
    if vuln_type == "logging_monitoring":
        findings = []

        # Check for exposed log endpoints
        for lp in LOG_PATHS:
            r = await _get(client, f"{base_url}{lp}", timeout=5)
            if r and r.status_code == 200 and len(r.text) > 20:
                findings.append(f"Log/debug endpoint accessible: {lp} (HTTP {r.status_code})")
                break

        # Check verbose error messages by triggering a 404/500
        err_resp = await _get(client, f"{base_url}/THIS_DOES_NOT_EXIST_9z9z")
        if err_resp:
            stack_indicators = ["traceback", "exception", "at line", "stack trace",
                                 "file \"/", "django.core", "werkzeug", "spring"]
            if any(ind in err_resp.text.lower() for ind in stack_indicators):
                findings.append("Verbose stack trace returned in error response — internal paths/versions exposed")

        # Spring Boot Actuator check
        actuator_resp = await _get(client, f"{base_url}/actuator", timeout=5)
        if actuator_resp and actuator_resp.status_code == 200:
            findings.append("/actuator endpoint exposed — Spring Boot management endpoints accessible")

        if not findings:
            return {"status": "passed", "severity": None,
                    "summary": "No exposed log endpoints detected — review server-side logging configuration manually"}
        return {"status": "success", "severity": "high", "summary": "; ".join(findings)}

    # ── Supply Chain ──────────────────────────────────────────────────────────
    if vuln_type == "supply_chain":
        findings = []
        import re as _re

        # Check for external scripts without SRI
        scripts = _re.findall(r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>', base_resp.text, _re.I)
        for s in scripts:
            if s.startswith("http") and "integrity=" not in base_resp.text[max(0, base_resp.text.find(s)-20):base_resp.text.find(s)+200]:
                findings.append(f"External script without SRI: {s[:80]}")
                break

        # Check for CDN links without integrity
        links = _re.findall(r'<link[^>]+href=["\']([^"\']+)["\'][^>]*>', base_resp.text, _re.I)
        for lk in links:
            if ("cdn" in lk or lk.startswith("https://fonts") or "cloudflare" in lk) and "integrity=" not in base_resp.text[max(0, base_resp.text.find(lk)-20):base_resp.text.find(lk)+200]:
                findings.append(f"External CSS/font without SRI: {lk[:80]}")
                break

        # Check for known vulnerable JS library patterns in page
        vuln_libs = ["jquery/1.", "jquery/2.0", "angular.js/1.0", "angular.js/1.1",
                     "bootstrap/3.0", "lodash/4.0.0"]
        for lib in vuln_libs:
            if lib in body:
                findings.append(f"Potentially outdated JavaScript library detected: {lib}")

        if not findings:
            return {"status": "passed", "severity": None,
                    "summary": "No obvious supply chain issues in page — review npm audit and pip-audit separately"}
        return {"status": "success", "severity": "medium", "summary": "; ".join(findings)}

    # ── Cryptographic Failures ────────────────────────────────────────────────
    if vuln_type == "cryptographic_failure":
        findings = []

        if not target_url.startswith("https://"):
            findings.append("No HTTPS — data transmitted in plaintext")

        hsts = h.get("strict-transport-security", "")
        if not hsts:
            findings.append("HSTS missing — no HTTPS enforcement via browser")
        elif "includesubdomains" not in hsts.lower():
            findings.append("HSTS missing includeSubDomains — subdomains can be intercepted")
        elif "preload" not in hsts.lower():
            findings.append("HSTS missing preload directive")

        # Check for weak cipher/TLS via protocol version header hints
        if h.get("x-tls-version") and "1.0" in h.get("x-tls-version", ""):
            findings.append("TLS 1.0 in use (X-TLS-Version header)")

        # JWT alg:none in responses
        import re as _re
        jwt_pattern = _re.findall(r'eyJ[A-Za-z0-9+/=]+\.eyJ[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]*', base_resp.text)
        if jwt_pattern:
            import base64, json as _json
            for tok in jwt_pattern[:2]:
                try:
                    header = _json.loads(base64.b64decode(tok.split(".")[0] + "==").decode())
                    if header.get("alg", "").lower() in ("none", "hs256"):
                        findings.append(f"JWT found in response with alg:{header.get('alg')} — check for alg:none acceptance")
                        break
                except Exception:
                    pass

        # Certificate check (basic)
        try:
            import ssl, socket
            host = target_url.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(5)
                s.connect((host, 443))
        except ssl.SSLCertVerificationError as e:
            findings.append(f"SSL certificate issue: {str(e)[:80]}")
        except Exception:
            pass

        if findings:
            return {"status": "success", "severity": "high", "summary": "; ".join(findings)}
        return {"status": "passed", "severity": None,
                "summary": "TLS and certificate appear correctly configured"}

    # ── Insecure Design ───────────────────────────────────────────────────────
    if vuln_type == "insecure_design":
        findings = []

        # IDOR patterns in page source
        idor_patterns = ["/api/user/", "/api/account/", "/api/profile/", "/api/order/",
                         "/api/file/", "/api/document/", "/users/", "/account/"]
        for p in idor_patterns:
            if p in base_resp.text:
                findings.append(f"Object reference pattern detected in page: {p} — test for IDOR")
                break

        # Try sequential ID access
        for path in ["/api/users/1", "/api/user/1", "/api/profile/1", "/api/orders/1"]:
            r = await _get(client, f"{base_url}{path}", timeout=6)
            if r and r.status_code == 200 and len(r.text) > 10:
                findings.append(f"Object accessible without auth check: {path} → HTTP {r.status_code}")
                break

        # Mass assignment indicator — check for role in API response body
        if '"role"' in base_resp.text or "'role'" in base_resp.text:
            findings.append("'role' field exposed in API response — test for mass assignment via PATCH")

        # Admin path accessible
        for ap in ["/admin", "/admin/", "/admin/users", "/api/admin"]:
            r = await _get(client, f"{base_url}{ap}", timeout=5)
            if r and r.status_code == 200:
                findings.append(f"Admin path accessible without role check: {ap}")
                break

        if findings:
            severity = "high" if any("IDOR" in f or "accessible" in f or "mass" in f for f in findings) else "medium"
            return {"status": "success", "severity": severity, "summary": "; ".join(findings)}
        return {"status": "passed", "severity": None,
                "summary": "No obvious IDOR or insecure design patterns found — manual review recommended"}

    # ── Exceptional Conditions ────────────────────────────────────────────────
    if vuln_type == "exceptional_conditions":
        findings = []

        # Malformed request probe
        malformed_resp = await _get(client, f"{base_url}/%00<invalid>", timeout=8)
        if malformed_resp and malformed_resp.status_code == 500:
            findings.append("Server returns 500 on malformed input — error handling may expose internals")
            if any(ind in malformed_resp.text.lower() for ind in ["traceback", "exception", "at line"]):
                findings.append("Stack trace returned in 500 response — internal paths exposed")

        # Open redirect check
        redirect_resp = await _get(client, f"{base_url}/?redirect=http://evil.com&next=http://evil.com&url=http://evil.com", timeout=8)
        if redirect_resp and redirect_resp.status_code in (301, 302, 303, 307, 308):
            loc = redirect_resp.headers.get("location", "")
            if "evil.com" in loc:
                findings.append(f"Open redirect confirmed: ?redirect= → {loc}")

        # Path traversal in static files
        traversal_resp = await _get(client, f"{base_url}/static/../../../../etc/passwd", timeout=8)
        if traversal_resp and "root:" in traversal_resp.text:
            findings.append("Path traversal via /static/ returns /etc/passwd — critical misconfiguration")

        if findings:
            severity = "high" if any("confirmed" in f or "returns" in f or "Stack" in f for f in findings) else "medium"
            return {"status": "success", "severity": severity, "summary": "; ".join(findings)}
        return {"status": "passed", "severity": None,
                "summary": "No obvious exceptional condition vulnerabilities detected — SSRF/redirect/traversal probes passed"}

    # ── Underprotected APIs ───────────────────────────────────────────────────
    if vuln_type == "underprotected_apis":
        findings = []

        # Check common API/doc paths
        exposed = []
        for path in API_DOC_PATHS:
            r = await _get(client, f"{base_url}{path}", timeout=5)
            if r and r.status_code < 400 and len(r.text) > 20:
                exposed.append(f"{path} (HTTP {r.status_code})")

        if exposed:
            findings.append(f"Exposed API/docs endpoints: {', '.join(exposed)}")

        # GraphQL introspection
        gql_resp = None
        try:
            gql_resp = await client.post(f"{base_url}/graphql",
                json={"query": "{__schema{types{name}}}"},
                timeout=8)
        except httpx.RequestError:
            pass
        if gql_resp and gql_resp.status_code == 200 and "__schema" in gql_resp.text:
            findings.append("GraphQL introspection enabled — full schema exposed")

        # Rate limiting check
        rate_headers_present = any(
            h_key in h for h_key in ["x-ratelimit-limit", "x-rate-limit-limit", "retry-after"]
        )
        if not rate_headers_present:
            findings.append("No rate limiting headers (X-RateLimit-*) detected on API")

        # Check for unauthenticated admin-ish endpoints
        for path in ["/api/admin/users", "/api/users", "/api/admin", "/api/v1/users"]:
            r = await _get(client, f"{base_url}{path}", timeout=6)
            if r and r.status_code == 200 and len(r.text) > 10:
                findings.append(f"Endpoint accessible without auth: {path} → HTTP {r.status_code}")
                break

        # Check for API key in URL patterns
        import re as _re
        api_key_pattern = _re.findall(r'[?&]api[_-]?key=([^&\s"\']{6,})', base_resp.text, _re.I)
        if api_key_pattern:
            findings.append("API key exposed in URL parameter in page source")

        if findings:
            return {"status": "success", "severity": "high", "summary": "; ".join(findings)}
        return {"status": "passed", "severity": None,
                "summary": "No obviously exposed API endpoints found"}

    # Fallback
    return {"status": "passed", "severity": None,
            "summary": "Scan completed — no obvious indicators found"}


async def run_scan(session_id: int, target_url: str, auth_info: dict | None, difficulty: str = "beginner") -> None:
    """Background task: iterate all vuln types, run AI + probe, persist results."""
    _session_start = _time.time()
    async with AsyncSessionLocal() as db:
        await db.execute(
            update(ScanSession).where(ScanSession.id == session_id).values(status="running")
        )
        await db.commit()

        # Reachability pre-check
        reachable = True
        try:
            async with httpx.AsyncClient(verify=False) as test_client:
                await test_client.get(target_url, timeout=8, follow_redirects=True)
        except httpx.RequestError:
            reachable = False

        async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
            for vuln_type in VULN_TYPES:
                result_row = await _get_or_create_result(db, session_id, vuln_type)

                if not reachable:
                    result_row.status = "failed"
                    result_row.findings = {"summary": "Target URL not reachable. Check URL and try again."}
                    result_row.severity = None
                    await db.commit()
                    continue

                # Generate AI scenario
                scenario_data: dict = {}
                try:
                    scenario_data = await generate_scenario(
                        vuln_type, difficulty,
                        session_id=session_id, target_url=target_url
                    )
                    from models.scenario import Scenario as ScenarioModel
                    sc = ScenarioModel(
                        vuln_type=vuln_type,
                        title=scenario_data.get("title"),
                        steps=scenario_data.get("steps"),
                        payloads=scenario_data.get("payloads"),
                        cvss_score=scenario_data.get("risk", {}).get("cvss_score"),
                    )
                    db.add(sc)
                    await db.flush()
                    result_row.scenario_id = sc.id
                except Exception as exc:
                    logger.warning("Scenario generation failed for %s: %s", vuln_type, exc)

                # HTTP probe (generic)
                _probe_start = _time.time()
                probe = await probe_target(client, target_url, vuln_type, auth_info)

                # Juice Shop-specific probe sequences (ADD — never remove generic probe above)
                from services.juice_shop_probes import run_juice_shop_scenarios, merge_probe_with_scenarios
                js_scenarios = await run_juice_shop_scenarios(client, target_url, vuln_type, auth_info)
                probe = merge_probe_with_scenarios(probe, js_scenarios)

                result_row.status = probe.get("status", "failed")
                result_row.severity = probe.get("severity")  # None for passed/failed/needs_info
                result_row.missing_info = probe.get("missing_info")
                result_row.findings = {
                    "summary": probe.get("summary", ""),
                    "detail": probe.get("detail", ""),
                    "scenario": {
                        "title": scenario_data.get("title", ""),
                        "description": scenario_data.get("description", ""),
                        "defense_tips": scenario_data.get("defense_tips", []),
                        "risk": scenario_data.get("risk", {}),
                    },
                    # Juice Shop scenario results (populated when target is Juice Shop)
                    "scenario_results":    probe.get("findings", {}).get("scenario_results", []),
                    "confirmed_scenarios": probe.get("findings", {}).get("confirmed_scenarios", []),
                    "tested_scenarios":    probe.get("findings", {}).get("tested_scenarios", 0),
                }
                result_row.reproduce_steps = generate_reproduce_steps(
                    vuln_type, target_url, probe.get("summary", "")
                )
                await db.commit()

                # ELK: log per-vuln result
                _probe_ms = int((_time.time() - _probe_start) * 1000)
                findings_obj = result_row.findings or {}
                elk.log_scan_result(
                    session_id=session_id,
                    vuln_type=vuln_type,
                    status=result_row.status,
                    severity=result_row.severity,
                    finding_summary=findings_obj.get("summary", ""),
                    scenarios_tested=findings_obj.get("tested_scenarios", 0),
                    scenarios_confirmed=len(findings_obj.get("confirmed_scenarios", [])),
                    total_duration_ms=_probe_ms,
                )

                # ELK: log each Juice Shop probe result individually
                for sc in findings_obj.get("scenario_results", []):
                    elk.log_probe_result(
                        session_id=session_id,
                        vuln_type=vuln_type,
                        scenario_name=sc.get("name", ""),
                        method=sc.get("request", {}).get("method", "GET"),
                        url=sc.get("request", {}).get("url", ""),
                        status_code=0,
                        confirmed=bool(sc.get("confirmed")),
                        evidence=sc.get("evidence", ""),
                        duration_ms=0,
                    )

        await db.execute(
            update(ScanSession).where(ScanSession.id == session_id).values(
                status="completed",
                completed_at=datetime.now(timezone.utc),
            )
        )
        await db.commit()

        # ELK: log session completion summary
        from sqlalchemy import select as _select
        all_results = (await db.execute(
            _select(ScanResult).where(ScanResult.session_id == session_id)
        )).scalars().all()
        n_vuln = sum(1 for r in all_results if r.status == "success" and r.severity)
        sev_rank = ["critical", "high", "medium", "low"]
        highest = next(
            (s for s in sev_rank if any(r.severity == s for r in all_results)), None
        )
        elk.log_session_complete(
            session_id=session_id,
            target_url=target_url,
            total_checks=len(all_results),
            vulnerabilities_found=n_vuln,
            highest_severity=highest,
            total_duration_ms=int((_time.time() - _session_start) * 1000),
        )


async def _get_or_create_result(db: AsyncSession, session_id: int, vuln_type: str) -> ScanResult:
    from sqlalchemy import select
    row = (await db.execute(
        select(ScanResult).where(
            ScanResult.session_id == session_id,
            ScanResult.vuln_type == vuln_type,
        )
    )).scalars().first()
    if not row:
        row = ScanResult(session_id=session_id, vuln_type=vuln_type, status="scanning")
        db.add(row)
        await db.flush()
    return row
