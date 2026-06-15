# FILE: backend/ai_engine/tools/inject_probe.py
# PURPOSE: Safe injection probe — sends canary/read-only payloads, checks for reflection
# SECURITY NOTE: Only safe canary payloads used; NO destructive SQL, shellcode, or RCE attempts

import re
import httpx

TOOL_SPEC = {
    "name": "inject_probe",
    "description": (
        "Sends a safe test payload to a specific parameter and checks if it appears "
        "unescaped in the response. Detects XSS reflection, SQLi errors, and SSTI.\n\n"
        "WHEN TO CALL: Only after http_probe confirms has_inputs=true OR a known "
        "injection endpoint exists. Do NOT call on static pages.\n\n"
        "DECISION LOGIC:\n"
        "- reflected=true AND escaped=false → XSS HIGH confirmed\n"
        "- reflected=true AND escaped=true → XSS mitigated, note in findings\n"
        "- has_sql_error=true → SQLi HIGH (check error message for DB type)\n"
        "- ssti_confirmed=true → SSTI CRITICAL (server-side template injection)\n"
        "- response_status=500 with has_stack_trace=true → injection caused server error\n"
        "- nothing triggered → passed for this payload\n\n"
        "SAFE PAYLOADS ONLY — use probe_type to select:\n"
        "- xss: <b>VULNTEST_XSS</b> (visible canary, not <script>)\n"
        "- sqli: ' OR '1'='1 (read-only comparison, no DROP/INSERT)\n"
        "- ssti: {{7*7}} (check if 49 appears in response)\n"
        "- custom: provide your own safe canary in the payload field"
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": (
                    "Full URL of the endpoint to probe. "
                    "Example: http://juice-shop:3000/rest/products/search. "
                    "MUST be the scan target URL, never a documentation URL."
                ),
            },
            "parameter": {
                "type": "string",
                "description": "Query parameter or body field name to inject into. Example: 'q', 'email', 'username'.",
            },
            "method": {
                "type": "string",
                "enum": ["GET", "POST"],
                "description": "HTTP method. GET injects via query param, POST injects via JSON body.",
            },
            "probe_type": {
                "type": "string",
                "enum": ["xss", "sqli", "ssti", "custom"],
                "description": "Vulnerability type to probe — determines safe payload selection.",
            },
            "payload": {
                "type": "string",
                "description": (
                    "Custom safe canary payload (only for probe_type=custom). "
                    "Must be read-only and non-destructive."
                ),
            },
        },
        "required": ["url", "parameter", "probe_type"],
    },
}

# Safe canary payloads only — never destructive
SAFE_PAYLOADS: dict[str, str] = {
    "xss":    "<b>VULNTEST_XSS_7x9z</b>",
    "sqli":   "' OR '1'='1'--",
    "ssti":   "{{7*7}}",
    "custom": "<b>VULNTEST_ABC123</b>",
}


async def execute(input: dict) -> dict:
    url = input.get("url", "")
    parameter = input.get("parameter", "q")
    method = input.get("method", "GET").upper()
    probe_type = input.get("probe_type", "custom")
    payload = input.get("payload") or SAFE_PAYLOADS.get(probe_type, SAFE_PAYLOADS["custom"])

    if not url:
        return {"error": "url is required", "reflected": False}

    async with httpx.AsyncClient(verify=False, timeout=10.0, follow_redirects=True) as client:
        try:
            if method == "POST":
                resp = await client.post(url, json={parameter: payload})
            else:
                resp = await client.get(url, params={parameter: payload})
        except httpx.RequestError as exc:
            return {"error": str(exc), "reflected": False, "url": url, "payload": payload}

    body = resp.text
    body_lower = body.lower()

    # Reflection check
    reflected = payload in body
    escaped_payload = payload.replace("<", "&lt;").replace(">", "&gt;")
    escaped = escaped_payload in body if "<" in payload else False

    # SQL error patterns
    sql_error_patterns = [
        "sql syntax", "you have an error in your sql", "ora-",
        "sqlite3", "syntax error near", "unclosed quotation",
        "mysql_fetch", "pg::", "sqlexception",
    ]
    has_sql_error = any(p in body_lower for p in sql_error_patterns)

    # SSTI check ({{7*7}} → 49 in response)
    ssti_confirmed = "49" in body if probe_type == "ssti" else False

    # Stack trace
    has_stack_trace = any(ind in body_lower for ind in
                          ["traceback", "stack trace", "exception at", "at line"])

    return {
        "url": url,
        "parameter": parameter,
        "probe_type": probe_type,
        "payload": payload,
        "response_status": resp.status_code,
        "reflected": reflected,
        "escaped": escaped,
        "xss_confirmed": reflected and not escaped and probe_type == "xss",
        "has_sql_error": has_sql_error,
        "ssti_confirmed": ssti_confirmed,
        "has_stack_trace": has_stack_trace,
        "body_snippet": body[:500],
    }
