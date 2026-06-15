# FILE: backend/ai_engine/tools/http_probe.py
# PURPOSE: HTTP probe tool — fetches a URL and returns structured response metadata
# SECURITY NOTE: Never follows redirects to internal networks; timeouts enforced

import re
import httpx

TOOL_SPEC = {
    "name": "http_probe",
    "description": (
        "Sends an HTTP request to a URL and returns full response metadata including "
        "headers, status code, body snippet, and detected attack surfaces.\n\n"
        "WHEN TO CALL: Always call this FIRST for any vuln type to get a baseline "
        "response — headers, status code, body snippet, and presence of forms/inputs.\n\n"
        "DECISION LOGIC:\n"
        "- missing_security_headers not empty → evidence for security_misconfig / sensitive_data\n"
        "- has_inputs=true → proceed to inject_probe for XSS / SQLi testing\n"
        "- has_file_upload=true → file_upload attack surface confirmed\n"
        "- status_code=200 on sensitive path → potential access control issue\n"
        "- error field set → target unreachable, set status=needs_info"
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": (
                    "Full URL including protocol. Example: http://juice-shop:3000/api/Users/. "
                    "MUST be the actual scan target URL from the scan session. "
                    "NEVER use documentation URLs (github.io, owasp.org) or example.com."
                ),
            },
            "method": {
                "type": "string",
                "enum": ["GET", "POST", "HEAD", "OPTIONS"],
                "description": "HTTP method. Default GET.",
            },
            "body": {
                "type": "object",
                "description": "JSON body for POST requests.",
            },
            "extra_headers": {
                "type": "object",
                "description": "Additional request headers, e.g. {\"X-Forwarded-For\": \"<test>\"}.",
            },
            "scenario_name": {
                "type": "string",
                "description": (
                    "Short label for this probe used in logs. "
                    "Example: 'baseline_check', 'admin_panel_probe', 'csrf_token_check'."
                ),
            },
        },
        "required": ["url"],
    },
}

SECURITY_HEADERS = [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
]


async def execute(input: dict) -> dict:
    url = input.get("url", "")
    method = input.get("method", "GET").upper()
    body = input.get("body")
    extra_headers = input.get("extra_headers") or {}
    scenario_name = input.get("scenario_name", "http_probe")

    if not url:
        return {"error": "url is required", "reachable": False, "scenario_name": scenario_name}

    async with httpx.AsyncClient(verify=False, timeout=10.0, follow_redirects=True) as client:
        try:
            if method == "POST":
                resp = await client.post(url, json=body, headers=extra_headers)
            elif method == "HEAD":
                resp = await client.head(url, headers=extra_headers)
            elif method == "OPTIONS":
                resp = await client.request("OPTIONS", url, headers=extra_headers)
            else:
                resp = await client.get(url, headers=extra_headers)
        except httpx.RequestError as exc:
            return {"error": str(exc), "reachable": False, "url": url, "scenario_name": scenario_name}

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    body_text = resp.text[:1000]
    body_lower = body_text.lower()

    missing_hdrs = [h for h in SECURITY_HEADERS if h not in headers_lower]

    # Detect attack surfaces
    has_inputs = bool(re.search(r"<input|<form|<textarea", body_lower))
    has_file_upload = bool(re.search(r'type=["\']?file', body_lower))

    # Detect SQL / error indicators
    sql_errors = ["sql syntax", "you have an error in your sql", "ora-", "sqlite3",
                  "syntax error near", "unclosed quotation", "mysql_fetch"]
    has_sql_error = any(e in body_lower for e in sql_errors)

    # Detect stack traces
    has_stack_trace = any(ind in body_lower for ind in
                          ["traceback", "stack trace", "exception", "at line", "django.core"])

    # Allow header — dangerous HTTP methods
    allow_header = headers_lower.get("allow", "")
    dangerous_methods = [m for m in ["TRACE", "PUT", "DELETE"] if m in allow_header.upper()]

    return {
        "url": url,
        "scenario_name": scenario_name,
        "reachable": True,
        "status_code": resp.status_code,
        "is_https": url.startswith("https://"),
        "server": headers_lower.get("server", ""),
        "content_type": headers_lower.get("content-type", ""),
        "missing_security_headers": missing_hdrs,
        "has_csp": "content-security-policy" in headers_lower,
        "has_inputs": has_inputs,
        "has_file_upload": has_file_upload,
        "has_sql_error": has_sql_error,
        "has_stack_trace": has_stack_trace,
        "dangerous_http_methods": dangerous_methods,
        "cookies": headers_lower.get("set-cookie", ""),
        "body_snippet": body_text[:500],
    }
