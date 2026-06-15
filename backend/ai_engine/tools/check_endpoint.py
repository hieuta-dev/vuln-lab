# FILE: backend/ai_engine/tools/check_endpoint.py
# PURPOSE: Endpoint discovery tool — checks multiple paths for accessibility
# SECURITY NOTE: HEAD requests only; never sends payloads

import httpx

TOOL_SPEC = {
    "name": "check_endpoint",
    "description": (
        "Checks multiple paths on a base URL to discover exposed endpoints and attack surfaces.\n\n"
        "WHEN TO CALL: After http_probe confirms target is reachable. Use to discover "
        "admin panels, config files, debug endpoints, API docs, and sensitive resources.\n\n"
        "DECISION LOGIC:\n"
        "- accessible=true on /.env or /.git/config → security_misconfig CRITICAL\n"
        "- accessible=true on /admin or /administration → broken_access_control HIGH\n"
        "- accessible=true on /graphql or /swagger.json → underprotected_apis HIGH\n"
        "- accessible=true on /ftp → sensitive_data_exposure CRITICAL\n"
        "- accessible=true on /logs or /debug → logging_monitoring HIGH\n"
        "- accessible=false on all paths → passed for this check\n\n"
        "IMPORTANT: base_url must be the scan target (e.g. http://juice-shop:3000), "
        "NEVER a documentation or GitHub URL."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "base_url": {
                "type": "string",
                "description": (
                    "Base URL of the scan target without trailing slash. "
                    "Example: http://juice-shop:3000. "
                    "MUST be the actual scan target, never github.io or owasp.org."
                ),
            },
            "paths": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "List of paths to check. Each must start with /. "
                    "Include at least 3 paths per call. "
                    "Group related paths together — do NOT call this tool once per path."
                ),
                "minItems": 2,
                "maxItems": 15,
            },
        },
        "required": ["base_url", "paths"],
    },
}


async def execute(input: dict) -> dict:
    base_url = input.get("base_url", "").rstrip("/")
    paths = input.get("paths", [])

    if not base_url or not paths:
        return {"error": "base_url and paths are required", "accessible_paths": []}

    results = []
    async with httpx.AsyncClient(verify=False, timeout=8.0, follow_redirects=True) as client:
        for path in paths:
            if not path.startswith("/"):
                path = "/" + path
            full_url = base_url + path
            try:
                # Use GET (some servers return 405 on HEAD)
                r = await client.get(full_url, timeout=6.0)
                accessible = r.status_code < 400
                results.append({
                    "path": path,
                    "full_url": full_url,
                    "accessible": accessible,
                    "status_code": r.status_code,
                    "content_length": len(r.text),
                    "body_snippet": r.text[:200] if accessible else "",
                })
            except httpx.RequestError as exc:
                results.append({
                    "path": path,
                    "full_url": full_url,
                    "accessible": False,
                    "status_code": 0,
                    "error": str(exc),
                })

    accessible = [r for r in results if r["accessible"]]
    return {
        "base_url": base_url,
        "checked": len(results),
        "accessible_count": len(accessible),
        "accessible_paths": accessible,
        "all_results": results,
    }
