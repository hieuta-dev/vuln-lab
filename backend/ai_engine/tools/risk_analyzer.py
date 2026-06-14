# FILE: backend/ai_engine/tools/risk_analyzer.py
# PURPOSE: CVSS-style risk scoring for the AI scenario agent
# SECURITY NOTE: Scores are educational approximations, not certified CVSS calculations

TOOL_SPEC = {
    "name": "analyze_risk",
    "description": (
        "Calculate a CVSS-style risk score and structured risk analysis "
        "for a vulnerability in context."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "vuln_type": {"type": "string"},
            "attack_vector": {
                "type": "string",
                "enum": ["network", "adjacent", "local", "physical"]
            },
            "authentication_required": {"type": "boolean"},
            "data_exposed": {
                "type": "array",
                "items": {"type": "string"},
                "description": "e.g. ['credentials', 'PII', 'session tokens', 'source code']"
            }
        },
        "required": ["vuln_type", "attack_vector"]
    }
}

BASE_SCORES = {
    "sql_injection":           {"score": 9.8, "severity": "Critical"},
    "xss":                     {"score": 7.4, "severity": "High"},
    "csrf":                    {"score": 6.5, "severity": "Medium"},
    "file_upload":             {"score": 9.0, "severity": "Critical"},
    "broken_auth":             {"score": 8.8, "severity": "High"},
    "security_misconfig":      {"score": 7.5, "severity": "High"},
    "sensitive_data_exposure": {"score": 7.5, "severity": "High"},
    "logging_monitoring":      {"score": 4.0, "severity": "Medium"},
    "supply_chain":            {"score": 9.0, "severity": "Critical"},
    "cryptographic_failure":   {"score": 7.5, "severity": "High"},
    "insecure_design":         {"score": 8.0, "severity": "High"},
    "exceptional_conditions":  {"score": 5.5, "severity": "Medium"},
    "underprotected_apis":     {"score": 8.6, "severity": "High"},
}

OWASP_MAPPING = {
    "sql_injection":           "A03:2021 – Injection",
    "xss":                     "A03:2021 – Injection (XSS)",
    "csrf":                    "A01:2021 – Broken Access Control",
    "file_upload":             "A04:2021 – Insecure Design / A08 – Security Failures",
    "broken_auth":             "A07:2021 – Identification and Authentication Failures",
    "security_misconfig":      "A05:2021 – Security Misconfiguration",
    "sensitive_data_exposure": "A02:2021 – Cryptographic Failures",
    "logging_monitoring":      "A09:2021 – Security Logging and Monitoring Failures",
    "supply_chain":            "A06:2021 – Vulnerable and Outdated Components",
    "cryptographic_failure":   "A02:2021 – Cryptographic Failures",
    "insecure_design":         "A04:2021 – Insecure Design",
    "exceptional_conditions":  "A04:2021 – Insecure Design",
    "underprotected_apis":     "A01:2021 – Broken Access Control",
}


async def execute(input: dict) -> dict:
    vuln_type = input["vuln_type"]
    attack_vector = input.get("attack_vector", "network")
    auth_required = input.get("authentication_required", False)
    data_exposed = input.get("data_exposed", [])

    base = BASE_SCORES.get(vuln_type, {"score": 5.0, "severity": "Medium"})
    score = base["score"]
    if auth_required:
        score = max(score - 1.5, 0)
    if attack_vector != "network":
        score = max(score - 1.0, 0)

    return {
        "cvss_score": round(score, 1),
        "severity": base["severity"],
        "owasp_category": OWASP_MAPPING.get(vuln_type, "OWASP Top 10"),
        "attack_vector": attack_vector,
        "authentication_required": auth_required,
        "data_at_risk": data_exposed,
        "impact_summary": (
            f"Exploiting {vuln_type.replace('_', ' ').title()} via {attack_vector} vector "
            f"can expose: {', '.join(data_exposed) if data_exposed else 'system integrity'}. "
            f"CVSS base score: {round(score, 1)} ({base['severity']})."
        )
    }
