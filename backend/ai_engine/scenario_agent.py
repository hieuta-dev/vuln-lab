# FILE: backend/ai_engine/scenario_agent.py
# PURPOSE: Public entry-point for scenario generation — delegates to the configured provider
# SECURITY NOTE: No SDK imported here; all provider details encapsulated in providers/

import time
from typing import Any

from .providers.factory import get_provider
from .fallback_content import (
    FALLBACK_CODE, PLACEHOLDER_STRINGS, _PLACEHOLDER_SET,
    get_fallback_payloads, is_placeholder,
)
from services.elk_logger import elk


def validate_scenario_content(data: dict, vuln_type: str) -> dict:
    """
    Validate and enrich AI-generated scenario content.
    Replaces placeholder strings with real content from fallback_content.py.
    """
    # ── Fix placeholder payloads ──────────────────────────────────────────────
    real_payloads = get_fallback_payloads(vuln_type)
    new_payloads: list[dict] = []
    for i, p in enumerate(data.get("payloads", [])):
        payload_str = p.get("payload", "")
        if is_placeholder(payload_str):
            if i < len(real_payloads):
                rp = real_payloads[i]
                p = {
                    "payload":          rp["payload"],
                    "description":      rp.get("description", p.get("description", "")),
                    "expected_outcome": rp.get("expected", p.get("expected_outcome", "")),
                }
        new_payloads.append(p)
    if new_payloads:
        data["payloads"] = new_payloads

    # ── Fix placeholder code examples ─────────────────────────────────────────
    code = data.get("code_examples", {})
    vuln_code   = code.get("vulnerable", "")
    secure_code = code.get("secure", "")
    fallback    = FALLBACK_CODE.get(vuln_type, {})

    if fallback:
        needs_vuln_fix   = is_placeholder(vuln_code) or len(vuln_code.strip()) < 50
        needs_secure_fix = is_placeholder(secure_code) or len(secure_code.strip()) < 50
        if needs_vuln_fix or needs_secure_fix:
            data["code_examples"] = {
                "vulnerable": fallback.get("vulnerable", vuln_code) if needs_vuln_fix   else vuln_code,
                "secure":     fallback.get("secure",     secure_code) if needs_secure_fix else secure_code,
            }

    # ── Clear placeholder step payloads (hide rather than show garbage) ───────
    for step in data.get("steps", []):
        if is_placeholder(step.get("payload", "")):
            step["payload"] = ""

    return data


async def generate_scenario(
    vuln_type: str,
    difficulty: str = "beginner",
    session_id: int = 0,
    target_url: str = "",
) -> dict[str, Any]:
    """
    Generate a structured attack scenario using the configured LLM provider.

    - target_url: when provided, the provider uses full scan mode (6 tools) with SYSTEM_SCAN_PROMPT.
      When empty, uses legacy 3-tool mode for the scenario lab.
    - session_id: used for ELK correlation across the full scan session.
    """
    provider = get_provider()
    start = time.time()

    result = await provider.run_agent_loop(
        vuln_type=vuln_type,
        difficulty=difficulty,
        target_url=target_url,
        session_id=session_id,
    )

    # Validate and enrich — replace any placeholders with real content
    result = validate_scenario_content(result, vuln_type)

    duration_ms = int((time.time() - start) * 1000)

    elk.log_agent_step(
        session_id=session_id,
        vuln_type=vuln_type,
        step_number=1,
        tool_name="generate_scenario",
        tool_input={"vuln_type": vuln_type, "difficulty": difficulty, "target_url": target_url},
        tool_output={
            "success": bool(result.get("title")),
            "result_summary": str(result.get("title", ""))[:200],
        },
        duration_ms=duration_ms,
    )

    return result
