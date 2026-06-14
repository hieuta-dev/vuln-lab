# FILE: backend/ai_engine/providers/ollama_provider.py
# PURPOSE: Ollama local LLM provider — single-shot mode (skips tool-use; llama3.2 is unreliable with tools)
# SECURITY NOTE: No external API key; all data stays local on OLLAMA_BASE_URL

import json
import logging
import re
from typing import Any

from openai import AsyncOpenAI

from .base import BaseProvider, ProviderResponse, ToolCall
from ..tools.payload_generator import execute as run_payloads
from ..tools.scenario_builder import execute as run_steps
from ..tools.risk_analyzer import execute as run_risk

logger = logging.getLogger(__name__)

# ── Prompt templates ──────────────────────────────────────────────────────────

SYSTEM_PROMPT = (
    "You are a cybersecurity expert. Return ONLY a valid JSON object. "
    "No markdown, no explanation, no code fences. Just the raw JSON object. "
    "If you cannot complete the full JSON, return a minimal valid JSON."
)

USER_PROMPT_TEMPLATE = """\
Generate a security lab scenario for vulnerability type "{vuln_type}" at "{difficulty}" level.

Use these pre-computed payloads and risk data:
PAYLOADS: {payloads_json}
RISK: {risk_json}

Return EXACTLY this JSON structure (all fields required):
{{
  "title": "short descriptive title",
  "vuln_type": "{vuln_type}",
  "description": "2-3 sentence description of the vulnerability and why it matters",
  "difficulty": "{difficulty}",
  "steps": [
    {{
      "step": 1,
      "phase": "Reconnaissance",
      "title": "Identify the target",
      "description": "what to observe or do",
      "payload": "example payload string"
    }},
    {{
      "step": 2,
      "phase": "Exploit",
      "title": "Inject the payload",
      "description": "how to exploit",
      "payload": "exploit payload"
    }},
    {{
      "step": 3,
      "phase": "Defense",
      "title": "Switch to Secure Mode",
      "description": "toggle security mode and observe it is blocked",
      "payload": ""
    }}
  ],
  "payloads": [
    {{"payload": "payload string", "description": "what it does", "expected_outcome": "what happens"}}
  ],
  "risk": {{
    "cvss_score": 7.5,
    "severity": "High",
    "owasp_category": "A03:2021 - Injection",
    "impact_summary": "brief impact description"
  }},
  "defense_tips": ["tip 1", "tip 2", "tip 3"],
  "code_examples": {{
    "vulnerable": "# vulnerable code example",
    "secure": "# secure code example"
  }}
}}"""

RETRY_PROMPT_TEMPLATE = """\
Return a minimal valid JSON for a {vuln_type} security scenario at {difficulty} level.
Use ONLY these exact keys: title, vuln_type, description, difficulty, steps, payloads, risk, defense_tips, code_examples.
steps must be an array with at least one object having: step, phase, title, description, payload.
payloads must be an array with at least one object having: payload, description, expected_outcome.
risk must have: cvss_score (number), severity (string), owasp_category (string), impact_summary (string).
code_examples must have: vulnerable (string), secure (string).
defense_tips must be an array of strings.
Return ONLY the JSON object, nothing else."""


# ── Robust JSON extractor ─────────────────────────────────────────────────────

def _extract_json_robust(text: str, vuln_type: str = "", difficulty: str = "") -> dict:
    """Five strategies + minimal fallback. Never raises."""

    # Strategy 1: direct parse
    try:
        return json.loads(text.strip())
    except Exception:
        pass

    # Strategy 2: find first { to last }
    try:
        start = text.index("{")
        end   = text.rindex("}") + 1
        return json.loads(text[start:end])
    except Exception:
        pass

    # Strategy 3: strip markdown fences
    try:
        clean = re.sub(r"```(?:json)?", "", text).strip()
        return json.loads(clean)
    except Exception:
        pass

    # Strategy 4: truncation repair — close unclosed braces/brackets
    try:
        start = text.index("{")
        fragment = text[start:]
        opens_brace   = fragment.count("{") - fragment.count("}")
        opens_bracket = fragment.count("[") - fragment.count("]")
        # close any open string first (naive: just try both)
        for suffix in ['"}' * opens_brace, "}" * opens_brace]:
            try:
                repaired = fragment + "]" * max(0, opens_bracket) + suffix
                return json.loads(repaired)
            except Exception:
                pass
    except Exception:
        pass

    # Strategy 5: extract any JSON-looking block with regex
    try:
        blocks = re.findall(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", text, re.DOTALL)
        for block in sorted(blocks, key=len, reverse=True):
            try:
                return json.loads(block)
            except Exception:
                continue
    except Exception:
        pass

    # Strategy 6: minimal valid fallback — never raise
    logger.warning("[OllamaProvider] all JSON extraction strategies failed; returning fallback")
    name = vuln_type.replace("_", " ").title()
    return {
        "title": f"{name} Security Scenario",
        "vuln_type": vuln_type,
        "description": (
            f"{name} is a common web vulnerability that allows attackers to compromise "
            "application security. Understanding this vulnerability helps defenders build "
            "more robust applications."
        ),
        "difficulty": difficulty,
        "steps": [
            {
                "step": 1,
                "phase": "Reconnaissance",
                "title": "Identify the attack surface",
                "description": f"Locate input fields or endpoints susceptible to {name}.",
                "payload": "Manual inspection required",
            },
            {
                "step": 2,
                "phase": "Exploit",
                "title": "Test the vulnerability",
                "description": "Send a crafted payload and observe the response.",
                "payload": "See OWASP documentation for sample payloads",
            },
            {
                "step": 3,
                "phase": "Defense",
                "title": "Apply the fix",
                "description": "Toggle to Secure Mode and verify the same payload is blocked.",
                "payload": "",
            },
        ],
        "payloads": [
            {
                "payload": "Manual testing required",
                "description": f"Payloads for {name}",
                "expected_outcome": "Depends on application behaviour",
            }
        ],
        "risk": {
            "cvss_score": 5.0,
            "severity": "Medium",
            "owasp_category": "OWASP Top 10",
            "impact_summary": f"Exploiting {name} can compromise application integrity.",
        },
        "defense_tips": [
            "Follow OWASP remediation guidelines",
            "Implement input validation and output encoding",
            "Use security headers and Content-Security-Policy",
        ],
        "code_examples": {
            "vulnerable": f"# Vulnerable {name} example — see OWASP docs",
            "secure":     f"# Secure {name} example — see OWASP docs",
        },
    }


# ── Provider class ────────────────────────────────────────────────────────────

class OllamaProvider(BaseProvider):
    def __init__(self, base_url: str, model: str) -> None:
        self._client = AsyncOpenAI(
            base_url=base_url,
            api_key="ollama",
            timeout=120.0,
        )
        self._model = model
        print(f"[OllamaProvider] init: base_url={base_url} model={model}", flush=True)

    # ── BaseProvider abstract methods (satisfy interface; not used in single-shot path) ──

    async def generate(
        self,
        messages: list[dict],
        tools: list[dict],
        system: str,
    ) -> ProviderResponse:
        openai_messages = [{"role": "system", "content": system}] + messages
        response = await self._client.chat.completions.create(
            model=self._model,
            messages=openai_messages,  # type: ignore[arg-type]
            timeout=120.0,
        )
        msg = response.choices[0].message
        return ProviderResponse(
            stop_reason="end_turn",
            text=msg.content,
            tool_calls=[],
            raw=msg,
        )

    def build_assistant_message(self, response: ProviderResponse) -> dict:
        return {"role": "assistant", "content": response.raw.content or ""}

    def build_tool_results_messages(
        self, tool_calls: list[ToolCall], results: list[Any]
    ) -> list[dict]:
        return []

    # ── Main entry point — single-shot, never raises ──────────────────────────

    async def run_agent_loop(
        self, vuln_type: str, difficulty: str = "beginner"
    ) -> dict[str, Any]:
        """
        Skips the tool-use loop entirely (llama3.2 is unreliable with function calling).
        Runs all three tools locally, embeds results in prompt, asks for one JSON response.
        Retries once with a simpler prompt on parse failure. Never raises.
        """
        print(f"[OllamaProvider] single-shot: vuln_type={vuln_type} difficulty={difficulty}", flush=True)

        # ── Gather tool data locally ──────────────────────────────────────────
        try:
            payloads_data = await run_payloads(
                {"vuln_type": vuln_type, "difficulty": difficulty, "context": "demo app"}
            )
        except Exception:
            payloads_data = {"payloads": []}

        try:
            risk_data = await run_risk(
                {"vuln_type": vuln_type, "attack_vector": "network", "data_exposed": ["credentials", "session"]}
            )
        except Exception:
            risk_data = {}

        # ── Attempt 1: full prompt ────────────────────────────────────────────
        user_prompt = USER_PROMPT_TEMPLATE.format(
            vuln_type=vuln_type,
            difficulty=difficulty,
            payloads_json=json.dumps(payloads_data.get("payloads", [])[:3]),
            risk_json=json.dumps(risk_data),
        )

        text1 = await self._call(user_prompt)
        print(f"[OllamaProvider] attempt-1 response ({len(text1)} chars): {text1[:120]!r}", flush=True)

        result = _extract_json_robust(text1, vuln_type, difficulty)
        if _is_valid_scenario(result):
            print("[OllamaProvider] attempt-1 succeeded", flush=True)
            return result

        # ── Attempt 2: simpler retry prompt ──────────────────────────────────
        print("[OllamaProvider] attempt-1 JSON incomplete; retrying with simpler prompt", flush=True)
        retry_prompt = RETRY_PROMPT_TEMPLATE.format(vuln_type=vuln_type, difficulty=difficulty)
        text2 = await self._call(retry_prompt)
        print(f"[OllamaProvider] attempt-2 response ({len(text2)} chars): {text2[:120]!r}", flush=True)

        result2 = _extract_json_robust(text2, vuln_type, difficulty)
        if _is_valid_scenario(result2):
            print("[OllamaProvider] attempt-2 succeeded", flush=True)
            return result2

        # ── Both attempts produced incomplete JSON — use fallback ─────────────
        print("[OllamaProvider] both attempts incomplete; using fallback scenario", flush=True)
        return _extract_json_robust("", vuln_type, difficulty)  # triggers strategy-6 fallback

    async def _call(self, user_prompt: str) -> str:
        """Single chat completion call. Returns raw text, never raises."""
        try:
            response = await self._client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user",   "content": user_prompt},
                ],
                temperature=0.3,
                max_tokens=4000,
                timeout=120.0,
            )
            return (response.choices[0].message.content or "").strip()
        except Exception as exc:
            print(f"[OllamaProvider] _call error: {exc}", flush=True)
            logger.warning("[OllamaProvider] LLM call failed: %s", exc)
            return ""


def _is_valid_scenario(d: dict) -> bool:
    """Return True only if the dict has all required top-level keys with non-empty values."""
    required = {"title", "vuln_type", "description", "steps", "payloads", "risk",
                "defense_tips", "code_examples"}
    if not required.issubset(d.keys()):
        return False
    if not isinstance(d.get("steps"), list) or len(d["steps"]) == 0:
        return False
    if not isinstance(d.get("payloads"), list) or len(d["payloads"]) == 0:
        return False
    if not isinstance(d.get("risk"), dict):
        return False
    if not isinstance(d.get("code_examples"), dict):
        return False
    return True
