# FILE: backend/ai_engine/providers/base.py
# PURPOSE: Abstract base class + shared agentic tool loop with input validation and ELK logging
# SECURITY NOTE: Concrete providers must never log API keys or raw tool payloads

import json
import logging
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..tools.payload_generator import TOOL_SPEC as PAYLOAD_SPEC, execute as run_payloads
from ..tools.scenario_builder  import TOOL_SPEC as STEPS_SPEC,   execute as run_steps
from ..tools.risk_analyzer     import TOOL_SPEC as RISK_SPEC,    execute as run_risk
from ..tools.http_probe        import TOOL_SPEC as HTTP_SPEC,    execute as run_http_probe
from ..tools.check_endpoint    import TOOL_SPEC as ENDPOINT_SPEC, execute as run_check_endpoint
from ..tools.inject_probe      import TOOL_SPEC as INJECT_SPEC,  execute as run_inject_probe
from ..prompts import SYSTEM_PROMPT, SYSTEM_SCAN_PROMPT

logger = logging.getLogger(__name__)

# ── Tool registries ───────────────────────────────────────────────────────────

# All 6 tools (used when a target_url is provided — full scan mode)
ALL_TOOLS_SCAN = [HTTP_SPEC, ENDPOINT_SPEC, INJECT_SPEC, PAYLOAD_SPEC, STEPS_SPEC, RISK_SPEC]

# Legacy 3 tools (scenario lab — no live target)
ALL_TOOLS = [PAYLOAD_SPEC, STEPS_SPEC, RISK_SPEC]

EXECUTORS: dict[str, Any] = {
    "generate_payloads":  run_payloads,
    "build_attack_steps": run_steps,
    "analyze_risk":       run_risk,
    "http_probe":         run_http_probe,
    "check_endpoint":     run_check_endpoint,
    "inject_probe":       run_inject_probe,
}

# Domains that must never be probed (block hallucinated documentation URLs)
_BLOCKED_DOMAINS = [
    "github.io", "github.com", "owasp.org",
    "example.com", "localhost:5432", "169.254.",
    "127.0.0.1:543", "w3schools",
]

USER_PROMPT_TEMPLATE = (
    "Generate a complete lab scenario for vulnerability: '{vuln_type}' "
    "at '{difficulty}' difficulty. "
    "Target the demo app's login form, comment field, and file upload. "
    "Call all three tools, then return the final JSON."
)

USER_PROMPT_SCAN_TEMPLATE = (
    "Scan target URL: {target_url}\n"
    "Vulnerability type to test: {vuln_type}\n"
    "Difficulty level: {difficulty}\n\n"
    "Follow the mandatory tool call order from the system prompt. "
    "Start with http_probe on the target URL, then check_endpoint, then inject_probe "
    "if inputs are found. Return the final JSON."
)


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class ToolCall:
    id: str
    name: str
    input: dict


@dataclass
class ProviderResponse:
    stop_reason: str               # "end_turn" | "tool_use"
    text: str | None
    tool_calls: list[ToolCall] = field(default_factory=list)
    raw: Any = None


def _extract_json(text: str) -> dict:
    text = re.sub(r"^```json\s*", "", text.strip())
    text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            return json.loads(match.group())
    raise ValueError("Could not extract valid JSON from response text")


# ── Input validation ──────────────────────────────────────────────────────────

def validate_tool_input(tool_name: str, tool_input: dict, target_url: str) -> dict:
    """
    Validates and corrects tool inputs before execution.
    Prevents the agent from calling wrong URLs (documentation, GitHub, etc.).
    """
    inp = dict(tool_input)  # shallow copy — don't mutate caller's dict

    if tool_name == "http_probe":
        url = inp.get("url", "")
        needs_fix = not url or any(d in url for d in _BLOCKED_DOMAINS)
        if not needs_fix and target_url:
            # Ensure URL uses the scan target's origin
            try:
                target_origin = "/".join(target_url.split("/")[:3])  # scheme://host:port
                if not url.startswith(target_origin):
                    needs_fix = True
            except Exception:
                pass
        if needs_fix and target_url:
            logger.warning("[validate_tool_input] http_probe URL corrected: %s → %s", url, target_url)
            inp["url"] = target_url
            inp["_url_corrected"] = True

    elif tool_name == "check_endpoint":
        base = inp.get("base_url", "")
        if not base or any(d in base for d in _BLOCKED_DOMAINS):
            logger.warning("[validate_tool_input] check_endpoint base_url corrected: %s → %s", base, target_url)
            inp["base_url"] = target_url

    elif tool_name == "inject_probe":
        url = inp.get("url", "")
        if not url or any(d in url for d in _BLOCKED_DOMAINS):
            logger.warning("[validate_tool_input] inject_probe URL corrected: %s → %s", url, target_url)
            inp["url"] = target_url

    return inp


# ── Abstract base provider ────────────────────────────────────────────────────

class BaseProvider(ABC):
    """
    Abstract LLM provider. Subclasses implement the three abstract methods;
    the agentic tool loop runs in this base class via run_agent_loop().
    """

    @abstractmethod
    async def generate(
        self, messages: list[dict], tools: list[dict], system: str
    ) -> ProviderResponse:
        ...

    @abstractmethod
    def build_assistant_message(self, response: ProviderResponse) -> dict:
        ...

    @abstractmethod
    def build_tool_results_messages(
        self, tool_calls: list[ToolCall], results: list[dict]
    ) -> list[dict]:
        ...

    # ── Shared agent loop ─────────────────────────────────────────────────────

    async def run_agent_loop(
        self,
        vuln_type: str,
        difficulty: str = "beginner",
        target_url: str = "",
        session_id: int = 0,
    ) -> dict[str, Any]:
        """
        Shared agentic tool loop used by AnthropicProvider.
        OllamaProvider overrides this with a single-shot approach.
        """
        # Choose tool set and prompt based on whether we have a live target
        if target_url:
            tools   = ALL_TOOLS_SCAN
            system  = SYSTEM_SCAN_PROMPT
            user_msg = USER_PROMPT_SCAN_TEMPLATE.format(
                target_url=target_url, vuln_type=vuln_type, difficulty=difficulty
            )
        else:
            tools   = ALL_TOOLS
            system  = SYSTEM_PROMPT
            user_msg = USER_PROMPT_TEMPLATE.format(vuln_type=vuln_type, difficulty=difficulty)

        messages: list[dict] = [{"role": "user", "content": user_msg}]
        step_num = 0

        # Lazy import to avoid circular dependency
        try:
            from services.elk_logger import elk as _elk
        except Exception:
            _elk = None

        for _ in range(8):
            response = await self.generate(messages, tools, system)
            messages.append(self.build_assistant_message(response))

            if response.stop_reason == "end_turn":
                if response.text:
                    return _extract_json(response.text)
                raise ValueError("Provider returned end_turn but no text content")

            if response.stop_reason == "tool_use" and response.tool_calls:
                results: list[dict] = []
                for tc in response.tool_calls:
                    step_num += 1
                    validated = validate_tool_input(tc.name, tc.input, target_url)
                    executor  = EXECUTORS.get(tc.name)

                    t_start = time.time()
                    if executor:
                        out = await executor(validated)
                    else:
                        out = {"error": f"unknown tool: {tc.name}"}
                    duration_ms = int((time.time() - t_start) * 1000)

                    # ELK: log each tool call
                    if _elk:
                        try:
                            _elk.log_agent_step(
                                session_id=session_id,
                                vuln_type=vuln_type,
                                step_number=step_num,
                                tool_name=tc.name,
                                tool_input=validated,
                                tool_output={
                                    "success": "error" not in out,
                                    "result_summary": str(out)[:200],
                                },
                                duration_ms=duration_ms,
                            )
                        except Exception:
                            pass  # logging must never crash the agent

                    results.append({"tool_call": tc, "result": out})

                messages.extend(self.build_tool_results_messages(
                    [r["tool_call"] for r in results],
                    [r["result"]    for r in results],
                ))

        raise RuntimeError("Agent loop exceeded maximum iterations")
