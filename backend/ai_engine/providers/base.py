# FILE: backend/ai_engine/providers/base.py
# PURPOSE: Abstract base class defining the LLM provider interface
# SECURITY NOTE: Concrete providers must never log API keys or raw tool payloads

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..tools.payload_generator import TOOL_SPEC as PAYLOAD_SPEC, execute as run_payloads
from ..tools.scenario_builder import TOOL_SPEC as STEPS_SPEC, execute as run_steps
from ..tools.risk_analyzer import TOOL_SPEC as RISK_SPEC, execute as run_risk

ALL_TOOLS = [PAYLOAD_SPEC, STEPS_SPEC, RISK_SPEC]

EXECUTORS: dict[str, Any] = {
    "generate_payloads": run_payloads,
    "build_attack_steps": run_steps,
    "analyze_risk": run_risk,
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

USER_PROMPT_TEMPLATE = (
    "Generate a complete lab scenario for vulnerability: '{vuln_type}' "
    "at '{difficulty}' difficulty. "
    "Target the demo app's login form, comment field, and file upload. "
    "Call all three tools, then return the final JSON."
)


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict


@dataclass
class ProviderResponse:
    stop_reason: str               # "end_turn" | "tool_use"
    text: str | None               # populated when stop_reason == "end_turn"
    tool_calls: list[ToolCall] = field(default_factory=list)
    raw: Any = None                # raw SDK response kept for provider-specific history building


def _extract_json(text: str) -> dict:
    text = re.sub(r"^```json\s*", "", text.strip())
    text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            return json.loads(match.group())
    raise ValueError(f"Could not extract valid JSON from response text")


class BaseProvider(ABC):
    """
    Abstract LLM provider. Subclasses implement the three abstract methods;
    the agentic tool loop runs in this base class via run_agent_loop().
    """

    # ── abstract interface ──────────────────────────────────────────────────

    @abstractmethod
    async def generate(
        self,
        messages: list[dict],
        tools: list[dict],
        system: str,
    ) -> ProviderResponse:
        """Single LLM call. Returns a normalised ProviderResponse."""
        ...

    @abstractmethod
    def build_assistant_message(self, response: ProviderResponse) -> dict:
        """
        Wrap the assistant turn in a message dict suitable for this provider's
        message history format.
        """
        ...

    @abstractmethod
    def build_tool_results_messages(
        self,
        tool_calls: list[ToolCall],
        results: list[dict],
    ) -> list[dict]:
        """
        Produce the message(s) that feed tool results back to the model.
        Anthropic uses a single user message with type=tool_result blocks;
        OpenAI uses one role=tool message per call.
        """
        ...

    # ── shared agent loop ───────────────────────────────────────────────────

    async def run_agent_loop(
        self, vuln_type: str, difficulty: str = "beginner"
    ) -> dict[str, Any]:
        messages: list[dict] = [
            {
                "role": "user",
                "content": USER_PROMPT_TEMPLATE.format(
                    vuln_type=vuln_type, difficulty=difficulty
                ),
            }
        ]

        for _ in range(8):
            response = await self.generate(messages, ALL_TOOLS, SYSTEM_PROMPT)
            messages.append(self.build_assistant_message(response))

            if response.stop_reason == "end_turn":
                if response.text:
                    return _extract_json(response.text)
                raise ValueError("Provider returned end_turn but no text content")

            if response.stop_reason == "tool_use" and response.tool_calls:
                results: list[dict] = []
                for tc in response.tool_calls:
                    executor = EXECUTORS.get(tc.name)
                    if executor:
                        result = await executor(tc.input)
                        results.append({"tool_call": tc, "result": result})
                messages.extend(self.build_tool_results_messages(
                    [r["tool_call"] for r in results],
                    [r["result"] for r in results],
                ))

        raise RuntimeError("Agent loop exceeded maximum iterations")
