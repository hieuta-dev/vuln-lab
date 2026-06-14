# FILE: backend/ai_engine/scenario_agent.py
# PURPOSE: Public entry-point for scenario generation — delegates to the configured provider
# SECURITY NOTE: No SDK imported here; all provider details encapsulated in providers/

from typing import Any

from .providers.factory import get_provider


async def generate_scenario(vuln_type: str, difficulty: str = "beginner") -> dict[str, Any]:
    """
    Generate a structured attack scenario using the configured LLM provider.
    Switch providers by setting AI_PROVIDER=anthropic|ollama in the environment.
    """
    provider = get_provider()
    return await provider.run_agent_loop(vuln_type, difficulty)
