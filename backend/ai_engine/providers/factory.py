# FILE: backend/ai_engine/providers/factory.py
# PURPOSE: Returns the configured LLM provider based on AI_PROVIDER env var
# SECURITY NOTE: Provider instances are singletons; API keys never leave the server

import os
from functools import lru_cache

from .base import BaseProvider


@lru_cache(maxsize=1)
def get_provider() -> BaseProvider:
    """
    Reads AI_PROVIDER from env and returns the singleton provider.

    AI_PROVIDER=ollama     →  OllamaProvider     (default — local Ollama)
    AI_PROVIDER=anthropic  →  AnthropicProvider
    """
    provider = os.getenv("AI_PROVIDER", "ollama").lower()

    if provider == "ollama":
        from .ollama_provider import OllamaProvider
        base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
        model = os.getenv("OLLAMA_MODEL", "llama3.2")
        return OllamaProvider(base_url=base_url, model=model)

    # default: anthropic
    from .anthropic_provider import AnthropicProvider
    model = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")
    return AnthropicProvider(model=model)
