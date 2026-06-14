# FILE: backend/ai_engine/providers/anthropic_provider.py
# PURPOSE: Anthropic Claude provider using full Tool Use agentic loop
# SECURITY NOTE: API key loaded from ANTHROPIC_API_KEY env var via SDK default

import json
from typing import Any

import anthropic

from .base import BaseProvider, ProviderResponse, ToolCall


class AnthropicProvider(BaseProvider):
    def __init__(self, model: str = "claude-sonnet-4-6") -> None:
        self._client = anthropic.AsyncAnthropic()
        self._model = model

    # ── BaseProvider interface ──────────────────────────────────────────────

    async def generate(
        self,
        messages: list[dict],
        tools: list[dict],
        system: str,
    ) -> ProviderResponse:
        response = await self._client.messages.create(
            model=self._model,
            max_tokens=4000,
            system=system,
            tools=tools,  # type: ignore[arg-type]
            messages=messages,  # type: ignore[arg-type]
        )

        tool_calls: list[ToolCall] = []
        text: str | None = None

        for block in response.content:
            if block.type == "tool_use":
                tool_calls.append(ToolCall(id=block.id, name=block.name, input=block.input))
            elif block.type == "text":
                text = block.text

        return ProviderResponse(
            stop_reason=response.stop_reason or "end_turn",
            text=text,
            tool_calls=tool_calls,
            raw=response.content,
        )

    def build_assistant_message(self, response: ProviderResponse) -> dict:
        # Anthropic expects the raw content blocks list
        return {"role": "assistant", "content": response.raw}

    def build_tool_results_messages(
        self,
        tool_calls: list[ToolCall],
        results: list[Any],
    ) -> list[dict]:
        # Anthropic: single user message containing all tool_result blocks
        return [
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": tc.id,
                        "content": json.dumps(result),
                    }
                    for tc, result in zip(tool_calls, results)
                ],
            }
        ]
