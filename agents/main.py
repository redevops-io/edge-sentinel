"""Agent service entrypoint."""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any, Dict, List

import httpx

from .config import AgentConfig
from .guardrails import Guardrails
from .harness_client import AgentHarnessClient
from .tools import TOOL_HANDLERS, TOOLS


class AgentService:
    """OpenAI-compatible agentic layer service."""

    def __init__(self, config: AgentConfig | None = None) -> None:
        self.config = config or AgentConfig.from_env()
        self.guardrails = Guardrails()
        self.harness = AgentHarnessClient()
        self._client: httpx.AsyncClient | None = None

    @property
    def http_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.config.openai_base_url,
                headers={"Authorization": f"Bearer {self.config.openai_api_key}"},
                timeout=60.0,
            )
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def chat(self, user_message: str, agent_id: str | None = None) -> str:
        """Run a single-turn chat with tool support and guardrails."""
        if not self.guardrails.validate_prompt(user_message):
            return "I cannot process that request."

        if agent_id:
            await self.harness.heartbeat(agent_id)

        messages: List[Dict[str, Any]] = [
            {
                "role": "system",
                "content": (
                    "You are a helpful assistant with access to tools. "
                    "Use a tool when appropriate."
                ),
            },
            {"role": "user", "content": user_message},
        ]

        response = await self.http_client.post(
            "/chat/completions",
            json={
                "model": self.config.model,
                "messages": messages,
                "tools": TOOLS,
                "temperature": self.config.temperature,
                "max_tokens": self.config.max_tokens,
            },
        )
        response.raise_for_status()
        payload = response.json()

        choice = payload["choices"][0]
        message = choice.get("message", {})

        tool_calls = message.get("tool_calls")
        if tool_calls:
            assistant_message: Dict[str, Any] = {
                "role": "assistant",
                "content": message.get("content") or "",
                "tool_calls": tool_calls,
            }
            messages.append(assistant_message)

            for call in tool_calls:
                function = call.get("function", {})
                name = function.get("name")
                arguments = json.loads(function.get("arguments", "{}"))
                handler = TOOL_HANDLERS.get(name)
                tool_result = await handler(arguments) if handler else "unknown tool"
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call.get("id", ""),
                        "name": name,
                        "content": str(tool_result),
                    }
                )

            follow_up = await self.http_client.post(
                "/chat/completions",
                json={
                    "model": self.config.model,
                    "messages": messages,
                    "temperature": self.config.temperature,
                    "max_tokens": self.config.max_tokens,
                },
            )
            follow_up.raise_for_status()
            content = follow_up.json()["choices"][0]["message"].get("content", "")
        else:
            content = message.get("content", "")

        content = self.guardrails.sanitize_response(content)
        return content

    async def register_with_harness(self, agent_id: str | None = None) -> Dict[str, Any]:
        """Register the agent with the harness."""
        agent_id = agent_id or str(uuid.uuid4())
        return await self.harness.register(
            agent_id=agent_id,
            metadata={
                "service": "agents-layer",
                "model": self.config.model,
            },
        )


async def main() -> None:
    """CLI entrypoint for the agent service."""
    service = AgentService()
    registration = await service.register_with_harness()
    agent_id = registration.get("agent_id")
    result = await service.chat("What is your status?", agent_id=agent_id)
    print(result)
    await service.close()


if __name__ == "__main__":
    asyncio.run(main())
