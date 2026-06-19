"""Client for the shared agent-harness library."""

from __future__ import annotations

import os
from typing import Any, Dict

from harness import HarnessClient


class AgentHarnessClient:
    """Thin wrapper around the shared agent-harness library."""

    def __init__(self, harness_url: str | None = None) -> None:
        self._harness_url = harness_url or os.environ.get(
            "AGENT_HARNESS_URL", "http://localhost:8000"
        )
        self._client = HarnessClient(base_url=self._harness_url)

    async def register(self, agent_id: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Register this agent with the harness."""
        return await self._client.register_agent(agent_id=agent_id, metadata=metadata)

    async def heartbeat(self, agent_id: str) -> Dict[str, Any]:
        """Send a heartbeat to the harness."""
        return await self._client.heartbeat(agent_id=agent_id)

    async def report_result(
        self, agent_id: str, task_id: str, result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Report the result of a task to the harness."""
        return await self._client.report_result(
            agent_id=agent_id, task_id=task_id, result=result
        )
