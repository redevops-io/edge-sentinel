"""Harness client helpers for the Edge Sentinel agent layer.

This module is part of the Edge Sentinel project and released under the
terms of the GNU Affero General Public License v3.0. See the LICENSE file
at the repository root for details.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

try:  # pragma: no cover - optional dependency for fallback mode
    import httpx
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

_DEFAULT_HARNESS_URL = "http://localhost:8900"


@dataclass
class _AsyncHarnessAdapter:
    """Adapter around the agent-harness client's async interface."""

    client: Any

    async def register_agent(self, agent_id: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        return await self.client.register_agent(agent_id=agent_id, metadata=metadata)

    async def heartbeat(self, agent_id: str) -> Dict[str, Any]:
        return await self.client.heartbeat(agent_id=agent_id)

    async def report_result(
        self, agent_id: str, task_id: str, payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        return await self.client.report_result(
            agent_id=agent_id, task_id=task_id, payload=payload
        )

    async def close(self) -> None:
        close = getattr(self.client, "aclose", None)
        if close:
            await close()


class _HttpHarnessClient:
    """Fallback HTTP client used when the shared library is unavailable."""

    def __init__(self, base_url: str) -> None:
        if httpx is None:
            raise RuntimeError(
                "httpx is required for HTTP harness fallback but is not installed."
            )
        self._client = httpx.AsyncClient(base_url=base_url.rstrip("/"))

    async def register_agent(self, agent_id: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        response = await self._client.post(
            "/agents/register", json={"agent_id": agent_id, "metadata": metadata}
        )
        response.raise_for_status()
        return response.json()

    async def heartbeat(self, agent_id: str) -> Dict[str, Any]:
        response = await self._client.post(
            "/agents/heartbeat", json={"agent_id": agent_id}
        )
        response.raise_for_status()
        return response.json()

    async def report_result(
        self, agent_id: str, task_id: str, payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        response = await self._client.post(
            "/agents/report",
            json={"agent_id": agent_id, "task_id": task_id, "payload": payload},
        )
        response.raise_for_status()
        return response.json()

    async def close(self) -> None:
        await self._client.aclose()


def _import_harness_client() -> Optional[_AsyncHarnessAdapter]:
    candidates = [
        ("agent_harness.client", "AsyncHarnessClient"),
        ("agent_harness", "AsyncHarnessClient"),
        ("harness", "HarnessClient"),
    ]

    for module_name, attr in candidates:
        try:
            module = __import__(module_name, fromlist=[attr])
            client_cls = getattr(module, attr)
            instance = client_cls(base_url=_DEFAULT_HARNESS_URL)
            return _AsyncHarnessAdapter(client=instance)
        except RuntimeError:
            # Optional dependency not available; continue to fallback logic.
            continue
        except ImportError:
            continue
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.debug("Failed to initialise harness client %s.%s: %s", module_name, attr, exc)
            continue
    return None


class AgentHarnessClient:
    """Thin wrapper around the shared agent harness implementation."""

    def __init__(self, base_url: str | None = None) -> None:
        resolved_url = base_url or os.environ.get("AGENT_HARNESS_URL", _DEFAULT_HARNESS_URL)
        self._fallback = _HttpHarnessClient(base_url=resolved_url)

        adapter = _import_harness_client()
        if adapter is not None:
            # Recreate adapter with caller-provided base URL.
            try:
                adapted_client = type(adapter.client)(base_url=resolved_url)
                self._client: Any = _AsyncHarnessAdapter(client=adapted_client)
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug("Falling back to HTTP harness client: %s", exc)
                self._client = self._fallback
        else:
            self._client = self._fallback

    async def register(self, agent_id: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        return await self._client.register_agent(agent_id=agent_id, metadata=metadata)

    async def heartbeat(self, agent_id: str) -> Dict[str, Any]:
        return await self._client.heartbeat(agent_id=agent_id)

    async def report_result(
        self, agent_id: str, task_id: str, result: Dict[str, Any]
    ) -> Dict[str, Any]:
        payload = json.loads(json.dumps(result))  # ensure JSON-serialisable copy
        return await self._client.report_result(agent_id=agent_id, task_id=task_id, payload=payload)

    async def close(self) -> None:
        await self._client.close()


def sync_register(agent_id: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
    """Best-effort synchronous registration helper for CLI entrypoints."""

    client = AgentHarnessClient()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(client.register(agent_id, metadata))
    finally:
        loop.run_until_complete(client.close())
        loop.close()
        asyncio.set_event_loop(None)
