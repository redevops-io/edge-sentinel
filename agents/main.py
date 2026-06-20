"""LangGraph-style orchestration for Edge Sentinel's agent layer.

This module is part of the Edge Sentinel project and released under the
terms of the GNU Affero General Public License v3.0. See the LICENSE file
at the repository root for details.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Any, Dict, Iterable, List, Mapping

try:  # pragma: no cover - optional dependency
    import httpx
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore[assignment]

from .config import AgentConfig
from .guardrails import GuardrailDecision, Guardrails
from .harness_client import AgentHarnessClient
from .tools import TOOL_HANDLERS, TOOLS

logger = logging.getLogger(__name__)

_AGENT_ROLES: Mapping[str, str] = {
    "alert_triage": (
        "You are the Alert Triage analyst. Triage incoming alerts, summarise context, "
        "and decide if escalation is needed."
    ),
    "threat_hunting": (
        "You are the Threat Hunting analyst. Use Suricata and Zeek telemetry to understand "
        "attack scope and identify indicators of compromise."
    ),
    "remediation": (
        "You are the Remediation engineer. Draft remediation steps, evaluate safety, and "
        "engage the firewall automation tools."
    ),
    "business_report": (
        "You are the Business Impact reporter. Translate technical findings into executive "
        "summary and recommended actions."
    ),
}


class AgentService:
    """OpenAI-compatible agentic coordination service."""

    def __init__(self, config: AgentConfig | None = None) -> None:
        self.config = config or AgentConfig.from_env()
        self.guardrails = Guardrails(self.config.guardrails)
        self.harness = AgentHarnessClient()
        self._client: httpx.AsyncClient | None = None

    @property
    def http_client(self) -> httpx.AsyncClient:
        if self._client is None:
            if httpx is None:
                raise RuntimeError(
                    "httpx is required for AgentService but is not installed. "
                    "Install the agents-layer package dependencies."
                )
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
        await self.harness.close()

    async def _invoke_model(
        self,
        messages: List[Dict[str, Any]],
        tools: Iterable[Dict[str, Any]] | None = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }
        if tools:
            payload["tools"] = list(tools)

        logger.debug("Invoking model with %d messages", len(messages))
        response = await self.http_client.post("/chat/completions", json=payload)
        response.raise_for_status()
        return response.json()

    async def _run_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        confidence: float | None = None,
    ) -> str:
        handler = TOOL_HANDLERS.get(tool_name)
        if not handler:
            logger.warning("No handler for tool %s", tool_name)
            return f"Tool {tool_name} not available"
        decision = self.guardrails.evaluate_tool_call(tool_name, arguments, confidence)
        if not decision.allow:
            return decision.reason
        return await handler(arguments, self.config)

    async def run_playbook(self, incident_summary: str, agent_id: str | None = None) -> Dict[str, Any]:
        """Execute the four-agent playbook for a given incident."""

        if not self.guardrails.validate_prompt(incident_summary):
            return {"error": "Prompt rejected by guardrails"}

        if agent_id:
            await self.harness.heartbeat(agent_id)

        history: List[Dict[str, Any]] = []

        # Phase 1: Alert Triage
        triage_messages = [
            {"role": "system", "content": _AGENT_ROLES["alert_triage"]},
            {"role": "user", "content": incident_summary},
        ]
        triage_result = await self._invoke_model(triage_messages, tools=TOOLS)
        triage_choice = triage_result["choices"][0]["message"]
        history.append({"phase": "alert_triage", "message": triage_choice})

        # Confidence established during triage gates downstream critical actions.
        triage_confidence = self._extract_confidence(triage_choice)

        follow_on_messages = triage_messages + [triage_choice]

        # Phase 1 tools
        for call in triage_choice.get("tool_calls", []) or []:
            tool_result = await self._handle_tool_call(call, follow_on_messages, triage_confidence)
            history.append({"phase": "alert_triage_tool", "tool": call, "result": tool_result})
            follow_on_messages.append(tool_result)

        # Phase 2: Threat Hunting
        hunting_messages = follow_on_messages + [
            {"role": "system", "content": _AGENT_ROLES["threat_hunting"]},
        ]
        hunting_result = await self._invoke_model(hunting_messages, tools=TOOLS)
        hunting_choice = hunting_result["choices"][0]["message"]
        history.append({"phase": "threat_hunting", "message": hunting_choice})
        hunting_messages.append(hunting_choice)

        hunting_confidence = self._extract_confidence(hunting_choice)
        for call in hunting_choice.get("tool_calls", []) or []:
            tool_result = await self._handle_tool_call(call, hunting_messages, hunting_confidence)
            history.append({"phase": "threat_hunting_tool", "tool": call, "result": tool_result})
            hunting_messages.append(tool_result)

        # Phase 3: Remediation
        remediation_messages = hunting_messages + [
            {"role": "system", "content": _AGENT_ROLES["remediation"]},
        ]
        remediation_result = await self._invoke_model(remediation_messages, tools=TOOLS)
        remediation_choice = remediation_result["choices"][0]["message"]
        history.append({"phase": "remediation", "message": remediation_choice})
        remediation_messages.append(remediation_choice)

        # Critical block/isolate actions happen here; gate them on the triage
        # confidence (falling back to the remediation step's own confidence).
        remediation_confidence = self._extract_confidence(remediation_choice)
        if remediation_confidence is None:
            remediation_confidence = triage_confidence
        for call in remediation_choice.get("tool_calls", []) or []:
            tool_result = await self._handle_tool_call(
                call, remediation_messages, remediation_confidence
            )
            history.append({"phase": "remediation_tool", "tool": call, "result": tool_result})
            remediation_messages.append(tool_result)

        # Phase 4: Business Report
        report_messages = remediation_messages + [
            {"role": "system", "content": _AGENT_ROLES["business_report"]},
        ]
        report_result = await self._invoke_model(report_messages)
        report_choice = report_result["choices"][0]["message"]
        history.append({"phase": "business_report", "message": report_choice})

        business_summary = self.guardrails.sanitize_response(report_choice.get("content", ""))

        run_id = str(uuid.uuid4())
        bundle = {
            "run_id": run_id,
            "summary": business_summary,
            "history": history,
        }

        if agent_id:
            await self.harness.report_result(agent_id, run_id, bundle)

        return bundle

    async def _handle_tool_call(
        self,
        call: Mapping[str, Any],
        messages: List[Dict[str, Any]],
        confidence: float | None = None,
    ) -> Dict[str, Any]:
        name = call.get("function", {}).get("name") or call.get("name")
        arguments_raw = call.get("function", {}).get("arguments") or call.get("arguments", "{}")
        try:
            arguments = json.loads(arguments_raw) if isinstance(arguments_raw, str) else arguments_raw
        except json.JSONDecodeError:
            arguments = {}
        result = await self._run_tool(name or "", arguments or {}, confidence)
        tool_message = {"role": "tool", "tool_call_id": call.get("id"), "content": result}
        messages.append(tool_message)
        return tool_message

    @staticmethod
    def _extract_confidence(choice: Mapping[str, Any]) -> float | None:
        """Best-effort extraction of a model/triage confidence score.

        Returns None when no confidence is reported, which causes
        ``evaluate_tool_call`` to default-deny critical actions.
        """

        for source in (choice, choice.get("metadata") if isinstance(choice, Mapping) else None):
            if isinstance(source, Mapping) and "confidence" in source:
                try:
                    return float(source["confidence"])
                except (TypeError, ValueError):
                    return None
        return None

    async def register_with_harness(self, agent_id: str | None = None) -> Dict[str, Any]:
        """Register the service with the agent harness bus."""

        agent_id = agent_id or str(uuid.uuid4())
        metadata = {
            "service": "edge-sentinel-agent-layer",
            "model": self.config.model,
        }
        return await self.harness.register(agent_id=agent_id, metadata=metadata)


async def main() -> None:
    """Command-line entrypoint for manual smoke testing."""

    logging.basicConfig(level=logging.INFO)
    service = AgentService()
    registration = await service.register_with_harness()
    agent_id = registration.get("agent_id")
    result = await service.run_playbook("Investigate Suricata alert on edge gateway", agent_id=agent_id)
    print(json.dumps(result, indent=2))
    await service.close()


if __name__ == "__main__":  # pragma: no cover - CLI convenience
    asyncio.run(main())
