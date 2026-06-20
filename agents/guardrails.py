"""Guardrail utilities for the Edge Sentinel agent layer.

This module is part of the Edge Sentinel project and released under the
terms of the GNU Affero General Public License v3.0. See the LICENSE file
at the repository root for details.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping

from .config import GuardrailSettings

_PROMPT_DENYLIST: Iterable[str] = (
    "ignore previous instructions",
    "disregard",
    "jailbreak",
    "system override",
    "start over",
    "reset system",
)

_CRITICAL_ACTIONS: Iterable[str] = (
    "opnsense_isolate_host",
    "opnsense_block_ip",
)

_SECRET_PATTERNS: Iterable[re.Pattern[str]] = (
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),
    re.compile(r"(?i)bearer\s+[a-z0-9-_]{10,}"),
    re.compile(r"ghp_[a-zA-Z0-9]{20,}"),
)


@dataclass(frozen=True)
class GuardrailDecision:
    """Outcome of evaluating a proposed agent action."""

    allow: bool
    reason: str


class Guardrails:
    """OWASP-for-agents guardrail helpers."""

    def __init__(self, settings: GuardrailSettings | None = None) -> None:
        self.settings = settings or GuardrailSettings.from_env()

    def validate_prompt(self, prompt: str) -> bool:
        """Return True when the prompt is allowed to proceed."""

        lower = prompt.lower()
        return all(term not in lower for term in _PROMPT_DENYLIST)

    def sanitize_response(self, response: str) -> str:
        """Sanitize the model response before returning it."""

        sanitized = re.sub(r"\s+", " ", response or "").strip()
        return sanitized[:4000]

    def redact_message(self, message: Mapping[str, Any]) -> Dict[str, Any]:
        """Redact sensitive tokens from structured data."""

        redacted: Dict[str, Any] = {}
        for key, value in message.items():
            if isinstance(value, str) and any(pattern.search(value) for pattern in _SECRET_PATTERNS):
                redacted[key] = "<redacted>"
            else:
                redacted[key] = value
        return redacted

    def evaluate_tool_call(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
        confidence: float | None = None,
    ) -> GuardrailDecision:
        """Check whether a tool call is allowed to execute."""

        if tool_name in _CRITICAL_ACTIONS and self.settings.require_human_for_isolation:
            ticket = arguments.get("change_ticket") if isinstance(arguments, Mapping) else None
            if not ticket:
                return GuardrailDecision(
                    allow=False,
                    reason=(
                        "Human approval required for network isolation/block actions. "
                        "Provide change_ticket evidence."
                    ),
                )

        if confidence is not None and confidence < self.settings.minimum_confidence:
            return GuardrailDecision(
                allow=False,
                reason=(
                    f"Confidence {confidence:.2f} below minimum {self.settings.minimum_confidence:.2f}."
                ),
            )

        return GuardrailDecision(allow=True, reason="Permitted")

    def annotate_audit_log(self, record: Mapping[str, Any]) -> Dict[str, Any]:
        """Create a sanitized audit log entry."""

        sanitized = self.redact_message(record)
        sanitized["guardrail"] = {
            "minimum_confidence": self.settings.minimum_confidence,
            "require_human_for_isolation": self.settings.require_human_for_isolation,
        }
        return sanitized
