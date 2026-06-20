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

# Defence-in-depth: keep these broad enough to catch realistic key shapes
# (e.g. "sk-proj-...", shorter prefixes, hyphen/underscore segments) without
# matching obvious non-secrets like the literal "sk-" with no key body.
_SECRET_PATTERNS: Iterable[re.Pattern[str]] = (
    re.compile(r"sk-[A-Za-z0-9][A-Za-z0-9_-]{6,}"),
    re.compile(r"(?i)bearer\s+[a-z0-9-_]{10,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{10,}"),
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
        """Redact sensitive tokens from structured data, recursing into nested
        dict/list values so secrets cannot hide below the top level."""

        return {key: self._redact_value(value) for key, value in message.items()}

    def _redact_value(self, value: Any) -> Any:
        if isinstance(value, str):
            if any(pattern.search(value) for pattern in _SECRET_PATTERNS):
                return "<redacted>"
            return value
        if isinstance(value, Mapping):
            return {key: self._redact_value(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._redact_value(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self._redact_value(item) for item in value)
        return value

    def evaluate_tool_call(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
        confidence: float | None = None,
    ) -> GuardrailDecision:
        """Check whether a tool call is allowed to execute."""

        is_critical = tool_name in _CRITICAL_ACTIONS

        if is_critical and self.settings.require_human_for_isolation:
            # A model-supplied change_ticket is not trustworthy evidence of human
            # approval: the LLM controls the arguments and can pass any value.
            # Critical actions therefore ALWAYS require approval unless the ticket
            # matches a configured, out-of-band allowlist.
            ticket = arguments.get("change_ticket") if isinstance(arguments, Mapping) else None
            if not self._ticket_approved(ticket):
                return GuardrailDecision(
                    allow=False,
                    reason=(
                        "Human approval required for network isolation/block actions. "
                        "Provide an approved change_ticket from the configured allowlist."
                    ),
                )

        if confidence is None:
            # Default-deny critical actions when the model/triage confidence is
            # unknown, rather than silently skipping the confidence gate.
            if is_critical:
                return GuardrailDecision(
                    allow=False,
                    reason="Confidence required for critical actions but was not provided.",
                )
        elif confidence < self.settings.minimum_confidence:
            return GuardrailDecision(
                allow=False,
                reason=(
                    f"Confidence {confidence:.2f} below minimum {self.settings.minimum_confidence:.2f}."
                ),
            )

        return GuardrailDecision(allow=True, reason="Permitted")

    def _ticket_approved(self, ticket: Any) -> bool:
        """Return True only when the ticket is on the configured allowlist."""

        if not ticket or not isinstance(ticket, str):
            return False
        return ticket in self.settings.approved_change_tickets

    def annotate_audit_log(self, record: Mapping[str, Any]) -> Dict[str, Any]:
        """Create a sanitized audit log entry."""

        sanitized = self.redact_message(record)
        sanitized["guardrail"] = {
            "minimum_confidence": self.settings.minimum_confidence,
            "require_human_for_isolation": self.settings.require_human_for_isolation,
        }
        return sanitized
