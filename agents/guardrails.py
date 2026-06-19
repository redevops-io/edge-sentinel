"""Input/output guardrails for the agent service."""

from __future__ import annotations

import re
from typing import Any, Dict, List


class Guardrails:
    """Simple guardrails applied to prompts and responses."""

    DENYLIST: List[str] = [
        "ignore previous instructions",
        "disregard",
        "jailbreak",
        "system override",
    ]

    @classmethod
    def validate_prompt(cls, prompt: str) -> bool:
        """Return True when the prompt is allowed."""
        lower = prompt.lower()
        return all(term not in lower for term in cls.DENYLIST)

    @classmethod
    def sanitize_response(cls, response: str) -> str:
        """Sanitize the model response before returning it."""
        # Trim excessive whitespace and truncate long lines for safety.
        sanitized = re.sub(r"\s+", " ", response).strip()
        return sanitized[:4000]

    @classmethod
    def redact_secrets(cls, message: Dict[str, Any]) -> Dict[str, Any]:
        """Redact sensitive-looking tokens from a message dictionary."""
        redacted = {}
        for key, value in message.items():
            if isinstance(value, str) and any(
                value.startswith(prefix) for prefix in ("sk-", "Bearer ", "ghp_")
            ):
                redacted[key] = "<redacted>"
            else:
                redacted[key] = value
        return redacted
