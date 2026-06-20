"""Configuration utilities for the Edge Sentinel agent layer.

This module is part of the Edge Sentinel project and released under the
terms of the GNU Affero General Public License v3.0. See the LICENSE file
at the repository root for details.
"""

from __future__ import annotations

import os
import os.path
from dataclasses import dataclass, field
from typing import Final, FrozenSet

_DEFAULT_BASE_URL: Final[str] = "http://localhost:11434/v1"
_DEFAULT_MODEL: Final[str] = "llama3.1"


@dataclass(frozen=True)
class ApplianceSettings:
    """Settings describing the on-premises appliance footprint."""

    suricata_eve_path: str
    zeek_conn_path: str
    zeek_dns_path: str
    opnsense_actions_path: str

    @classmethod
    def from_env(cls) -> "ApplianceSettings":
        base = os.environ.get("APPLIANCE_DATA_ROOT", "/var/lib/edge-sentinel")
        return cls(
            suricata_eve_path=os.environ.get(
                "SURICATA_EVE_PATH", os.path.join(base, "suricata", "eve.json")
            ),
            zeek_conn_path=os.environ.get(
                "ZEEK_CONN_PATH", os.path.join(base, "zeek", "conn.log.json")
            ),
            zeek_dns_path=os.environ.get(
                "ZEEK_DNS_PATH", os.path.join(base, "zeek", "dns.log.json")
            ),
            opnsense_actions_path=os.environ.get(
                "OPNSENSE_ACTIONS_PATH", os.path.join(base, "opnsense", "actions.log")
            ),
        )


@dataclass(frozen=True)
class GuardrailSettings:
    """Settings controlling guardrail behaviour."""

    minimum_confidence: float
    require_human_for_isolation: bool
    approved_change_tickets: FrozenSet[str] = field(default_factory=frozenset)

    @classmethod
    def from_env(cls) -> "GuardrailSettings":
        raw_tickets = os.environ.get("APPROVED_CHANGE_TICKETS", "")
        approved = frozenset(
            ticket.strip() for ticket in raw_tickets.split(",") if ticket.strip()
        )
        return cls(
            minimum_confidence=float(os.environ.get("MIN_CONFIDENCE", "0.65")),
            require_human_for_isolation=os.environ.get(
                "REQUIRE_HUMAN_FOR_ISOLATION", "true"
            ).lower()
            in {"1", "true", "yes"},
            approved_change_tickets=approved,
        )


@dataclass(frozen=True)
class AgentConfig:
    """Runtime configuration for the agent service."""

    openai_base_url: str
    openai_api_key: str
    model: str
    temperature: float
    max_tokens: int
    appliance: ApplianceSettings
    guardrails: GuardrailSettings

    @classmethod
    def from_env(cls) -> "AgentConfig":
        """Load configuration from environment variables."""

        base_url = os.environ.get("OPENAI_BASE_URL", _DEFAULT_BASE_URL)
        api_key = os.environ.get("OPENAI_API_KEY", "token-not-set")
        model = os.environ.get("MODEL", _DEFAULT_MODEL)
        temperature = float(os.environ.get("TEMPERATURE", "0.2"))
        max_tokens = int(os.environ.get("MAX_TOKENS", "1536"))

        appliance = ApplianceSettings.from_env()
        guardrails = GuardrailSettings.from_env()

        return cls(
            openai_base_url=base_url,
            openai_api_key=api_key,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            appliance=appliance,
            guardrails=guardrails,
        )
