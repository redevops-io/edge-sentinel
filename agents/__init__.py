"""Edge Sentinel agentic layer.

This module is part of the Edge Sentinel project and released under the
terms of the GNU Affero General Public License v3.0. See the LICENSE file
at the repository root for details.
"""

from __future__ import annotations

from .config import AgentConfig, ApplianceSettings, GuardrailSettings
from .guardrails import Guardrails
from .main import AgentService

__all__ = [
    "AgentConfig",
    "ApplianceSettings",
    "GuardrailSettings",
    "Guardrails",
    "AgentService",
]

__version__ = "0.1.0"
