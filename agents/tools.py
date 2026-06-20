"""Operational tooling for the Edge Sentinel agent layer.

This module is part of the Edge Sentinel project and released under the
terms of the GNU Affero General Public License v3.0. See the LICENSE file
at the repository root for details.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict

from .config import AgentConfig

logger = logging.getLogger(__name__)

ToolHandler = Callable[[Dict[str, Any], AgentConfig], Awaitable[str]]


@dataclass(frozen=True)
class ToolSpec:
    """Describes a tool to expose to the model."""

    name: str
    description: str
    parameters: Dict[str, Any]

    def as_openai_function(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


def _load_file(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        logger.warning("Tool requested missing file: %s", path)
        return ""
    except OSError as exc:  # pragma: no cover - defensive logging
        logger.error("Failed to read %s: %s", path, exc)
        return ""


async def read_suricata_eve(_: Dict[str, Any], config: AgentConfig) -> str:
    """Return latest Suricata EVE alerts scoped to the appliance."""

    content = _load_file(config.appliance.suricata_eve_path)
    if not content:
        return "No Suricata eve.json data available."
    try:
        records = [json.loads(line) for line in content.splitlines() if line.strip()]
    except json.JSONDecodeError:
        return content[:4096]
    return json.dumps(records[-50:], indent=2) if records else "[]"


async def read_zeek_conn(_: Dict[str, Any], config: AgentConfig) -> str:
    """Return a tail of Zeek conn.log entries."""

    content = _load_file(config.appliance.zeek_conn_path)
    return content[-8192:] if content else "No Zeek conn.log data available."


async def read_zeek_dns(_: Dict[str, Any], config: AgentConfig) -> str:
    """Return a tail of Zeek dns.log entries."""

    content = _load_file(config.appliance.zeek_dns_path)
    return content[-8192:] if content else "No Zeek dns.log data available."


async def opnsense_block_ip(args: Dict[str, Any], config: AgentConfig) -> str:
    """Record a block_ip action for the OPNsense firewall."""

    ip = args.get("ip_address")
    reason = args.get("reason", "Requested by agent")
    if not ip:
        return "ip_address is required"
    entry = {
        "action": "block_ip",
        "ip_address": ip,
        "reason": reason,
    }
    path = Path(config.appliance.opnsense_actions_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")
    except OSError as exc:  # pragma: no cover
        logger.error("Failed to record OPNsense action: %s", exc)
        return f"Failed to record action: {exc}"
    return f"Block request recorded for {ip}"


async def opnsense_isolate_host(args: Dict[str, Any], config: AgentConfig) -> str:
    """Record a host isolation action."""

    host = args.get("hostname")
    ticket = args.get("change_ticket")
    if not host:
        return "hostname is required"
    entry = {
        "action": "isolate_host",
        "hostname": host,
        "change_ticket": ticket,
    }
    path = Path(config.appliance.opnsense_actions_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")
    except OSError as exc:  # pragma: no cover
        logger.error("Failed to record OPNsense action: %s", exc)
        return f"Failed to record action: {exc}"
    return f"Isolation request recorded for {host}"


TOOL_SPECS: Dict[str, ToolSpec] = {
    "read_suricata_eve": ToolSpec(
        name="read_suricata_eve",
        description="Read the latest Suricata eve.json alerts from the appliance.",
        parameters={"type": "object", "properties": {}, "required": []},
    ),
    "read_zeek_conn": ToolSpec(
        name="read_zeek_conn",
        description="Tail Zeek conn.log entries.",
        parameters={"type": "object", "properties": {}, "required": []},
    ),
    "read_zeek_dns": ToolSpec(
        name="read_zeek_dns",
        description="Tail Zeek dns.log entries.",
        parameters={"type": "object", "properties": {}, "required": []},
    ),
    "opnsense_block_ip": ToolSpec(
        name="opnsense_block_ip",
        description="Request the OPNsense firewall to block an IP address.",
        parameters={
            "type": "object",
            "properties": {
                "ip_address": {"type": "string", "description": "IP address to block."},
                "reason": {"type": "string", "description": "Reason for the block."},
            },
            "required": ["ip_address"],
        },
    ),
    "opnsense_isolate_host": ToolSpec(
        name="opnsense_isolate_host",
        description="Request isolation of a host via OPNsense network automation.",
        parameters={
            "type": "object",
            "properties": {
                "hostname": {"type": "string", "description": "Host to isolate."},
                "change_ticket": {
                    "type": "string",
                    "description": "Change management ticket authorizing the isolation.",
                },
            },
            "required": ["hostname"],
        },
    ),
}

TOOLS = [spec.as_openai_function() for spec in TOOL_SPECS.values()]


TOOL_HANDLERS: Dict[str, ToolHandler] = {
    "read_suricata_eve": read_suricata_eve,
    "read_zeek_conn": read_zeek_conn,
    "read_zeek_dns": read_zeek_dns,
    "opnsense_block_ip": opnsense_block_ip,
    "opnsense_isolate_host": opnsense_isolate_host,
}
