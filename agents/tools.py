"""Tool definitions registered with the agent service."""

from __future__ import annotations

from typing import Any, Awaitable, Callable, Dict

ToolHandler = Callable[[Dict[str, Any]], Awaitable[str]]


TOOLS: list[Dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "get_status",
            "description": "Return the current status of the agent service.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "echo",
            "description": "Echo the provided message back to the caller.",
            "parameters": {
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "The message to echo.",
                    }
                },
                "required": ["message"],
            },
        },
    },
]


async def handle_get_status(_arguments: Dict[str, Any]) -> str:
    """Return a simple status message."""
    return "agent service is running"


async def handle_echo(arguments: Dict[str, Any]) -> str:
    """Echo the provided message."""
    return arguments.get("message", "")


TOOL_HANDLERS: Dict[str, ToolHandler] = {
    "get_status": handle_get_status,
    "echo": handle_echo,
}
