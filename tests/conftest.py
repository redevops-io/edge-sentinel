"""Test-only helpers: stub external dependencies not available in CI."""

import sys
import types


def _stub_harness():
    """Provide a minimal stub for the optional agent-harness library."""
    if "harness" in sys.modules:
        return

    stub = types.ModuleType("harness")

    class HarnessClient:
        def __init__(self, base_url: str = "http://localhost:8000") -> None:
            self.base_url = base_url

        async def register_agent(self, **kwargs):
            return {"agent_id": kwargs.get("agent_id"), "status": "registered"}

        async def heartbeat(self, **kwargs):
            return {"status": "ok"}

        async def report_result(self, **kwargs):
            return {"status": "reported"}

    stub.HarnessClient = HarnessClient
    sys.modules["harness"] = stub


_stub_harness()
