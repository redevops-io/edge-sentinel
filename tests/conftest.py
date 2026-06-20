"""Pytest fixtures and compatibility helpers for isolated testing."""

from __future__ import annotations

import os
import sys
import types
from collections.abc import Generator
from pathlib import Path
from typing import Any, Dict

import pytest


@pytest.fixture(autouse=True)
def fake_openai_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure OpenAI-compatible environment variables are present for imports."""

    monkeypatch.setenv("OPENAI_BASE_URL", "http://localhost:9999/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-1234567890")
    monkeypatch.setenv("MODEL", "test-model")


@pytest.fixture
def sample_suricata_alert() -> Dict[str, Any]:
    """Representative Suricata EVE JSON line for tool tests."""

    return {
        "timestamp": "2024-06-01T12:00:00.000Z",
        "src_ip": "10.0.0.5",
        "dest_ip": "198.51.100.7",
        "alert": {
            "signature": "ET MALWARE Possible Emotet Command and Control",
            "category": "A Network Trojan was detected",
            "severity": 1,
        },
        "proto": "TCP",
        "app_proto": "http",
        "http": {
            "hostname": "malicious.example",
            "url": "/payload",
            "http_user_agent": "curl/8.0.1",
        },
    }


@pytest.fixture
def sample_zeek_log() -> Dict[str, Any]:
    """Representative Zeek conn.log record for correlating telemetry."""

    return {
        "ts": "2024-06-01T12:00:05.000Z",
        "uid": "C1VZ7p3JlLn",
        "id.orig_h": "10.0.0.5",
        "id.resp_h": "198.51.100.7",
        "proto": "tcp",
        "service": "http",
        "duration": 3.2,
        "orig_bytes": 512,
        "resp_bytes": 2048,
        "conn_state": "S1",
    }


def _stub_harness() -> None:
    """Provide a minimal stub for the optional agent-harness library."""

    if "harness" in sys.modules:
        return

    stub = types.ModuleType("harness")

    class HarnessClient:
        def __init__(self, base_url: str = "http://localhost:8000") -> None:
            self.base_url = base_url

        async def register_agent(self, **kwargs: Any):
            return {"agent_id": kwargs.get("agent_id"), "status": "registered"}

        async def heartbeat(self, **kwargs: Any):
            return {"status": "ok"}

        async def report_result(self, **kwargs: Any):
            return {"status": "reported"}

    stub.HarnessClient = HarnessClient
    sys.modules["harness"] = stub


_stub_harness()
