"""Validate the agents module can be imported without a live LLM or harness."""

import importlib
import sys
import types

import pytest


MODULE_NAMES = [
    "agents",
    "agents.config",
    "agents.guardrails",
    "agents.tools",
]


def test_agents_package_is_importable():
    """Top-level package import succeeds and exposes expected symbols."""
    import agents

    assert isinstance(agents, types.ModuleType)
    assert hasattr(agents, "AgentService")
    assert hasattr(agents, "__version__")
    assert agents.__version__ == "0.1.0"


@pytest.mark.parametrize("name", MODULE_NAMES)
def test_module_imports(name: str):
    """Each agents submodule can be imported independently."""
    module = importlib.import_module(name)
    assert isinstance(module, types.ModuleType)
    assert module.__name__ == name


def test_main_module_imports_symbols():
    """agents.main exposes AgentService without requiring environment variables."""
    from agents.main import AgentService

    assert isinstance(AgentService, type)
