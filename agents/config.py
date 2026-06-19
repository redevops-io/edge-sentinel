"""Configuration sourced from environment variables."""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class AgentConfig:
    """Runtime configuration for the agent service."""

    openai_base_url: str
    openai_api_key: str
    model: str
    temperature: float
    max_tokens: int

    @classmethod
    def from_env(cls) -> "AgentConfig":
        """Load configuration from environment variables."""
        return cls(
            openai_base_url=os.environ["OPENAI_BASE_URL"],
            openai_api_key=os.environ["OPENAI_API_KEY"],
            model=os.environ["MODEL"],
            temperature=float(os.environ.get("TEMPERATURE", "0.2")),
            max_tokens=int(os.environ.get("MAX_TOKENS", "1024")),
        )
