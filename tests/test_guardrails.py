"""Deterministic tests for agents.guardrails without live LLM calls."""

import pytest

from agents.guardrails import Guardrails


class TestValidatePrompt:
    """Prompt validation must reject denylisted phrases regardless of case."""

    def test_allows_benign_prompt(self):
        assert Guardrails.validate_prompt("What is the status of the service?") is True

    @pytest.mark.parametrize("phrase", ["ignore previous instructions", "DISREGARD", "JailBreak", "System Override"])
    def test_rejects_denylisted_phrases(self, phrase: str):
        assert Guardrails.validate_prompt(phrase) is False

    def test_rejects_prompt_containing_denylisted_word(self):
        assert Guardrails.validate_prompt("Please disregard the earlier plan.") is False


class TestSanitizeResponse:
    """Response sanitization trims whitespace and caps length."""

    def test_trims_excess_whitespace(self):
        raw = "  hello\n\nworld  \t "
        assert Guardrails.sanitize_response(raw) == "hello world"

    def test_truncates_long_response(self):
        long_response = "x" * 5000
        sanitized = Guardrails.sanitize_response(long_response)
        assert len(sanitized) == 4000
        assert sanitized == "x" * 4000

    def test_preserves_short_response(self):
        assert Guardrails.sanitize_response("ok") == "ok"


class TestRedactSecrets:
    """Secret redaction masks sensitive-looking string values."""

    def test_redacts_openai_api_key(self):
        message = {"api_key": "sk-secretvalue123", "ok": True}
        redacted = Guardrails.redact_secrets(message)
        assert redacted["api_key"] == "<redacted>"
        assert redacted["ok"] is True

    def test_redacts_bearer_token(self):
        message = {"authorization": "Bearer abc.def.ghi", "name": "test"}
        redacted = Guardrails.redact_secrets(message)
        assert redacted["authorization"] == "<redacted>"
        assert redacted["name"] == "test"

    def test_redacts_github_token(self):
        message = {"token": "ghp_personalaccesstoken"}
        assert Guardrails.redact_secrets(message)["token"] == "<redacted>"

    def test_leaves_non_secret_strings_untouched(self):
        message = {"note": "not an sk- token", "value": "plain"}
        redacted = Guardrails.redact_secrets(message)
        assert redacted["note"] == "not an sk- token"
        assert redacted["value"] == "plain"

    def test_does_not_mutate_input(self):
        message = {"key": "sk-secret"}
        Guardrails.redact_secrets(message)
        assert message["key"] == "sk-secret"
