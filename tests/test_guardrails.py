"""Deterministic tests for agents.guardrails without live LLM calls."""

from __future__ import annotations

import pytest

from agents.guardrails import GuardrailDecision, Guardrails


@pytest.fixture
def guardrails() -> Guardrails:
    """Provide a guardrails instance with default settings."""

    return Guardrails()


class TestValidatePrompt:
    """Prompt validation must reject denylisted phrases regardless of case."""

    def test_allows_benign_prompt(self, guardrails: Guardrails):
        assert guardrails.validate_prompt("What is the status of the service?") is True

    @pytest.mark.parametrize(
        "phrase",
        [
            "ignore previous instructions",
            "DISREGARD",
            "JailBreak",
            "System Override",
        ],
    )
    def test_rejects_denylisted_phrases(self, guardrails: Guardrails, phrase: str):
        assert guardrails.validate_prompt(phrase) is False

    def test_rejects_prompt_containing_denylisted_word(self, guardrails: Guardrails):
        assert guardrails.validate_prompt("Please disregard the earlier plan.") is False


class TestSanitizeResponse:
    """Response sanitization trims whitespace and caps length."""

    def test_trims_excess_whitespace(self, guardrails: Guardrails):
        raw = "  hello\n\nworld  \t "
        assert guardrails.sanitize_response(raw) == "hello world"

    def test_truncates_long_response(self, guardrails: Guardrails):
        long_response = "x" * 5000
        sanitized = guardrails.sanitize_response(long_response)
        assert len(sanitized) == 4000
        assert sanitized == "x" * 4000

    def test_preserves_short_response(self, guardrails: Guardrails):
        assert guardrails.sanitize_response("ok") == "ok"


class TestRedactSecrets:
    """Secret redaction masks sensitive-looking string values."""

    def test_redacts_openai_api_key(self, guardrails: Guardrails):
        message = {"api_key": "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234", "ok": True}
        redacted = guardrails.redact_message(message)
        assert redacted["api_key"] == "<redacted>"
        assert redacted["ok"] is True

    def test_redacts_bearer_token(self, guardrails: Guardrails):
        message = {"authorization": "Bearer tokenwithalphanumeric1", "name": "test"}
        redacted = guardrails.redact_message(message)
        assert redacted["authorization"] == "<redacted>"
        assert redacted["name"] == "test"

    def test_redacts_github_token(self, guardrails: Guardrails):
        message = {"token": "ghp_ABCD1234EFGH5678IJKL"}
        assert guardrails.redact_message(message)["token"] == "<redacted>"

    def test_leaves_non_secret_strings_untouched(self, guardrails: Guardrails):
        message = {"note": "not an sk- token", "value": "plain"}
        redacted = guardrails.redact_message(message)
        assert redacted["note"] == "not an sk- token"
        assert redacted["value"] == "plain"

    def test_does_not_mutate_input(self, guardrails: Guardrails):
        message = {"key": "sk-secret"}
        guardrails.redact_message(message)
        assert message["key"] == "sk-secret"


class TestEvaluateToolCall:
    """Confidence gating and human approval requirements."""

    def test_allows_noncritical_with_high_confidence(self, guardrails: Guardrails):
        decision = guardrails.evaluate_tool_call("read_suricata_eve", {}, confidence=0.9)
        assert decision == GuardrailDecision(allow=True, reason="Permitted")

    def test_blocks_low_confidence_call(self, guardrails: Guardrails):
        decision = guardrails.evaluate_tool_call("read_suricata_eve", {}, confidence=0.1)
        assert decision.allow is False
        assert "Confidence" in decision.reason

    @pytest.mark.parametrize("tool_name", ["opnsense_isolate_host", "opnsense_block_ip"])
    def test_requires_change_ticket_for_critical_actions(
        self, guardrails: Guardrails, tool_name: str
    ):
        decision = guardrails.evaluate_tool_call(tool_name, {"hostname": "bad.local"})
        assert decision.allow is False
        assert "Human approval" in decision.reason

    def test_allows_critical_action_with_ticket(self, guardrails: Guardrails):
        decision = guardrails.evaluate_tool_call(
            "opnsense_isolate_host",
            {"hostname": "bad.local", "change_ticket": "CHG-123"},
            confidence=0.9,
        )
        assert decision.allow is True


class TestAnnotateAuditLog:
    """Audit log annotations must include guardrail metadata without leaking secrets."""

    def test_includes_guardrail_settings(self, guardrails: Guardrails):
        record = {"agent": "triage", "api_key": "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234"}
        annotated = guardrails.annotate_audit_log(record)
        assert annotated["api_key"] == "<redacted>"
        assert annotated["guardrail"]["minimum_confidence"] == guardrails.settings.minimum_confidence
        assert (
            annotated["guardrail"]["require_human_for_isolation"]
            == guardrails.settings.require_human_for_isolation
        )
