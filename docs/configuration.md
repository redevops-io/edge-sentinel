# Edge Sentinel Configuration

This guide outlines how to configure Edge Sentinel for local and hybrid deployments, focusing on environment variables, model endpoints, guardrails, human-in-the-loop controls, and log retention.

## Environment variables

Populate a `.env` file (copy `.env.example` first) with the variables below. They are read by the agent service, the harness client, and supporting tooling at runtime.

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENAI_BASE_URL` | Yes | Base URL of the OpenAI-compatible endpoint (local Ollama or remote cloud).
| `OPENAI_API_KEY` | Yes | API key or token passed as the `Authorization: Bearer` header.
| `MODEL` | Yes | Model identifier exposed by the configured endpoint.
| `TEMPERATURE` | No | Override sampling temperature for completions (default `0.2`).
| `MAX_TOKENS` | No | Maximum tokens per completion (default `1024`).
| `AGENT_HARNESS_URL` | No | Base URL of the edge harness service (`http://localhost:8000` by default).
| `SENTINEL_LOG_LEVEL` | No | Logging verbosity for the agent container (default `info`).
| `SENTINEL_MEMORY_URL` | No | Redis URL for memory/state persistence (default `redis://localhost:6379/0`).

> **Tip:** Keep `.env` files out of source control. The repository ships with `.env.example` as a template; copy and customize it for each environment.

## Local vs. optional cloud operation

- **Local-first:** Run Ollama on the edge appliance and expose it on `http://ollama:11434/v1`. Set `OPENAI_BASE_URL=http://ollama:11434/v1`, leave `OPENAI_API_KEY` blank or use a local token, and choose a locally hosted `MODEL` (for example `llama3.1`).
- **Cloud fallback:** If latency and privacy requirements permit, point `OPENAI_BASE_URL` at a cloud provider (e.g., `https://api.openai.com/v1`). Provide the cloud key in `OPENAI_API_KEY` and select the corresponding `MODEL`. Switching between local and cloud is a redeploy-safe `.env` change.
- **Hybrid:** Use local inference for steady-state workflows and configure a cloud override in disaster recovery plans. Guardrails apply consistently regardless of endpoint.

## Guardrails and human-in-the-loop configuration

- **Prompt validation:** `agents.guardrails.Guardrails.validate_prompt()` blocks denylisted instructions. Extend the `DENYLIST` list in `agents/guardrails.py` when new policy constraints arise.
- **Response sanitation:** `sanitize_response()` trims and caps outputs before returning them to operators or downstream automations.
- **Secret redaction:** `redact_secrets()` redacts tokens prefixed with `sk-`, `Bearer`, or `ghp_` inside structured tool outputs. Customize prefixes to match your credential patterns.
- **Approval gating:** The Remediation workflow publishes proposed actions to the harness. Require human approval by enforcing change control in the harness UI/API before executing firewall or routing changes.
- **Audit traces:** All workflow steps are reported to the harness using `AgentHarnessClient.report_result()`. Ensure the harness service retains action logs in accordance with compliance requirements.

## Log retention guidance

- **Suricata / OPNsense logs:** Store at least 14 days of `eve.json` and firewall logs locally to support retroactive correlation. Use rotate-compress pipelines to keep disk usage predictable.
- **Zeek logs:** Persist `conn.log`, `dns.log`, and application protocol logs for 30 days, or longer if required by policy. Index critical fields (source/destination, JA3, user agents) for fast hunting queries.
- **Agent service logs:** Route stdout/stderr to the platform log store (e.g., Loki, Elastic). Align retention with your incident response SLA; 90 days is a common baseline.
- **Harness audit records:** Follow organizational retention rules for change management—store remediation approvals and denials alongside ticketing references.

> **Note:** Avoid exporting telemetry outside the edge tenancy unless the data has been reviewed for sensitivity and complies with regional regulations.

## Configuration checklist

1. Copy `.env.example` to `.env` and populate mandatory secrets.
2. Choose your inference endpoint (local Ollama or cloud) and set `OPENAI_BASE_URL`, `OPENAI_API_KEY`, and `MODEL` accordingly.
3. Size persistence volumes for Suricata and Zeek logs to meet retention targets.
4. Review `agents/guardrails.py` and align denylisted terms with internal policy.
5. Enable authentication and TLS on the harness and LLM endpoints before moving to production.
6. Document the human approval flow for remediation steps and verify escalation on change rejection.
