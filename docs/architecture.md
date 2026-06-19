# Edge Sentinel Architecture

Edge Sentinel is an open-core operations platform that closes the autonomous edge-operations loop. It pairs an open-source telemetry core with an LLM-powered agentic layer that observes, reasons, and remediates at the edge.

This document describes the OSS core, the agentic layer, the LLM endpoint integration, the harness reference, and the data flow between components.

## Overview

```text
┌─────────────────────────────────────────────┐
│           Agent Layer (Edge Sentinel)       │
│  Planner ──► Critic ──► Actor ──► Memory    │
│         LLM (OpenAI-compatible)             │
└───────────────────────┬─────────────────────┘
                        │ control / events
┌───────────────────────▼─────────────────────┐
│         OSS Core (OpenTelemetry)            │
│  Collector ──► Store ──► Alerting rules     │
└─────────────────────────────────────────────┘
```

The **OSS core** is an OpenTelemetry pipeline: collectors receive telemetry, stores persist it, and alerting rules surface anomalies. The **agent layer** consumes those anomalies, plans remediation steps, critiques them for safety, executes approved actions, and records outcomes to memory.

## OSS core

The OSS core is responsible for telemetry collection, storage, and alerting at the edge. It is built on open standards (OpenTelemetry) so data ownership is preserved and vendor lock-in is avoided.

- **Collector** — Receives logs, metrics, and traces from edge workloads.
- **Store** — Persists telemetry for correlation and historical analysis.
- **Alerting rules** — Surface anomalies that should be escalated to the agent layer.

The default `docker-compose.yml` deploys a placeholder `core` service using `nginx:alpine` to represent the OSS core entrypoint. In a production deployment this service is replaced by the OpenTelemetry Collector and backing stores.

## Agentic layer

The agentic layer is implemented in the `agents/` Python package. It is an OpenAI-compatible agent service that runs as a Docker container alongside the OSS core.

### Responsibilities

- **Planner** — Receives an alert or user message and plans a response, optionally invoking tools.
- **Critic** — Applies guardrails to prompts and model outputs before they are acted upon.
- **Actor** — Executes tool calls registered by the service and returns results to the LLM.
- **Memory** — Records outcomes and state via the harness client (for example, registration, heartbeats, and task results).

### Components

| File | Purpose |
|------|---------|
| `agents/main.py` | `AgentService` entrypoint, orchestrates chat, tool calls, harness integration, and HTTP client lifecycle. |
| `agents/config.py` | `AgentConfig` dataclass loaded from environment variables. |
| `agents/guardrails.py` | Input/output guardrails: prompt denylist, response sanitization, and secret redaction. |
| `agents/harness_client.py` | `AgentHarnessClient` wrapper around the shared `agent-harness` library for registration, heartbeats, and result reporting. |
| `agents/tools.py` | Tool schemas and handlers exposed to the LLM (`get_status`, `echo`). |
| `agents/__init__.py` | Package exports (`AgentService`, `__version__`). |

### Agent service lifecycle

1. `AgentService` is constructed from `AgentConfig.from_env()`.
2. On startup, `register_with_harness()` obtains an `agent_id` from the harness.
3. For each request, `chat()` validates the prompt, heartbeats if an `agent_id` is known, calls the LLM, runs any tool calls, and returns a sanitized response.
4. On shutdown, `close()` releases the `httpx.AsyncClient`.

## LLM endpoint integration

The agent service integrates with any OpenAI-compatible LLM endpoint.

Configuration is sourced from environment variables (see [configuration.md](./configuration.md)):

- `OPENAI_BASE_URL` — Base URL for the chat completions endpoint.
- `OPENAI_API_KEY` — Bearer token sent in the `Authorization` header.
- `MODEL` — Model identifier, e.g. `gpt-4o`.
- `TEMPERATURE` and `MAX_TOKENS` — Sampling parameters.

The service sends requests to `/chat/completions` with a system message, user message, tool definitions, and sampling parameters. When the model requests a tool call, the service executes the handler, appends the result to the conversation, and asks the model for a final response.

## Harness reference

The `agents/harness_client.py` module provides a thin wrapper around the shared `agent-harness` library (`harness.HarnessClient`), which is declared as a dependency in `pyproject.toml`:

```toml
dependencies = [
    "agent-harness @ git+https://github.com/redevops-io/agent-harness.git",
    ...
]
```

The harness URL defaults to `http://localhost:8000` and can be overridden with `AGENT_HARNESS_URL`.

### Operations

- `register(agent_id, metadata)` — Register the agent with the harness and obtain an identity.
- `heartbeat(agent_id)` — Keep the agent registration alive during a request.
- `report_result(agent_id, task_id, result)` — Report the outcome of a task.

## Data flow

A typical anomaly-to-remediation flow looks like this:

1. Edge workloads emit logs, metrics, and traces to the OpenTelemetry Collector (OSS core).
2. The OSS core stores telemetry and evaluates alerting rules.
3. When a rule fires, the anomaly is passed to the agentic layer as an input prompt.
4. The agent layer validates the prompt through `Guardrails.validate_prompt()`.
5. The agent service calls the configured OpenAI-compatible LLM with tools.
6. If the model requests a tool, `AgentService` dispatches it to the matching handler in `TOOL_HANDLERS`.
7. Tool results are sent back to the LLM for a final, human-readable response.
8. The final response is sanitized by `Guardrails.sanitize_response()`.
9. Outcomes are reported to the harness via `AgentHarnessClient.report_result()`.
10. Heartbeats keep the agent registered while it is active.

This loop turns raw telemetry into operational decisions without replacing the observability tools already in place.
