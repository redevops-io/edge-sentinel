# Edge Sentinel Configuration

This document describes how to configure Edge Sentinel: environment variables, Docker Compose deployment, and agent service configuration.

## Environment variables

Edge Sentinel reads environment variables from a `.env` file. Copy `.env.example` to `.env` and edit it for your deployment:

```bash
cp .env.example .env
```

The following variables are defined in `.env.example`:

### LLM provider (OpenAI-compatible)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OPENAI_BASE_URL` | Yes | `https://api.openai.com/v1` | Base URL of the OpenAI-compatible API. |
| `OPENAI_API_KEY` | Yes | `sk-your-key-here` | API key sent as a Bearer token. Keep secret. |
| `MODEL` | Yes | `gpt-4o` | Model identifier to use for completions. |

### OpenTelemetry endpoints

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OTEL_COLLECTOR_ENDPOINT` | Yes | `localhost:4317` | Host and port of the OpenTelemetry Collector (gRPC). |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Yes | `http://localhost:4317` | OTLP endpoint URL for telemetry export. |

### Sentinel runtime

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SENTINEL_LOG_LEVEL` | Yes | `info` | Log level for Sentinel services. |
| `SENTINEL_MEMORY_URL` | Yes | `redis://localhost:6379/0` | URL of the memory / state store (Redis). |

### Agent service configuration

The `agents/config.py` module defines additional runtime variables used by the agentic layer:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OPENAI_BASE_URL` | Yes | — | Same as above; used to build the `httpx.AsyncClient` base URL. |
| `OPENAI_API_KEY` | Yes | — | Same as above; sent in the `Authorization` header. |
| `MODEL` | Yes | — | Model passed to `/chat/completions`. |
| `TEMPERATURE` | No | `0.2` | Sampling temperature. |
| `MAX_TOKENS` | No | `1024` | Maximum tokens per completion. |

The `agents/harness_client.py` module reads:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `AGENT_HARNESS_URL` | No | `http://localhost:8000` | Base URL of the agent harness service. |

## Docker Compose deployment

The provided `docker-compose.yml` defines two services on a shared bridge network `edge-sentinel`:

### `core`

- **Image:** `nginx:alpine`
- **Container name:** `edge-sentinel-core`
- **Ports:** `80:80`, `443:443`
- **Environment:** loaded from `.env.example`
- **Network:** `edge-sentinel`
- **Restart policy:** `unless-stopped`

In the default stack this service represents the OSS core entrypoint. Replace it with the OpenTelemetry Collector and backing stores in production.

### `agent`

- **Image:** `python:3.11-slim`
- **Container name:** `edge-sentinel-agent`
- **Command:** `python -m http.server 8080`
- **Ports:** `8080:8080`
- **Environment:** loaded from `.env.example`
- **Network:** `edge-sentinel`
- **Restart policy:** `unless-stopped`

In a real deployment this service runs the `agents` package (for example, `python -m agents.main`) using the image built from `pyproject.toml`.

### Network

```yaml
networks:
  edge-sentinel:
    driver: bridge
```

Both services attach to the `edge-sentinel` network so the agent can reach the core and harness endpoints by DNS name.

## Useful commands

```bash
# Start the stack
make up

# Stop the stack
make down

# Follow logs
make logs

# Run tests
make test

# Lint the codebase
make lint
```

## Agent package configuration

The agent service is configured in Python through `agents.config.AgentConfig`:

```python
from agents.config import AgentConfig

config = AgentConfig.from_env()
```

`AgentConfig` is a frozen dataclass, so instances are immutable after creation. Required values must be present in the environment; missing variables raise a `KeyError` at startup.

### Tool registration

Tools are defined in `agents/tools.py`. Each tool has:

- An OpenAI-compatible function schema in `TOOLS`.
- An async handler in `TOOL_HANDLERS` mapped by function name.

Add new tools by extending both `TOOLS` and `TOOL_HANDLERS`.

### Guardrails

`agents/guardrails.Guardrails` provides:

- `validate_prompt(prompt)` — rejects prompts containing denylisted phrases.
- `sanitize_response(response)` — trims whitespace and truncates responses to 4000 characters.
- `redact_secrets(message)` — redacts strings starting with `sk-`, `Bearer `, or `ghp_`.

Configure behavior by editing `guardrails.py`; no additional environment variables are required.
