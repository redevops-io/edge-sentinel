# Edge Sentinel

> From legacy firefighting to **reDevOps**: an autonomous agent layer for edge operations.

## The positioning triplet

**Pain** — Edge operations teams drown in dashboards, alerts, and runbooks. Incidents start at the edge but require humans to correlate logs, metrics, and traces before they can act.

**Legacy** — Existing observability stacks collect telemetry but stop at visualization. They leave the diagnose-decide-remediate loop to operators, which is slow, error-prone, and does not scale.

**reDevOps** — Edge Sentinel closes the loop. It pairs an open-source telemetry core with an LLM-powered agent layer that observes, reasons, and remediates at the edge.

## What Edge Sentinel does

Edge Sentinel is an open-core operations platform that watches your edge infrastructure, understands incidents in context, and takes safe, auditable actions. It turns raw telemetry into operational decisions without replacing the tools you already run.

## Value propositions

1. **Cut MTTR with autonomous triage** — The agent correlates signals across logs, metrics, and traces to pinpoint root cause faster than manual investigation.
2. **Reduce alert fatigue** — Semantic filtering and reasoning suppress noise and escalate only actionable issues.
3. **Operate at the edge** — Lightweight components run close to your workloads, so decisions happen even when connectivity is intermittent.
4. **Safe, auditable automation** — Every plan, approval, and action is logged and reviewable.
5. **Built on open standards** — The OSS core uses OpenTelemetry, so you keep data ownership and avoid vendor lock-in.

## Architecture

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

## Quickstart

```bash
# 1. Clone and enter the repo
git clone https://github.com/example/edge-sentinel.git
cd edge-sentinel

# 2. Copy and edit environment variables
cp .env.example .env
# Edit .env with your LLM credentials and OpenTelemetry endpoints

# 3. Start the stack
make up

# 4. Run the test suite
make test

# 5. Watch logs
make logs
```

## License

See [LICENSE](./LICENSE).
