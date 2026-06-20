# Edge Sentinel

> A self-hosted AGPL agentic appliance that helps SMEs stay a step ahead of ransomware and edge-borne threats.

## The positioning triplet

**Pain** — SMEs are drowning in cyber risk: ransomware crews probe branch offices, OT sites, and retail edges faster than lean security teams can respond.

**Legacy** — FortiGate stacks, Palo Alto appliances, and managed-SOC retainers promise coverage but land as costly, complex bundles that still leave operators translating alerts into action.

**reDevOps** — Edge Sentinel is the reDevOps answer: a self-hosted, AGPL agentic appliance that pairs open-source network sensors with autonomous response loops you can actually run on-site.

## What Edge Sentinel does

Edge Sentinel fuses proven open-source network defense with an LLM-native agent. OPNsense captures edge traffic, Suricata and Zeek enrich it with detections, and Ollama serves local models that feed an agent built on LangGraph. The Python agent layer, powered by the agent-harness library, triages incidents, summarizes impact in plain owner language, and automates guarded mitigations while preserving full auditability.

## Value propositions

1. **Data ownership, guaranteed by AGPL** — Keep packet captures, flow logs, and remediation history in your own infrastructure with an AGPL-licensed stack you can inspect and extend.
2. **Owner-language incident reports** — Translate IDS hits and Zeek metadata into plain-language briefings aligned with what business owners need to hear.
3. **Local AI triage** — Run Ollama-hosted models orchestrated by LangGraph to score ransomware risk and prioritize Suricata alerts without handing data to third parties.
4. **No subscription creep** — Deploy from source, scale at your pace, and avoid per-seat or per-sensor upcharges.
5. **Plug-and-play edge appliance** — Drop OPNsense, Suricata, Zeek, and the agent layer into an existing network, connect to your own LLM endpoint, and start closing loops in minutes.

## Architecture

```text
┌────────────────────────────────────────────────────────────┐
│                     OSS Core (network edge)                │
│  OPNsense firewall  ─┬─► Suricata IDS  ─┬─► Zeek analytics │
│                      │                  │                  │
│                      ▼                  ▼                  │
│              Enriched telemetry & alerts                   │
└──────────────────────┬──────────────────────────────────────┘
                       │ event stream / context
┌──────────────────────▼──────────────────────────────────────┐
│          Agent Layer (LangGraph + agent-harness)            │
│  Perception ─► Triage ─► Plan ─► Critique ─► Act ─► Memory  │
│        (local Ollama models + OpenAI-compatible fallback)   │
└─────────────────────────────────────────────────────────────┘
```

- **OPNsense** enforces edge policy and mirrors packet data for inspection.
- **Suricata** flags signature and anomaly detections, including ransomware indicators.
- **Zeek** adds protocol-aware context and asset attribution.
- **Ollama** hosts local language and reasoning models, with LangGraph orchestrating the investigation flow.
- **Agent layer** leverages agent-harness to coordinate tools, validate remediation plans, and record AGPL-compliant audit trails.

## Quickstart

```bash
# 1. Clone and enter the repo
git clone https://github.com/example/edge-sentinel.git
cd edge-sentinel

# 2. Copy default environment variables
cp .env.example .env
# Edit .env to set OPENAI_BASE_URL, OPENAI_API_KEY, MODEL, and local sensor endpoints

# 3. Launch the stack (OSS core + agent layer)
docker-compose up -d

# 4. Follow the agent and sensor logs
docker-compose logs -f agent

# 5. Run tests or linting as needed
docker-compose exec agent pytest
```

## License

Edge Sentinel is released under the [AGPL-3.0 license](./LICENSE) so you can audit, adapt, and redistribute the entire appliance.
