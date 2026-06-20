# Edge Sentinel Architecture

Edge Sentinel delivers a four-layer edge-operations stack that blends battle-tested network telemetry with an agentic automation layer. Each layer is explicitly scoped so operators can reason about the hand-offs from packet capture to human-approved remediation.

## Layer overview

```text
Layer 4 ─ Agentic Workflows (Alert Triage, Threat Hunting, Remediation, Business Report)
Layer 3 ─ Ollama + LangGraph local AI brain
Layer 2 ─ Zeek connection logging & protocol analysis
Layer 1 ─ OPNsense 25.7+ perimeter with Suricata 8 (Emerging Threats rules)
```

## Layer 1 — OPNsense 25.7+ perimeter

- **Role:** Acts as the edge firewall, NAT gateway, and VPN concentrator for branch or on-prem sites.
- **Suricata 8 integration:** OPNsense 25.7+ bundles Suricata 8 for IDS/IPS. Edge Sentinel enables the Emerging Threats ruleset to flag malicious signatures and anomaly classes in real time.
- **Data products:**
  - Firewall pass/block events and policy hits.
  - Suricata alert logs (fast.log, eve.json) forwarded to Layer 2.
  - VPN session metadata for operator awareness.
- **Operational notes:** Suricata operates in IDS mode by default; switching to IPS mode should follow staged rollouts with change-control review.

## Layer 2 — Zeek telemetry fabric

- **Role:** Zeek ingests mirrored traffic or Suricata-forwarded events to produce high-fidelity connection logs and protocol transcripts.
- **Outputs:** `conn.log`, `http.log`, `dns.log`, and custom notice streams that capture higher-level behaviors than raw packet alerts.
- **Enrichment:** Zeek adds context (service types, user agents, TLS certificate fingerprints) that the agentics layer uses to distinguish benign from malicious traffic patterns.
- **Integration:** Logs are shipped to object storage or the Edge Sentinel datastore via Filebeat/Vector, ensuring consistent schemas for downstream analytics.

## Layer 3 — Ollama + LangGraph local AI brain

- **Role:** Hosts the on-prem LLM runtime and orchestration graph that powers decision-making without external data egress.
- **Components:**
  - **Ollama:** Provides GPU/CPU-accelerated model serving compatible with OpenAI-style APIs.
  - **LangGraph:** Orchestrates multi-node reasoning, tool invocation, and memory checkpointing for complex incident workflows.
- **Interfaces:** Exposes an OpenAI-compatible endpoint consumed by the agent service (`agents/` package). The same endpoint can be swapped for a cloud provider by editing environment variables (see configuration doc).
- **Resilience:** Local tensor checkpoints and prompt caches keep inference available during WAN outages.

## Layer 4 — Agentic workflows and scope boundaries

- **Workflows:**
  1. **Alert Triage** — Correlates Suricata, Zeek, and OPNsense events to prioritize incidents and recommend operator follow-up.
  2. **Threat Hunting** — Builds hypotheses from Zeek-derived behaviors, running guided searches against recent telemetry.
  3. **Remediation** — Drafts remediation plans, proposes firewall/routing changes, and sequences execution tasks with human approval gates.
  4. **Business Report** — Summarizes incident impact and remediation status for stakeholders in clear, auditable language.

- **Scope boundaries ("should" responsibilities):**
  - Ingest and reason over alerts, connection metadata, and historical findings.
  - Recommend configuration adjustments and remediation steps with clear rationale.
  - Request human sign-off before enforcing disruptive network policy changes.
  - Document actions to the agent harness for traceability and after-action review.

- **Out-of-scope ("should not" activities):**
  - Modify OPNsense firmware, base OS packages, or hypervisor settings autonomously.
  - Disable protective controls (e.g., Suricata rule sets, VPN multi-factor) without explicit operator approval.
  - Execute irreversible remediation (e.g., host reimaging) until a human validates prerequisites.
  - Exfiltrate sensitive telemetry outside the controlled environment.

## Cross-layer data flow

1. OPNsense 25.7+ and Suricata 8 emit firewall, VPN, and IDS/IPS events.
2. Zeek enriches those events with protocol context and writes structured logs.
3. Collectors (e.g., Filebeat, Vector, or the harness client) stream logs into the local data lake used by LangGraph nodes.
4. The agent service retrieves high-signal events, validates them through guardrails, and queries the Ollama-served model via the OpenAI-compatible API.
5. LangGraph coordinates LLM reasoning, tool usage, and memory, returning structured plans.
6. Agentic workflows apply the plans: triaging alerts, forming hunts, drafting remediation actions, and producing executive-friendly reports.
7. Human operators review suggested actions, approve or reject remediation steps, and feed decisions back into the harness for learning and audit trails.

## Deployment considerations

- Each layer is containerized in `docker-compose.yml`: networking ensures the agent service can reach Ollama, Zeek exporters, and the harness.
- Persistent volumes store Suricata and Zeek logs, enabling replay during model fine-tuning or post-incident forensics.
- Secure transport (TLS) and role-based credentials should be enforced on inter-layer APIs to keep telemetry confined to the edge tenancy.
