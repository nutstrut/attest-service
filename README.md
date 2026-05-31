# attest-service

Single-call verification and Agent Activation Flow orchestration for agent
execution integrity. The service runs pre-execution continuity evaluation,
post-execution settlement verification, and stores public evidence records for
Explorer v1.

Part of the DefaultVerifier infrastructure alongside settlement-witness and
continuity-analyzer.

## Architecture

```text
attest-service (:3004)
  -> continuity-analyzer (:3002)
  -> settlement-witness (:3001)
```

Storage is append-only JSONL:

- `attest_sessions_master.jsonl`
- `agent_registry_master.jsonl`
- `agent_activation_master.jsonl`
- `activation_analytics_master.jsonl`
- `attest_chains_master.jsonl`
- `attest_receipts_master.jsonl`

## Existing Attestation Endpoints

- `POST /v1/attest`
- `POST /v1/attest/begin`
- `POST /v1/attest/complete`
- `GET /v1/attest/session/{session_id}`
- `GET /v1/attest/chain/{chain_id}`

Existing receipt lookup and browser-side verification behavior must remain
compatible with legacy receipts. Receipts without `receipt_context`, `agent_id`,
`activation_id`, or `chain_id` must still render, look up, and verify.

## Agent Activation Flow V1

Activation stages are monotonic:

```text
registered -> activated -> verified -> chained -> continuous
```

Receipt contexts:

```text
activation_demo
real_task
continuity_pair
```

TrustScore is completely separate. This service does not compute or mutate
TrustScore. Explorer links to existing TrustScore pages at:

```text
/trustscore/{agent_id}
```

The existing badge system is unchanged. Explorer only displays the existing
badge image at:

```text
/badge/{agent_id}.svg
```

## New API Endpoints

- `POST /v1/agents/register`
- `GET /v1/agents?limit=50`
- `GET /v1/agents/{agent_id}`
- `POST /v1/agents/{agent_id}/activate`
- `POST /v1/agents/{agent_id}/continuity`
- `GET /v1/agents/{agent_id}/activations?limit=50`
- `GET /v1/agents/{agent_id}/summary`
- `GET /v1/activation/{activation_id}`
- `GET /v1/chains?limit=50`
- `GET /v1/chains?agent_id={agent_id}&limit=50`
- `GET /v1/receipts?agent_id={agent_id}&limit=50`
- `GET /v1/explorer/metrics`

List endpoints default to `limit=50` and cap at `limit=200`.

Default sorting:

- Agents: `updated_at desc`
- Chains: `created_at desc`
- Activations: `created_at desc`
- Receipts: existing sort is preserved where Explorer already has a receipt source; local receipt records sort by `created_at desc`.

## Explorer V1

Explorer v1 has these top-level navigation tabs:

```text
Overview
Agents
Receipts
Chains
Metrics
```

Do not redesign Explorer branding. Add tabs and views within the existing
Default Settlement visual style.

### Overview

Shows existing Explorer metrics and recent receipts, plus:

- `registered_agents_total`
- `activated_agents_total`
- `verified_agents_total`
- `activation_conversion_rate`
- `chains_total`

### Agents

Lists registered agents with:

- `agent_id`
- `display_name`
- `activation_stage`
- `latest_activation_id`
- `latest_chain_id`
- `latest_sar_receipt_id`
- `updated_at`

Each `agent_id` links to Agent Detail using the client-side route:

```text
#/agent/{agent_id}
```

Agent IDs may contain `:` and other special characters. Explorer must
URL-encode `agent_id` when building links and decode it before API calls.

### Agent Detail

Agent Detail is reached from the Agents tab and is not a top-level tab.

Locked client-side route:

```text
#/agent/{agent_id}
```

It displays:

- `agent_id`
- `display_name`
- `activation_stage`
- status / latest registry state
- `registered_at`
- `updated_at`
- `latest_activation_id`
- `latest_chain_id`
- `latest_sar_receipt_id`
- TrustScore link: `/trustscore/{agent_id}`
- Badge image: `/badge/{agent_id}.svg`
- Markdown badge embed snippet
- Recent receipts for this agent
- Recent chains for this agent
- Activation history
- Evidence summary

Preferred data source:

```text
GET /v1/agents/{agent_id}/summary
```

Summary response includes:

```json
{
  "evidence_summary": {
    "receipt_count": 0,
    "chain_count": 0,
    "activation_count": 0,
    "latest_activity_at": "ISO-8601 string|null"
  }
}
```

Required empty states:

- `No registered agents yet.`
- `No chains yet.`
- `No receipts yet.`
- `No activation history yet.`

### Receipts

Preserve existing receipt view, lookup, and browser-side verification behavior.
Add `receipt_context` where available. Legacy receipts without activation fields
must remain compatible.

### Chains

Lists chain records with:

- `chain_id`
- `agent_id`
- `continuity_receipt_id`
- `sar_receipt_id`
- stage/context
- `created_at`

Use:

```text
GET /v1/chains
GET /v1/chains?agent_id={agent_id}
```

### Metrics

Shows the exact output of:

```text
GET /v1/explorer/metrics
```

Example:

```json
{
  "registered_agents_total": 100,
  "activated_agents_total": 72,
  "verified_agents_total": 64,
  "activation_conversion_rate": 0.72,
  "chains_total": 81,
  "generated_at": "2026-05-31T18:15:00Z"
}
```

## Quick Start

```bash
curl -X POST https://defaultverifier.com/v1/attest \
  -H "Content-Type: application/json" \
  --data @v1-attest-pass-test.json
```

Register an agent:

```bash
curl -X POST http://127.0.0.1:3004/v1/agents/register \
  -H "Content-Type: application/json" \
  --data @v1-agent-register-test.json
```

Activate an agent:

```bash
curl -X POST http://127.0.0.1:3004/v1/agents/agent%3Ademo-alpha/activate \
  -H "Content-Type: application/json" \
  --data @v1-agent-activate-demo-test.json
```

## Example Payloads

- `v1-attest-pass-test.json` - all continuity predicates pass, SAR returns PASS
- `v1-attest-partial-fail-test.json` - executor_continuity fails, SAR returns FAIL
- `v1-agent-register-test.json` - register a demo agent
- `v1-agent-activate-demo-test.json` - activation demo request
- `v1-agent-continuity-pair-test.json` - continuity pair request

## Deployment

Systemd:

```bash
cp attest-service.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable attest-service
systemctl start attest-service
```

Nginx:

```nginx
location /v1/attest {
    proxy_pass http://127.0.0.1:3004;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}

location /v1/agents {
    proxy_pass http://127.0.0.1:3004;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}

location /v1/chains {
    proxy_pass http://127.0.0.1:3004;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}

location /v1/explorer {
    proxy_pass http://127.0.0.1:3004;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
```
