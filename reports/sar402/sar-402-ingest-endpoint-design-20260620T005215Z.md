# SAR-402 Ingest Endpoint — Design

**Date:** 2026-06-20T00:52:15Z
**Service:** `attest-service` (DefaultVerifier)
**Route:** `POST /v1/sar-402/receipts`
**Module:** [`sar402_receipts.py`](../../sar402_receipts.py)

## Purpose

Expose a credible, minimal, public-facing ingestion surface that external x402
resource-server middleware (the `@defaultsettlement/sar-402` TypeScript SDK) can
POST a **resource-server-built, normalized SAR-402 receipt** to. DefaultVerifier
**records** the evidence and returns a receipt id + Explorer URL. The resource
server retains control over payment handling, execution, and delivery.

SAR = **Settlement Attestation Receipt**.

## Why a new endpoint (not `/v1/attest`, not `/pay/url-summary`)

- `/v1/attest` is a different **internal** contract: it requires
  `continuity_input` + `sar_input` and forwards to internal continuity /
  settlement-witness services (`127.0.0.1:3002` / `:3001`). It is not a drop-in
  ingest target and the SDK must not be retargeted to it.
- `/pay/url-summary` is an all-in-one **paid demo** that performs delivery and
  builds its own receipt through the Morpheus builder. It does not ingest an
  externally-built receipt.
- The SDK already defaults to `/v1/sar-402/receipts`
  (`PROPOSED_RECEIPT_PATH` in `client.ts`). This endpoint makes that default real.

## Doctrine enforced

> Capability ≠ Authority · Authority ≠ Execution · Execution ≠ Verification ·
> Verification must leave evidence · Verified restraint is the product ·
> Recommendation ≠ approval · Approval ≠ execution · Transport ≠ authority

The endpoint **records evidence**. It never executes the resource action,
authorizes delivery, custodies/moves funds, or controls resource release.

## What it accepts

A JSON object matching the SDK's normalized `sar_402_settlement_v0.1` payload
(`Sar402Payload` in the SDK's `types.ts` / output of `buildSar402Payload` in
`normalize.ts`). The caller does **not** need to know the internal
`continuity_input + sar_input` shapes.

Privacy default: hashes + metadata only. `delivery.evidence_digest` and the
optional `request_digest` are digests, never raw bodies. No raw request/response
body is required or stored.

## What it refuses (hard 4xx, nothing stored)

| Condition | Response |
|---|---|
| `verification_mode == "gate"` | 422 — gate unsupported in Phase 1 (record-only) |
| `authority_binding.verifier_has_execution_authority` ≠ `false` | 422 |
| `authority_binding.verifier_controls_resource_release` present & ≠ `false` | 422 |
| `authority_binding.resource_server_controls_delivery` present & ≠ `true` | 422 |
| missing required schema field (committed validator) | 422 |
| missing `integrity.digest` (used as receipt id) | 422 |
| committed schema / authority / continuity violation | 422 |
| API key configured but missing/wrong | 401 |
| persistence failure (internal) | 500 (no fake success) |

These are **hard rejections**, not warnings/downgrades/silent rewrites.

## Authority boundary enforcement

Two layers, both run **before** persistence:

1. **Explicit Phase-1 hard-rejects** (`authority_binding_errors`) on the SDK's
   richer authority binding — the three doctrine fields above.
2. **Committed validator** (`morpheus.sar402.validate.validate_receipt`) which
   re-checks `verifier_has_execution_authority == false`, gate-controller
   forbidden-identity rules, and continuity semantics against the committed
   schema (`sar-402-settlement-v0.1.schema.json`).

### Schema projection (documented gap)

The committed schema is `additionalProperties: false`. The SDK's
`authority_binding` carries two extra doctrine booleans
(`verifier_controls_resource_release`, `resource_server_controls_delivery`) and
may carry a root `request_digest` — none of which are in the committed schema.
To validate without bypassing the schema, the endpoint validates a
**projection** containing exactly the committed-schema fields (extra authority
booleans stripped, which we enforce independently and more strictly), while
**storing the full original payload**. See `schema_projection`.

This is the one genuine SDK↔schema divergence. Recommended follow-up: extend the
profile to `sar-402-settlement-v0.2` adding the two authority booleans, or have
the SDK omit them (the canonical `verifier_has_execution_authority: false` is
already mandatory).

## Response shape

```json
{
  "status": "recorded",
  "receipt_id": "sha256:...",
  "explorer_url": "https://defaultverifier.com/explorer?receipt_id=sha256%3A...",
  "receipt_lookup_path": "/v1/attest/receipt/sha256%3A...",
  "profile": "sar-402",
  "schema_id": "sar_402_settlement_v0.1",
  "mode": "record",
  "schema_backend": "jsonschema-draft2020-12",
  "authority_binding": { "verifier_has_execution_authority": false, "acting_party": "resource_server" },
  "receipt": { "...": "full stored receipt incl. receipt_id" }
}
```

- `receipt_id` = the payload's `integrity.digest` (`sha256:...`). The SDK reads
  `receipt_id` and `explorer_url` defensively; both are present.
- `explorer_url` points at the public Explorer frontend (configurable via
  `SAR402_EXPLORER_BASE`). `receipt_lookup_path` is the **live, provable** backend
  route that returns the stored receipt.

## Persistence / Explorer compatibility

Receipts are stored via the existing `write_receipt` → `RECEIPT_LEDGER`
(`attest_receipts_master.jsonl`) machinery — the same store Explorer / recent
receipts read. They are retrievable by id via `find_receipt` /
`GET /v1/attest/receipt/{id}` and listed by `GET /v1/receipts`. `agent_id` is set
to the receipt's `derived_agent_id` so agent-scoped surfaces include it.

## Auth (Phase 1, Option B)

Optional API key via `SAR402_INGEST_API_KEY`, enforced **only when set**
(`Authorization: Bearer <key>`). Unset = early-adopter/demo open access with
strict validation. Rate limiting is a documented TODO (no per-IP limiter yet).
