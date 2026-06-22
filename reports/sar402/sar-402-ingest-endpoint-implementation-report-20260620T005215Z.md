# SAR-402 Ingest Endpoint — Implementation Report

**Date:** 2026-06-20T00:52:15Z
**Service:** `attest-service` (DefaultVerifier)
**Status:** Implemented, tested locally, route registered.

## What was added

| File | Change |
|---|---|
| [`sar402_receipts.py`](../../sar402_receipts.py) | New module: `POST /v1/sar-402/receipts` router + testable core `record_sar402_receipt`. |
| [`attest_service.py`](../../attest_service.py) | Registered `sar402_receipts_router` via `app.include_router`. |
| [`tests/test_sar402_receipts.py`](../../tests/test_sar402_receipts.py) | New test suite (11 tests). |

Confirmed registered routes: `POST /v1/sar-402/receipts`, `POST /v1/attest`,
`POST /pay/url-summary` all present. No existing route was modified or retargeted.

## What it accepts

The SDK's normalized `sar_402_settlement_v0.1` payload (full receipt incl.
`integrity.digest`). No `continuity_input + sar_input` required. Hashes/metadata
only — raw request/response bodies are neither required nor stored.

## What it refuses

Gate mode; `verifier_has_execution_authority` ≠ false; `verifier_controls_resource_release`
≠ false; `resource_server_controls_delivery` ≠ true; missing required fields;
missing `integrity.digest`; any committed-schema/authority/continuity violation
→ **422, nothing stored, no Explorer link**. Bad/missing API key (when configured)
→ 401. Internal persistence failure → 500 (never a fake success).

## How authority boundaries are enforced

1. Explicit Phase-1 hard-rejects (`authority_binding_errors`) on the three SDK
   doctrine fields — run before persistence.
2. Committed Morpheus validator (`validate_receipt`) on a schema-conformant
   projection (committed schema + authority boundary + continuity semantics).

The endpoint records that **the resource server controls delivery** and never
states/implies DefaultVerifier controlled delivery, execution, or funds.

### Documented schema gap

Committed schema is `additionalProperties: false`; the SDK authority binding adds
`verifier_controls_resource_release` / `resource_server_controls_delivery` and may
add `request_digest`. We validate a projection of the committed-schema fields
(enforcing the extra booleans ourselves) and **store the full payload**. Follow-up:
align via `sar-402-settlement-v0.2` (add the booleans) or drop them in the SDK.

## How it relates to SDK Phase 1

The SDK (`packages/sar-402/src/client.ts`) already defaults to:

```
DEFAULT_ENDPOINT       = 'https://defaultverifier.com'
PROPOSED_RECEIPT_PATH  = '/v1/sar-402/receipts'
```

**The backend route now matches the SDK's configured path exactly:
`POST /v1/sar-402/receipts`.** The SDK posts the payload and reads `receipt_id`
and `explorer_url` from the JSON response — both are returned by this endpoint.
No SDK code change is required for the path to work.

**Recommended (doc-only) SDK follow-up — optional, not blocking:** the comments
in `client.ts` / `types.ts` and the README still say the route is "not yet
exposed / pending backend support." Those notes are now stale and should be
updated to state the route is live. This is documentation only; functionally the
SDK and backend are aligned today.

## Explorer compatibility — proven, not assumed

`tests/test_sar402_receipts.py::test_receipt_is_persisted_and_discoverable`:

- Creates a receipt through the endpoint.
- Confirms it is persisted in the same `RECEIPT_LEDGER` Explorer reads.
- Looks it up by id via `find_receipt` **and** `GET /v1/attest/receipt/{id}`
  (the live, non-dead lookup route returned as `receipt_lookup_path`).
- Confirms `GET /v1/receipts` (recent-receipts surface) includes it.

**Remaining for the public Explorer frontend:** `explorer_url` points at
`https://sarexplorer.com/?receipt_id=...` (configurable via
`SAR402_EXPLORER_BASE`; the legacy `defaultverifier.com/explorer` surface
remains compatible). The backend data is fully present and queryable; whether
that exact frontend URL renders the receipt depends on the Explorer web app
surfacing `sar_402_settlement` records from the shared ledger — a frontend
follow-up. The **provable live link today** is `receipt_lookup_path`
(`/v1/attest/receipt/{id}`). We do not claim a rendered "live Explorer link" as
complete.

## Auth

Phase 1 Option B: optional `SAR402_INGEST_API_KEY`, enforced only when set
(`Authorization: Bearer`). Unset = open early-adopter access + strict validation.
Rate limiting = documented TODO (no limiter yet).

## Tests run

`python3 -m pytest tests/` → **35 passed** (24 existing `/pay/url-summary` +
11 new). Highlights:

- valid payload accepted; response has `receipt_id` + Explorer URL;
- projection passes the committed validator;
- persisted + discoverable by id and in recent receipts;
- missing required field → 422 (nothing stored);
- `verifier_has_execution_authority: true` → 422 (no receipt, no link);
- `verifier_controls_resource_release: true` → 422;
- `resource_server_controls_delivery: false` → 422;
- gate mode → 422 (nothing stored);
- missing `integrity.digest` → 422;
- raw bodies not required;
- optional API key enforced only when configured.

Existing `/pay/url-summary` tests unchanged and passing. `/v1/attest` route
untouched (no automated tests exist for it in this repo; behavior unchanged).

## What remains before public release

1. **Rate limiting** on the ingest endpoint (currently a TODO placeholder).
2. **Schema v0.2 alignment** for the two extra authority booleans (remove the
   projection workaround).
3. **Explorer frontend** rendering of `sar_402_settlement` receipts at the public
   `explorer_url`.
4. **SDK doc refresh** marking the route live (functional path already matches).
5. Decide production default for `SAR402_INGEST_API_KEY` (open vs. required).

## Success condition

> The TypeScript SAR-402 middleware can POST normalized evidence to
> `POST /v1/sar-402/receipts` on DefaultVerifier. DefaultVerifier records the
> evidence and returns a receipt id and Explorer URL, while the resource server
> retains control over payment handling, execution, and delivery.

Met at the backend/API level (path matches, evidence recorded, id + URL
returned, authority boundary enforced). Public-Explorer rendering and rate
limiting remain as listed follow-ups.
