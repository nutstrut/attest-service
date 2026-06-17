# SAR-402 Controlled Demo Loop — `/pay/url-summary` v0.1

**Date:** 2026-06-17
**Repos touched:** `/home/ubuntu/attest-service` (only).
**Authoritative dependency (unchanged):** `/home/ubuntu/morpheus` — `morpheus.sar402` +
`morpheus.sar402_agent`.

## What this is

The first runnable controlled SAR-402 demo loop. A controlled, x402-style paid
URL-summary action that:

1. Accepts a controlled request (`url` to fetch, or inline `text` for a
   network-free deterministic run).
2. Produces **deterministic delivery evidence**: `requested_url`, `resolved_url`,
   `status_code`, `title`, `word_count`, `content_sha256`, a short deterministic
   `excerpt`, `delivered_at`, and a `delivery_evidence_digest` binding the whole
   delivered object.
3. Normalizes payment + delivery evidence into the **committed** demo ingestion
   shape (`morpheus.sar402_agent.normalize_demo`).
4. Calls the **committed** Morpheus SAR-402 runner (`run_evidence_doc`), which
   builds via the committed builder and re-validates via the committed validator.
5. Preserves source evidence, normalized view, receipt, and a run report under
   `reports/sar402-demo/runs/` (gitignored).
6. Returns enough to inspect/link the generated receipt.

No receipt is hand-written. No new schema is defined. The SAR-402 builder /
validator / ingestion layer in `/home/ubuntu/morpheus` remains authoritative.

## Outcome: **Option B — controlled demo payment evidence**

> The generated receipt was produced from **controlled `x402_demo` payment
> evidence — NOT a real on-chain settlement.**

The delivery leg is real (the resource is actually fetched/summarized and bound
by digest). The **payment leg is demo**: there is no wallet, facilitator, or
settled transaction. The demo nature is made visible, not hidden:

- response field `payment_evidence: "x402_demo"` + an explicit note,
- the receipt `payment` block carries demo-marked values (`payer` =
  `0xDEMO…PAYER`, `payment_ref` = `x402_demo:<digest>`,
  `facilitator` = `x402_demo_facilitator`),
- run report records `source_kind: demo_url_summary`,
- receipt `issuer.environment` = `test`.

`payment_state` is `verified` because the schema vocabulary is
`(verified|unverified|failed|indeterminate)` — there is no separate "demo" state.
The demo provenance is therefore carried in the fields above, not by mislabeling
the state.

### Exact blocker to a real x402 payment

A real x402 settlement requires evidence the environment does not currently have:

- a funded payer **wallet / private key** (e.g. a Base USDC account),
- an **x402 facilitator / paywall** to issue the 402 quote and verify payment
  (e.g. an x402 middleware + facilitator endpoint),
- the **on-chain transaction hash** of the actual payment to use as
  `payment_ref` instead of the synthetic `x402_demo:` reference.

None of these secrets/dependencies are present, so a live payment cannot be
executed in this pass without fabricating one — which is explicitly out of bounds.

### Exact next bounded pass (do this next, not more SAR-402 hardening)

Wire a real wallet + facilitator + x402 payment and feed the **real** payment
evidence into the *same* ingestion path. Concretely:

1. Provide secrets (never commit): `X402_PAYER_PRIVATE_KEY`,
   `X402_FACILITATOR_URL`, `X402_PAY_TO`, `X402_NETWORK` (e.g. `eip155:8453`),
   `X402_ASSET` (e.g. USDC contract / `currency`+`decimals`).
2. Add an x402 client step in `pay_url_summary.py` that requests the 402 quote,
   pays it via the wallet, and captures the real `tx`, `from`, `paid_at`,
   `verified_at`, and quote fields.
3. Replace the `DEMO_*` constants / `x402_demo` block with those real values;
   the `normalize_demo` shape and the committed SAR-402 layer are unchanged.
4. Set `payment_evidence: "x402_live"` and `issuer.environment` accordingly.

`demo_payment_evidence` must NOT become the production assumption — it is a
bounded stand-in for the payment leg only.

## Files created / changed (attest-service)

- `pay_url_summary.py` — new: delivery + evidence-doc + endpoint (`POST /pay/url-summary`).
- `attest_service.py` — include the new router.
- `tests/test_pay_url_summary.py` — new: 11 tests covering the loop.
- `.gitignore` — ignore `reports/sar402-demo/runs/`.
- `reports/sar402-demo/url-summary-demo-report-v0.1.md` — this report.

## How to run

```bash
cd /home/ubuntu/attest-service

# Tests
python3 -m pytest tests/test_pay_url_summary.py -q

# Live server
python3 -m uvicorn attest_service:app --port 8099

# Inline text (network-free, deterministic):
curl -s -X POST http://127.0.0.1:8099/pay/url-summary \
  -H 'Content-Type: application/json' \
  -d '{"text":"Greenhouse Realty Group note: inventory tightened.","title":"demo","mode":"record"}'

# Real URL fetch (real delivery evidence):
curl -s -X POST http://127.0.0.1:8099/pay/url-summary \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com","mode":"record"}'

# Gate-mode (pre-delivery proof) — names an external controller:
curl -s -X POST http://127.0.0.1:8099/pay/url-summary \
  -H 'Content-Type: application/json' \
  -d '{"text":"...","mode":"gate","gate_controller":"resource_server:greenhouse-demo"}'
```

Artifacts land in `reports/sar402-demo/runs/<run_id>/`:
`source-evidence.json`, `normalized-evidence.json`, `receipt.json`, `report.json`.

## Sample generated record-mode receipt (preserved)

`reports/sar402-demo/runs/20260617T222956Z-record-demo_url_summary/receipt.json`

| field | value |
|---|---|
| schema_id | `sar_402_settlement_v0.1` |
| profile | `sar-402` |
| sar_verdict | `PASS` |
| verification_mode | `record` |
| verification_point | `post_delivery` |
| payment_state | `verified` (from `x402_demo` evidence) |
| delivery_state | `confirmed` |
| settlement_state | `delivered` |
| continuity.executor_continuity | `PASS` |
| authority_binding | `{acting_party: resource_server, verifier_has_execution_authority: false}` |
| integrity.digest | `sha256:7176983e…b909f0869` |

## Constraints honored

- No commit, no push, no deploy.
- Frontend untouched.
- SAR-402 architecture / schema / package unchanged; ingestion layer is authoritative.
- No real payment faked; demo evidence explicitly labeled.
- Verifier holds no execution authority; no forbidden gate controller permitted
  (enforced by the committed validator, covered by tests).
