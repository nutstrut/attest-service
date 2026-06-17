# Real x402 Payment Evidence — `/pay/url-summary` v0.1

**Date:** 2026-06-17
**Repos touched:** `/home/ubuntu/attest-service` (only).
**Authoritative dependency (unchanged):** `/home/ubuntu/morpheus` — `morpheus.sar402` +
`morpheus.sar402_agent`. No SAR-402 schema, builder, validator, or governing
architecture was modified.

## Outcome: **Option B — code fully prepared for real x402 evidence; a real
on-chain payment was NOT executed (no funded wallet / facilitator account /
secrets present).**

The `/pay/url-summary` loop now supports two explicit, mutually-exclusive
payment-evidence modes:

- `x402_demo` — the existing controlled demo/test evidence (unchanged behavior),
- `x402_live` — real x402 evidence, verified (and, in record mode, settled)
  through the standard documented x402 **facilitator** verify/settle flow.

The live path is wired end-to-end through the *same* committed Morpheus SAR-402
ingestion layer (`run_evidence_doc` → committed builder → committed validator).
It was exercised with **real-shaped** facilitator verify/settle responses (an
injected facilitator client in tests) and produces a valid SAR-402 receipt whose
`payment_ref` is the real on-chain transaction reference. It refuses to run on a
real network only because no facilitator account, payer wallet, funding, or
secrets are configured in this environment.

## What was implemented

- **`x402_live.py`** (new): the honest live-payment boundary.
  - `X402Config` + `load_x402_config(...)` — loads/validates live config from
    env; lists every missing field clearly; normalizes `base` → `eip155:8453`.
  - `FacilitatorClient` — HTTP adapter for the standard x402 facilitator
    `/verify` + `/settle` endpoints (compatible with the Coinbase CDP / x402
    facilitator request/response shape). Injectable so an alternative documented
    facilitator can be swapped in and so tests run without network/wallet.
  - `build_payment_requirements(...)` — the standard x402 `PaymentRequirements`
    object the facilitator verifies against.
  - `verify_and_settle(...)` — runs verify (and settle for record mode); returns
    a result **only when the facilitator reports the payment valid**; raises
    `X402VerificationError` otherwise. Also rejects a facilitator-confirmed payer
    that does not match `X402_PAYER_ADDRESS`.
  - `build_live_x402_block(...)` — maps the verified result into the committed
    `normalize_demo` `x402` shape, preserving raw facilitator payloads as
    `quote_raw` / `payment_raw` without changing the SAR-402 schema.
- **`pay_url_summary.py`** (changed): added `payment_mode` + `x402_payment`
  request fields; split the evidence-doc builder into a payment-block builder and
  a shared envelope (`assemble_evidence_doc`); added `build_evidence_for_mode`
  dispatch and live error mapping (400 config / 402 unverified). `run_url_summary`
  now takes injectable `env` / `facilitator`. Response/summary now surface
  `payment_evidence`, `payment_ref`, and `facilitator`.
- **`tests/test_pay_url_summary.py`** (changed): added 13 live-mode tests.

### The honesty boundary (why `payment_state: verified` stays truthful)

The committed `build_record_mode_receipt` **always** stamps
`payment_state: verified` — there is no builder knob to express an unverified
payment in record mode. Therefore the honesty must live *before* the builder:
the live path only ever hands evidence to the committed builder **after** a real
facilitator verification (and, for record mode, a successful settlement with a
real transaction reference) has succeeded. If verification is missing, invalid,
incomplete, or the payer mismatches, the code **raises and produces no receipt**.
Live mode never silently falls back to demo evidence.

## Files changed

| File | Change |
|---|---|
| `x402_live.py` | new — live config + facilitator verify/settle adapter + live evidence normalization |
| `pay_url_summary.py` | modes (`x402_demo` / `x402_live`), shared envelope, live dispatch, response metadata |
| `tests/test_pay_url_summary.py` | +13 live-mode tests (config validation, no-fallback, verified loop, unverified/settlement/payer failures, authority boundary, secret non-leak, raw-payload preservation) |
| `reports/sar402-demo/real-x402-payment-evidence-report-v0.1.md` | this report |

## Test command and result

```bash
cd /home/ubuntu/attest-service
python3 -m pytest tests/test_pay_url_summary.py -q
```

Result: **24 passed** (11 pre-existing demo/gate/authority tests + 13 new
live-mode tests; no regressions).

## How live mode differs from demo mode

| | `x402_demo` | `x402_live` |
|---|---|---|
| payment evidence | synthetic, demo-marked | real facilitator-verified |
| `payment.from` (payer) | `0xDEMO…PAYER` | configured/verified wallet |
| `payment.tx` (`payment_ref`) | `x402_demo:<digest>` | **real on-chain tx hash** |
| `facilitator` | `x402_demo_facilitator` | configured facilitator URL |
| network / pay_to / asset / amount | demo constants | configured live values |
| verification | none (no wallet) | facilitator `/verify` (+ `/settle` for record) |
| if payment can't be verified | n/a (always “passes”) | **raises 402, no receipt** |
| raw evidence | none | `x402.quote_raw` + `x402.payment_raw` preserved |
| mode visible in | request, evidence doc, run report, HTTP response | same + real values in the SAR-402 payment block |

## Exact env/config required for a live x402 payment

```bash
export X402_MODE=x402_live
export X402_FACILITATOR_URL=https://<your-x402-facilitator>/   # /verify + /settle
export X402_PAY_TO=0x<resource-server-recipient-address>
export X402_NETWORK=base            # normalized to CAIP-2 eip155:8453
export X402_ASSET=USDC
export X402_ASSET_DECIMALS=6
export X402_ASSET_ADDRESS=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913  # Base USDC (optional but recommended)
export X402_AMOUNT=1000             # integer string, smallest unit (0.001 USDC)
export X402_PAYER_ADDRESS=0x<payer-wallet-address>
# Only if/when a local signing flow is wired (NOT in this pass); never commit/print:
# export X402_PAYER_PRIVATE_KEY=0x<payer-private-key>
```

`X402_MODE` may also be overridden per request via `payment_mode` in the body.
A `.env` file is gitignored; secrets are never committed, logged, or written to
artifacts (`X402Config.repr` and `public_dict()` redact the private key — covered
by a test).

## Evidence fields expected from a real x402 payment

- **Quote / 402 challenge:** quote id, resource, price (`amount`+`asset`+`decimals`),
  `pay_to`, network (CAIP-2), `quoted_at`, `expires_at`.
- **Payment payload (`x402_payment`, the decoded `X-PAYMENT` object):** payer,
  scheme, network, and the signed authorization payload.
- **Facilitator `/verify` response:** `isValid`, `invalidReason`, `payer`.
- **Facilitator `/settle` response (record mode):** `success`, `transaction`
  (the real on-chain tx hash → `payment_ref`), `network`, `payer`.
Raw `/verify` and `/settle` responses and the `PaymentRequirements` are preserved
under `x402.payment_raw` / `x402.quote_raw`.

## Was a real payment executed?

**No.** No funded wallet, facilitator account, or secrets exist in this
environment. The live path was validated with **real-shaped** facilitator
responses via an injected client. Producing a real on-chain payment here would
require fabricating wallet/settlement evidence, which is explicitly out of bounds.

## Generated receipt (live path, real-shaped facilitator evidence)

A live-path run preserves artifacts under
`reports/sar402-demo/runs/<run_id>/` (gitignored): `source-evidence.json`,
`normalized-evidence.json`, `receipt.json`, `report.json`.

Receipt summary from the verified live-path loop:

| field | value |
|---|---|
| schema_id | `sar_402_settlement_v0.1` |
| profile | `sar-402` |
| sar_verdict | `PASS` |
| verification_mode | `record` |
| verification_point | `post_delivery` |
| payment_state | `verified` (from real facilitator verify+settle) |
| delivery_state | `confirmed` |
| settlement_state | `delivered` |
| continuity.executor_continuity | `PASS` |
| authority_binding | `{acting_party: resource_server, verifier_has_execution_authority: false}` |
| integrity.digest | `sha256:…` (canonical) |
| payment_ref | real on-chain tx hash (e.g. `0x5f60…aabbcc`) — **not** `x402_demo:` |
| facilitator | configured `X402_FACILITATOR_URL` |

## Blockers (no real payment executed)

1. No x402 **facilitator** account / endpoint configured (`X402_FACILITATOR_URL`).
2. No **payer wallet** configured (`X402_PAYER_ADDRESS`) and no signed
   `x402_payment` payload available.
3. The payer wallet must be **funded** with the asset (e.g. Base USDC) to settle.
4. (For local signing) no `X402_PAYER_PRIVATE_KEY` and no signing dependency
   (`eth-account` / `x402`) wired — this pass accepts a *pre-signed*
   `x402_payment` payload instead.

## Next bounded pass: real wallet/facilitator execution

This is the next operational blocker, **not** completion. `x402_demo` must not
become the permanent state by accident.

- **Exact missing env vars:** `X402_FACILITATOR_URL`, `X402_PAY_TO`,
  `X402_PAYER_ADDRESS` (and `X402_AMOUNT`, `X402_NETWORK`, `X402_ASSET` if not yet
  set). `X402_PAYER_PRIVATE_KEY` only if local signing is added.
- **Payer wallet needed?** Yes — a wallet that controls `X402_PAYER_ADDRESS`.
- **Must it be funded?** Yes — funded with the target asset on the target network
  to settle the transfer.
- **Target network:** Base — `X402_NETWORK=base` (CAIP-2 `eip155:8453`).
- **Target asset:** USDC (Base USDC `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`,
  6 decimals).
- **Target facilitator:** a documented x402 facilitator exposing `/verify` and
  `/settle` (e.g. the Coinbase CDP / x402 facilitator); set its base URL as
  `X402_FACILITATOR_URL` and complete any required account setup.
- **Exact command/curl/test to run once config exists:**

  ```bash
  # 1. set the env vars above (real facilitator + funded payer wallet)
  # 2. start the server
  python3 -m uvicorn attest_service:app --port 8099

  # 3. obtain the 402 quote + produce a signed x402 payment payload for the
  #    resource, then submit it for verify/settle + SAR-402 receipt generation:
  curl -s -X POST http://127.0.0.1:8099/pay/url-summary \
    -H 'Content-Type: application/json' \
    -d '{
      "url": "https://example.com",
      "mode": "record",
      "payment_mode": "x402_live",
      "x402_payment": { ...decoded X-PAYMENT payload... }
    }'
  ```

  Test that exercises the same path with real-shaped facilitator evidence:

  ```bash
  python3 -m pytest tests/test_pay_url_summary.py \
    -k "live_mode_full_loop_pass_with_mocked_facilitator" -q
  ```

- **Receipt field that proves the payment is real (not `x402_demo`):**
  `receipt.payment.payment_ref` (response `receipt_summary.payment_ref`) — for a
  real payment it is the on-chain settlement **transaction hash** returned by the
  facilitator `/settle` call, and it never carries the `x402_demo:` prefix.
  `receipt.payment.facilitator` is the configured facilitator URL (not
  `x402_demo_facilitator`), and `response.payment_evidence == "x402_live"`.

## Sample commands

```bash
# Demo mode (network-free, deterministic; default when X402_MODE unset):
curl -s -X POST http://127.0.0.1:8099/pay/url-summary \
  -H 'Content-Type: application/json' \
  -d '{"text":"Greenhouse Realty Group note: inventory tightened.","mode":"record"}'

# Live mode (requires live env + a signed x402_payment payload):
curl -s -X POST http://127.0.0.1:8099/pay/url-summary \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com","mode":"record","payment_mode":"x402_live","x402_payment":{ ... }}'
```

## Confirmation

Demo evidence is **not** presented as real settlement: demo runs are labelled
`payment_evidence: x402_demo` with a `payment_ref` of `x402_demo:<digest>` and an
explicit note; live runs require real facilitator verification and never fall
back to demo evidence. The verifier holds no execution authority in either mode
(`verifier_has_execution_authority: false`), enforced by the committed validator
and covered by tests. No commit, no push, no deploy.
