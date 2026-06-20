# SAR-402 Live Ingestion Verification

- **Date (UTC):** 2026-06-20T01:38:11Z
- **Service commit:** `8e9f8f3` (feat: add SAR-402 receipt ingestion endpoint)
- **Host:** defaultverifier.com (Cloudflare → nginx → attest-service on 127.0.0.1:3004)
- **Code changed:** **No.** No production code, SDK, or nginx was modified. Only a
  read-only verification script was added under `reports/sar402/`.

## Endpoint tested

`POST https://defaultverifier.com/v1/sar-402/receipts` (record mode)

Payload built with the exact fixture shape from
[tests/test_sar402_receipts.py](tests/test_sar402_receipts.py) — the
`_base_payload()` / `_unique_payload(tag)` helpers were reproduced verbatim
(same canonicalization, same `sha256:` integrity digest) so the live test matches
the validated test fixture.

> Note: requests must send a browser-style `User-Agent`. Cloudflare returns
> `403 error code: 1010` for the default Python `urllib` agent. This is an edge
> WAF rule, not an application behavior.

## 1. Acceptance (record mode) — PASS

Full JSON response captured. Confirmed fields:

| Field | Expected | Observed |
|---|---|---|
| `status` | `recorded` | `recorded` ✓ |
| `receipt_id` | starts `sha256:` | `sha256:f8d131f82ea723e6931b5479eebc277e3e7c86e9b833ebf4a1fa8076a516bf68` ✓ |
| `explorer_url` | present | `https://defaultverifier.com/explorer?receipt_id=sha256%3Af8d131...bf68` ✓ |
| `receipt_lookup_path` | present | `/v1/attest/receipt/sha256%3Af8d131...bf68` ✓ |
| `profile` | `sar-402` | `sar-402` ✓ |
| `schema_id` | `sar_402_settlement_v0.1` | `sar_402_settlement_v0.1` ✓ |
| `mode` | `record` | `record` ✓ |

HTTP status: **200**. `schema_backend: local-structural`. Returned
`authority_binding.verifier_has_execution_authority = false`.

- **Generated receipt id:** `sha256:f8d131f82ea723e6931b5479eebc277e3e7c86e9b833ebf4a1fa8076a516bf68`
- **Lookup path:** `/v1/attest/receipt/sha256%3Af8d131f82ea723e6931b5479eebc277e3e7c86e9b833ebf4a1fa8076a516bf68`
- **Explorer URL:** `https://defaultverifier.com/explorer?receipt_id=sha256%3Af8d131f82ea723e6931b5479eebc277e3e7c86e9b833ebf4a1fa8076a516bf68`

## 2. Live lookup — PASS

`GET https://defaultverifier.com/v1/attest/receipt/{receipt_id}` → **HTTP 200**,
returns the stored record with matching `receipt_id`,
`receipt_type: sar_402_settlement`, `receipt_context: real_task`,
`created_at: 2026-06-20T01:35:38Z`. The receipt is persisted into the same store
the live lookup route reads.

## 3. Recent-receipts verification — PASS (locally); public path caveat

- The new receipt **is present** in the recent-receipts surface
  (`GET /v1/receipts` on the app, 127.0.0.1:3004): HTTP 200, appears as the
  most-recent entry (`has_new: true`, count 200). This is the same surface the
  test `test_receipt_is_persisted_and_discoverable` asserts against.
- **Caveat — public path not proxied:**
  `GET https://defaultverifier.com/v1/receipts` returns **nginx 404**. The nginx
  config (`/etc/nginx/sites-enabled/default`) proxies only `/v1/agents`,
  `/v1/sar-402/`, and `/v1/attest` to attest-service (3004). The recent-list
  endpoint `/v1/receipts` was **never publicly exposed**; the public
  `/settlement-witness/receipts*` surfaces proxy to a *different* service
  (127.0.0.1:3001) and do not reflect SAR-402 ingestion.
- This is a **pre-existing exposure gap, not a route regression**, so per the
  task constraints nginx was **left unmodified**. Persistence itself is fully
  confirmed via the public lookup route (HTTP 200 above) and the local
  recent-list surface.

## 4. Authority hard rejection — PASS

Unique payload with `authority_binding.verifier_has_execution_authority = true`,
POSTed live → **HTTP 422**:

```json
{"detail":{"authority_errors":["authority_binding.verifier_has_execution_authority must be exactly false — DefaultVerifier records evidence and never holds execution authority"]}}
```

Rejected payload digest:
`sha256:8f2598e08a45eb31bc2430fb36fa5c0d7a62e2e21ece7868d34261d3daee0281`.
Lookup `GET /v1/attest/receipt/{that digest}` → **HTTP 404** → no receipt stored
for the rejected payload. ✓

## 5. Gate rejection — PASS

Unique payload with `verification_mode = "gate"`, POSTed live → **HTTP 422**:

```json
{"detail":"verification_mode 'gate' is not supported by this ingestion endpoint in Phase 1 (record-only). gate mode asserts an external release controller and is out of scope here."}
```

## 6. Explorer URL check — PASS (HTML only)

`GET` of the returned `explorer_url` → **HTTP 200**, ~136 KB HTML (not a 404).

> **Frontend caveat:** only the HTML document fetch was performed. Visual
> Explorer rendering of this receipt (that the receipt actually displays in the
> browser UI) was **not** confirmed and still requires visual verification in a
> browser.

## Commands / script used

Script: [reports/sar402/live_ingest_check.py](reports/sar402/live_ingest_check.py)
(reproduces `_base_payload`/`_unique_payload` from the test, sends record /
authority-true / gate payloads, and checks lookup + explorer + recent surfaces).

```
python3 reports/sar402/live_ingest_check.py
# plus:
curl -A 'Mozilla/5.0' https://defaultverifier.com/v1/attest/receipt/<enc-id>      # 200
curl http://127.0.0.1:3004/v1/receipts?limit=200                                  # 200, has_new=true
curl -A 'Mozilla/5.0' https://defaultverifier.com/v1/receipts                     # 404 (not proxied)
```

## Doctrine preservation

Nothing in this verification asserts that Default Settlement executes, authorizes
delivery, controls resource release, custodies funds, or moves funds. The
endpoint enforces the doctrine: it hard-rejects any claim of verifier execution
authority or resource-release control and rejects gate mode. Holds:

- Capability ≠ Authority
- Authority ≠ Execution
- Execution ≠ Verification
- Verification must leave evidence
- Resource server controls delivery
- DefaultVerifier records evidence

## Final conclusion

**Live endpoint: READY (with one non-blocking public-exposure caveat).**

`POST /v1/sar-402/receipts` is live on defaultverifier.com, accepts a valid
SAR-402 record-mode payload, returns a `sha256:` receipt id with lookup +
explorer metadata, persists the receipt (confirmed live via
`/v1/attest/receipt/{id}` = 200 and the recent-receipts surface), and
hard-rejects both false verifier authority (422, nothing stored) and gate mode
(422).

Non-blocking caveats:
1. The recent-list endpoint is not publicly proxied at `/v1/receipts` (pre-existing
   nginx gap; lookup-by-id is the working public discovery path). Left unchanged
   per constraints — flag for a follow-up nginx route addition if a public recent
   list is desired.
2. Explorer was verified only as an HTML 200; in-browser visual rendering of the
   receipt is unconfirmed.
