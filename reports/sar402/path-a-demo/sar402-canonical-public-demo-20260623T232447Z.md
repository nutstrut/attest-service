# SAR-402 Canonical Public Demo Receipt — PREP (not published)

**Generated (UTC):** 2026-06-23T23:24:47.340025+00:00  
**Artifact id:** `sar402-canonical-public-demo-20260623T232447Z`  
**Proposed payload:** `sar402-canonical-public-demo-20260623T232447Z.payload.json`  
**Status:** Local preparation only. Nothing published, posted, or deployed. Awaiting Keith approval.

> This receipt has **not** been ingested. The production ledger was not touched. The id below is the id the live receipt *will* have iff the payload is ingested byte-for-byte unchanged.

---

## 1. Purpose

Canonical public SAR-402 demonstration receipt: a deliberate, purpose-built public proof that DefaultVerifier records SAR-402 delivery evidence in a payload-bound, role-separated, publicly inspectable form.

**Claim (bounded):**

```text
This receipt is prepared so that, after approved live ingest, DefaultVerifier will have recorded this SAR-402 delivery event and the receipt will be publicly inspectable, payload-bound, and role-separated.
```

## 2. Expected receipt_context after live ingest

`public_demo` — selected at ingest time via the query param `?receipt_context=public_demo`, **not** embedded in the inner payload. The inner SAR-402 payload carries no `receipt_context` field; the ingest wrapper records it on the ledger record. Default without the param is `real_task`, so the demo label is a deliberate, explicit opt-in.

## 3. Expected receipt_id / digest (computed locally)

```text
sha256:ecbcd91bc7dbd847f7cab1dbe4605878cbed499d7726c1db1acc81e3e6e8b177
```

- Computed by the committed authoritative helper `morpheus.sar402.builder.compute_integrity`.
- Independently recomputed the long way (canonical bytes, see §4): **match = TRUE**.
- Dry-run through the real ingestion core `record_sar402_receipt(..., persist=False, receipt_context="public_demo")` adopted `receipt_id` = this value: **TRUE** (no ledger write performed).

## 4. Exact digest computation method

**Canonicalization is `sorted_keys_compact_v0`, NOT RFC 8785 / JCS.** (The task brief said "JCS/RFC 8785"; the committed code does not use JCS — see `morpheus/sar402/builder.py:canonical_json` which is annotated "Not RFC 8785 JCS", and `constants.CANONICALIZATION = 'sorted_keys_compact_v0'`. This report uses the *actual* committed method so the precomputed id matches the live ingest id.)

Method:

1. Take the inner SAR-402 payload **excluding** the `integrity` block.
2. Canonical JSON = `json.dumps(obj, sort_keys=True, separators=(',',':'), ensure_ascii=False)` (UTF-8).
3. `receipt_id = 'sha256:' + sha256(canonical_bytes).hexdigest()`.
4. The live ingest path (`record_sar402_receipt`) **adopts** the inbound `integrity.digest` verbatim as `receipt_id` — it does not recompute. So an unchanged payload yields exactly this id.

Third-party recomputation:

```bash
python3 - <<'PY'
import hashlib, json
p = json.load(open('sar402-canonical-public-demo-20260623T232447Z.payload.json'))
p.pop('integrity', None)  # digest is over the receipt EXCLUDING integrity
canon = json.dumps(p, sort_keys=True, separators=(',',':'),
                   ensure_ascii=False).encode('utf-8')
print('sha256:' + hashlib.sha256(canon).hexdigest())
PY
# expect: sha256:ecbcd91bc7dbd847f7cab1dbe4605878cbed499d7726c1db1acc81e3e6e8b177
```

## 5. Exact POST command (for Keith to approve LATER — do not run yet)

```bash
curl -sS -X POST \
  'https://defaultverifier.com/v1/sar-402/receipts?receipt_context=public_demo' \
  -H 'Content-Type: application/json' \
  --data @sar402-canonical-public-demo-20260623T232447Z.payload.json
# (add -H 'Authorization: Bearer <key>' iff SAR402_INGEST_API_KEY is set)
```

## 6. Exact public lookup command (after publication)

```bash
curl -sS 'https://defaultverifier.com/v1/attest/receipt/sha256%3Aecbcd91bc7dbd847f7cab1dbe4605878cbed499d7726c1db1acc81e3e6e8b177'
# expect a record with receipt_type=sar_402_settlement, receipt_context=public_demo
```

Live lookup path: `/v1/attest/receipt/sha256%3Aecbcd91bc7dbd847f7cab1dbe4605878cbed499d7726c1db1acc81e3e6e8b177`

## 7. SAR Explorer URL pattern (after publication)

```text
https://sarexplorer.com/?receipt_id=sha256%3Aecbcd91bc7dbd847f7cab1dbe4605878cbed499d7726c1db1acc81e3e6e8b177
```

## 8. Claim boundaries

Authority binding (preserved):

```text
verifier_has_execution_authority   = false
verifier_controls_resource_release = false
resource_server_controls_delivery  = true
acting_party                       = resource_server
```

This receipt does NOT claim:

- No mainnet payment (testnet chain eip155:84532, issuer.environment = test).
- No legal payment finality.
- No DefaultVerifier delivery authority.
- No DefaultVerifier payment execution.
- No DefaultVerifier access authorization.
- No DefaultVerifier resource-release control.
- No production Path B verifier-key signature attribution (Path B pending).

Identity provenance: the payer/recipient addresses are deterministically derived demo addresses — the first 20 bytes of SHA-256 over documented public seed strings (`defaultverifier.com/demo/sar-402#public-demo-payer-v1` / `defaultverifier.com/demo/sar-402#public-demo-recipient-v1`) — reproducible by anyone, with no private keys used or asserted. They are not placeholder `0xPAYER...` strings. Chain is Base Sepolia testnet (`eip155:84532`).

---

*Canonical public SAR-402 demo receipt — prepared locally, not published. Path B (verifier-key signature attribution) remains pending and is not included here.*
