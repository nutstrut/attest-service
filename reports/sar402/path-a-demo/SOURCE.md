# SAR-402 Path A Public Demo — Fixture Source & Receipt-ID Derivation

This directory holds the canonical public SAR-402 Path A demo payload and its
prepared receipt. This note clarifies a distinction that has caused confusion:
**the resolver response is not the digest preimage.**

## The four objects (do not conflate them)

1. **Resolver response / lookup envelope**
   What `GET /v1/attest/receipt/{receipt_id}` returns. It is a *wrapper*:
   `receipt_id`, `receipt_type`, `receipt_context`, `created_at`, `agent_id`,
   and a nested `receipt` object. The envelope exists for stable lookup — it is
   **not** the bytes the `receipt_id` is hashed over.

2. **Canonical digest preimage**
   The exact byte string the `receipt_id` is computed from.

3. **`payload_without_integrity`**
   The inner SAR-402 payload with its `integrity` block removed. This — not the
   resolver envelope, and not the full payload including `integrity` — is what
   gets canonicalized to form the digest preimage.

4. **`receipt_id` derivation**
   ```
   receipt_id = sha256(sorted_keys_compact_v0(payload_without_integrity))
   ```
   Canonicalization is `sorted_keys_compact_v0`
   (`json.dumps(obj, sort_keys=True, separators=(',',':'), ensure_ascii=False)`,
   UTF-8), **not** RFC 8785 / JCS.

## Why hashing a resolver response does not reproduce the receipt_id

Hashing a resolver/lookup envelope body will **not** reproduce the `receipt_id`,
because the envelope is a lookup wrapper, not the preimage. To re-derive the id,
start from the payload fixture in this directory, drop the `integrity` block,
canonicalize with `sorted_keys_compact_v0`, and SHA-256 the bytes.

## Known values (this fixture)

- Payload: `sar402-canonical-public-demo-v2-20260623T234156Z.payload.json`
- receipt_id: `sha256:91e2ae85f03c7a8e7df10e8862895b99456cb13abc50b4e23ba84f1c15b3b8c9`

## Recompute (third party)

```bash
python3 - <<'PY'
import hashlib, json
p = json.load(open('sar402-canonical-public-demo-v2-20260623T234156Z.payload.json'))
p.pop('integrity', None)  # digest is over the payload EXCLUDING integrity
canon = json.dumps(p, sort_keys=True, separators=(',',':'),
                   ensure_ascii=False).encode('utf-8')
print('sha256:' + hashlib.sha256(canon).hexdigest())
PY
# expect: sha256:91e2ae85f03c7a8e7df10e8862895b99456cb13abc50b4e23ba84f1c15b3b8c9
```
