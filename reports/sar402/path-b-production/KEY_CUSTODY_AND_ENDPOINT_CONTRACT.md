# SAR-402 Path B — Key Custody & Endpoint Contract (Production Design)

**Status:** DESIGN ONLY. No production code, no keys created or printed, no
deployment files touched, no public receipts mutated. **Path B is not live.**
**Date:** 2026-06-24
**Scope:** Specify the production key-custody model, read endpoint contract,
storage model, boundary language, Explorer/CLI implications, test plan, and
rollout sequence for SAR-402 Path B recording attribution. This document does
not authorize implementation; it is the contract to review before any
production signing or endpoint work begins.

Governing references:
- Governed schema: `~/morpheus/org/schemas/SAR402_RECORDING_WRAPPER_V1.md`
- Production plan: [PLAN.md](PLAN.md)
- Demo implementation (reference crypto core): [sar402_recording_wrapper.py](../../../sar402_recording_wrapper.py)
- Path A core: [sar402_receipts.py](../../../sar402_receipts.py), [attest_service.py](../../../attest_service.py)

> **Doctrine, restated and non-negotiable.**
> - Capability ≠ Authority · Authority ≠ Execution · Execution ≠ Verification
> - Verification must leave evidence · Verified restraint is the product.
> - The **inner SAR-402 receipt** is **resource-server evidence** (a content
>   hash supplied by the resource server), never a DefaultVerifier signature.
> - The **Path B wrapper** attributes **DefaultVerifier's own recording /
>   observation / ingestion act only**. A wrapper signature must never read as
>   DefaultVerifier having delivered the resource, executed payment, authorized
>   access, controlled release, settled on mainnet, validated an invoice, or
>   created legal/fiscal finality.

---

## 1. Production key custody model

### 1.1 Key generation

- **Algorithm:** Ed25519 (carried from the proven demo core; small keys,
  deterministic signatures, trivial third-party verification). No change.
- **Generation site:** the production signing seed (32-byte Ed25519 seed) is
  generated **inside the managed secret system** (KMS / HSM / sealed-secret
  tooling), not on a developer laptop, not in CI, not by this repo. Generation
  is a deliberate, audited operator action performed in the rollout step, **not
  now**.
- **No generation in this design step.** This document does not create, derive,
  print, or commit any key material. The `public_key_hex()` helper exists for
  publishing a public key only when an operator explicitly intends to.

### 1.2 Private key storage

- The private seed lives **only** in a managed secret store. Acceptable forms,
  best to weakest:
  1. **KMS / HSM-backed signer** — the seed never leaves the boundary; the
     service requests signatures over canonical bytes. *Preferred.*
  2. **Sealed/encrypted secret** decrypted into process memory at boot
     (e.g. cloud secret manager, sealed-secrets). Acceptable.
  3. **Raw hex seed injected as an environment variable at boot**
     (`SAR402_RECORDING_SIGNING_KEY_HEX`). **Weakest acceptable form** — only
     if 1–2 are unavailable, and never written to disk, logs, or images.
- The seed is **never** placed in a receipt, wrapper, response body, log line,
  error message, crash dump, or git history.

### 1.3 Public key & key-id publication

- The **public key (raw 32-byte hex)** and its **kid** are published so any
  third party can verify attribution offline.
- **Publication location:** `GET /.well-known/sar-keys.json` on
  `defaultverifier.com`, a JWKS-style document listing each key by kid, its
  raw public key, algorithm, `status` (`active` | `retiring` | `revoked`),
  `not_before`, optional `not_after`, and a one-line **purpose** string
  asserting *recording attribution only*.
- A static mirror of the published key (kid + hex + purpose) also ships in the
  Path B verification doc / CLI bundle so verification does not require a live
  fetch.

Illustrative `/.well-known/sar-keys.json`:

```json
{
  "keys": [
    {
      "kid": "defaultverifier-recording-ed25519-1",
      "kty": "OKP",
      "crv": "Ed25519",
      "alg": "Ed25519",
      "public_key_hex": "<raw 32-byte public key hex>",
      "use": "sar402_recording_attribution",
      "purpose": "Attributes DefaultVerifier's recording act only; not delivery, payment, access, release, settlement, or finality.",
      "status": "active",
      "not_before": "2026-07-01T00:00:00Z"
    }
  ]
}
```

### 1.4 Recommended key-id format

```
defaultverifier-recording-ed25519-<n>
```

- `defaultverifier` — issuing party.
- `recording` — **authority scope**, making the scope unmistakable and visually
  distinct from any SAR signing key (e.g. `sar-prod-ed25519-03`).
- `ed25519` — algorithm.
- `<n>` — monotonic rotation index (`1`, `2`, …). First production kid:
  `defaultverifier-recording-ed25519-1`.

The kid is opaque to verifiers (they select the key by exact-match), but the
embedded scope word `recording` is a human-readable guard against reuse.

### 1.5 Rotation strategy

- Every wrapper carries `recording_key_id`; verifiers select the public key by
  kid. Rotation is therefore **additive and non-breaking**.
- To rotate: generate `…-recording-ed25519-(n+1)`, publish it as `active`,
  flip the prior key to `retiring` (still verifiable, no longer signs), and
  begin signing new wrappers with the new kid.
- **Never re-sign or mutate** existing wrappers on rotation. Old wrappers
  remain valid under their original (now `retiring`/`revoked`) kid, which stays
  published for verification.
- Suggested cadence: scheduled annual rotation plus immediate rotation on
  suspected compromise. No automatic expiry that would strand old wrappers —
  retired keys keep their public half published indefinitely for verification.

### 1.6 Revocation strategy

- Revocation = setting `status: "revoked"` (with `revoked_at`) in
  `sar-keys.json`. The public key **remains published** so historical
  signatures can still be checked, but verifiers MUST surface a clear warning
  that the signing key was revoked as of `revoked_at`.
- Distinguish two cases in tooling/UI:
  - **Routine retirement** (`retiring`): wrappers signed before retirement
    remain trustworthy.
  - **Compromise revocation** (`revoked`): wrappers signed at/after `revoked_at`
    are untrustworthy; Explorer/CLI must flag them, not silently pass.
- Revocation never deletes wrappers and never mutates Path A.

### 1.7 What must never be committed

- Private Ed25519 seeds (hex or otherwise), KMS unseal material, `.env` files
  containing `SAR402_RECORDING_SIGNING_KEY_HEX`, key backups, or any byte from
  which the private key can be reconstructed.
- Only the **public** key + kid + purpose may be committed/published.

### 1.8 Environment variable naming

The existing env interface from the demo module is **accepted as-is** for the
raw-seed deployment form:

| Variable | Meaning | Accepted? |
|---|---|---|
| `SAR402_RECORDING_SIGNING_KEY_HEX` | Hex 32-byte Ed25519 seed (signer only) | ✅ Accepted |
| `SAR402_RECORDING_PUBLIC_KEY_HEX` | Hex 32-byte raw public key (verify/publish) | ✅ Accepted |
| `SAR402_RECORDING_KID` | Active recording key id | ✅ Accepted |

Rationale: the names are already scoped (`SAR402_RECORDING_*`), unambiguous
about authority scope, and already wired into `load_signing_key` /
`load_public_key` / `load_kid` with no-default, returns-`None`-when-unset
semantics. No rename needed. If/when a KMS-backed signer replaces the raw seed,
add `SAR402_RECORDING_KMS_KEY_ARN` (or equivalent) and leave
`SAR402_RECORDING_SIGNING_KEY_HEX` unset — the signer abstraction selects the
backend.

### 1.9 Same key vs. dedicated recording key — **decision**

**Recommendation: a SEPARATE, dedicated recording-attribution key
(`defaultverifier-recording-ed25519-1`), NOT the existing
`sar-prod-ed25519-03` SAR production signing key.**

Reasoning:
- **Authority separation is the product.** The core doctrine is that
  capability, authority, execution, and verification are distinct and that
  verification leaves *bounded* evidence. Reusing one key for both SAR signing
  authority and recording attribution **conflates two authorities in a single
  credential** — exactly the conflation Path B exists to prevent. A separate
  key makes "this signature is recording attribution only" cryptographically,
  not just textually, true.
- **Blast radius / rotation independence.** Compromise or rotation of the
  recording key must not force rotation of the SAR signing key, and vice versa.
  Separate keys give independent lifecycles and revocation.
- **Clean published purpose.** A dedicated kid carries `use:
  sar402_recording_attribution` in `sar-keys.json`; a shared key would have to
  advertise two incompatible purposes.
- **Cost is low and one-time:** the only added work is publishing the new key
  at `/.well-known/sar-keys.json` — which Path B needs to stand up anyway.

The "same key is simpler" argument does not outweigh authority conflation;
simplicity here buys exactly the ambiguity the doctrine forbids. **Decision:
dedicated recording key.**

---

## 2. Endpoint contract

### 2.1 Proposed read endpoint

```
GET /v1/sar-402/recording/{receipt_id}
```

Returns the recording wrapper bound to `receipt_id` (the **inner** receipt id),
if one exists. This is a **new, separate** surface; the live
`GET /v1/attest/receipt/{id}` lookup is **unchanged** and keeps returning the
bare Path A record. Separation prevents client breakage and Path A/Path B
conflation.

### 2.2 Authentication — **decision: fully public (read)**

The read endpoint is **public, no credentials required.**

Reasoning: Path B's value *is* independent verifiability — "anyone can confirm
DefaultVerifier's recording act is attributable to a published key." Requiring
auth would gate the proof behind DefaultVerifier and weaken it to a
trust-us assertion. The data served is already non-secret (it embeds an
already-public receipt and a signature verifiable against a published key).
Abuse surface is read-only and mitigated with rate limiting / caching / CDN,
not authentication. **Default to public; no specific reason to deviate for the
read path.** (Issuance — §2.4 — is the opposite: operator-authenticated.)

### 2.3 Request / response shape

**Request:** `GET /v1/sar-402/recording/{receipt_id}` — `receipt_id` is the
inner SAR-402 receipt id (`sha256:<hex>`), URL-encoded.

**200 OK** — wrapper found. Returns the governed
`sar402_recording_wrapper_v1` object **verbatim** (the exact signed bytes,
including the embedded inner `receipt` and `recording_signature`), plus a thin
non-signed envelope for verifier convenience:

```json
{
  "wrapper": { "...": "the verbatim sar402_recording_wrapper_v1 object" },
  "verification": {
    "kid": "defaultverifier-recording-ed25519-1",
    "alg": "Ed25519",
    "canonicalization": "sorted_keys_compact_v0",
    "public_key_url": "https://defaultverifier.com/.well-known/sar-keys.json",
    "signed_field_note": "Signature is over canonical wrapper bytes excluding recording_signature."
  }
}
```

The `verification` block is advisory only and is **not** signed; verifiers MUST
verify against `wrapper` itself. The `wrapper` bytes served MUST reproduce the
exact canonical signing input so third parties recompute the signature.

### 2.4 POST / create endpoint — now or later?

**Later.** Do **not** ship a create endpoint in the first release. The first
production wrapper (the canonical `public_demo` receipt) is produced **offline**
by an operator-run tool and written to the wrapper store, then served read-only.

A future `POST /v1/sar-402/recording` is **operator-authenticated** (not
public), takes a `receipt_id` already on the Path A ledger, builds and stores
the signed wrapper, and is gated behind the read/render/verify surface being
public and stable. Deferring it keeps the first release's attack surface to a
read-only lookup.

### 2.5 Error & lookup behavior

| Case | Status | Body / behavior |
|---|---|---|
| **Known wrapped receipt** | `200` | Wrapper + verification envelope (§2.3). |
| **Unknown receipt id** (not in Path A ledger) | `404` | `{"error":"receipt_not_found"}`. Do not disclose whether any id exists beyond not-found. |
| **Receipt exists (Path A) but no wrapper** | `404` | `{"error":"no_recording_wrapper","receipt_id":"…","hint":"Path A receipt exists; no Path B recording wrapper has been issued."}` — distinct code from unknown id, so callers can tell "no wrapper yet" from "no such receipt". |
| **Invalid receipt id** (malformed, not `sha256:<hex>`) | `400` | `{"error":"invalid_receipt_id"}`. Validate format before lookup. |
| **Key unavailable** (active recording key not configured at runtime) | `503` | `{"error":"recording_key_unavailable"}`. Read serving of already-stored wrappers SHOULD NOT depend on the private key; this applies only if a serving path needs key context. Never 200 with an unsigned/partial wrapper. |
| **Signature verification failure** (stored wrapper fails self-verify) | `500` | `{"error":"wrapper_integrity_error"}`. A stored wrapper that does not verify is an internal data-integrity fault: log, alert, and refuse to serve it as valid. Never return a wrapper the service cannot itself verify. |

All error bodies are JSON, contain no key material and no internal paths, and
never mutate state.

### 2.6 Wrapper-only vs. wrapper + inner receipt reference

Return the **wrapper, which already embeds the inner receipt verbatim** (the
schema's `receipt` field), **plus a reference** to the canonical Path A lookup
for the inner receipt:

- The embedded inner receipt is required for signature verification (it is part
  of the signed bytes) — it cannot be omitted without breaking verification.
- Additionally include `verification.inner_receipt_lookup =
  "/v1/attest/receipt/{wrapped_receipt_id}"` so a client can cross-check the
  embedded copy against the live Path A record. The embedded copy is
  authoritative for verification; the reference is for cross-checking only.

---

## 3. Storage model

### 3.1 Separate store — **yes**

Path B wrappers are stored in a **separate** append-only ledger from Path A
receipts. They never co-mingle with the inner receipt ledger
(`attest_receipts_master.jsonl`), so Path A's shape, lookups, and guarantees
are provably untouched.

- **Proposed file/table name:** `attest_recording_wrappers_master.jsonl`
  (one JSON wrapper object per line), mirroring the Path A ledger naming and
  the existing `write_receipt` append convention. A future DB table would be
  `sar402_recording_wrappers` with the same semantics.

### 3.2 Idempotency

- Writes are **idempotent on the content digest of the signed wrapper view**
  (canonical bytes excluding `recording_signature`). Re-submitting an
  identical recording act for the same inner receipt + same kid + same
  timestamps is a no-op that returns the existing wrapper, not a duplicate row.
- Each stored row carries `recording_event_id` (server UUID) as a stable
  handle.

### 3.3 Multiple wrappers per inner receipt — allowed, bounded

- **Allowed.** A single inner receipt MAY have more than one wrapper — e.g. one
  signed under `…-ed25519-1` and a later one under `…-ed25519-2` after
  rotation, or an `observation` wrapper and a separate `ingestion` wrapper.
- The read endpoint `GET …/recording/{receipt_id}` returns the **current
  canonical wrapper** for that receipt (most recent `active`-kid wrapper). A
  `?all=true` variant MAY return the full list. (For the first release, with
  exactly one wrapper for the canonical demo receipt, single-return is
  sufficient; design the store for many.)

### 3.4 Updated wrappers, rotated keys, duplicate submissions

- **Updated wrappers:** never edit in place. A "correction" is a **new** wrapper
  row (new `recording_event_id`); the prior row is retained for audit. Append
  only.
- **Rotated keys:** new wrappers sign under the new kid; existing wrappers keep
  their original kid and remain valid against the still-published public key.
  No re-signing.
- **Duplicate submissions:** collapsed by the idempotency digest (§3.2) — the
  existing wrapper is returned, no new row.

---

## 4. Boundary language (public-safe)

### 4.1 What Path B **means** (exact public-safe copy)

> **DefaultVerifier Recording Attribution (SAR-402 Path B).**
> DefaultVerifier observed and recorded a SAR-402 delivery-evidence receipt
> submitted by a resource server, and signed *its own act of recording*. This
> signature is cryptographically attributable to DefaultVerifier's published
> recording key, and binds exactly this inner receipt. A valid signature proves
> one thing: **DefaultVerifier recorded this receipt, attributable to key
> `<kid>`.**

### 4.2 What Path B **does not** mean (exact public-safe copy)

> **This recording attribution does NOT mean DefaultVerifier:**
> - delivered the resource,
> - executed or settled payment,
> - authorized access,
> - controlled or released the resource,
> - settled anything on mainnet,
> - validated an invoice,
> - vouched for tax or fiscal correctness, or
> - created legal or payment finality.
>
> The underlying delivery evidence was **created by the resource server**.
> DefaultVerifier holds **no execution authority** and **no release control**.
> DefaultVerifier attributes **its own recording / observation / ingestion act
> only**.

### 4.3 Enforcement

- The machine-readable `authority_boundary` block (signed, cannot be silently
  widened) carries `verifier_has_execution_authority = false`,
  `verifier_controls_resource_release = false`,
  `source_evidence_created_by = "resource_server"`, and the
  `does_not_attest_to` list.
- `recording_context` is restricted to `observation` | `ingestion`;
  **`attestation` is forbidden** because it can be misread as attesting to
  delivery content.
- The existing overclaim scanner gates all production-facing copy against this
  language before publication.

---

## 5. Explorer & CLI implications

### 5.1 Explorer: distinguishing Path A from Path B

- The Explorer MUST render the two as **separate, clearly labeled blocks** and
  never merge them into "DefaultVerifier verified/approved the delivery."
- Suggested labels:
  - **Path A → "Delivery Evidence Receipt"** — "Resource server submitted this
    delivery evidence; DefaultVerifier recorded it."
  - **Path B → "DefaultVerifier Recording Attribution"** — "DefaultVerifier's
    recording act is cryptographically attributable to key `<kid>`."
- For a wrapped receipt, Path B view shows: `recording_key_id`,
  `recording_context`, the `authority_boundary` block **verbatim** (including
  the three non-execution booleans and the `does_not_attest_to` list), key
  `status` from `sar-keys.json` (with a warning banner if `revoked`), and a
  **machine-checkable verify** affordance (or link to the CLI/verification doc).
- Path A and Path B panels are visually separated; roles never flip
  (`recorded_by = defaultverifier` vs inner `acting_party = resource_server`).

### 5.2 CLI: verifying wrapper-level attribution

- Ship a small standalone verifier that wraps
  `verify_recording_wrapper(wrapper, public_key=…)` + the published key from
  `sar-keys.json`, so a third party verifies attribution offline in minutes.
- CLI MUST: fetch (or accept a pinned copy of) the public key by kid, recompute
  canonical bytes (`sorted_keys_compact_v0`) excluding `recording_signature`,
  verify the Ed25519 signature, check `recording_key_id == recording_signature.kid`,
  check `wrapped_receipt_id`/`wrapped_receipt_digest` against the embedded inner
  receipt, and check the `authority_boundary` is present and unweakened.
- CLI output states plainly: "Recording attribution verified for `<receipt_id>`
  under key `<kid>`. This attests to recording only — not delivery, payment,
  access, release, settlement, or finality."

### 5.3 Test-environment warnings (`issuer.environment = test`)

- When the embedded inner receipt's `issuer.environment` is `test` (or any
  non-mainnet value), both Explorer and CLI MUST display a prominent
  **"TEST / NON-PRODUCTION"** badge, and the wrapper's `does_not_attest_to`
  list will include `mainnet_settlement` (already enforced by
  `does_not_attest_to_for`). The badge text: "This receipt is a test/demo
  artifact; the recording does not imply mainnet settlement." The canonical
  `public_demo` receipt is a demonstration artifact and MUST carry this badge.

---

## 6. Test plan

Carry forward the existing green demo tests (signature/tamper/kid/boundary/enum,
30 wrapper + 52 combined + 76 full) and add the production-specific matrix.

### 6.1 Unit tests
- Wrapper build produces all governed top-level fields; constants match the
  schema (`wrapper_type`, `wrapper_version`, `recorded_by`, `signature_alg`).
- Inner receipt embedded **byte-identical** to source (build is add-only;
  assert byte-equality).
- `wrapped_receipt_id`/`wrapped_receipt_digest` adopted verbatim from inner
  receipt; refuse to wrap when id ≠ integrity.digest.

### 6.2 Endpoint tests
- `200` returns verbatim wrapper that re-verifies against the published key.
- `404 receipt_not_found` for unknown id; `404 no_recording_wrapper` for a
  Path A receipt with no wrapper (distinct codes).
- `400 invalid_receipt_id` for malformed ids.
- `503 recording_key_unavailable` path returns no partial/unsigned wrapper.
- Contract test: `GET /v1/attest/receipt/{id}` response is **unchanged** when
  Path B is enabled.

### 6.3 Signature-failure tests
- Tampered wrapper field, tampered embedded inner receipt, tampered/garbled
  signature → verification fails and (stored case) endpoint returns `500
  wrapper_integrity_error`, never a 200.

### 6.4 Key-mismatch tests
- Wrong public key fails. `recording_key_id` ≠ `recording_signature.kid` fails.
  `recording_signature.alg` ≠ `signature_alg` fails. Revoked-kid wrapper
  surfaces a warning in CLI/Explorer.

### 6.5 Wrong `recording_context` tests
- `attestation`, empty, and any non-enum value rejected at build and verify.

### 6.6 No-wrapper case
- Path A receipt present, no wrapper stored → `404 no_recording_wrapper`; no
  state mutation; Path A lookup still returns the bare record.

### 6.7 Canonical `public_demo` wrapper case
- Wrap `sha256:91e2ae85f03c7a8e7df10e8862895b99456cb13abc50b4e23ba84f1c15b3b8c9`
  and assert `wrapped_receipt_id == sha256:91e2ae85…`, inner receipt
  byte-identical, `does_not_attest_to` includes `mainnet_settlement`, and a
  third party reproduces the exact signed bytes from the published wrapper
  (cross-version canonicalization stability).

### 6.8 Regression: Path B never mutates Path A
- After wrapping, `attest_receipts_master.jsonl` and the canonical lookup
  response are byte-unchanged; no `recording_signature`/`recording_key_id`
  leaks into the inner record; wrappers live only in
  `attest_recording_wrappers_master.jsonl`.

---

## 7. Rollout plan

Strictly ordered; each gate must pass before the next. **No public
announcement until every prior step passes.**

1. **Design doc** (this file) reviewed and approved alongside
   `SAR402_RECORDING_WRAPPER_V1.md` and [PLAN.md](PLAN.md).
2. **Internal test wrapper** for the existing canonical `public_demo` receipt,
   built offline with a **test** key, verified independently. No production
   key, not served publicly.
3. **Read-only endpoint** `GET /v1/sar-402/recording/{receipt_id}` shipped
   (404 when no wrapper); contract test guards the unchanged Path A lookup.
4. **Explorer display** rendering Path A vs Path B distinctly with the
   `authority_boundary` and test badge.
5. **CLI verification** tool shipped and documented for offline third-party
   verification.
6. **Production key setup** — generate the dedicated recording key in the
   managed secret store, publish kid + public key at
   `/.well-known/sar-keys.json` (separate, audited operator step).
7. **Staging validation** — wrap the canonical `public_demo` receipt with the
   production key offline, serve via the read endpoint in staging, verify with
   the public CLI, confirm Path A untouched.
8. **Public announcement** — only after 1–7 pass, and only for `public_demo`
   first. `real_task` receipts remain unwrapped until the read/render/verify
   surface has been public and stable; issuance automation (`POST`, §2.4) is a
   later, operator-gated step.

---

*Design only. No production code changed, no keys created/printed/rotated, no
deployment files modified, no public receipts mutated, no public API behavior
changed. Path B is not live.*
