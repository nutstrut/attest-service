# SAR-402 Path B — Production Wrapper-Level Recording Attribution: Implementation Plan & Contract Review

**Status:** PLAN ONLY. No production code, no keys, no deployment. Path B is **not** live.
**Date:** 2026-06-24
**Scope:** Promote the existing Path B *demo* recording-attribution wrapper to a reviewed production design. Decide whether the current primitives are sufficient before any production signing is implemented.

> Doctrine, restated and non-negotiable. The inner SAR-402 receipt remains
> **resource-server evidence**. The Path B wrapper records **DefaultVerifier's
> recording/observation event** and nothing more. A wrapper signature must never
> be readable as DefaultVerifier having executed payment, delivered the resource,
> authorized access, controlled release, or created the underlying delivery
> evidence.

---

## 1. Current state

### 1.1 What exists

| Concern | Location | Status |
|---|---|---|
| Path A ingestion core (inner receipt) | [sar402_receipts.py:229](sar402_receipts.py) `record_sar402_receipt` | Live, public |
| Path A persistence | [attest_service.py:401](attest_service.py) `write_receipt` → `attest_receipts_master.jsonl` | Live |
| Path A public lookup | [attest_service.py:980](attest_service.py) `get_receipt` → `/v1/attest/receipt/{id}` | Live |
| Committed inner schema/validator | `morpheus.sar402.schema` / `morpheus.sar402.validate` (`/home/ubuntu/morpheus`) | Live |
| Path B wrapper build/verify | [sar402_recording_wrapper.py](sar402_recording_wrapper.py) | **Demo only** |
| Path B wrapper tests | [tests/test_sar402_recording_wrapper.py](tests/test_sar402_recording_wrapper.py) — 18 tests, all green | Demo only |
| Path B demo generator | [reports/sar402/path-b-demo/generate_demo.py](reports/sar402/path-b-demo/generate_demo.py) | Offline, ephemeral key |
| Canonical public_demo receipt (Path A) | `sha256:91e2ae85f03c7a8e7df10e8862895b99456cb13abc50b4e23ba84f1c15b3b8c9` | Live, public |

### 1.2 Findings against the required review

**2. Is there a reusable production signing path?**
No production signing path exists anywhere in the service. The *only* signing/verification
code in the repo is `sar402_recording_wrapper.build_recording_wrapper` /
`verify_recording_wrapper`. Its crypto core is sound and reusable (Ed25519, a
documented `sorted_keys_compact_v0` canonicalization, signature over
wrapper-minus-signature, inner-receipt binding via `receipt_id ==
integrity.digest`), but it is **not wired into any endpoint, route, persistence
path, or CLI**. It is exercised only by the test suite and the offline demo
generator.

**3. What key material signs production receipts today?**
None. Path A does **not** sign receipts. `record_sar402_receipt` *adopts*
the submitter-supplied `integrity.digest` verbatim as the `receipt_id`
([sar402_receipts.py:305](sar402_receipts.py)) and `write_receipt` appends the
record to a plaintext JSONL ledger with no signature. The inner receipt's
integrity is a **content hash supplied by the resource server**, explicitly *not*
a DefaultVerifier signature. There is therefore no production private key to
locate, and nothing to print. The wrapper module exposes optional env loaders
(`SAR402_RECORDING_SIGNING_KEY_HEX`, `SAR402_RECORDING_PUBLIC_KEY_HEX`,
`SAR402_RECORDING_KID`) but these are unused in production and return `None` when
unset (verified by `test_env_loaders_optional_and_roundtrip`). **No keys were
read, created, or printed for this review.**

**4. Where is signature verification implemented?**
Only `sar402_recording_wrapper.verify_recording_wrapper`. There is no
verification endpoint and no Explorer/CLI verification surface. The existing
`/v1/attest/receipt/{id}` lookup returns the stored Path A record as-is and does
not verify anything cryptographically.

**5. Do SAR Explorer / CLI understand wrapper-level attribution?**
No. The Explorer link is a bare key lookup
(`DEFAULT_EXPLORER_BASE = "https://sarexplorer.com/?receipt_id="`,
[sar402_receipts.py:72](sar402_receipts.py)) and the backend lookup returns the
ledger record. Neither renders, distinguishes, nor verifies a recording wrapper.
There is no CLI verifier shipped.

**Conclusion for the "primitives sufficient?" gate:** The cryptographic
primitive (build/verify/canonicalization/inner-binding) **is** sufficient and
well-tested. What is missing for production is everything *around* it: a managed
production key + published kid, a storage/representation decision, an
API/endpoint surface, Explorer/CLI rendering, a field-schema that satisfies the
required Path B fields below, and an expanded test matrix. **Recommendation: do
not implement production signing until the schema (§2) and the
endpoint/storage decision (§3, §8) are approved** — the crypto does not need
reworking, but the contract around it does.

---

## 2. Proposed production schema

### 2.1 Gap between the demo wrapper and the required Path B fields

The current demo wrapper uses a thinner field set with different names. The
required production fields and their mapping:

| Required field | Demo wrapper today | Action |
|---|---|---|
| `wrapper_type` | (implicit in `recording_wrapper_version`) | **Add** explicit `wrapper_type = "sar402_recording_attribution"` |
| `wrapped_receipt_id` | `receipt_id` | **Rename/duplicate**; keep clear it is the inner id |
| `wrapped_receipt_digest` | (same value as `receipt_id`; Path A id == `integrity.digest`) | **Add** as an explicit field even though it currently equals the id, to survive any future id/digest divergence |
| `recording_event_id` | — | **Add** (server-generated UUID for the recording act) |
| `recording_context` `"observation"\|"ingestion"\|"attestation"` | — | **Add**, constrained enum |
| `recorded_by` | `recorded_by = "defaultverifier"` | Keep |
| `recording_service` | — | **Add** (e.g. `"attest-service/sar-402"`) |
| `recording_key_id` | `verifier_kid` + `recording_signature.kid` | **Rename** to `recording_key_id`; keep the dual-location consistency check |
| `recording_signature` | `recording_signature.signature` (b64) | Keep |
| `signature_alg` | `recording_signature.alg = "Ed25519"` | Keep / surface at top level too |
| `signed_at` | — (only `recorded_at`) | **Add**, distinct from the observation time |
| `observed_at` / `recorded_at` | `recorded_at` | Keep; add `observed_at` if observation time ≠ signing time |
| `authority_boundary` / non-execution assertions | `claims.{signature_attests_to, does_not_attest_to}` | **Promote** to a first-class `authority_boundary` block carrying explicit booleans below |
| `verifier_has_execution_authority=false` | only inside inner `authority_binding` | **Add at wrapper level** |
| `verifier_controls_resource_release=false` | only inside inner `authority_binding` | **Add at wrapper level** |
| `source_evidence_created_by=resource_server` | implied by inner `authority_binding.acting_party` | **Add at wrapper level**, explicit |

> Note on `recording_context`: `"attestation"` here means *attestation of the
> recording act* (DefaultVerifier attests "I recorded this"), **never**
> attestation of delivery content. The enum value must not leak into copy that
> reads as "DefaultVerifier attested the delivery." See §7.

### 2.2 Proposed production wrapper shape (illustrative, not yet built)

```json
{
  "wrapper_type": "sar402_recording_attribution",
  "wrapper_version": "sar402_recording_wrapper_v1",
  "recording_event_id": "rec:<uuid>",
  "recording_context": "ingestion",
  "recorded_by": "defaultverifier",
  "recording_service": "attest-service/sar-402",
  "recording_key_id": "<published-prod-kid>",
  "wrapped_receipt_id": "sha256:<inner-id>",
  "wrapped_receipt_digest": "sha256:<inner-integrity-digest>",
  "observed_at": "<iso8601>",
  "recorded_at": "<iso8601>",
  "signed_at": "<iso8601>",
  "signature_alg": "Ed25519",
  "authority_boundary": {
    "signature_attests_to": "recording_attribution_only",
    "does_not_attest_to": [
      "resource_delivery", "payment_execution",
      "access_authorization", "release_control", "legal_payment_finality"
    ],
    "verifier_has_execution_authority": false,
    "verifier_controls_resource_release": false,
    "source_evidence_created_by": "resource_server"
  },
  "receipt": { "...": "the inner SAR-402 receipt, embedded verbatim, NOT mutated" },
  "recording_signature": {
    "alg": "Ed25519",
    "kid": "<published-prod-kid>",
    "signature": "<base64>"
  }
}
```

**Invariants (carried from the demo, kept in production):**
- Signature is computed over canonical bytes of the wrapper **excluding**
  `recording_signature`. Any change to any signed field — including any byte of
  the embedded inner receipt — breaks verification.
- `wrapped_receipt_id` / `wrapped_receipt_digest` are **adopted** from the inner
  receipt; DefaultVerifier never recomputes or re-issues the content hash.
- The inner receipt is embedded **verbatim** and never mutated (the wrapper only
  adds an outer layer).
- `recording_key_id` must equal `recording_signature.kid`, and `recorded_by`
  must be `defaultverifier`, or verification fails.

### 2.3 Schema-governance question
The inner SAR-402 schema (`additionalProperties: false`, committed in `morpheus`)
must remain untouched — Path B sits strictly above it. The wrapper schema is a
**new, separate** artifact. Decision needed (open question): does the wrapper
schema live in `morpheus` alongside the inner schema, or in `attest-service`?
Recommendation: define it in `morpheus` for single-source-of-truth governance,
mirroring how the inner schema is already the source of truth.

---

## 3. Endpoint / API options

The inner receipt lookup `/v1/attest/receipt/{id}` is **live and public** and
must not change shape (constraint: do not change public API behavior). Options:

**Option A — separate wrapper endpoint (recommended).**
`GET /v1/sar-402/recording/{receipt_id}` returns the recording wrapper for a
receipt *if one exists*, else 404. The existing lookup is untouched and keeps
returning the bare Path A record. Clean separation; zero risk to existing
clients; Explorer can opt-in to fetch the wrapper.

**Option B — additive field on the existing lookup.**
Add an optional `recording_attribution` sibling field to the existing response,
populated only when a wrapper exists. Lower friction for clients that already
hit the lookup, but it changes the response shape of a live public endpoint and
risks Path A/Path B conflation. *Not recommended for the first release.*

**Option C — wrapper issuance endpoint.**
`POST /v1/sar-402/recording` (authenticated, internal/operator-only) that takes a
`receipt_id` already on the ledger and produces+stores the signed wrapper. Needed
eventually to *create* wrappers, but issuance should be gated behind operator
auth and is a later step than read-side rendering.

**Recommendation:** Ship **Option A** read surface first against a small set of
deliberately-wrapped `public_demo` receipts; defer Option C issuance automation
and never default Option B onto the live lookup.

---

## 4. Signing / key strategy

**Constraints honored:** do not create or rotate keys; do not print secrets. This
section is design only.

- **Algorithm:** Ed25519 (already proven by the demo; small keys, deterministic,
  easy third-party verification).
- **Key custody:** the production signing seed must live in a managed secret
  (KMS / sealed secret / host env injected at boot), never in the repo, never in
  a receipt, never logged. The existing env loader contract
  (`SAR402_RECORDING_SIGNING_KEY_HEX`) is an acceptable *interface* but a raw hex
  seed in plain env is the weakest acceptable form; prefer a KMS-backed signer if
  available.
- **kid:** a single stable, **published** `recording_key_id` for the first
  production key (e.g. `defaultverifier-recording-ed25519-1`). The public key
  (raw hex) and kid get published in a verification doc so third parties can
  verify independently — `public_key_hex()` already exists for this.
- **Rotation:** design for it now (kid in every wrapper; verifiers select key by
  kid) but **do not rotate or create anything in this plan**.
- **Boundary:** the signing key proves *recording attribution only*. It is **not**
  a payment/delivery key and must never be reused for any execution-authority
  purpose. Document this in the key's published description.

**Decision gate:** production signing code is wired only after (a) a managed key +
published kid exist (separate, approved step), and (b) §2 schema is approved.

---

## 5. Explorer / CLI implications

- **Explorer must render Path A and Path B distinctly.** Path A = "resource
  server submitted this delivery evidence; DefaultVerifier recorded it." Path B =
  "DefaultVerifier's recording act is cryptographically attributable to key
  `<kid>`." The UI must never merge these into "DefaultVerifier verified/approved
  the delivery."
- The Explorer should show, for a wrapped receipt: the recording key id, the
  `authority_boundary` block verbatim (including the three non-execution
  booleans), and a **machine-checkable verify** affordance (or link to a CLI/doc).
- **CLI:** ship a small standalone verifier (`verify_recording_wrapper` +
  published public key) so a third party can verify attribution offline in
  minutes. The demo already documents the reproduction steps; productionize them
  into a script.
- Until rendering exists, a wrapper served by Option A is opaque to the public —
  so Explorer rendering should land **with or before** any public announcement.

---

## 6. Tests required before production

Carry over the existing demo/test guarantees and add the production-specific
cases. (Existing green tests already cover several of these.)

Already covered by `tests/test_sar402_recording_wrapper.py`:
- [x] Inner receipt embedded verbatim and **not mutated** (`build` is add-only).
- [x] Wrapped-receipt / inner-receipt tamper fails verification.
- [x] Wrapper-field tamper fails verification.
- [x] Signature tamper fails verification.
- [x] Correct-key verification passes; wrong key fails.
- [x] `receipt_id` swap (digest mismatch) fails verification.
- [x] kid mismatch fails verification.
- [x] Claims/boundary tamper (widening what the signature attests to) fails.
- [x] Env loaders optional; missing kid rejected.

To add for production:
- [ ] **Signs only the wrapper payload, never rewrites the inner receipt** —
      assert byte-equality of the embedded inner receipt vs the source.
- [ ] **Missing `authority_boundary` / non-execution assertions fails** (build
      refuses; verify rejects a wrapper lacking them).
- [ ] **`verifier_has_execution_authority = true` (or any non-false) fails** at
      wrapper level — mirror the Path A `authority_binding_errors` hard-reject.
- [ ] **`verifier_controls_resource_release = true` fails**; **`source_evidence_created_by != resource_server` fails**.
- [ ] **`recording_context` outside the enum fails.**
- [ ] **The canonical `public_demo` receipt `sha256:91e2ae85…` can be wrapped
      without changing its inner `receipt_id`** — explicit regression test that
      `wrapped_receipt_id == sha256:91e2ae85…` and the inner receipt is byte-identical.
- [ ] **Path A response/ledger shape unchanged** when wrapping is enabled
      (no `recording_signature`/`recording_key_id` leaks into the inner record).
- [ ] **Cross-version canonicalization** stability: third party reproduces the
      exact signed bytes from the published wrapper.
- [ ] **Public lookup `/v1/attest/receipt/{id}` response unchanged** (Option A) —
      contract test guarding the live endpoint.

---

## 7. Claim boundaries — the three things that must never be conflated

1. **Observing / recording evidence submission (this is all Path B asserts).**
   DefaultVerifier received a receipt from a resource server and signed *its own
   act of recording it*. Truth content: "a recording happened, attributable to
   key `<kid>`, binding exactly this inner receipt." Nothing about whether the
   underlying delivery is real, correct, or complete.

2. **Attesting to delivery content (Path B must NOT do this).**
   A claim that the delivered resource matches what was paid for / that the
   evidence is substantively correct. DefaultVerifier did not deliver and did not
   inspect-and-vouch-for the goods. The wrapper signature is **not** a content
   attestation. The enum value `recording_context: "attestation"` means
   *attestation of the recording*, and copy must say so explicitly to avoid this
   misreading.

3. **Executing payment or delivery (Path B must NOT imply this).**
   The resource server executed payment verification (via its own facilitator)
   and performed delivery. DefaultVerifier holds **no execution authority** and
   **no release control**. This is enforced in Path A by `authority_binding_errors`
   and must be re-asserted at the wrapper level via the three booleans
   (`verifier_has_execution_authority=false`,
   `verifier_controls_resource_release=false`,
   `source_evidence_created_by=resource_server`).

**Mechanisms preventing misread:**
- Machine-readable `authority_boundary` in every wrapper (signed, so it cannot be
  silently widened).
- The overclaim scanner already used by the demo generator, extended to gate any
  production-facing copy.
- Explorer rendering that visually separates "recorded by DefaultVerifier" from
  "delivered by resource server."
- `recorded_by = defaultverifier` while inner `authority_binding.acting_party =
  resource_server` — roles never flip.

---

## 8. Deployment sequence

1. **Approve §2 schema** (field names, enum, wrapper-level boundary booleans) and
   decide schema home (`morpheus` vs `attest-service`).
2. **Provision a managed production recording key + published kid** (separate
   approved step; not in this plan). Publish the public key + kid in a
   verification doc.
3. **Implement production wrapper module** (evolve the demo module to the §2
   schema; keep the crypto core) + expand the test matrix (§6). No endpoint yet.
4. **Wrap the canonical `public_demo` receipt offline** as the first production
   Path B artifact (see §9), store it in a wrapper store (separate from the inner
   ledger). Verify it independently with the published key.
5. **Ship Option A read endpoint** `GET /v1/sar-402/recording/{id}` (404 when no
   wrapper). Contract-test that `/v1/attest/receipt/{id}` is unchanged.
6. **Ship Explorer rendering + CLI verifier** that distinguishes Path A from
   Path B and renders the `authority_boundary`.
7. **Only then** announce Path B as live, and only for `public_demo` first.
8. **Later:** Option C operator-gated issuance for `real_task` receipts, after the
   read/render/verify surface has been public and stable.

**Deployment risks & answers:**
- *Should the existing public lookup return the wrapper by default?* **No.** It
  must keep returning the bare Path A record. Wrapper is a separate endpoint
  (Option A).
- *Separate endpoint?* **Yes** — `GET /v1/sar-402/recording/{id}`.
- *Should Explorer show Path A and Path B separately?* **Yes**, explicitly, to
  prevent conflation.
- *Could existing clients break if wrapper shape changes?* Not if Path B is a
  separate endpoint/store; Path A clients are untouched. The risk only appears
  under Option B (rejected for v1).
- *Wrap the canonical receipt or mint a fresh one?* See §9.

---

## 9. Recommendation: wrap the canonical receipt vs. issue a fresh first wrapper

**Recommendation: wrap the existing canonical `public_demo` receipt
`sha256:91e2ae85f03c7a8e7df10e8862895b99456cb13abc50b4e23ba84f1c15b3b8c9` as the
first production Path B example — served via the separate Option A endpoint, with
the inner receipt left byte-for-byte unchanged.**

Why:
- Wrapping is **provably non-mutating**: the wrapper embeds the inner receipt
  verbatim and binds `wrapped_receipt_id` to the *already-public*
  `sha256:91e2ae85…`. The live `/v1/attest/receipt/{id}` lookup keeps returning
  the unchanged Path A record (constraint: do not mutate public receipts — honored).
- It reuses the **existing canonical public reference** (the live lookup and
  `defaultverifier.com/demo/sar-402`), so the first Path B artifact demonstrates
  attribution over the exact receipt the public already knows — the strongest
  possible demo of "the wrapper binds *this* receipt."
- The canonical receipt is already a `public_demo` artifact (an explicit
  demonstration context, not a real settlement), so wrapping it as a
  demonstration is truthful and low-risk.
- A fresh receipt would dilute the canonical reference, require publishing a new
  inner receipt, and prove less (it would not show Path B binding to the
  already-trusted id).

Guardrails on this choice:
- Serve the wrapper **only** at the new endpoint; never alter the canonical
  lookup response.
- The first wrapper must be signed by the **production** key + published kid
  (not the demo ephemeral key), and independently verifiable.
- Keep `real_task` receipts **unwrapped** until the read/render/verify surface is
  public and reviewed.

---

## 10. Open questions

1. Wrapper schema home: `morpheus` (governance) vs `attest-service` (locality)?
2. Where is the production recording key custodied (KMS vs injected env seed)?
3. Wrapper storage: new ledger (`attest_recording_wrappers_master.jsonl`) vs a
   field on a separate store? (Must not co-mingle with the inner receipt ledger.)
4. Does `observed_at` ever differ from `recorded_at`/`signed_at` in practice, or
   collapse to one timestamp for the ingestion path?
5. `recording_context` default for the live ingestion path — `"ingestion"`?
6. Should the published verification doc + CLI ship in this repo or alongside SAR
   Explorer?
7. Versioning: is this `sar402_recording_wrapper_v1` (production) distinct from
   the demo `v0.1`, and do we need to verify both during a transition?

---

## 11. Recommended next implementation step

**Do not write production signing yet.** The single next step is:

> **Draft and circulate the §2 production wrapper schema** (explicit field names,
> the `recording_context` enum, and the three wrapper-level non-execution
> booleans), plus the schema-home decision (§10 Q1), for Keith/Morpheus review.

Once that schema is approved *and* a managed production key + published kid exist
(separate approved step), the implementation order is: evolve the wrapper module
to the approved schema → expand the test matrix (§6) → wrap the canonical
`public_demo` receipt offline and verify it → ship the Option A read endpoint →
ship Explorer/CLI rendering. The crypto core needs no rework; the contract,
schema, key, and surfaces around it do.

---

*Plan only. No production code changed, no keys created or rotated, no
deployment, no public API behavior changed, no public receipts mutated. Path B is
not live.*
