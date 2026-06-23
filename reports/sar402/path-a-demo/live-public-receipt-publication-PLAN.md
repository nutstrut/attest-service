# SAR-402 Path A — Live Public Receipt Publication

**Planning document — no code, no publication, no deploy.**
Date: 2026-06-23 · Author: Claude (for Keith review) · Scope: Path A only.

This document is a plan. Nothing in it has been executed. No receipt has been
published, the demo page has not been edited, no key has been used, and nothing
has been deployed. It ends with exact commands for Keith to approve later.

---

## 0. Current state (verified against the repo)

| Thing | Value / location | Status |
|---|---|---|
| Demo page | `~/sar-explorer/demo-sar-402.html` → `https://defaultverifier.com/demo/sar-402` | Live, says "publication pending" |
| Demo page receipt id | `sha256:ecf8…063185` | **Does not resolve** publicly (`receipt not found`) |
| Demo page evidence digest | `sha256:1156…608c8` | **Does not resolve** publicly (it is an evidence digest, not a receipt id — never expected to resolve) |
| A public SAR-402 receipt | `sha256:f8d1…bf68` | **Resolves**; `receipt_context: real_task`; resource `https://api.example.com/v1/summary`; `created_at 2026-06-20` |
| Live ingest path | `POST /v1/sar-402/receipts` → `record_sar402_receipt` (`sar402_receipts.py`) | Live |
| Live lookup path | `GET /v1/attest/receipt/{id}` → `attest_service.get_receipt` (`:980`) | Live |
| Explorer URL template | `https://sarexplorer.com/?receipt_id=` (`sar402_receipts.py:72`) | Live |

**Critical constraint discovered in code (drives Section 2):**

- `sar402_receipts.py:82` hardcodes `RECEIPT_CONTEXT = "real_task"` for *every*
  receipt ingested through the live `POST /v1/sar-402/receipts` path.
- `attest_service.py:50` defines `ReceiptContext = Literal["activation_demo",
  "real_task", "continuity_pair"]` — a **closed** set. There is **no** SAR-402
  "public demo artifact" context value today, and `sar_402_settlement` is not a
  `ReceiptContext` (it is the `receipt_type`).
- Therefore a receipt published through the live path *as the code stands today*
  will carry `receipt_context: real_task` — exactly like the existing public
  `f8d1…` receipt, and exactly like the local `ecf8…` demo record already shows
  on the page. **`receipt_context` cannot currently signal "demo" without a code
  change.** This is the single most important planning fact below.

---

## 1. Which receipt should become the canonical public proof?

### Option A — publish the existing local demo receipt `ecf8…063185`
The `ecf8…` digest was computed by `generate_demo.py` over a payload whose
`issuer.environment = test`, `timestamps` pinned to `2026-06-23`, payer/recipient
are obvious placeholders (`0xPAYER000…0002`, `0xRECIPIENT…0001`), and
`payment.resource` / `delivery.delivered_resource` point at
`https://defaultverifier.example/explainers/sar-402` — a **non-resolving
`.example` domain** (`generate_demo.py:119`). The id is content-addressed, so to
make `ecf8…` resolve you must POST a byte-identical payload to the live path.

- ✅ Demo page needs no id change.
- ❌ Bakes the `.example` placeholder resource and accidental-looking placeholder
  payer into the *canonical public* artifact — the exact thing the milestone is
  meant to avoid.
- ❌ It was generated for a throwaway local ledger, not designed as a public
  proof. Repurposing it is "reverse-justifying a local hash."

### Option B — repoint the demo page to the already-public `f8d1…bf68`
- ✅ Resolves today; zero publication step.
- ❌ It is a `real_task` receipt from 2026-06-20 with resource
  `https://api.example.com/v1/summary` (another `.example`/non-owned host). It
  was not built as the Path A canonical demo, and the user has explicitly said it
  is **not** the canonical demo receipt. Using it conflates "proof that public
  lookup works" with "the demo's own receipt."
- ❌ Its provenance/intent is not demonstration; claim boundaries get muddy.

### Option C — generate and publish a fresh, purpose-built canonical demo receipt — **RECOMMENDED**
Create one receipt deliberately for public demonstration, with a
DefaultVerifier-owned, stable, resolvable resource and a clearly demo-signalling
identity, ingest it through the live path, confirm public resolution, then update
the page to the new id.

- ✅ Clean provenance: built to be the public proof, not repurposed.
- ✅ Lets us fix the placeholder-resource and placeholder-payer problems *before*
  anything is public and permanent.
- ✅ Single canonical id across page, lookup, Explorer, and Morpheus evidence.
- ⚠️ Requires a deliberate publication step (POST to live ledger) and a page
  edit — both gated on Keith.
- ⚠️ Surfaces the `receipt_context` limitation (Section 2) as a real decision
  rather than letting it slip by.

**Recommendation: Option C.** It is the only option that produces a deliberate,
clean, indefinitely-valid public proof. A & B both permanently enshrine an
artifact that was never designed to be the canonical public receipt.

---

## 2. What makes a "fresh canonical public demo receipt" canonical

A receipt is canonical for this milestone iff **all** of the following hold. Each
maps to a concrete field or path.

1. **Purpose-built.** Generated specifically for public demonstration (its own
   generator/config, not the throwaway-ledger local demo path).
2. **Demo-signalling `agent_id`.** Use a payer address that *reads as
   intentional demo*, not an accidental placeholder. Recommended:
   a clearly-labelled demo payer such as
   `0xDEM00000000000000000000000000000000DEMO` is still placeholder-shaped — so
   prefer instead a real DefaultVerifier-controlled testnet (Base Sepolia or a
   clearly demo) address, yielding e.g.
   `agent:x402:eip155:84532:0x<real-demo-addr>`. The agent id must not look like
   a typo'd real payer.
3. **No real payer addresses** and **no accidental-looking placeholders**
   (`0xPAYER000…0002` style is forbidden — it reads as a bug, not a choice).
4. **Real, DefaultVerifier-owned resource that resolves or is clearly described.**
   Forbidden: `.example` hosts, `api.example.com`, expiring URLs, temp test
   endpoints, anything that can go offline.
5. **Stable resource.** Preferred delivered/resource URL:
   `https://defaultverifier.com/demo/sar-402` (the demo page itself — owned,
   stable, already live). This must remain valid **indefinitely**.
6. **Ingested through the live path** `POST /v1/sar-402/receipts` (not a local
   throwaway ledger), so it lands in the production ledger SAR Explorer reads.
7. **Publicly resolvable** through `GET /v1/attest/receipt/{receipt_id}`.
8. **Renders through SAR Explorer** at
   `https://sarexplorer.com/?receipt_id=<id>`.
9. **Preserved in Morpheus** with explicit publication intent (Section 8).
10. **Demonstration-signalling metadata.** ⚠️ **Decision required.** As the code
    stands, the live path forces `receipt_context: real_task` and there is no
    SAR-402 demo context enum value. Options:
    - (a) Accept `receipt_context: real_task` and signal "demo" *only* through
      `issuer.environment = test`, the demo `agent_id`, and the
      `defaultverifier.com/demo/sar-402` resource. (No code change.)
    - (b) Add a `"public_demo"` (or similar) value to the `ReceiptContext`
      `Literal` (`attest_service.py:50`) and let the SAR-402 path set it
      (`sar402_receipts.py:82`). **This is a code change and is out of scope for
      this planning task** — flag for a follow-up if Keith wants schema-level
      demo signalling.
    Recommendation: ship Option C with (a) for now; raise (b) as a small,
    separate, reviewed change if "demo" must be machine-readable in
    `receipt_context`. Do not silently publish a `real_task` receipt while
    *calling* it a demo on the page without the `environment=test` +
    demo-resource signals making the demo nature unambiguous.
11. **Path B attribution-ready.** The inner payload must leave
    `integrity.signature` absent/optional and keep
    `verifier_has_execution_authority = false`, so Path B can later populate the
    recording signature without reshaping the receipt.

---

## 3. What "public" means technically

"Public" for this milestone = the canonical receipt id satisfies all of:

1. **Resolves** via `GET https://defaultverifier.com/v1/attest/receipt/{id}` and
   returns the stored ledger record (not `{"detail":"receipt not found"}`).
2. **Renders** via `https://sarexplorer.com/?receipt_id={id}`.
3. **Preserved** in repo (`reports/sar402/path-a-demo/`) and in Morpheus evidence
   with the exact id and publication command.
4. **Clear claim boundaries on the page** (Section 5) — record-only, no signing,
   no finality.
5. **No ambiguity** between "local demo-mode evidence" and "publicly published
   receipt." Today the page says publication is *pending*; after publication the
   page must stop describing the receipt as local-only and stop saying the
   Explorer URL "does not yet resolve." The two states must never be mixed in
   one render.

---

## 4. Code / data paths involved (inspected)

| Path | Role | Notes for publication |
|---|---|---|
| `sar402_receipts.py` | Live ingestion (`record_sar402_receipt`, route `/v1/sar-402/receipts`) | Adopts `integrity.digest` as `receipt_id`; hardcodes `receipt_type="sar_402_settlement"`, `receipt_context="real_task"`; `agent_id` from `identity.derived_identity.derived_agent_id`. Auth via `SAR402_INGEST_API_KEY` (enforced only if set). |
| `attest_service.py` | `write_receipt` (`:401`), `get_receipt` (`:980`), `RECEIPT_LEDGER` (`:32` → `attest_receipts_master.jsonl`), `ReceiptContext` enum (`:50`) | This is the **production** ledger. Publishing writes here. |
| `attest_receipts_master.jsonl` | Production receipt ledger | Append-only; the file the public lookup reads. A published demo receipt becomes a permanent line here. |
| `reports/sar402/path-a-demo/generate_demo.py` | Local offline generator | Points `RECEIPT_LEDGER` at a throwaway ledger and uses `.example` resource + placeholder payer. **Must be adapted (new generator/config) for canonical publication — do not reuse as-is.** |
| SAR Explorer URL | `DEFAULT_EXPLORER_BASE = https://sarexplorer.com/?receipt_id=` (`:72`) | Override via `SAR402_EXPLORER_BASE`. Explorer must read the same production ledger. |
| `receipt_context` / agent identity conventions | `ReceiptContext` Literal (`:50`); `derived_agent_id` shape `agent:x402:<chain>:<addr>` | No demo context value exists (Section 2.10). |

---

## 5. What must NOT be claimed

Carry every existing Path A boundary forward unchanged, plus publication-specific
ones:

- ❌ No mainnet payment unless actually true (keep `issuer.environment = test`;
  do not imply mainnet/Base settlement occurred).
- ❌ No legal payment finality.
- ❌ No verifier **delivery** authority.
- ❌ No verifier **access** authorization.
- ❌ No verifier **payment execution**.
- ❌ No verifier **release** control.
- ❌ No production Path B key attribution — Path B is code/test/report only
  (commit `ae11ecb`), **not deployed**, **no production key published**. The page
  must keep "Path B queued / not implemented here" until Path B is actually
  deployed.
- ❌ No "publicly inspectable receipt" / "resolves on the public surface"
  language until **the exact canonical receipt id resolves publicly**. This is
  the gating condition for every page edit in Section 6.

---

## 6. Exact page language that changes IF (and only if) publication succeeds

Only apply these edits after the canonical id verifiably resolves publicly
(Section 7). The new id replaces `ecf8…063185` everywhere it appears
(`demo-sar-402.html` lines ~337, 339, 340, 344, 440, 444).

| Loc | Current "pending" phrase | Proposed replacement (only if it resolves) |
|---|---|---|
| `meta description` (:7) | "Local demo-mode evidence; live public receipt publication pending." | "Publicly resolvable SAR-402 receipt, payload-bound and role-separated." |
| `og:description` (:14) | "Local demo-mode evidence; live public publication pending." | "Recorded and publicly resolvable on SAR Explorer." |
| `thesis` (:219) | "resolvable by receipt ID once published" | "resolvable by receipt ID on the public surface" |
| `claim` (:220) | "structured for public inspection" | "publicly inspectable" |
| **mode-banner** (:227–230) | "Local demo mode · live public publication pending"; "production ledger was not touched … public SAR Explorer link does not yet resolve this receipt because live publication is pending." | "Published · publicly resolvable"; "recorded through the live ingestion path into the production ledger and resolvable by receipt ID; `issuer.environment = test` (demo/testnet evidence, not mainnet finality)." |
| `#proves` bullets (:245, 247) | "into a local demo ledger here"; "resolvable on the public surface once published" | "into the production ledger"; "resolves on the public surface" |
| receipt code block (:347, 352) | "resolved against the throwaway demo ledger, not production"; `created_at: 2026-06-23T17:01:58Z` | "resolved against the production ledger"; new `created_at` from the live record |
| `.pending` callout (:340) | "Live public receipt publication pending — this URL does not yet resolve the demo receipt" | **Remove** the `.pending` element entirely. |
| proof-chain step 6 (:310) | "resolvable once live publication lands" | "resolvable now on the public surface" |
| reproduce step 1/2 (:441, 445) | "local demo ledger here"; "public publication pending; renders … once published" | "the production ledger"; "renders the same receipt on SAR Explorer" |
| `#artifacts` lead (:470) | "Live public receipt publication on SAR Explorer is pending." | "Live public receipt published on SAR Explorer." |
| `netchip` dot / mode tag | amber "pending" affordance | flip to a published/neutral state |
| footer (:499) | "local, reproducible SAR-402 Path A demo; live public receipt publication is pending." | "publicly resolvable SAR-402 Path A demo receipt." |

⚠️ If `receipt_context` stays `real_task` (Section 2.10a), keep the line at :353
showing `receipt_context` honest — it will read `real_task`, **not** a demo
value. Do not relabel it as a demo context on the page unless option (b) ships.
The `issuer.environment = test` row (:423) must stay to keep the demo/testnet
boundary unambiguous.

**Do not pre-edit any of this.** All page edits are gated on Section 7 passing
against the *exact* canonical id.

---

## 7. Validation steps (run after publication, before any page edit)

Let `RID` = the canonical receipt id (the inner payload's `integrity.digest`).

1. **Public lookup resolves:**
   ```bash
   curl -sS "https://defaultverifier.com/v1/attest/receipt/$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$RID")" | head -c 800
   ```
   Expect the stored record (with `receipt_id`, `receipt_type:
   sar_402_settlement`, `receipt_context`, `agent_id`, `receipt`), **not**
   `{"detail":"receipt not found"}`.

2. **Old ids are honestly handled:** confirm whether the page still references
   any non-resolving id; `ecf8…` / `1156…` must not be presented as publicly
   resolvable.

3. **Explorer renders:** open
   `https://sarexplorer.com/?receipt_id=<url-encoded RID>` and confirm it renders
   the receipt (not an empty/not-found state).

4. **Page id == live id:** grep the page for the receipt id and confirm every
   occurrence equals `RID` (and is URL-encoded where used in a path/URL):
   ```bash
   grep -n "sha256" ~/sar-explorer/demo-sar-402.html
   ```

5. **Resource is stable & DefaultVerifier-owned:** confirm the receipt's
   `payment.resource` / `delivery.delivered_resource` is
   `https://defaultverifier.com/demo/sar-402` (or another owned, resolving URL) —
   **no `.example`, no `api.example.com`, no temp/expiring host.**

6. **Overclaim greps (must return nothing):**
   ```bash
   grep -niE "defaultverifier (signed|cryptographically signed|delivered|authorized|executed payment|settled|proves legal)|legal payment finality is proven|verifier_kid" ~/sar-explorer/demo-sar-402.html
   ```
   Plus confirm "publicly inspectable / resolves" language appears **only**
   alongside the now-resolving `RID`.

7. **Path B still bounded:** confirm the page keeps Path B as "queued / not
   implemented here" and `issuer.environment = test` remains shown.

---

## 8. Evidence Morpheus should preserve after publication

Write a new Morpheus proof artifact (alongside the existing
`~/morpheus/reports/proof-artifacts/sar-402/path-a-demo-*.md`) capturing:

1. **Canonical receipt id** (`RID`) and the inner `integrity.digest` it derives
   from.
2. **Publication command / path** actually used (the `POST /v1/sar-402/receipts`
   invocation + which generator/config produced the payload).
3. **Public lookup result** — the actual JSON returned by
   `GET /v1/attest/receipt/{RID}` (proof it resolves), with timestamp.
4. **SAR Explorer URL** — `https://sarexplorer.com/?receipt_id=<RID>`.
5. **Claim-boundary notes** — the Section 5 list, reaffirmed; explicit note that
   `issuer.environment = test` and (if 2.10a) `receipt_context = real_task` with
   the demo nature signalled by environment + agent id + owned resource.
6. **Path B status** — explicitly **pending / not deployed** (commit `ae11ecb`
   is code/test/report only; no production key). State whether Path B attribution
   is included (it is not) so the evidence is unambiguous.
7. **Resource ownership note** — that the delivered/resource URL is
   DefaultVerifier-owned and intended to remain valid indefinitely.

---

## 9. Recommended sequence + exact next commands (for Keith to approve)

> Nothing below has run. Steps 2–4 mutate the production ledger / public page and
> are **gated on Keith's approval**.

**Step 0 — decide `receipt_context` (Section 2.10):** accept `real_task` + env
signalling (no code change), or schedule a separate reviewed change to add a demo
enum value. *Decision needed before generating the payload.*

**Step 1 — build the canonical payload (local, no publish):** adapt a generator
(new copy of `generate_demo.py`) so that:
- `payment.resource` and `delivery.delivered_resource` =
  `https://defaultverifier.com/demo/sar-402`,
- payer / `derived_agent_id` = a deliberate demo identity (Section 2.2),
- `issuer.environment = "test"`, `integrity.signature` absent,
- recompute `integrity.digest` → this becomes `RID`.
Review the payload JSON before any POST.

**Step 2 — publish to the live ledger (GATED):**
```bash
# (set SAR402_INGEST_API_KEY auth header if the env var is configured)
curl -sS -X POST https://defaultverifier.com/v1/sar-402/receipts \
  -H 'Content-Type: application/json' \
  --data @canonical-demo-receipt.json
# capture the returned receipt_id, explorer_url, receipt_lookup_path
```

**Step 3 — validate (Section 7):** run all 7 checks. **If any fail, stop — do not
touch the page.**

**Step 4 — update the page (GATED, only if Step 3 fully passes):** apply the
Section 6 edits, replacing every `ecf8…` occurrence with `RID`, remove the
`.pending` callout, flip the mode banner to "published," then re-run the
Section 7 grep checks against the edited file. Deploy the page per the existing
`~/sar-explorer/deploy.sh` process.

**Step 5 — preserve evidence (Section 8):** write the Morpheus proof artifact and
commit the updated demo generator/config + plan references in `attest-service`.

---

### One-line summary
Generate a fresh, purpose-built SAR-402 demo receipt with a DefaultVerifier-owned
stable resource (`defaultverifier.com/demo/sar-402`) and a deliberate demo
identity, publish it through the live `POST /v1/sar-402/receipts` path, verify it
resolves publicly and renders on SAR Explorer, *then* swap the page id and flip
the "pending" language — keeping record-only / no-signing / no-finality / Path-B-
pending boundaries intact, and noting that `receipt_context` will read
`real_task` unless a separate schema change is approved.
