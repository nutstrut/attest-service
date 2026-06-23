#!/usr/bin/env python3
"""Prepare the *canonical public* SAR-402 demo receipt payload (PREP ONLY).

LOCAL / OFFLINE. This script does NOT POST to the live endpoint, does NOT deploy,
and does NOT write the production ledger. It:

  1. Builds a fresh, purpose-built inner SAR-402 settlement payload for public
     demonstration (owned resource, deliberate testnet demo identity, authority
     boundaries preserved).
  2. Computes the expected ``receipt_id`` using the *authoritative* committed
     helper ``morpheus.sar402.builder.compute_integrity`` — the same
     canonicalization the receipt's ``integrity`` block declares.
  3. Validates the payload through the committed ``validate_receipt``.
  4. Dry-runs the real ingestion core ``record_sar402_receipt(..., persist=False,
     receipt_context="public_demo")`` to prove the live path would ACCEPT it and
     that the adopted ``receipt_id`` equals the precomputed digest — WITHOUT
     persisting anything.
  5. Writes the proposed payload JSON + a markdown review report.

Canonicalization note (IMPORTANT). The SAR-402 receipt id is NOT RFC 8785 / JCS.
The committed pipeline uses ``sorted_keys_compact_v0`` (json.dumps with
``sort_keys=True, separators=(",",":"), ensure_ascii=False``) — see
``morpheus/sar402/builder.py:canonical_json`` ("Not RFC 8785 JCS") and
``morpheus/sar402/constants.py: CANONICALIZATION = 'sorted_keys_compact_v0'``.
The live ingest path (``sar402_receipts.record_sar402_receipt``) does not compute
the digest at all: it *adopts* the inbound ``integrity.digest`` verbatim as the
``receipt_id``. So the precomputed id below is what the live receipt id WILL be
iff the payload is ingested byte-for-byte unchanged.

Run:

    PYTHONPATH=~/morpheus python3 \
        reports/sar402/path-a-demo/generate_canonical_public_demo.py
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# --- repo + morpheus import wiring (same convention as the test suite) -------
ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import attest_service as svc  # noqa: E402
from sar402_receipts import (  # noqa: E402
    DEMO_RECEIPT_CONTEXT,
    RECEIPT_TYPE,
    explorer_url_for,
    lookup_path_for,
    record_sar402_receipt,
)

# Authoritative committed helpers (single source of truth for canonicalization
# + the integrity digest). We do NOT re-implement the digest.
from morpheus.sar402 import constants as sar_const  # noqa: E402
from morpheus.sar402.builder import (  # noqa: E402
    canonical_json,
    compute_integrity,
    derive_agent_id,
)
from morpheus.sar402.validate import validate_receipt  # noqa: E402

# The real /pay/url-summary delivery builder — reused so the delivered payload
# (and its evidence digest) is a genuine capture, not a hand-written object.
from pay_url_summary import (  # noqa: E402
    UrlSummaryInput,
    _canonical_digest,
    build_delivery_object,
)

OUT_DIR = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Canonical demo constants
# ---------------------------------------------------------------------------

# Stable, DefaultVerifier-owned resource. Must remain valid indefinitely.
DEMO_RESOURCE_URL = "https://defaultverifier.com/demo/sar-402"

# Base *Sepolia* testnet (NOT Base mainnet 8453). Using a testnet chain id makes
# the "no mainnet payment / no legal finality" boundary structural, not just a
# note. Pairs with issuer.environment = test.
DEMO_CHAIN = "eip155:84532"

# Deliberate, reproducible demo identities. NOT placeholder "0xPAYER..." strings
# and NOT real custodied wallets: each address is the first 20 bytes of a
# SHA-256 over a documented public seed string that literally names the demo.
# Anyone can recompute these; nobody holds their keys.
PAYER_SEED = "defaultverifier.com/demo/sar-402#public-demo-payer-v1"
RECIPIENT_SEED = "defaultverifier.com/demo/sar-402#public-demo-recipient-v1"


def _demo_addr(seed: str) -> str:
    return "0x" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:40]


DEMO_PAYER = _demo_addr(PAYER_SEED)
DEMO_RECIPIENT = _demo_addr(RECIPIENT_SEED)
DEMO_AGENT_ID = derive_agent_id(DEMO_CHAIN, DEMO_PAYER)

# Fixed, internally-coherent demo timestamps (deterministic; declared
# demo/testnet evidence). Order: quoted -> paid -> verified -> delivered, with
# quote expiration AFTER delivery. The delivery capture's own delivered_at is
# overridden with T_DELIVERED so the receipt timeline is consistent (the
# original capture used wall-clock now(), which drifted past quote expiry).
T_QUOTED = "2026-06-23T00:00:00Z"
T_PAID = "2026-06-23T00:00:03Z"
T_VERIFIED = "2026-06-23T00:00:05Z"
T_DELIVERED = "2026-06-23T00:00:07Z"
T_ISSUED = "2026-06-23T00:00:08Z"
T_QUOTE_EXPIRES = "2026-06-23T00:09:30Z"

# Inline source content the resource server "fetched and summarized" (network-
# free, deterministic) — describes the demo itself.
DEMO_SOURCE_CONTENT = (
    "<title>SAR-402 public demonstration receipt</title>"
    "<p>This is the canonical public SAR-402 demonstration receipt for "
    "DefaultVerifier. A resource server delivered a paid resource and emitted "
    "settlement evidence; DefaultVerifier records the evidence as a SAR-402 "
    "settlement receipt. DefaultVerifier records evidence only: it does not "
    "deliver the resource, authorize access, execute payment, or control "
    "resource release. This is testnet/demo evidence, not mainnet payment and "
    "not legal payment finality.</p>"
)

PURPOSE = (
    "Canonical public SAR-402 demonstration receipt: a deliberate, purpose-built "
    "public proof that DefaultVerifier records SAR-402 delivery evidence in a "
    "payload-bound, role-separated, publicly inspectable form."
)

# Prep-stage claim — FUTURE tense. The receipt is not yet ingested, so we do
# NOT use present-tense "is publicly inspectable" language. The present-tense
# claim only becomes true after the exact receipt id resolves publicly.
CLAIM = (
    "This receipt is prepared so that, after approved live ingest, DefaultVerifier "
    "will have recorded this SAR-402 delivery event and the receipt will be "
    "publicly inspectable, payload-bound, and role-separated."
)

NOT_CLAIMED = [
    "No mainnet payment (testnet chain eip155:84532, issuer.environment = test).",
    "No legal payment finality.",
    "No DefaultVerifier delivery authority.",
    "No DefaultVerifier payment execution.",
    "No DefaultVerifier access authorization.",
    "No DefaultVerifier resource-release control.",
    "No production Path B verifier-key signature attribution (Path B pending).",
]


def capture_delivered_payload() -> dict:
    """Capture a REAL delivered payload from the /pay/url-summary delivery logic
    (network-free, deterministic), bound to the owned demo resource URL."""
    inp = UrlSummaryInput(
        url=DEMO_RESOURCE_URL,
        text=DEMO_SOURCE_CONTENT,
        title="SAR-402 public demonstration receipt",
        mode="record",
        save=False,
    )
    # Pin the delivery time to the fixed, coherent T_DELIVERED (instead of
    # wall-clock now()) so the captured delivered_at — and the evidence digest
    # computed over it — stays inside the quote window. delivered_at is rendered
    # as now.isoformat().replace("+00:00","Z") (pay_url_summary), so this UTC
    # datetime reproduces T_DELIVERED exactly.
    delivered_dt = datetime.strptime(T_DELIVERED, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    return build_delivery_object(inp, now=delivered_dt)


def build_payload(delivered: dict) -> dict:
    """Build the inner SAR-402 settlement payload, then attach the integrity
    block computed by the authoritative committed helper."""
    payload = {
        "schema_id": sar_const.SCHEMA_ID,
        "profile": sar_const.PROFILE,
        "sar_type": "Settlement Attestation Receipt",
        "sar_verdict": "PASS",
        "verification_point": "post_delivery",
        "verification_mode": "record",
        "authority_binding": {
            "verifier_has_execution_authority": False,
            "verifier_controls_resource_release": False,
            "resource_server_controls_delivery": True,
            "acting_party": "resource_server",
        },
        "payment_state": "verified",
        "delivery_state": "confirmed",
        "settlement_state": "delivered",
        "continuity": {
            "object_continuity": "PASS",
            "constraint_continuity": "PASS",
            "temporal_continuity": "PASS",
            "authority_continuity": "PASS",
            "executor_continuity": "PASS",
        },
        "payment": {
            "resource": delivered["requested_url"],
            "quote_id": "q_public_demo_v2",
            "price": {"amount": "10000", "asset": "USDC", "decimals": 6},
            "amount_paid": {"amount": "10000", "asset": "USDC", "decimals": 6},
            "asset": "USDC",
            "chain": DEMO_CHAIN,
            "recipient": DEMO_RECIPIENT,
            "payer": DEMO_PAYER,
            # Clearly-typed demo reference (schema allows any string; payment_ref
            # is "tx hash / settlement id"). Deliberately NOT a hex-shaped fake
            # tx hash — a reader sees immediately this is a demonstration, not a
            # real settlement transaction.
            "payment_ref": "demo:canonical-public-demo-v2-20260623",
        },
        "delivery": {
            "delivered_resource": delivered["resolved_url"],
            "evidence_type": delivered.get("evidence_type", "http_response"),
            "evidence_digest": delivered["delivery_evidence_digest"],
            "status_code": delivered["status_code"],
            "delivered_at": delivered["delivered_at"],
        },
        "identity": {
            "payer": DEMO_PAYER,
            "derived_identity": {
                "registration_mode": sar_const.REGISTRATION_MODE_DERIVED,
                "derived_agent_id": DEMO_AGENT_ID,
                "identity_status": "derived",
            },
        },
        "timestamps": {
            "quoted_at": T_QUOTED,
            "paid_at": T_PAID,
            "verified_at": T_VERIFIED,
            "delivered_at": delivered["delivered_at"],
            "issued_at": T_ISSUED,
            "quote_expires_at": T_QUOTE_EXPIRES,
        },
        "issuer": {
            "verifier": "DefaultVerifier",
            "verifier_version": "0.1.0",
            "environment": "test",
        },
        "notes": (
            "Canonical public SAR-402 demonstration receipt v2 (testnet/demo). "
            "Recorded evidence only; no DefaultVerifier signature; not mainnet "
            "payment; not legal payment finality."
        ),
    }
    # Authoritative integrity (digest over the receipt EXCLUDING the integrity
    # block, sorted_keys_compact_v0). The digest value is adopted as receipt_id.
    payload["integrity"] = compute_integrity(payload)
    return payload


def main() -> int:
    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y%m%dT%H%M%SZ")
    artifact_id = f"sar402-canonical-public-demo-v2-{timestamp}"

    delivered = capture_delivered_payload()
    payload = build_payload(delivered)
    expected_receipt_id = payload["integrity"]["digest"]

    # v2 must NOT collide with the v1 digest (which was mis-stored as real_task).
    V1_RECEIPT_ID = (
        "sha256:ecbcd91bc7dbd847f7cab1dbe4605878cbed499d7726c1db1acc81e3e6e8b177"
    )
    assert expected_receipt_id != V1_RECEIPT_ID, "v2 digest must differ from v1"

    # Cross-check: recompute the digest the long way over the payload sans
    # integrity, to prove the report's stated method reproduces the id.
    sans_integrity = {k: v for k, v in payload.items() if k != "integrity"}
    recomputed = "sha256:" + hashlib.sha256(
        canonical_json(sans_integrity).encode("utf-8")
    ).hexdigest()
    assert recomputed == expected_receipt_id, "digest recomputation mismatch"

    # Committed validator must accept exactly what the live ingest validates
    # (the schema projection of the payload).
    validate_receipt(_projection_safe(payload))

    # Dry-run the REAL ingestion core: prove the live path would accept it and
    # adopt receipt_id == precomputed digest. persist=False => NO ledger write.
    dry = record_sar402_receipt(
        payload, persist=False, receipt_context=DEMO_RECEIPT_CONTEXT
    )
    assert dry["status"] == "recorded"
    assert dry["receipt_id"] == expected_receipt_id, "adopted id != precomputed"

    # Evidence-digest self-consistency (third-party recomputable).
    delivered_wo = {
        k: v for k, v in delivered.items() if k != "delivery_evidence_digest"
    }
    evidence_recomputed = _canonical_digest(delivered_wo)
    assert evidence_recomputed == delivered["delivery_evidence_digest"]

    payload_path = OUT_DIR / f"{artifact_id}.payload.json"
    report_path = OUT_DIR / f"{artifact_id}.md"

    payload_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    report_path.write_text(
        render_report(
            artifact_id=artifact_id,
            generated_at=now.isoformat(),
            payload=payload,
            delivered=delivered,
            expected_receipt_id=expected_receipt_id,
            dry=dry,
            payload_filename=payload_path.name,
        ),
        encoding="utf-8",
    )

    print(f"artifact_id        : {artifact_id}")
    print(f"expected_receipt_id: {expected_receipt_id}")
    print(f"receipt_context    : {DEMO_RECEIPT_CONTEXT} (selected at ingest)")
    print(f"resource           : {DEMO_RESOURCE_URL}")
    print(f"chain              : {DEMO_CHAIN}")
    print(f"agent_id           : {DEMO_AGENT_ID}")
    print(f"digest recomputed  : {recomputed == expected_receipt_id}")
    print(f"dry-run accepted   : {dry['status'] == 'recorded'}")
    print(f"payload            : {payload_path}")
    print(f"report             : {report_path}")
    return 0


def _projection_safe(payload: dict) -> dict:
    """Validate through the same projection the live ingest uses, so we exercise
    exactly what record_sar402_receipt validates."""
    from sar402_receipts import schema_projection

    return schema_projection(payload)


def render_report(
    *,
    artifact_id: str,
    generated_at: str,
    payload: dict,
    delivered: dict,
    expected_receipt_id: str,
    dry: dict,
    payload_filename: str,
) -> str:
    enc_id = expected_receipt_id.replace(":", "%3A")
    lines: list[str] = []
    A = lines.append

    A("# SAR-402 Canonical Public Demo Receipt — v2 — PREP (not published)")
    A("")
    A(f"**Generated (UTC):** {generated_at}  ")
    A(f"**Artifact id:** `{artifact_id}`  ")
    A(f"**Proposed payload:** `{payload_filename}`  ")
    A("**Status:** Local preparation only. Nothing published, posted, or "
      "deployed. Awaiting Keith approval.")
    A("")
    A("> This receipt has **not** been ingested. The production ledger was not "
      "touched. The id below is the id the live receipt *will* have iff the "
      "payload is ingested byte-for-byte unchanged.")
    A("")
    A("---")
    A("")

    A("## 0. Why v2 (supersedes v1)")
    A("")
    A("The v1 prepared payload "
      "(`sha256:ecbcd91bc7dbd847f7cab1dbe4605878cbed499d7726c1db1acc81e3e6e8b177`) "
      "was POSTed to production **before the service restart**, while the live "
      "service was still running the old code. The POST succeeded but the live "
      "service ignored the `receipt_context=public_demo` query param and stored "
      "the ledger record as **`receipt_context: real_task`**. v1 is therefore "
      "**not** the canonical `public_demo` receipt and must not be reused or "
      "reposted.")
    A("")
    A("After restart, production correctly enforces the constrained context: an "
      "invalid value now returns HTTP 422 "
      "`{\"detail\":\"invalid receipt_context: must be one of real_task, "
      "public_demo\"}`. This v2 payload has a **different digest** from v1 and is "
      "the canonical artifact to publish as `public_demo`.")
    A("")
    A("---")
    A("")

    A("## 1. Purpose")
    A("")
    A(PURPOSE)
    A("")
    A("**Claim (bounded):**")
    A("")
    A("```text")
    A(CLAIM)
    A("```")
    A("")

    A("## 2. Expected receipt_context after live ingest")
    A("")
    A("`public_demo` — selected at ingest time via the query param "
      "`?receipt_context=public_demo`, **not** embedded in the inner payload. "
      "The inner SAR-402 payload carries no `receipt_context` field; the ingest "
      "wrapper records it on the ledger record. Default without the param is "
      "`real_task`, so the demo label is a deliberate, explicit opt-in.")
    A("")

    A("## 3. Expected receipt_id / digest (computed locally)")
    A("")
    A(f"```text\n{expected_receipt_id}\n```")
    A("")
    A("- Computed by the committed authoritative helper "
      "`morpheus.sar402.builder.compute_integrity`.")
    A("- Independently recomputed the long way (canonical bytes, see §4): "
      "**match = TRUE**.")
    A("- Dry-run through the real ingestion core "
      "`record_sar402_receipt(..., persist=False, receipt_context=\"public_demo\")` "
      f"adopted `receipt_id` = this value: **{str(dry['receipt_id'] == expected_receipt_id).upper()}** "
      "(no ledger write performed).")
    A("")

    A("## 4. Exact digest computation method")
    A("")
    A("**Canonicalization is `sorted_keys_compact_v0`, NOT RFC 8785 / JCS.** "
      "(The task brief said \"JCS/RFC 8785\"; the committed code does not use "
      "JCS — see `morpheus/sar402/builder.py:canonical_json` which is annotated "
      "\"Not RFC 8785 JCS\", and `constants.CANONICALIZATION = "
      "'sorted_keys_compact_v0'`. This report uses the *actual* committed "
      "method so the precomputed id matches the live ingest id.)")
    A("")
    A("Method:")
    A("")
    A("1. Take the inner SAR-402 payload **excluding** the `integrity` block.")
    A("2. Canonical JSON = `json.dumps(obj, sort_keys=True, "
      "separators=(',',':'), ensure_ascii=False)` (UTF-8).")
    A("3. `receipt_id = 'sha256:' + sha256(canonical_bytes).hexdigest()`.")
    A("4. The live ingest path (`record_sar402_receipt`) **adopts** the inbound "
      "`integrity.digest` verbatim as `receipt_id` — it does not recompute. So "
      "an unchanged payload yields exactly this id.")
    A("")
    A("Third-party recomputation:")
    A("")
    A("```bash")
    A(f"python3 - <<'PY'")
    A("import hashlib, json")
    A(f"p = json.load(open('{payload_filename}'))")
    A("p.pop('integrity', None)  # digest is over the receipt EXCLUDING integrity")
    A("canon = json.dumps(p, sort_keys=True, separators=(',',':'),")
    A("                   ensure_ascii=False).encode('utf-8')")
    A("print('sha256:' + hashlib.sha256(canon).hexdigest())")
    A("PY")
    A(f"# expect: {expected_receipt_id}")
    A("```")
    A("")

    A("## 5. Exact POST command (for Keith to approve LATER — do not run yet)")
    A("")
    A("```bash")
    A("curl -sS -X POST \\")
    A("  'https://defaultverifier.com/v1/sar-402/receipts?receipt_context=public_demo' \\")
    A("  -H 'Content-Type: application/json' \\")
    A(f"  --data @{payload_filename}")
    A("# (add -H 'Authorization: Bearer <key>' iff SAR402_INGEST_API_KEY is set)")
    A("```")
    A("")

    A("## 6. Exact public lookup command (after publication)")
    A("")
    A("```bash")
    A(f"curl -sS 'https://defaultverifier.com/v1/attest/receipt/{enc_id}'")
    A("# expect a record with receipt_type=sar_402_settlement, "
      "receipt_context=public_demo")
    A("```")
    A("")
    A(f"Live lookup path: `{lookup_path_for(expected_receipt_id)}`")
    A("")

    A("## 7. SAR Explorer URL pattern (after publication)")
    A("")
    A(f"```text\n{explorer_url_for(expected_receipt_id)}\n```")
    A("")

    A("## 8. Claim boundaries")
    A("")
    A("Authority binding (preserved):")
    A("")
    A("```text")
    A("verifier_has_execution_authority   = false")
    A("verifier_controls_resource_release = false")
    A("resource_server_controls_delivery  = true")
    A("acting_party                       = resource_server")
    A("```")
    A("")
    A("This receipt does NOT claim:")
    A("")
    for nc in NOT_CLAIMED:
        A(f"- {nc}")
    A("")
    A("Identity provenance: the payer/recipient addresses are deterministically "
      "derived demo addresses — the first 20 bytes of SHA-256 over documented "
      "public seed strings (`"
      f"{PAYER_SEED}` / `{RECIPIENT_SEED}`) — reproducible by anyone, with no "
      "private keys used or asserted. They are not placeholder `0xPAYER...` "
      "strings. Chain is Base Sepolia testnet (`eip155:84532`).")
    A("")
    A("---")
    A("")
    A("*Canonical public SAR-402 demo receipt — prepared locally, not published. "
      "Path B (verifier-key signature attribution) remains pending and is not "
      "included here.*")
    A("")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
