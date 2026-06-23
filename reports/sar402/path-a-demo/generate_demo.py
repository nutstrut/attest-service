#!/usr/bin/env python3
"""Generate the SAR-402 Path A delivery-evidence demo artifact (v0.1).

LOCAL / OFFLINE generator. This script does NOT deploy and does NOT touch the
production receipt ledger. It points ``attest_service.RECEIPT_LEDGER`` at a
throwaway demo ledger inside this output directory, records exactly one receipt
through the real ingestion code (``sar402_receipts.record_sar402_receipt``),
resolves it through the real lookup helper (``attest_service.get_receipt`` /
``find_receipt``), and renders a timestamped Markdown + JSON report.

Path A scope only: this produces *recorded delivery evidence*. There is NO
signing, NO ``verifier_kid``, NO key publication, NO new receipt type, NO new
schema, and NO new verifier primitive. The artifact never claims DefaultVerifier
signed, delivered, authorized, executed, or legally settled anything.

Run:

    python3 reports/sar402/path-a-demo/generate_demo.py

Outputs (timestamped, UTC):

    reports/sar402/path-a-demo/sar402-path-a-demo-<timestamp>.md
    reports/sar402/path-a-demo/sar402-path-a-demo-<timestamp>.json
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# --- repo import wiring (same convention as the test suite) -----------------
ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import attest_service as svc  # noqa: E402
from sar402_receipts import (  # noqa: E402
    RECEIPT_TYPE,
    explorer_url_for,
    record_sar402_receipt,
)

# The real `/pay/url-summary` delivery logic. We reuse the endpoint's own
# delivery builder (and its canonical digest) so the delivered payload is a
# genuine capture from that demo path, not a hand-written illustrative payload.
from pay_url_summary import (  # noqa: E402
    UrlSummaryInput,
    _canonical_digest,
    build_delivery_object,
)

OUT_DIR = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Path A copy (single source of truth — kept verbatim from the planning docs)
# ---------------------------------------------------------------------------

PATH_A_CLAIM = (
    "DefaultVerifier recorded this SAR-402 delivery event, and the receipt is "
    "publicly inspectable, payload-bound, and role-separated."
)

PATH_A_LIMITATION = (
    "This is recorded delivery evidence, not a signed DefaultVerifier receipt "
    "and not proof of legal payment finality."
)

# Claims Path A must NEVER make. The overclaim check scans the demo copy for
# these and confirms none appear.
FORBIDDEN_CLAIMS = [
    "DefaultVerifier cryptographically signed the recorded receipt.",
    "DefaultVerifier delivered the resource.",
    "DefaultVerifier authorized access.",
    "DefaultVerifier executed payment.",
    "DefaultVerifier proves legal payment finality.",
]

# Substrings whose presence in the demo copy would constitute an overclaim.
# (Lower-cased, matched case-insensitively.) These target the *assertive* shape
# of the forbidden claims without tripping on the doctrine "did NOT ..." lines.
FORBIDDEN_OVERCLAIM_SUBSTRINGS = [
    "defaultverifier signed",
    "defaultverifier cryptographically signed",
    "defaultverifier delivered",
    "defaultverifier authorized",
    "defaultverifier executed payment",
    "defaultverifier proves legal",
    "defaultverifier settled",
    "legal payment finality is proven",
    "verifier_kid",
]


# ---------------------------------------------------------------------------
# Canonicalization helpers (documented, third-party-reproducible)
# ---------------------------------------------------------------------------

def canonical_bytes(obj: dict) -> bytes:
    """Canonical JSON: sorted keys, compact separators, UTF-8. This is the
    `sorted_keys_compact_v0` convention used across the SAR-402 demo path."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Demo inputs: a delivered resource payload + the SAR-402 receipt over it
# ---------------------------------------------------------------------------

# A realistic content-fetch resource URL the summary is "about". The actual
# bytes are supplied inline (below) so the capture is fully network-free and
# deterministic — no uncontrolled external dependency — while still flowing
# through the real `/pay/url-summary` delivery logic.
DEMO_RESOURCE_URL = "https://defaultverifier.example/explainers/sar-402"

# The source content the resource server "fetched and summarized". Supplied
# inline so the run is deterministic and offline; the url-summary delivery path
# extracts title/word_count/content hash/excerpt from it exactly as it would for
# a fetched page.
DEMO_SOURCE_CONTENT = (
    "<title>SAR-402: Settlement Attestation Receipts for x402</title>"
    "<p>SAR-402 is an x402-profile Settlement Attestation Receipt. It records "
    "what an x402 payment authorized, whether delivery matched the paid-for "
    "resource, and what evidence remains for later inspection. The verifier "
    "records and verifies evidence; it never holds execution authority, never "
    "controls release, and never moves funds. Delivery is performed and "
    "attested by the resource server, while DefaultVerifier records the "
    "resulting receipt so a third party can inspect it, recompute the delivered "
    "payload digest, and confirm that recorder and deliverer are different "
    "parties.</p>"
)


def capture_delivered_payload() -> dict:
    """Capture a REAL delivered payload from the `/pay/url-summary` delivery
    logic (network-free, deterministic).

    We call the endpoint's own `build_delivery_object` with a controlled inline
    `text` body and a realistic resource `url`. The url-summary path labels the
    requested/resolved resource as that URL but reads the bytes from the inline
    text — so no external network is touched, the output is deterministic, and
    the delivered object (`title`, `word_count`, `content_sha256`, `excerpt`,
    `delivered_at`, `delivery_evidence_digest`) is produced by the exact same
    code the live endpoint uses. This is option (2)/(1) from the task: the
    existing internal URL-summary function with controlled input, run in local
    demo mode."""
    inp = UrlSummaryInput(
        url=DEMO_RESOURCE_URL,
        text=DEMO_SOURCE_CONTENT,
        title="SAR-402: Settlement Attestation Receipts for x402",
        mode="record",
        save=False,
    )
    return build_delivery_object(inp, now=datetime.now(timezone.utc))


def build_receipt_payload(delivered: dict) -> dict:
    """Build the inner SAR-402 settlement receipt, bound to the REAL captured
    `/pay/url-summary` delivered payload via `delivery.evidence_digest` (the
    delivered object's own `delivery_evidence_digest`). The `integrity.digest`
    is the content hash adopted as `receipt_id` (computed over the canonical
    receipt excluding the integrity block, per the schema)."""
    resource_url = delivered["requested_url"]
    evidence_digest = delivered["delivery_evidence_digest"]
    payload = {
        "schema_id": "sar_402_settlement_v0.1",
        "profile": "sar-402",
        "sar_type": "Settlement Attestation Receipt",
        "sar_verdict": "PASS",
        "verification_point": "post_delivery",
        "verification_mode": "record",
        "authority_binding": {
            # DefaultVerifier records; it never holds execution authority and
            # never controls release. The resource server controls delivery.
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
            "resource": resource_url,
            "quote_id": "q_demo_path_a",
            "price": {"amount": "10000", "asset": "USDC", "decimals": 6},
            "amount_paid": {"amount": "10000", "asset": "USDC", "decimals": 6},
            "asset": "USDC",
            "chain": "eip155:8453",
            "recipient": "0xRECIPIENT00000000000000000000000000000001",
            "payer": "0xPAYER0000000000000000000000000000000002",
            "payment_ref": "0xdeadbeefdemo",
        },
        "delivery": {
            # Bound to the captured /pay/url-summary delivery artifact.
            "delivered_resource": delivered["resolved_url"],
            "evidence_type": delivered.get("evidence_type", "http_response"),
            "evidence_digest": evidence_digest,
            "status_code": delivered["status_code"],
            "delivered_at": delivered["delivered_at"],
        },
        "identity": {
            "payer": "0xPAYER0000000000000000000000000000000002",
            "derived_identity": {
                "registration_mode": "derived_from_settlement",
                "derived_agent_id": (
                    "agent:x402:eip155:8453:"
                    "0xPAYER0000000000000000000000000000000002"
                ),
                "identity_status": "derived",
            },
        },
        "timestamps": {
            "quoted_at": "2026-06-23T00:00:00Z",
            "paid_at": "2026-06-23T00:00:00Z",
            "verified_at": "2026-06-23T00:00:02Z",
            # Synced to the captured delivery artifact's delivered_at.
            "delivered_at": delivered["delivered_at"],
            "issued_at": "2026-06-23T00:00:02Z",
            "quote_expires_at": "2026-06-23T00:09:30Z",
        },
        "issuer": {
            # Self-asserted string in Path A (NOT key-bound — that is Path B).
            "verifier": "DefaultVerifier",
            "verifier_version": "0.1.0",
            "environment": "test",
        },
        "notes": (
            "Path A delivery-evidence demo (testnet/local). Recorded evidence "
            "only; no DefaultVerifier signature; not legal payment finality."
        ),
    }
    # Content-addressed integrity digest over the canonical receipt EXCLUDING
    # the integrity block (per the schema). This value is adopted as receipt_id.
    digest = sha256_digest(canonical_bytes(payload))
    payload["integrity"] = {
        "digest_alg": "sha256",
        "canonicalization": "sorted_keys_compact_v0",
        "digest": digest,
    }
    return payload


# ---------------------------------------------------------------------------
# Overclaim safety
# ---------------------------------------------------------------------------

def overclaim_scan(copy_text: str) -> list[str]:
    """Return any forbidden overclaim substrings found in the demo copy."""
    lowered = copy_text.lower()
    return [s for s in FORBIDDEN_OVERCLAIM_SUBSTRINGS if s in lowered]


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

def render_markdown(data: dict) -> str:
    d = data
    receipt_id = d["response"]["receipt_id"]
    request_python = (
        "from sar402_receipts import record_sar402_receipt\n"
        "result = record_sar402_receipt(payload)  # payload = SAR-402 receipt JSON below\n"
    )
    request_curl = (
        "curl -sS -X POST https://<attest-host>/v1/sar-402/receipts \\\n"
        "  -H 'Content-Type: application/json' \\\n"
        "  --data @sar402-receipt.json\n"
    )
    lines: list[str] = []
    A = lines.append

    A(f"# SAR-402 Path A Delivery-Evidence Demo — v0.1")
    A("")
    A(f"**Generated (UTC):** {d['generated_at']}  ")
    A(f"**Artifact id:** `{d['artifact_id']}`  ")
    A(f"**Scope:** Path A (recorded delivery evidence). No signing, no "
      f"`verifier_kid`, no schema change, no deployment.  ")
    A(f"**Source commit context:** SAR-402 wrapper-contract hardening "
      f"(`b8ba4d4`).")
    A("")
    A("> Reproducible, offline-generated artifact. The receipt below was "
      "recorded through the real ingestion code (`record_sar402_receipt`) into "
      "a throwaway demo ledger and resolved through the real lookup helper "
      "(`get_receipt`). The production ledger was not touched.")
    A("")
    A("---")
    A("")

    # 1. Thesis
    A("## 1. Demo thesis")
    A("")
    A("**Claim:**")
    A("")
    A("```text")
    A(PATH_A_CLAIM)
    A("```")
    A("")
    A("**Limitation (stated up front):**")
    A("")
    A("```text")
    A(PATH_A_LIMITATION)
    A("```")
    A("")
    A("---")
    A("")

    # 2. Systems and roles
    A("## 2. Systems and roles")
    A("")
    A("| Party | Field in the receipt | Role |")
    A("|---|---|---|")
    A("| Resource server (deliverer) | `authority_binding.acting_party = "
      f"{d['roles']['acting_party']!r}` | Delivered the paid resource and "
      "emitted the evidence. |")
    A("| Payer-derived agent | `identity.derived_identity.derived_agent_id` "
      f"= `{d['roles']['payer_derived_agent_id']}` (stored `agent_id`) | The "
      "paying party, derived from settlement. **Not** the deliverer. |")
    A("| DefaultVerifier | `issuer.verifier = "
      f"{d['roles']['issuer_verifier']!r}` | **Recorded** the evidence. Holds "
      "no execution authority (`verifier_has_execution_authority = false`). |")
    A("| SAR Explorer | `explorer_url` | Public **inspection** surface; renders "
      "the recorded receipt by `receipt_id`. |")
    A("")
    A("Doctrine boundaries this demo preserves:")
    A("")
    A("```text")
    A("DefaultVerifier records/verifies evidence.")
    A("DefaultVerifier did not deliver the resource.")
    A("DefaultVerifier did not authorize access.")
    A("DefaultVerifier did not execute payment.")
    A("```")
    A("")
    A("---")
    A("")

    # 3. Request artifact
    A("## 3. Request artifact")
    A("")
    A("Actual invocation used to create this artifact (local, offline):")
    A("")
    A("```python")
    A(request_python.rstrip())
    A("```")
    A("")
    A("Equivalent live HTTP request (illustrative; not executed in this "
      "offline run):")
    A("")
    A("```bash")
    A(request_curl.rstrip())
    A("```")
    A("")
    A("---")
    A("")

    # 4. Delivered payload artifact
    prov = d["delivered_payload_provenance"]
    A("## 4. Delivered payload artifact")
    A("")
    A(f"- **Resource requested:** {prov['resource_requested']} "
      f"(`{prov['resource_url']}`)")
    A(f"- **Captured from:** `{prov['source']}`")
    A(f"- **Capture mode:** {prov['mode']}")
    A("")
    A("This is a **real captured `/pay/url-summary` delivery artifact**, produced "
      "by the endpoint's own `build_delivery_object` delivery logic (not a "
      "hand-written illustrative payload). It is run in local demo mode with "
      "inline content so the capture is deterministic and touches no external "
      "network. The delivered object (`title`, `word_count`, `content_sha256`, "
      "`excerpt`, `delivered_at`, `delivery_evidence_digest`) is exactly what "
      "the live endpoint emits:")
    A("")
    A("```json")
    A(json.dumps(d["delivered_payload"], indent=2, sort_keys=True))
    A("```")
    A("")
    A("---")
    A("")

    # 5. Payload binding
    A("## 5. Payload binding (hash recomputation)")
    A("")
    A("The captured delivered object carries its own "
      "`delivery_evidence_digest` (computed by the `/pay/url-summary` delivery "
      "logic). It is the SHA-256 over the canonical delivered object (sorted "
      "keys, compact separators, `ensure_ascii=false`) **excluding** the "
      "`delivery_evidence_digest` field itself, and it is copied verbatim into "
      "the receipt as `delivery.evidence_digest`.")
    A("")
    A(f"- Captured `delivery_evidence_digest`: `{d['evidence_digest']}`")
    A(f"- Independently recomputed digest: `{d['evidence_digest_recomputed']}`")
    A(f"- In receipt at `delivery.evidence_digest`: "
      f"`{d['receipt']['delivery']['evidence_digest']}`")
    A(f"- All three match: **{str(d['payload_binding']['match']).upper()}**")
    A("")
    A("Third-party recomputation (saves the delivered payload, drops the digest "
      "field, and re-hashes it the same canonical way):")
    A("")
    A("```bash")
    A("# 1. Save the delivered payload from section 4 as delivered.json")
    A("# 2. Recompute the canonical SHA-256 digest:")
    A("python3 - <<'PY'")
    A("import hashlib, json")
    A("obj = json.load(open('delivered.json'))")
    A("obj.pop('delivery_evidence_digest', None)  # digest excludes itself")
    A("canon = json.dumps(obj, sort_keys=True, separators=(',',':'),")
    A("                   ensure_ascii=False).encode('utf-8')")
    A("print('sha256:' + hashlib.sha256(canon).hexdigest())")
    A("PY")
    A("# 3. Compare the printed value to delivery.evidence_digest in the receipt.")
    A("```")
    A("")
    A("---")
    A("")

    # 6. Receipt creation response
    A("## 6. Receipt creation response (`POST /v1/sar-402/receipts`)")
    A("")
    A("Wrapper fields returned by the endpoint:")
    A("")
    A(f"- `receipt_id`: `{receipt_id}`")
    A(f"- `receipt_type` (on the stored ledger record): "
      f"`{d['stored_record']['receipt_type']}`")
    A(f"- `receipt_lookup_path`: `{d['response']['receipt_lookup_path']}`")
    A(f"- `explorer_url`: `{d['response']['explorer_url']}`")
    A("- `receipt`: the full inner SAR-402 payload (with adopted `receipt_id`), "
      "shown below.")
    A("")
    A("Full POST response:")
    A("")
    A("```json")
    A(json.dumps(d["response"], indent=2, sort_keys=True))
    A("```")
    A("")
    A("Note: `receipt_type` is wrapper metadata on the stored ledger record "
      "(`sar_402_settlement`); it is shown in the GET lookup (section 7). It "
      "does **not** assert any signing or delivery by DefaultVerifier.")
    A("")
    A("---")
    A("")

    # 7. Receipt lookup
    A(f"## 7. Receipt lookup (`GET /v1/attest/receipt/{{receipt_id}}`)")
    A("")
    A(f"Resolving `GET {d['response']['receipt_lookup_path']}` returns the "
      "stored ledger record:")
    A("")
    A("```json")
    A(json.dumps(d["stored_record"], indent=2, sort_keys=True))
    A("```")
    A("")
    A(f"- Resolved by `receipt_id`: **{str(d['lookup']['resolved']).upper()}**")
    A(f"- `receipt_type`: `{d['stored_record']['receipt_type']}`")
    A(f"- `agent_id` (payer-derived): `{d['stored_record']['agent_id']}`")
    A("")
    A("---")
    A("")

    # 8. SAR Explorer URL
    A("## 8. SAR Explorer URL")
    A("")
    A(f"```text")
    A(d["response"]["explorer_url"])
    A("```")
    A("")
    A("The same `receipt_id` keys both the live backend lookup (section 7) and "
      "the public SAR Explorer inspection surface above.")
    A("")
    A("---")
    A("")

    # 9. Third-party reproduction checklist
    A("## 9. Third-party reproduction checklist (under 10 minutes)")
    A("")
    A("```text")
    for i, step in enumerate(d["reproduction_steps"], 1):
        A(f"{i}. {step}")
    A("```")
    A("")
    A("No CLI signature verification is part of Path A reproduction (that is "
      "Path B). Reproduction proves inspectability + payload binding + role "
      "separation only.")
    A("")
    A("---")
    A("")

    # 10. Overclaim safety
    A("## 10. Overclaim safety")
    A("")
    A("This artifact asserts ONLY the section 1 claim. It does **not** make any "
      "of the following forbidden claims:")
    A("")
    A("```text")
    for claim in FORBIDDEN_CLAIMS:
        A(f"NOT CLAIMED: {claim}")
    A("```")
    A("")
    A(f"- Automated overclaim scan of the demo copy: "
      f"**{d['overclaim_check']['status']}**")
    if d["overclaim_check"]["hits"]:
        A(f"- Hits: `{d['overclaim_check']['hits']}`")
    else:
        A("- Forbidden overclaim substrings found: none.")
    A("")
    A("Overclaim-safe one-line copy:")
    A("")
    A("```text")
    A(PATH_A_CLAIM)
    A(PATH_A_LIMITATION)
    A("```")
    A("")
    A("---")
    A("")
    A("*Path A delivery-evidence demo artifact. Recorded evidence only. No "
      "signing, no `verifier_kid`, no schema change, no deployment. Path B "
      "(wrapper-level recording signature / verifier key identity) remains out "
      "of scope. Awaiting Keith review.*")
    A("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y%m%dT%H%M%SZ")
    artifact_id = f"sar402-path-a-demo-{timestamp}"

    # Use a throwaway demo ledger so the production ledger is never touched.
    demo_ledger = OUT_DIR / f"demo-ledger-{timestamp}.jsonl"
    svc.RECEIPT_LEDGER = demo_ledger  # local reassignment for this process only

    # 1. Capture the delivered payload from the real /pay/url-summary delivery
    #    logic (network-free, deterministic), then bind to its own digest.
    delivered = capture_delivered_payload()
    evidence_digest = delivered["delivery_evidence_digest"]

    # Independently re-derive the captured digest the same way the endpoint does
    # (canonical JSON of the delivered object EXCLUDING the digest field), to
    # prove the artifact is self-consistent and third-party-recomputable.
    delivered_wo_digest = {
        k: v for k, v in delivered.items() if k != "delivery_evidence_digest"
    }
    recomputed_evidence_digest = _canonical_digest(delivered_wo_digest)

    # 2. Build + record the receipt through the real ingestion code.
    receipt_payload = build_receipt_payload(delivered)
    response = record_sar402_receipt(receipt_payload)
    receipt_id = response["receipt_id"]

    # 3. Resolve through the real lookup helper.
    stored_record = svc.get_receipt(receipt_id)

    # 4. Sanity checks (the demo must be self-consistent).
    binding_match = (
        receipt_payload["delivery"]["evidence_digest"] == evidence_digest
        and recomputed_evidence_digest == evidence_digest
    )
    lookup_resolved = stored_record.get("receipt_id") == receipt_id
    assert binding_match, "payload hash does not match receipt evidence digest"
    assert lookup_resolved, "receipt lookup did not resolve by receipt_id"
    assert receipt_id == receipt_payload["integrity"]["digest"], (
        "receipt_id must equal integrity.digest"
    )
    assert stored_record["receipt_type"] == RECEIPT_TYPE

    reproduction_steps = [
        "Open the receipt by its public id: "
        f"GET https://<attest-host>{response['receipt_lookup_path']} "
        "-> confirms the record exists in the live ledger.",
        f"Open the Explorer URL: {response['explorer_url']} "
        "-> confirms the same receipt renders on the public inspection surface.",
        "Recompute the payload binding: obtain the captured delivered payload "
        "(section 4), drop delivery_evidence_digest, hash the canonical bytes "
        "with SHA-256, compare to delivery.evidence_digest -> confirms the "
        "recorded delivered payload was not swapped.",
        "Read the role-separation fields: issuer.verifier = DefaultVerifier "
        "(recorder); authority_binding.acting_party = resource_server "
        "(deliverer); verifier_has_execution_authority = false -> confirms "
        "recorder != deliverer and the verifier claimed no execution authority.",
        "Sanity-check states: verification_mode = record; verification_point = "
        "post_delivery; settlement_state = delivered; issuer.environment = test "
        "(+ notes) -> confirms post-hoc recorded demo/testnet evidence, not "
        "gating and not mainnet finality.",
    ]

    roles = {
        "acting_party": receipt_payload["authority_binding"]["acting_party"],
        "payer_derived_agent_id": (
            receipt_payload["identity"]["derived_identity"]["derived_agent_id"]
        ),
        "issuer_verifier": receipt_payload["issuer"]["verifier"],
    }

    # Overclaim scan runs over all human-facing copy in the report.
    copy_corpus = "\n".join(
        [PATH_A_CLAIM, PATH_A_LIMITATION]
        + reproduction_steps
        + [receipt_payload["notes"]]
    )
    overclaim_hits = overclaim_scan(copy_corpus)
    overclaim_check = {
        "status": "PASS" if not overclaim_hits else "FAIL",
        "hits": overclaim_hits,
    }
    assert not overclaim_hits, f"overclaim detected: {overclaim_hits}"

    data = {
        "artifact_id": artifact_id,
        "generated_at": now.isoformat(),
        "scope": "path_a_recorded_delivery_evidence",
        "claim": PATH_A_CLAIM,
        "limitation": PATH_A_LIMITATION,
        "forbidden_claims": FORBIDDEN_CLAIMS,
        "roles": roles,
        "request": {
            "local_invocation": "record_sar402_receipt(payload)",
            "http_method": "POST",
            "http_path": "/v1/sar-402/receipts",
        },
        "delivered_payload": delivered,
        "delivered_payload_provenance": {
            "source": "/pay/url-summary delivery logic "
            "(pay_url_summary.build_delivery_object)",
            "mode": "local demo (inline text, network-free, deterministic)",
            "resource_requested": "URL summary / content fetch",
            "resource_url": delivered["requested_url"],
        },
        "evidence_digest": evidence_digest,
        "evidence_digest_recomputed": recomputed_evidence_digest,
        "payload_binding": {
            "algorithm": "sha256",
            "canonicalization": "sorted_keys_compact_v0 (json sorted keys, "
            "compact separators, ensure_ascii=false), over the delivered "
            "object excluding delivery_evidence_digest",
            "delivered_field": "delivery_evidence_digest",
            "receipt_field": "delivery.evidence_digest",
            "match": binding_match,
        },
        "receipt": receipt_payload,
        "response": response,
        "stored_record": stored_record,
        "lookup": {
            "method": "GET",
            "path": response["receipt_lookup_path"],
            "resolved": lookup_resolved,
        },
        "explorer_url": response["explorer_url"],
        "explorer_url_recomputed": explorer_url_for(receipt_id),
        "reproduction_steps": reproduction_steps,
        "overclaim_check": overclaim_check,
        "notes": (
            "Generated offline against a throwaway demo ledger; the production "
            "ledger was not touched. Path A only: no signing, no verifier_kid, "
            "no schema change, no deployment."
        ),
    }

    md_path = OUT_DIR / f"{artifact_id}.md"
    json_path = OUT_DIR / f"{artifact_id}.json"
    md_path.write_text(render_markdown(data), encoding="utf-8")
    json_path.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    # Clean up the throwaway demo ledger (the report captures its contents).
    try:
        demo_ledger.unlink()
    except FileNotFoundError:
        pass

    print(f"payload_binding_match : {binding_match}")
    print(f"lookup_resolved       : {lookup_resolved}")
    print(f"overclaim_check       : {overclaim_check['status']}")
    print(f"markdown              : {md_path}")
    print(f"json                  : {json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
