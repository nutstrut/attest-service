#!/usr/bin/env python3
"""Generate the SAR-402 Path B recording-attribution demo artifact (v0.1).

LOCAL / OFFLINE generator. This does NOT deploy, does NOT touch the production
receipt ledger, and does NOT publish a production key. It:

  1. Builds a real Path A inner receipt through the real ingestion core
     (``sar402_receipts.record_sar402_receipt``, ``persist=False``).
  2. Wraps it in a signed recording-attribution envelope through the real Path B
     code (``sar402_recording_wrapper.build_recording_wrapper``), using an
     EPHEMERAL, demo-only Ed25519 key generated for this run.
  3. Verifies the wrapper, then proves tamper-detection on the inner receipt, a
     wrapper field, and the signature.
  4. Scans the copy for overclaims and renders a timestamped Markdown + JSON
     report.

Path B scope only: this proves *recording attribution* — DefaultVerifier
recorded this receipt, attributable to a verifier key (``verifier_kid``), and a
third party with the public key can verify the attribution. The signature
attests to recording attribution ONLY. It does NOT attest to resource delivery,
payment execution, access authorization, release control, or legal payment
finality. Signing is not execution authority. The inner SAR-402 schema is
unchanged.

Run:

    python3 reports/sar402/path-b-demo/generate_demo.py
"""

from __future__ import annotations

import copy
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sar402_receipts import record_sar402_receipt  # noqa: E402
from sar402_recording_wrapper import (  # noqa: E402
    DOES_NOT_ATTEST_TO,
    RECORDED_BY,
    RECORDING_WRAPPER_VERSION,
    SIGNATURE_ALG,
    SIGNATURE_ATTESTS_TO,
    build_recording_wrapper,
    public_key_hex,
    verify_recording_wrapper,
)

# Reuse the committed Path A demo's receipt builder so Path B wraps the SAME
# kind of real, payload-bound inner receipt the Path A artifact uses.
sys.path.insert(0, str(ROOT / "reports" / "sar402" / "path-a-demo"))
from generate_demo import (  # type: ignore  # noqa: E402
    build_receipt_payload,
    capture_delivered_payload,
)

OUT_DIR = Path(__file__).resolve().parent

# Demo-only verifier_kid. NOT the production key id; this run uses an ephemeral
# key generated below and publishes only that ephemeral public key.
DEMO_KID = "sar-demo-ed25519-pathb"

PATH_B_CLAIM = (
    "DefaultVerifier recorded this SAR-402 receipt, the recording is "
    "attributable to a named verifier key (verifier_kid), and a third party "
    "holding the public key can verify that recording attribution."
)

PATH_B_LIMITATION = (
    "The recording signature attests to recording attribution ONLY. It is not "
    "a claim of resource delivery, payment execution, access authorization, "
    "release control, or legal payment finality. Signing is not execution "
    "authority."
)

FORBIDDEN_CLAIMS = [
    "DefaultVerifier delivered the resource.",
    "DefaultVerifier executed payment.",
    "DefaultVerifier authorized access.",
    "DefaultVerifier controlled release.",
    "DefaultVerifier proves legal payment finality.",
    "The signature attests to payment or delivery.",
]

FORBIDDEN_OVERCLAIM_SUBSTRINGS = [
    "defaultverifier delivered",
    "defaultverifier executed payment",
    "defaultverifier authorized",
    "defaultverifier controlled release",
    "defaultverifier proves legal",
    "signature attests to payment",
    "signature attests to delivery",
    "legal payment finality is proven",
    "mainnet payment",
]


def overclaim_scan(copy_text: str) -> list[str]:
    lowered = copy_text.lower()
    return [s for s in FORBIDDEN_OVERCLAIM_SUBSTRINGS if s in lowered]


def main() -> int:
    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y%m%dT%H%M%SZ")
    artifact_id = f"sar402-path-b-demo-{timestamp}"

    # 1. Real Path A inner receipt (payload-bound), not persisted.
    delivered = capture_delivered_payload()
    receipt_payload = build_receipt_payload(delivered)
    path_a = record_sar402_receipt(receipt_payload, persist=False)
    inner_receipt = path_a["receipt"]

    # 2. Wrap with an EPHEMERAL demo key (no production key is used or published).
    signing_key = Ed25519PrivateKey.generate()
    pub_hex = public_key_hex(signing_key)
    recorded_at = now.isoformat()
    wrapper = build_recording_wrapper(
        inner_receipt, signing_key=signing_key, kid=DEMO_KID, recorded_at=recorded_at
    )

    # 3. Verify, then prove tamper-detection (three independent tampers).
    pub = signing_key.public_key()
    verify_ok = verify_recording_wrapper(wrapper, public_key=pub)

    t_receipt = copy.deepcopy(wrapper)
    t_receipt["receipt"]["payment"]["amount_paid"]["amount"] = "999999"
    tamper_receipt_detected = not verify_recording_wrapper(t_receipt, public_key=pub)

    t_field = copy.deepcopy(wrapper)
    t_field["recorded_at"] = "1999-01-01T00:00:00+00:00"
    tamper_field_detected = not verify_recording_wrapper(t_field, public_key=pub)

    t_sig = copy.deepcopy(wrapper)
    s = t_sig["recording_signature"]["signature"]
    t_sig["recording_signature"]["signature"] = ("AA" + s[2:]) if s[:2] != "AA" else ("BB" + s[2:])
    tamper_sig_detected = not verify_recording_wrapper(t_sig, public_key=pub)

    wrong_key = Ed25519PrivateKey.generate().public_key()
    wrong_key_rejected = not verify_recording_wrapper(wrapper, public_key=wrong_key)

    assert verify_ok, "untampered wrapper must verify"
    assert tamper_receipt_detected, "inner-receipt tamper must be detected"
    assert tamper_field_detected, "wrapper-field tamper must be detected"
    assert tamper_sig_detected, "signature tamper must be detected"
    assert wrong_key_rejected, "wrong key must be rejected"

    reproduction_steps = [
        "Obtain the wrapper JSON (section 4) and the demo public key (section 5).",
        "Drop the recording_signature field; canonicalize the remaining wrapper "
        "as sorted-keys/compact UTF-8 JSON (sorted_keys_compact_v0).",
        "Ed25519-verify the base64-decoded recording_signature.signature over "
        "those canonical bytes with the public key -> attribution verifies.",
        "Confirm receipt_id == receipt.integrity.digest (the recording binds the "
        "exact inner receipt; a swapped receipt fails verification).",
        "Read the claims block: signature_attests_to = recording_attribution_only "
        "and does_not_attest_to lists delivery/payment/access/release/finality -> "
        "the signature is recording attribution, not delivery/payment authority.",
    ]

    copy_corpus = "\n".join(
        [PATH_B_CLAIM, PATH_B_LIMITATION] + reproduction_steps
    )
    overclaim_hits = overclaim_scan(copy_corpus)
    overclaim_check = {"status": "PASS" if not overclaim_hits else "FAIL", "hits": overclaim_hits}
    assert not overclaim_hits, f"overclaim detected: {overclaim_hits}"

    data = {
        "artifact_id": artifact_id,
        "generated_at": recorded_at,
        "scope": "path_b_recording_attribution",
        "claim": PATH_B_CLAIM,
        "limitation": PATH_B_LIMITATION,
        "forbidden_claims": FORBIDDEN_CLAIMS,
        "verifier_kid": DEMO_KID,
        "demo_public_key_hex_ed25519_raw": pub_hex,
        "key_note": (
            "EPHEMERAL demo key generated for this run only. Not the production "
            "verifier key; no production key is used or published here."
        ),
        "signature_alg": SIGNATURE_ALG,
        "recording_wrapper_version": RECORDING_WRAPPER_VERSION,
        "recorded_by": RECORDED_BY,
        "claims_block": {
            "signature_attests_to": SIGNATURE_ATTESTS_TO,
            "does_not_attest_to": list(DOES_NOT_ATTEST_TO),
        },
        "path_a_response": path_a,
        "wrapper": wrapper,
        "verification": {
            "untampered_verifies": verify_ok,
            "inner_receipt_tamper_detected": tamper_receipt_detected,
            "wrapper_field_tamper_detected": tamper_field_detected,
            "signature_tamper_detected": tamper_sig_detected,
            "wrong_key_rejected": wrong_key_rejected,
        },
        "reproduction_steps": reproduction_steps,
        "overclaim_check": overclaim_check,
        "notes": (
            "Generated offline. No deployment, no production ledger write, no "
            "production key. Path B only: wrapper-level recording attribution. "
            "Inner SAR-402 schema unchanged."
        ),
    }

    # The overclaim scan targets the *assertive* demo copy (claim, limitation,
    # reproduction steps). The "NOT CLAIMED:" disclaimer lines and the section-2
    # boundary sentence intentionally contain the forbidden phrases as denials,
    # so they are excluded from the scan (same convention as the Path A demo).
    md = render_markdown(data)

    md_path = OUT_DIR / f"{artifact_id}.md"
    json_path = OUT_DIR / f"{artifact_id}.json"
    md_path.write_text(md, encoding="utf-8")
    json_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"untampered_verifies   : {verify_ok}")
    print(f"tamper_receipt        : {tamper_receipt_detected}")
    print(f"tamper_field          : {tamper_field_detected}")
    print(f"tamper_signature      : {tamper_sig_detected}")
    print(f"overclaim_check       : {overclaim_check['status']}")
    print(f"markdown              : {md_path}")
    print(f"json                  : {json_path}")
    return 0


def render_markdown(d: dict) -> str:
    lines: list[str] = []
    A = lines.append
    A("# SAR-402 Path B Recording-Attribution Demo — v0.1")
    A("")
    A(f"**Generated (UTC):** {d['generated_at']}  ")
    A(f"**Artifact id:** `{d['artifact_id']}`  ")
    A("**Scope:** Path B (wrapper-level recording attribution). Adds a signed "
      "recording envelope around a Path A receipt. The inner SAR-402 schema is "
      "unchanged. No deployment, no production key, no production ledger write.  ")
    A("")
    A("> Reproducible, offline-generated artifact. The inner receipt was built "
      "through the real ingestion core (`record_sar402_receipt`) and wrapped "
      "through the real Path B code (`build_recording_wrapper`) using an "
      "**ephemeral demo key**. The production ledger and production keys were "
      "not touched.")
    A("")
    A("---")
    A("")
    A("## 1. Demo thesis")
    A("")
    A("**Claim:**")
    A("")
    A("```text")
    A(d["claim"])
    A("```")
    A("")
    A("**Limitation (stated up front):**")
    A("")
    A("```text")
    A(d["limitation"])
    A("```")
    A("")
    A("---")
    A("")
    A("## 2. What the signature does and does not attest to")
    A("")
    A("```json")
    A(json.dumps(d["claims_block"], indent=2, sort_keys=True))
    A("```")
    A("")
    A("The recording signature is RECORDING ATTRIBUTION ONLY. A valid signature "
      "means \"DefaultVerifier recorded this receipt under "
      f"`{d['verifier_kid']}`\" — nothing more. It does not assert that "
      "DefaultVerifier delivered the resource, moved or executed payment, "
      "authorized access, controlled release, or proved legal finality. Signing "
      "is not execution authority.")
    A("")
    A("---")
    A("")
    A("## 3. Verification + tamper-evidence results")
    A("")
    v = d["verification"]
    A(f"- Untampered wrapper verifies: **{str(v['untampered_verifies']).upper()}**")
    A(f"- Inner-receipt tamper detected: **{str(v['inner_receipt_tamper_detected']).upper()}**")
    A(f"- Wrapper-field tamper detected: **{str(v['wrapper_field_tamper_detected']).upper()}**")
    A(f"- Signature tamper detected: **{str(v['signature_tamper_detected']).upper()}**")
    A(f"- Wrong key rejected: **{str(v['wrong_key_rejected']).upper()}**")
    A("")
    A("---")
    A("")
    A("## 4. The signed recording wrapper")
    A("")
    A("```json")
    A(json.dumps(d["wrapper"], indent=2, sort_keys=True))
    A("```")
    A("")
    A("---")
    A("")
    A("## 5. Verification key (ephemeral demo key)")
    A("")
    A(f"- `verifier_kid`: `{d['verifier_kid']}`")
    A(f"- Ed25519 public key (raw, hex): `{d['demo_public_key_hex_ed25519_raw']}`")
    A("")
    A(f"> {d['key_note']}")
    A("")
    A("---")
    A("")
    A("## 6. Third-party verification (under 10 minutes)")
    A("")
    A("```text")
    for i, step in enumerate(d["reproduction_steps"], 1):
        A(f"{i}. {step}")
    A("```")
    A("")
    A("---")
    A("")
    A("## 7. Overclaim safety")
    A("")
    A("This artifact asserts ONLY the section 1 claim, bounded by section 2. It "
      "does **not** make any of the following forbidden claims:")
    A("")
    A("```text")
    for claim in d["forbidden_claims"]:
        A(f"NOT CLAIMED: {claim}")
    A("```")
    A("")
    A(f"- Automated overclaim scan: **{d['overclaim_check']['status']}**")
    A("")
    A("---")
    A("")
    A("*Path B recording-attribution demo artifact. Recording attribution only; "
      "not delivery, payment, access, release, or legal finality; signing is not "
      "execution authority. Offline, ephemeral demo key, no deployment. Not "
      "promoted as public/live. Awaiting Keith review.*")
    A("")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
