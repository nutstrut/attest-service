"""Tests for the controlled /pay/url-summary SAR-402 demo loop.

These prove the full loop end-to-end *through the committed Morpheus SAR-402
package/layer* — they never hand-build or hand-validate a receipt. Inline `text`
mode keeps the delivery leg network-free and deterministic.
"""

from __future__ import annotations

import copy
import os
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

# attest-service modules are top-level; make them importable.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pay_url_summary import (  # noqa: E402
    UrlSummaryInput,
    build_demo_evidence_doc,
    build_delivery_object,
    run_url_summary,
)

# The committed, authoritative validator and ingestion layer.
from morpheus.sar402.validate import validate_receipt  # noqa: E402
from morpheus.sar402_agent import EvidenceError, run_evidence_doc  # noqa: E402

from datetime import datetime, timezone  # noqa: E402


SAMPLE_TEXT = (
    "Greenhouse Realty Group quarterly market note. " * 12
    + "Inventory tightened while median days-on-market fell."
)


def _record_input(**kw):
    base = dict(text=SAMPLE_TEXT, title="Q-note", mode="record", save=False)
    base.update(kw)
    return UrlSummaryInput(**base)


# ---------------------------------------------------------------------------
# Delivery evidence
# ---------------------------------------------------------------------------

def test_endpoint_produces_delivery_evidence():
    now = datetime.now(timezone.utc)
    delivered = build_delivery_object(_record_input(), now=now)
    for key in (
        "requested_url",
        "resolved_url",
        "status_code",
        "title",
        "word_count",
        "content_sha256",
        "excerpt",
        "delivered_at",
        "delivery_evidence_digest",
    ):
        assert key in delivered, key
    assert delivered["word_count"] > 0
    assert delivered["content_sha256"].startswith("sha256:")
    assert delivered["delivery_evidence_digest"].startswith("sha256:")


def test_delivery_digest_is_deterministic_for_same_input():
    now = datetime.now(timezone.utc)
    a = build_delivery_object(_record_input(), now=now)
    b = build_delivery_object(_record_input(), now=now)
    assert a["delivery_evidence_digest"] == b["delivery_evidence_digest"]


# ---------------------------------------------------------------------------
# Full record-mode loop through the committed package
# ---------------------------------------------------------------------------

def test_record_mode_full_loop_pass():
    result = run_url_summary(_record_input())
    s = result["receipt_summary"]
    receipt = result["receipt"]

    # Generated through the committed package + re-validates through the
    # committed validator (defense in depth; run_evidence_doc already validated).
    validate_receipt(receipt)

    assert result["payment_evidence"] == "x402_demo"
    assert s["schema_id"] == "sar_402_settlement_v0.1"
    assert s["profile"] == "sar-402"
    assert s["sar_verdict"] == "PASS"
    assert s["verification_mode"] == "record"
    assert s["verification_point"] == "post_delivery"
    assert s["payment_state"] == "verified"
    assert s["delivery_state"] == "confirmed"
    assert s["settlement_state"] == "delivered"
    assert s["continuity"]["executor_continuity"] == "PASS"
    assert s["authority_binding"]["verifier_has_execution_authority"] is False
    assert s["integrity_digest"].startswith("sha256:")


def test_record_mode_preserves_artifacts(tmp_path, monkeypatch):
    import pay_url_summary

    monkeypatch.setattr(pay_url_summary, "DEMO_RUNS_DIR", tmp_path)
    result = run_url_summary(_record_input(save=True))
    artifacts = result["artifacts"]
    assert artifacts is not None
    for name in ("source_evidence", "normalized_evidence", "receipt"):
        assert Path(artifacts[name]).is_file(), name


# ---------------------------------------------------------------------------
# Authority boundary preserved
# ---------------------------------------------------------------------------

def test_no_authority_boundary_violation():
    receipt = run_url_summary(_record_input())["receipt"]
    binding = receipt["authority_binding"]
    assert binding["verifier_has_execution_authority"] is False
    # acting_party is clarity, never authority.
    assert binding["acting_party"] == "resource_server"


# ---------------------------------------------------------------------------
# Gate mode (pre-delivery proof)
# ---------------------------------------------------------------------------

def test_gate_mode_pre_delivery_indeterminate_executor():
    inp = _record_input(
        mode="gate",
        gate_controller="resource_server:greenhouse-demo",
        release_policy="release_on_PASS_escalate_on_INDETERMINATE_withhold_on_FAIL",
    )
    receipt = run_url_summary(inp)["receipt"]
    validate_receipt(receipt)
    assert receipt["verification_mode"] == "gate"
    assert receipt["verification_point"] == "payment_verified_pre_delivery"
    assert receipt["continuity"]["executor_continuity"] == "INDETERMINATE"
    assert "delivery" not in receipt
    assert receipt["authority_binding"]["gate_controller"] == "resource_server:greenhouse-demo"
    assert receipt["authority_binding"]["verifier_has_execution_authority"] is False


def test_gate_mode_requires_controller():
    with pytest.raises(HTTPException) as exc:
        run_url_summary(_record_input(mode="gate"))
    assert exc.value.status_code == 422


def test_forbidden_gate_controller_rejected():
    for forbidden in ("DefaultVerifier", "Morpheus", "SettlementWitness", "sar-402-impl"):
        with pytest.raises(HTTPException) as exc:
            run_url_summary(
                _record_input(mode="gate", gate_controller=forbidden)
            )
        # Rejected cleanly by the committed authority guard via the endpoint.
        assert exc.value.status_code == 422


# ---------------------------------------------------------------------------
# Invalid evidence is rejected by the committed ingestion layer
# ---------------------------------------------------------------------------

def test_missing_payment_evidence_fails():
    now = datetime.now(timezone.utc)
    delivered = build_delivery_object(_record_input(), now=now)
    doc = build_demo_evidence_doc(_record_input(), delivered, now=now)
    # Drop the payment transaction reference -> required field missing.
    del doc["x402"]["payment"]["tx"]
    with pytest.raises(EvidenceError):
        run_evidence_doc(doc, source="demo", save=False)


def test_missing_delivery_fails_for_post_delivery_record_mode():
    now = datetime.now(timezone.utc)
    delivered = build_delivery_object(_record_input(), now=now)
    doc = build_demo_evidence_doc(_record_input(), delivered, now=now)
    # Record (post-delivery) mode without delivery evidence is meaningless.
    doc["x402"].pop("delivery", None)
    with pytest.raises(EvidenceError):
        run_evidence_doc(doc, source="demo", save=False)


def test_verifier_execution_authority_assertion_rejected():
    now = datetime.now(timezone.utc)
    delivered = build_delivery_object(_record_input(), now=now)
    doc = build_demo_evidence_doc(_record_input(), delivered, now=now)
    doc["authority"]["verifier_has_execution_authority"] = True
    with pytest.raises(EvidenceError):
        run_evidence_doc(doc, source="demo", save=False)


# ---------------------------------------------------------------------------
# Live x402 payment mode
# ---------------------------------------------------------------------------

from pay_url_summary import run_url_summary as _run  # noqa: E402
from x402_live import (  # noqa: E402
    MODE_LIVE,
    X402ConfigError,
    load_x402_config,
    verify_and_settle,
)

# A real-shaped on-chain settlement reference (NOT an `x402_demo:` synthetic).
LIVE_TX = "0x5f6071829a3b4c5d6e7f8091a2b3c4d5e6f70811223344556677889900aabbcc"
LIVE_PAYER = "0xBe2C1d0A9b8E7c6D5a4B3e2F1c0D9a8B7e6C5d40"
LIVE_PAY_TO = "0x77E1aB2c3D4e5F6071829A3b4C5d6E7f8091A2b3"

LIVE_ENV = {
    "X402_MODE": "x402_live",
    "X402_FACILITATOR_URL": "https://x402.example/facilitator",
    "X402_PAY_TO": LIVE_PAY_TO,
    "X402_NETWORK": "base",
    "X402_ASSET": "USDC",
    "X402_AMOUNT": "1000",
    "X402_PAYER_ADDRESS": LIVE_PAYER,
}

LIVE_PAYMENT_PAYLOAD = {
    "x402Version": 1,
    "scheme": "exact",
    "network": "eip155:8453",
    "payer": LIVE_PAYER,
    "payload": {"signature": "0xsig", "authorization": {"from": LIVE_PAYER}},
}


class _MockFacilitator:
    """Stands in for a real x402 facilitator with real-shaped verify/settle."""

    def __init__(self, *, valid=True, settle_ok=True, payer=LIVE_PAYER):
        self.valid = valid
        self.settle_ok = settle_ok
        self.payer = payer
        self.calls = []

    def verify(self, requirements, payment_payload):
        self.calls.append(("verify", requirements, payment_payload))
        return {"isValid": self.valid, "invalidReason": None if self.valid else "bad_sig", "payer": self.payer}

    def settle(self, requirements, payment_payload):
        self.calls.append(("settle", requirements, payment_payload))
        if not self.settle_ok:
            return {"success": False, "errorReason": "insufficient_funds", "transaction": None}
        return {"success": True, "transaction": LIVE_TX, "network": "eip155:8453", "payer": self.payer}


def _live_input(**kw):
    base = dict(
        text=SAMPLE_TEXT, title="Q-note", mode="record", save=False,
        payment_mode="x402_live", x402_payment=LIVE_PAYMENT_PAYLOAD,
    )
    base.update(kw)
    return UrlSummaryInput(**base)


def test_demo_mode_still_works_via_env_default():
    # No live config; default mode is demo and the full loop still passes.
    result = _run(_record_input(), env={})
    assert result["payment_evidence"] == "x402_demo"
    assert result["receipt_summary"]["sar_verdict"] == "PASS"
    assert result["receipt_summary"]["payment_ref"].startswith("x402_demo:")


def test_live_config_validation_rejects_missing_fields():
    with pytest.raises(X402ConfigError) as exc:
        load_x402_config(mode_override="x402_live", env={"X402_MODE": "x402_live"})
    msg = str(exc.value)
    for field in ("X402_FACILITATOR_URL", "X402_PAY_TO", "X402_NETWORK", "X402_AMOUNT", "X402_PAYER_ADDRESS"):
        assert field in msg


def test_live_config_normalizes_base_to_caip2():
    cfg = load_x402_config(env=LIVE_ENV)
    assert cfg.mode == MODE_LIVE
    assert cfg.network == "eip155:8453"
    assert cfg.is_live


def test_missing_live_config_fails_clearly_through_endpoint():
    # Request asks for live but env has no live config -> clean 400, no receipt.
    with pytest.raises(HTTPException) as exc:
        _run(_live_input(), env={})
    assert exc.value.status_code == 400


def test_live_mode_does_not_fall_back_to_demo_when_payment_missing():
    inp = _live_input(x402_payment=None)
    with pytest.raises(HTTPException) as exc:
        _run(inp, env=LIVE_ENV)
    assert exc.value.status_code == 422
    assert "demo" in str(exc.value.detail).lower()


def test_live_mode_full_loop_pass_with_mocked_facilitator():
    fac = _MockFacilitator()
    result = _run(_live_input(), env=LIVE_ENV, facilitator=fac)
    s = result["receipt_summary"]
    receipt = result["receipt"]
    validate_receipt(receipt)

    assert result["payment_evidence"] == "x402_live"
    assert s["sar_verdict"] == "PASS"
    assert s["verification_mode"] == "record"
    assert s["verification_point"] == "post_delivery"
    assert s["payment_state"] == "verified"
    assert s["delivery_state"] == "confirmed"
    assert s["settlement_state"] == "delivered"
    assert s["continuity"]["executor_continuity"] == "PASS"
    assert s["authority_binding"]["verifier_has_execution_authority"] is False
    # Real evidence propagation: real tx, facilitator, payer, recipient.
    assert s["payment_ref"] == LIVE_TX
    assert not s["payment_ref"].startswith("x402_demo:")
    assert s["facilitator"] == LIVE_ENV["X402_FACILITATOR_URL"]
    assert receipt["payment"]["payer"] == LIVE_PAYER
    assert receipt["payment"]["recipient"] == LIVE_PAY_TO
    assert receipt["payment"]["chain"] == "eip155:8453"
    assert receipt["payment"]["amount_paid"]["asset"] == "USDC"
    assert receipt["payment"]["amount_paid"]["amount"] == "1000"
    # Facilitator was actually consulted (verify + settle).
    assert [c[0] for c in fac.calls] == ["verify", "settle"]


def test_live_unverified_payment_fails_and_makes_no_receipt():
    fac = _MockFacilitator(valid=False)
    with pytest.raises(HTTPException) as exc:
        _run(_live_input(), env=LIVE_ENV, facilitator=fac)
    assert exc.value.status_code == 402
    assert "not verified" in str(exc.value.detail).lower()


def test_live_incomplete_settlement_fails():
    fac = _MockFacilitator(settle_ok=False)
    with pytest.raises(HTTPException) as exc:
        _run(_live_input(), env=LIVE_ENV, facilitator=fac)
    assert exc.value.status_code == 402


def test_live_payer_mismatch_rejected():
    fac = _MockFacilitator(payer="0xDEADBEEF00000000000000000000000000000000")
    with pytest.raises(HTTPException) as exc:
        _run(_live_input(), env=LIVE_ENV, facilitator=fac)
    assert exc.value.status_code == 402


def test_live_record_mode_requires_delivery_evidence():
    # verify_and_settle with settle for record mode; build_live block needs
    # delivery. Directly exercise verify_and_settle then block builder.
    from datetime import datetime, timezone
    from x402_live import build_live_x402_block, X402VerificationError
    cfg = load_x402_config(env=LIVE_ENV)
    fac = _MockFacilitator()
    res = verify_and_settle(cfg, resource="inline:text", payment_payload=LIVE_PAYMENT_PAYLOAD, settle=True, facilitator=fac)
    with pytest.raises(X402VerificationError):
        build_live_x402_block(cfg, res, resource="inline:text", delivered=None, now=datetime.now(timezone.utc), record_mode=True)


def test_live_authority_boundary_preserved():
    fac = _MockFacilitator()
    receipt = _run(_live_input(), env=LIVE_ENV, facilitator=fac)["receipt"]
    assert receipt["authority_binding"]["verifier_has_execution_authority"] is False
    assert receipt["authority_binding"]["acting_party"] == "resource_server"


def test_live_config_never_serializes_private_key():
    env = dict(LIVE_ENV, X402_PAYER_PRIVATE_KEY="0xSECRETKEYMUSTNOTLEAK")
    cfg = load_x402_config(env=env)
    public = cfg.public_dict()
    assert "0xSECRETKEYMUSTNOTLEAK" not in str(public)
    assert public["payer_private_key_present"] is True
    # repr must not leak the key either.
    assert "0xSECRETKEYMUSTNOTLEAK" not in repr(cfg)


def test_live_raw_facilitator_payloads_preserved_in_evidence_doc():
    from datetime import datetime, timezone
    from pay_url_summary import build_delivery_object, build_evidence_for_mode
    now = datetime.now(timezone.utc)
    delivered = build_delivery_object(_live_input(), now=now)
    fac = _MockFacilitator()
    doc, label = build_evidence_for_mode(_live_input(), delivered, now=now, env=LIVE_ENV, facilitator=fac)
    assert label == "x402_live"
    assert doc["payment_evidence"] == "x402_live"
    assert "payment_raw" in doc["x402"]
    assert doc["x402"]["payment_raw"]["verify"]["isValid"] is True
    assert doc["x402"]["payment_raw"]["settle"]["transaction"] == LIVE_TX
    assert "quote_raw" in doc["x402"]
