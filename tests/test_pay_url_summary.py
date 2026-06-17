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
