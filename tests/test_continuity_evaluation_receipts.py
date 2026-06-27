"""Tests for the SIGNED Continuity Evaluation Receipt (Path C Step 2B).

These prove the signing module (`continuity_evaluation_receipts`) and the routes
(`attest_service.post_continuity_evaluation_receipt` /
`get_continuity_evaluation_receipt`):

  * the signed receipt shape matches ds.continuity_evaluation.v0.1 exactly;
  * signature.key_id equals evaluator_id; signature is excluded from the
    signing input;
  * tampering with any signed-core field (action_ref / evaluation_state /
    policy_ref / evaluated_at) fails verification;
  * a wrong public key fails verification;
  * missing key config makes POST fail safely (503) — no unsigned/partial
    receipt is produced or stored;
  * the Step 2A GET response remains unchanged and unsigned;
  * no acceptance_spec is accepted or introduced anywhere in Step 2B;
  * idempotent POST returns stored:false with the existing receipt;
  * a different signed receipt for the same action_ref is a conflict (409).

All ledgers are monkeypatched to temp files; no real/production key is used.
"""

from __future__ import annotations

import base64
import copy
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import attest_service as svc  # noqa: E402
import action_commitment_store as acstore  # noqa: E402
import deterministic_evaluation_store as estore  # noqa: E402
import continuity_evaluation_receipts as crmod  # noqa: E402

# Reuse the Step 2A test scaffolding for committing + evaluating.
from test_deterministic_evaluation_store import (  # noqa: E402
    _ACCEPTANCE_SPEC,
    _RELEASE_POLICY,
    _PASS_OUTPUT,
)


# A throwaway Ed25519 seed (32 bytes). NEVER a production key.
_TEST_SEED = bytes(range(32))
_TEST_PRIV_B64 = base64.b64encode(_TEST_SEED).decode("ascii")
_EVALUATOR_ID = "agent:defaultverifier:continuity-v1"
_POLICY_REF = "policy:default-settlement/sar-402-deterministic-conditional-release-v1"


def _expected_pub_b64() -> str:
    key = Ed25519PrivateKey.from_private_bytes(_TEST_SEED)
    return crmod._public_key_spki_b64(key.public_key())


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """Isolate all three ledgers and set valid signing env."""
    monkeypatch.setattr(acstore, "ACTION_COMMITMENT_LEDGER", tmp_path / "ac.jsonl")
    monkeypatch.setattr(
        estore, "DETERMINISTIC_EVALUATION_LEDGER", tmp_path / "eval.jsonl"
    )
    monkeypatch.setattr(
        crmod, "CONTINUITY_EVALUATION_RECEIPT_LEDGER", tmp_path / "receipts.jsonl"
    )
    monkeypatch.setenv(crmod.ENV_PRIVATE_KEY_B64, _TEST_PRIV_B64)
    monkeypatch.setenv(crmod.ENV_EVALUATOR_ID, _EVALUATOR_ID)
    monkeypatch.setenv(crmod.ENV_POLICY_REF, _POLICY_REF)
    monkeypatch.delenv(crmod.ENV_PUBLIC_KEY_B64, raising=False)
    return tmp_path


def _commit_and_evaluate(tag: str = "x") -> str:
    """Store an Action Commitment + run Step 2A, return the action_ref."""
    request_body: dict = {
        "resource": f"urn:example:{tag}",
        "ds_conditional_release": {
            "profile_schema_id": "ds.conditional_release_profile.v0.1",
            "acceptance_spec": _ACCEPTANCE_SPEC,
            "release_policy": _RELEASE_POLICY,
        },
    }
    arc = {
        "schema_id": acstore.ACTION_REQUEST_SCHEMA_ID,
        "method": "POST",
        "target": {"path": "/deliver"},
        "content_type": "application/json",
        "body_digest": acstore._sha256(request_body),
    }
    ac = {
        "schema_id": acstore.ACTION_COMMITMENT_SCHEMA_ID,
        "agent_id": f"agent:{tag}",
        "action_type": "sar402.resource_delivery",
        "request_digest": acstore._sha256(arc),
        "idempotency_key": f"idem-{tag}",
    }
    action_ref = acstore._sha256(ac)
    acstore.store_action_commitment({
        "record_type": acstore.RECORD_TYPE,
        "record_version": acstore.RECORD_VERSION,
        "request_body": request_body,
        "action_request_commitment": arc,
        "action_commitment": ac,
        "action_ref": action_ref,
    })
    svc.post_evaluate_deterministic(
        svc.DeterministicEvaluateInput(action_ref=action_ref, submitted_output=_PASS_OUTPUT)
    )
    return action_ref


# ---------------------------------------------------------------------------
# Shape + signature binding
# ---------------------------------------------------------------------------

def test_signed_receipt_shape_matches_schema(isolated):
    action_ref = _commit_and_evaluate()
    resp = svc.post_continuity_evaluation_receipt(action_ref)

    assert resp["status"] == "continuity_receipt_issued"
    assert resp["stored"] is True
    receipt = resp["receipt"]

    core_keys = {k for k in receipt if k != "signature"}
    assert core_keys == {
        "schema_id",
        "action_ref",
        "evaluator_id",
        "evaluation_state",
        "policy_ref",
        "evaluated_at",
    }
    assert receipt["schema_id"] == "ds.continuity_evaluation.v0.1"
    assert receipt["action_ref"] == action_ref
    assert receipt["evaluator_id"] == _EVALUATOR_ID
    assert receipt["evaluation_state"] == "PASS"  # derived from Step 2A result
    assert receipt["policy_ref"] == _POLICY_REF
    assert isinstance(receipt["evaluated_at"], str) and receipt["evaluated_at"]

    sig = receipt["signature"]
    assert set(sig) == {"alg", "key_id", "public_key", "signature"}
    assert sig["alg"] == "ed25519"


def test_signature_key_id_equals_evaluator_id(isolated):
    action_ref = _commit_and_evaluate()
    receipt = svc.post_continuity_evaluation_receipt(action_ref)["receipt"]
    assert receipt["signature"]["key_id"] == receipt["evaluator_id"]


def test_signature_excluded_from_signing_input(isolated):
    action_ref = _commit_and_evaluate()
    receipt = svc.post_continuity_evaluation_receipt(action_ref)["receipt"]

    # Mutating the signature block does not change the signing input.
    before = crmod.canonical_signing_input(receipt)
    mutated = copy.deepcopy(receipt)
    mutated["signature"]["signature"] = "AAAA"
    after = crmod.canonical_signing_input(mutated)
    assert before == after
    # And the signing input has no signature key.
    assert b"signature" not in before


def test_evaluated_at_is_fresh_not_from_step_2a(isolated):
    action_ref = _commit_and_evaluate()
    step2a = estore.get_deterministic_evaluation(action_ref)
    # Step 2A record must not carry evaluated_at at all.
    assert "evaluated_at" not in step2a
    receipt = svc.post_continuity_evaluation_receipt(action_ref)["receipt"]
    assert "evaluated_at" in receipt


# ---------------------------------------------------------------------------
# Verification: tampering + wrong key
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "field,value",
    [
        ("action_ref", "sha256:" + "0" * 64),
        ("evaluation_state", "FAIL"),
        ("policy_ref", "policy:tampered"),
        ("evaluated_at", "2000-01-01T00:00:00Z"),
    ],
)
def test_tampering_core_field_fails_verification(isolated, field, value):
    action_ref = _commit_and_evaluate()
    receipt = svc.post_continuity_evaluation_receipt(action_ref)["receipt"]
    pub = _expected_pub_b64()
    # Valid as issued.
    crmod.verify_continuity_evaluation_receipt(receipt, pub)
    tampered = copy.deepcopy(receipt)
    tampered[field] = value
    with pytest.raises(crmod.ContinuityReceiptVerificationError):
        crmod.verify_continuity_evaluation_receipt(tampered, pub)


def test_wrong_public_key_fails_verification(isolated):
    action_ref = _commit_and_evaluate()
    receipt = svc.post_continuity_evaluation_receipt(action_ref)["receipt"]
    other = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    wrong_pub = crmod._public_key_spki_b64(other.public_key())
    with pytest.raises(crmod.ContinuityReceiptVerificationError):
        crmod.verify_continuity_evaluation_receipt(receipt, wrong_pub)


# ---------------------------------------------------------------------------
# Safe failure on missing key config
# ---------------------------------------------------------------------------

def test_missing_key_config_fails_safely(isolated, monkeypatch):
    monkeypatch.delenv(crmod.ENV_PRIVATE_KEY_B64, raising=False)
    action_ref = _commit_and_evaluate()
    with pytest.raises(HTTPException) as ei:
        svc.post_continuity_evaluation_receipt(action_ref)
    assert ei.value.status_code == 503
    # No receipt was produced or stored.
    assert crmod.get_continuity_evaluation_receipt(action_ref) is None


# ---------------------------------------------------------------------------
# Step 2A unchanged + no acceptance_spec
# ---------------------------------------------------------------------------

def test_step_2a_get_remains_unchanged_and_unsigned(isolated):
    action_ref = _commit_and_evaluate()
    before = copy.deepcopy(svc.get_evaluate_deterministic(action_ref))
    svc.post_continuity_evaluation_receipt(action_ref)
    after = svc.get_evaluate_deterministic(action_ref)
    assert after == before
    record = after["record"]
    for forbidden in ("signature", "kid", "key_id", "evaluated_at"):
        assert forbidden not in record


def test_no_acceptance_spec_introduced(isolated):
    action_ref = _commit_and_evaluate()
    receipt = svc.post_continuity_evaluation_receipt(action_ref)["receipt"]
    assert "acceptance_spec" not in receipt
    # POST takes no body; there is no parameter to inject a spec through.


# ---------------------------------------------------------------------------
# Idempotency + conflict
# ---------------------------------------------------------------------------

def test_idempotent_post_returns_stored_false(isolated):
    action_ref = _commit_and_evaluate()
    first = svc.post_continuity_evaluation_receipt(action_ref)
    assert first["stored"] is True
    second = svc.post_continuity_evaluation_receipt(action_ref)
    assert second["stored"] is False
    assert second["receipt"] == first["receipt"]


def test_conflict_on_different_signed_receipt(isolated):
    action_ref = _commit_and_evaluate()
    first = svc.post_continuity_evaluation_receipt(action_ref)["receipt"]
    # Forge a different signed receipt for the same action_ref directly in store.
    different = copy.deepcopy(first)
    different["evaluated_at"] = "1999-12-31T23:59:59Z"
    with pytest.raises(crmod.ContinuityReceiptConflict):
        crmod.store_continuity_evaluation_receipt(different)


# ---------------------------------------------------------------------------
# Route guards
# ---------------------------------------------------------------------------

def test_post_malformed_action_ref_422(isolated):
    with pytest.raises(HTTPException) as ei:
        svc.post_continuity_evaluation_receipt("not-a-sha")
    assert ei.value.status_code == 422


def test_post_missing_step_2a_record_404(isolated):
    valid_ref = "sha256:" + "a" * 64
    with pytest.raises(HTTPException) as ei:
        svc.post_continuity_evaluation_receipt(valid_ref)
    assert ei.value.status_code == 404


def test_get_404_when_no_receipt(isolated):
    action_ref = _commit_and_evaluate()
    with pytest.raises(HTTPException) as ei:
        svc.get_continuity_evaluation_receipt(action_ref)
    assert ei.value.status_code == 404


def test_get_does_not_auto_sign(isolated):
    action_ref = _commit_and_evaluate()
    with pytest.raises(HTTPException):
        svc.get_continuity_evaluation_receipt(action_ref)
    # Still nothing stored after a GET.
    assert crmod.get_continuity_evaluation_receipt(action_ref) is None


def test_get_returns_existing_receipt(isolated):
    action_ref = _commit_and_evaluate()
    issued = svc.post_continuity_evaluation_receipt(action_ref)["receipt"]
    got = svc.get_continuity_evaluation_receipt(action_ref)
    assert got["receipt"] == issued
    assert got["action_ref"] == action_ref


def test_get_malformed_action_ref_422(isolated):
    with pytest.raises(HTTPException) as ei:
        svc.get_continuity_evaluation_receipt("nope")
    assert ei.value.status_code == 422
