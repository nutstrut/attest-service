"""Tests for the unsigned deterministic evaluation store + Path C Step 2A routes.

These prove the storage layer (`deterministic_evaluation_store`) and the routes
(`attest_service.post_evaluate_deterministic` / `get_evaluate_deterministic`):

  * a stored Action Commitment is evaluated by action_ref using the COMMITTED
    spec (never a caller-submitted one);
  * unknown action_ref is rejected (404);
  * a request carrying a caller-submitted acceptance_spec is refused (422 via
    the input model's extra=forbid);
  * the evaluation result is stored and retrievable by action_ref;
  * idempotent retry with the identical canonical record is safe;
  * a different evaluation record for the same action_ref is a conflict, AND a
    different submitted_output for an already-evaluated action_ref is a conflict;
  * the record preserves bounded language: no release claim, no signing claim,
    no execution proof.

Nothing here signs, and both ledgers are monkeypatched to temp files.
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import attest_service as svc  # noqa: E402
import action_commitment_store as acstore  # noqa: E402
import deterministic_evaluation_store as estore  # noqa: E402
from deterministic_evaluation_store import (  # noqa: E402
    DeterministicEvaluationConflict,
    DeterministicEvaluationRecordError,
    get_deterministic_evaluation,
    store_deterministic_evaluation,
    validate_deterministic_evaluation_record,
)


@pytest.fixture
def isolated_ledgers(tmp_path, monkeypatch):
    """Point BOTH the commitment ledger and the evaluation ledger at temp files."""
    monkeypatch.setattr(acstore, "ACTION_COMMITMENT_LEDGER", tmp_path / "ac.jsonl")
    eledger = tmp_path / "eval.jsonl"
    monkeypatch.setattr(estore, "DETERMINISTIC_EVALUATION_LEDGER", eledger)
    return eledger


# A committed acceptance spec that PASSes on the canonical output below.
_ACCEPTANCE_SPEC = {
    "spec_id": "spec.test-delivery",
    "evaluator_type": "deterministic",
    "checks": [
        {"kind": "field_present", "inputs": {"output_path": "$.manifest"}, "failure_behavior": "FAIL"},
        {"kind": "numeric_threshold", "inputs": {"output_path": "$.manifest.row_count"},
         "expected": {"op": ">=", "value": 1000}, "failure_behavior": "FAIL"},
        {"kind": "content_type_equals", "inputs": {"output_path": "$.headers.content_type"},
         "expected": "application/json", "failure_behavior": "FAIL"},
    ],
}
_RELEASE_POLICY = {
    "release_on": "PASS", "withhold_on": "FAIL",
    "manual_review_on": "INDETERMINATE", "timeout_behavior": "manual_review",
}
_PASS_OUTPUT = {"headers": {"content_type": "application/json"},
                "status_code": 200, "manifest": {"row_count": 1200}}
_FAIL_OUTPUT = {"headers": {"content_type": "application/json"},
                "status_code": 200, "manifest": {"row_count": 10}}


def _commit(tag: str = "x", with_profile: bool = True) -> str:
    """Store a committed Action Commitment record; return its action_ref."""
    request_body: dict = {"resource": f"urn:example:{tag}"}
    if with_profile:
        request_body["ds_conditional_release"] = {
            "profile_schema_id": "ds.conditional_release_profile.v0.1",
            "acceptance_spec": _ACCEPTANCE_SPEC,
            "release_policy": _RELEASE_POLICY,
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
    return action_ref


def _post(action_ref: str, output: dict):
    return svc.post_evaluate_deterministic(
        svc.DeterministicEvaluateInput(action_ref=action_ref, submitted_output=output)
    )


# ---------------------------------------------------------------------------
# Storage layer (direct)
# ---------------------------------------------------------------------------

def _eval_record(action_ref: str, result: str = "PASS") -> dict:
    return {
        "record_type": estore.RECORD_TYPE,
        "record_version": estore.RECORD_VERSION,
        "action_ref": action_ref,
        "result": result,
        "checks": [],
        "declared_release_intent": "should release",
        "submitted_output": {"a": 1},
    }


def test_store_and_retrieve(isolated_ledgers):
    ref = "sha256:" + "a" * 64
    rec = _eval_record(ref)
    assert store_deterministic_evaluation(rec) is True
    assert get_deterministic_evaluation(ref) == rec


def test_idempotent_identical_record(isolated_ledgers):
    ref = "sha256:" + "b" * 64
    rec = _eval_record(ref)
    assert store_deterministic_evaluation(rec) is True
    assert store_deterministic_evaluation(copy.deepcopy(rec)) is False
    assert len(isolated_ledgers.read_text().splitlines()) == 1


def test_conflict_on_different_record(isolated_ledgers):
    ref = "sha256:" + "c" * 64
    store_deterministic_evaluation(_eval_record(ref, "PASS"))
    with pytest.raises(DeterministicEvaluationConflict):
        store_deterministic_evaluation(_eval_record(ref, "FAIL"))


def test_conflict_on_different_submitted_output(isolated_ledgers):
    ref = "sha256:" + "d" * 64
    rec = _eval_record(ref)
    store_deterministic_evaluation(rec)
    other = copy.deepcopy(rec)
    other["submitted_output"] = {"a": 2}
    with pytest.raises(DeterministicEvaluationConflict):
        store_deterministic_evaluation(other)


def test_validate_rejects_signing_fields(isolated_ledgers):
    ref = "sha256:" + "e" * 64
    rec = _eval_record(ref)
    rec["signature"] = {"sig": "x"}
    with pytest.raises(DeterministicEvaluationRecordError):
        validate_deterministic_evaluation_record(rec)


def test_validate_returns_action_ref(isolated_ledgers):
    ref = "sha256:" + "f" * 64
    assert validate_deterministic_evaluation_record(_eval_record(ref)) == ref


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

def test_evaluate_stored_commitment_pass(isolated_ledgers):
    ref = _commit("pass")
    resp = _post(ref, _PASS_OUTPUT)
    assert resp["status"] == "evaluated"
    assert resp["stored"] is True
    assert resp["result"] == "PASS"
    assert resp["declared_release_intent"] == "should release"
    assert resp["evaluation_lookup_path"].endswith(ref.replace(":", "%3A"))


def test_evaluate_stored_commitment_fail(isolated_ledgers):
    ref = _commit("fail")
    resp = _post(ref, _FAIL_OUTPUT)
    assert resp["result"] == "FAIL"
    assert resp["declared_release_intent"] == "should withhold"


def test_unknown_action_ref_returns_404(isolated_ledgers):
    with pytest.raises(HTTPException) as exc:
        _post("sha256:" + "0" * 64, _PASS_OUTPUT)
    assert exc.value.status_code == 404


def test_invalid_action_ref_returns_422(isolated_ledgers):
    with pytest.raises(HTTPException) as exc:
        _post("not-a-sha", _PASS_OUTPUT)
    assert exc.value.status_code == 422


def test_caller_submitted_acceptance_spec_is_refused(isolated_ledgers):
    # The input model forbids any extra field, including acceptance_spec.
    with pytest.raises(ValidationError):
        svc.DeterministicEvaluateInput(
            action_ref="sha256:" + "0" * 64,
            submitted_output={},
            acceptance_spec={"checks": []},
        )


def test_commitment_without_profile_is_terminal_indeterminate(isolated_ledgers):
    # A committed action with no conditional-release profile is NOT a transport
    # error: absence is an audit conclusion -> terminal INDETERMINATE artifact.
    ref = _commit("noprofile", with_profile=False)
    resp = _post(ref, _PASS_OUTPUT)
    assert resp["result"] == "INDETERMINATE"
    assert resp["reason_code"] == "MISSING_CONDITIONAL_RELEASE_PROFILE"
    assert resp["declared_release_intent"] == "manual_review"
    record = resp["record"]
    assert record["checks"] == []
    assert record["reason_code"] == "MISSING_CONDITIONAL_RELEASE_PROFILE"
    # Stored + retrievable.
    got = svc.get_evaluate_deterministic(ref)
    assert got["record"]["reason_code"] == "MISSING_CONDITIONAL_RELEASE_PROFILE"


def _commit_profile_variant(tag: str, profile: dict) -> str:
    """Commit an action whose ds_conditional_release profile is `profile`."""
    request_body = {"resource": f"urn:example:{tag}", "ds_conditional_release": profile}
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
    return action_ref


def test_profile_missing_acceptance_spec_is_terminal_indeterminate(isolated_ledgers):
    ref = _commit_profile_variant(
        "noaspec",
        {"profile_schema_id": "ds.conditional_release_profile.v0.1", "release_policy": _RELEASE_POLICY},
    )
    resp = _post(ref, _PASS_OUTPUT)
    assert resp["result"] == "INDETERMINATE"
    assert resp["reason_code"] == "MISSING_ACCEPTANCE_SPEC"
    assert resp["declared_release_intent"] == "manual_review"
    assert resp["record"]["checks"] == []


def test_malformed_acceptance_spec_is_terminal_indeterminate(isolated_ledgers):
    # acceptance_spec present but invalid shape (checks not an array).
    ref = _commit_profile_variant(
        "badaspec",
        {
            "profile_schema_id": "ds.conditional_release_profile.v0.1",
            "acceptance_spec": {"spec_id": "bad", "checks": "not-an-array"},
            "release_policy": _RELEASE_POLICY,
        },
    )
    resp = _post(ref, _PASS_OUTPUT)
    assert resp["result"] == "INDETERMINATE"
    assert resp["reason_code"] == "INVALID_ACCEPTANCE_SPEC"
    assert resp["declared_release_intent"] == "manual_review"
    assert resp["record"]["checks"] == []


def test_clean_pass_has_no_reason_code_noise(isolated_ledgers):
    ref = _commit("cleanpass")
    resp = _post(ref, _PASS_OUTPUT)
    assert resp["result"] == "PASS"
    assert "reason_code" not in resp
    assert "reason_code" not in resp["record"]


def test_store_and_get_route_roundtrip(isolated_ledgers):
    ref = _commit("roundtrip")
    _post(ref, _PASS_OUTPUT)
    got = svc.get_evaluate_deterministic(ref)
    assert got["action_ref"] == ref
    assert got["result"] == "PASS"
    assert got["record"]["action_ref"] == ref


def test_get_route_missing_returns_404(isolated_ledgers):
    with pytest.raises(HTTPException) as exc:
        svc.get_evaluate_deterministic("sha256:" + "0" * 64)
    assert exc.value.status_code == 404


def test_post_idempotent_identical_evaluation(isolated_ledgers):
    ref = _commit("idem")
    assert _post(ref, _PASS_OUTPUT)["stored"] is True
    assert _post(ref, _PASS_OUTPUT)["stored"] is False


def test_post_conflict_on_different_output(isolated_ledgers):
    ref = _commit("conflict")
    _post(ref, _PASS_OUTPUT)
    with pytest.raises(HTTPException) as exc:
        _post(ref, _FAIL_OUTPUT)
    assert exc.value.status_code == 409


def test_bounded_language_no_release_or_signing_or_execution_claim(isolated_ledgers):
    ref = _commit("bounded")
    record = _post(ref, _PASS_OUTPUT)["record"]
    # No signing surface.
    assert "signature" not in record and "kid" not in record and "key_id" not in record
    assert record["record_type"] == "deterministic_evaluation_record"
    claim = record["bounded_claim"].lower()
    assert "unsigned" in claim
    assert "not a continuity evaluation receipt" in claim
    assert "not proof of execution" in claim
    assert "not an actual release" in claim
    # declared intent is explicitly declared, not an actual release.
    assert record["declared_release_intent"] == "should release"
