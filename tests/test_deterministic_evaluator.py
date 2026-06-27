"""Tests for the deterministic acceptance-spec evaluator (Python port).

These prove the Python evaluator (`deterministic_evaluator`) produces the same
aggregate result, per-check detail shape, and aggregation behavior as the SDK
TypeScript evaluator
(`defaultsettlement-sdk/packages/continuity/src/deterministic-evaluator.ts`),
including a direct parity check against the SDK's committed example fixtures.

The evaluator never accepts a caller-substituted spec at the architecture level
(that boundary is enforced by the route, tested in
`test_deterministic_evaluation_store.py`); here we test the pure helper.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import deterministic_evaluator as ev  # noqa: E402
from deterministic_evaluator import (  # noqa: E402
    DeterministicEvaluationError,
    derive_declared_release_intent,
    evaluate_acceptance_spec,
)

SDK_FIXTURES = (
    Path.home()
    / "defaultsettlement-sdk/packages/continuity/examples/deterministic-conditional-release"
)


def _spec(*checks) -> dict:
    return {"spec_id": "spec.test", "evaluator_type": "deterministic", "checks": list(checks)}


# ---------------------------------------------------------------------------
# Aggregate results
# ---------------------------------------------------------------------------

def test_pass_case():
    spec = _spec(
        {"kind": "field_present", "inputs": {"output_path": "$.manifest"}},
        {"kind": "numeric_threshold", "inputs": {"output_path": "$.manifest.row_count"},
         "expected": {"op": ">=", "value": 1000}},
    )
    out = {"manifest": {"row_count": 1200}}
    result = evaluate_acceptance_spec(spec, out)
    assert result["result"] == "PASS"
    assert [c["status"] for c in result["checks"]] == ["satisfied", "satisfied"]


def test_fail_case():
    spec = _spec(
        {"kind": "numeric_threshold", "inputs": {"output_path": "$.manifest.row_count"},
         "expected": {"op": ">=", "value": 1000}, "failure_behavior": "FAIL"},
    )
    result = evaluate_acceptance_spec(spec, {"manifest": {"row_count": 740}})
    assert result["result"] == "FAIL"
    assert result["checks"][0]["status"] == "unsatisfied"


def test_indeterminate_case():
    # An unevaluable check (json_schema gap) with no hard FAIL -> INDETERMINATE.
    spec = _spec(
        {"kind": "json_schema", "external_refs": {"schema_ref": "sha256:" + "a" * 64}},
    )
    result = evaluate_acceptance_spec(spec, {})
    assert result["result"] == "INDETERMINATE"
    assert result["checks"][0]["status"] == "unevaluable"
    assert result["checks"][0]["reason"] == "json_schema_not_implemented"


def test_hard_fail_dominates_indeterminate():
    spec = _spec(
        {"kind": "json_schema", "external_refs": {"schema_ref": "sha256:" + "a" * 64}},
        {"kind": "field_equals", "inputs": {"output_path": "$.status"}, "expected": "ok",
         "failure_behavior": "FAIL"},
    )
    # status mismatches (hard FAIL) while json_schema is unevaluable (INDETERMINATE).
    result = evaluate_acceptance_spec(spec, {"status": "bad"})
    assert result["result"] == "FAIL"


def test_unsatisfied_indeterminate_behavior_routes_indeterminate():
    spec = _spec(
        {"kind": "field_equals", "inputs": {"output_path": "$.status"}, "expected": "ok",
         "failure_behavior": "INDETERMINATE"},
    )
    result = evaluate_acceptance_spec(spec, {"status": "bad"})
    assert result["result"] == "INDETERMINATE"


# ---------------------------------------------------------------------------
# Per-check kinds
# ---------------------------------------------------------------------------

def test_field_present():
    spec = _spec({"kind": "field_present", "inputs": {"output_path": "$.manifest"}})
    assert evaluate_acceptance_spec(spec, {"manifest": {"a": 1}})["checks"][0] == {
        "kind": "field_present", "status": "satisfied", "observed": {"a": 1},
    }
    missing = evaluate_acceptance_spec(spec, {})
    assert missing["checks"][0]["status"] == "unsatisfied"
    assert missing["checks"][0]["observed"] is None
    assert missing["result"] == "FAIL"  # default failure_behavior is FAIL


def test_field_equals():
    spec = _spec({"kind": "field_equals", "inputs": {"output_path": "$.status"}, "expected": "ok"})
    assert evaluate_acceptance_spec(spec, {"status": "ok"})["checks"][0]["status"] == "satisfied"
    assert evaluate_acceptance_spec(spec, {"status": "no"})["checks"][0]["status"] == "unsatisfied"
    # Absent path -> unevaluable (NOT unsatisfied) -> INDETERMINATE.
    absent = evaluate_acceptance_spec(spec, {})
    assert absent["checks"][0]["status"] == "unevaluable"
    assert absent["result"] == "INDETERMINATE"


def test_numeric_threshold_ops():
    for op, val, observed, expect in [
        (">=", 1000, 1000, "satisfied"),
        (">", 1000, 1000, "unsatisfied"),
        ("<=", 10, 10, "satisfied"),
        ("<", 10, 10, "unsatisfied"),
        ("==", 5, 5, "satisfied"),
    ]:
        spec = _spec({"kind": "numeric_threshold", "inputs": {"output_path": "$.n"},
                      "expected": {"op": op, "value": val}})
        assert evaluate_acceptance_spec(spec, {"n": observed})["checks"][0]["status"] == expect

    # Non-number observed -> unsatisfied with reason.
    spec = _spec({"kind": "numeric_threshold", "inputs": {"output_path": "$.n"},
                  "expected": {"op": ">=", "value": 1}})
    detail = evaluate_acceptance_spec(spec, {"n": "x"})["checks"][0]
    assert detail["status"] == "unsatisfied"
    assert detail["reason"] == "observed value is not a number"

    # Bad expected shape -> unevaluable.
    bad = _spec({"kind": "numeric_threshold", "inputs": {"output_path": "$.n"}, "expected": {"op": "~", "value": 1}})
    assert evaluate_acceptance_spec(bad, {"n": 1})["checks"][0]["status"] == "unevaluable"


def test_numeric_threshold_bool_is_not_a_number():
    spec = _spec({"kind": "numeric_threshold", "inputs": {"output_path": "$.n"},
                  "expected": {"op": ">=", "value": 1}})
    detail = evaluate_acceptance_spec(spec, {"n": True})["checks"][0]
    assert detail["status"] == "unsatisfied"
    assert detail["reason"] == "observed value is not a number"


def test_hash_equals():
    target = {"b": 2, "a": 1}
    digest = ev._sha256_canonical(target)
    spec = _spec({"kind": "hash_equals", "inputs": {"output_path": "$.payload"}, "expected": digest})
    assert evaluate_acceptance_spec(spec, {"payload": target})["checks"][0]["status"] == "satisfied"
    assert evaluate_acceptance_spec(spec, {"payload": {"a": 9}})["checks"][0]["status"] == "unsatisfied"
    # Non content-addressed expected -> unevaluable.
    bad = _spec({"kind": "hash_equals", "inputs": {"output_path": "$.payload"}, "expected": "latest"})
    assert evaluate_acceptance_spec(bad, {"payload": target})["checks"][0]["status"] == "unevaluable"


def test_hash_equals_whole_output_when_no_path():
    out = {"a": 1}
    spec = _spec({"kind": "hash_equals", "expected": ev._sha256_canonical(out)})
    assert evaluate_acceptance_spec(spec, out)["checks"][0]["status"] == "satisfied"


def test_content_type_equals():
    spec = _spec({"kind": "content_type_equals", "inputs": {"output_path": "$.headers.content_type"},
                  "expected": "application/json"})
    assert evaluate_acceptance_spec(spec, {"headers": {"content_type": "application/json"}})["checks"][0]["status"] == "satisfied"
    assert evaluate_acceptance_spec(spec, {"headers": {"content_type": "text/html"}})["checks"][0]["status"] == "unsatisfied"


def test_http_status_equals():
    spec = _spec({"kind": "http_status_equals", "inputs": {"output_path": "$.status_code"}, "expected": 200})
    assert evaluate_acceptance_spec(spec, {"status_code": 200})["checks"][0]["status"] == "satisfied"
    assert evaluate_acceptance_spec(spec, {"status_code": 500})["checks"][0]["status"] == "unsatisfied"


def test_json_schema_bounded_behavior():
    # content-addressed ref -> bounded INDETERMINATE with the documented reason.
    ok = _spec({"kind": "json_schema", "external_refs": {"schema_ref": "sha256:" + "c" * 64}})
    d = evaluate_acceptance_spec(ok, {})["checks"][0]
    assert d["status"] == "unevaluable" and d["reason"] == "json_schema_not_implemented"
    # mutable ref -> rejected at validation time (hard spec error).
    mutable = _spec({"kind": "json_schema", "external_refs": {"schema_ref": "https://x/schema"}})
    with pytest.raises(DeterministicEvaluationError):
        evaluate_acceptance_spec(mutable, {})


def test_unsupported_check_kind_rejected():
    with pytest.raises(DeterministicEvaluationError):
        evaluate_acceptance_spec(_spec({"kind": "regex_match"}), {})


def test_spec_shape_errors():
    with pytest.raises(DeterministicEvaluationError):
        evaluate_acceptance_spec({"checks": "nope"}, {})
    with pytest.raises(DeterministicEvaluationError):
        evaluate_acceptance_spec({"checks": [], "evaluator_type": "ml"}, {})
    with pytest.raises(DeterministicEvaluationError):
        evaluate_acceptance_spec(_spec({"kind": "field_present", "failure_behavior": "MAYBE"}), {})


# ---------------------------------------------------------------------------
# Declared release intent mapping
# ---------------------------------------------------------------------------

def test_declared_release_intent_default_mapping():
    assert derive_declared_release_intent("PASS", None) == "should release"
    assert derive_declared_release_intent("FAIL", None) == "should withhold"
    assert derive_declared_release_intent("INDETERMINATE", None) == "manual_review"
    assert derive_declared_release_intent("EVALUATOR_TIMEOUT", None) == "manual_review"


def test_declared_release_intent_follows_committed_policy():
    policy = {"release_on": "PASS", "withhold_on": "FAIL",
              "manual_review_on": "INDETERMINATE", "timeout_behavior": "escalate"}
    assert derive_declared_release_intent("PASS", policy) == "should release"
    assert derive_declared_release_intent("FAIL", policy) == "should withhold"
    assert derive_declared_release_intent("INDETERMINATE", policy) == "manual_review"
    assert derive_declared_release_intent("EVALUATOR_TIMEOUT", policy) == "escalate"


# ---------------------------------------------------------------------------
# Parity against the SDK committed example fixtures
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not SDK_FIXTURES.exists(), reason="SDK fixtures not present")
def test_parity_with_sdk_pass_fixture():
    body = json.loads((SDK_FIXTURES / "request-body.json").read_text())
    spec = body["ds_conditional_release"]["acceptance_spec"]
    output = json.loads((SDK_FIXTURES / "sample-output-pass.json").read_text())
    expected = json.loads((SDK_FIXTURES / "evaluation-pass.json").read_text())

    outcome = evaluate_acceptance_spec(spec, output)
    assert outcome["result"] == expected["result"] == "PASS"
    assert outcome["checks"] == expected["checks"]


@pytest.mark.skipif(not SDK_FIXTURES.exists(), reason="SDK fixtures not present")
def test_parity_with_sdk_fail_fixture():
    body = json.loads((SDK_FIXTURES / "request-body.json").read_text())
    spec = body["ds_conditional_release"]["acceptance_spec"]
    output = json.loads((SDK_FIXTURES / "sample-output-fail.json").read_text())
    expected = json.loads((SDK_FIXTURES / "evaluation-fail.json").read_text())

    outcome = evaluate_acceptance_spec(spec, output)
    assert outcome["result"] == expected["result"] == "FAIL"
    assert outcome["checks"] == expected["checks"]
