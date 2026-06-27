"""Deterministic acceptance-spec evaluator (v0.1) — Python port.

This is a line-for-line behavioral port of the SDK evaluator
(``defaultsettlement-sdk/packages/continuity/src/deterministic-evaluator.ts``).
It takes a COMMITTED acceptance spec (the one that rides inside the Action
Request body at ``ds_conditional_release.acceptance_spec``, covered by
``body_digest``) plus a submitted output, and produces an inspectable result.

Bounded claim (and nothing more):

    A deterministic evaluator applied a declared acceptance spec to a referenced
    output and produced a recorded result.

It does NOT sign anything, does NOT prove objective correctness, payment or
resource release, actual release, execution, or legal sufficiency. The caller
MUST NOT submit an ``acceptance_spec``; the spec is always retrieved from the
committed Action Commitment record (see ``attest_service`` Path C routes).

Parity goal: for the same ``(spec, output)`` this produces an identical
``result`` and identical per-check ``checks`` to the TypeScript evaluator. Any
behavioral difference is documented inline as a GAP.
"""

from __future__ import annotations

import hashlib
from numbers import Number
from typing import Any, Mapping, Optional

# Reuse the committed-chain canonicalization so the evaluator's hashing /
# structural-equality value domain cannot drift from the store's. This is the
# `sorted_keys_compact_v0` / @defaultsettlement/canonical canonicalJson v0.1
# convention.
from action_commitment_store import _is_sha256, canonical_json_bytes

# Aggregate results. Mirrors EvaluationResult.
RESULT_PASS = "PASS"
RESULT_FAIL = "FAIL"
RESULT_INDETERMINATE = "INDETERMINATE"
RESULT_EVALUATOR_TIMEOUT = "EVALUATOR_TIMEOUT"

# Supported deterministic check kinds for v0.1 (mirrors CHECK_KINDS).
CHECK_KINDS = frozenset(
    {
        "field_present",
        "field_equals",
        "numeric_threshold",
        "hash_equals",
        "content_type_equals",
        "http_status_equals",
        "json_schema",
    }
)

THRESHOLD_OPS = frozenset({">=", ">", "<=", "<", "=="})

# Sentinel for dot-path traversal: distinguishes "path absent" from "path
# present with value None". Mirrors the TS ABSENT symbol.
_ABSENT = object()


class DeterministicEvaluationError(ValueError):
    """Spec shape / external-ref integrity error (mirrors ContinuityRecordError)."""


def _is_number(value: Any) -> bool:
    """True for JSON numbers only. Excludes bool (JS booleans are not numbers)."""
    return isinstance(value, Number) and not isinstance(value, bool)


def _resolve_dot_path(output: Any, path: Any) -> Any:
    """Minimal dot-path traversal: a leading ``$`` then dot-separated object keys.

    Mirrors resolveDotPath. Array indexing, wildcards, and filters are out of
    scope (a documented gap, NOT a reason to add a dependency). Returns
    ``_ABSENT`` when any segment is missing or traversal hits a non-object."""
    if not isinstance(path, str) or path == "":
        return _ABSENT
    if path == "$":
        return output
    if not path.startswith("$."):
        return _ABSENT
    segments = path[2:].split(".")
    current: Any = output
    for seg in segments:
        if seg == "":
            return _ABSENT
        # TS: null | non-object | array -> ABSENT. A Mapping excludes lists.
        if not isinstance(current, Mapping):
            return _ABSENT
        if seg not in current:
            return _ABSENT
        current = current[seg]
    return current


def _is_content_addressed(ref: Any) -> bool:
    """Mutable references are forbidden: every external ref must be sha256:<digest>."""
    return _is_sha256(ref)


def _deep_equal(a: Any, b: Any) -> bool:
    """Deep structural equality over the v0.1 JSON value domain (via canonical JSON)."""
    return canonical_json_bytes(a) == canonical_json_bytes(b)


def _sha256_canonical(value: Any) -> str:
    """sha256 over canonical JSON of ``value``, as ``sha256:<hex>`` (mirrors sha256Hex)."""
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _unevaluable(kind: str, reason: str, expected: Any = _ABSENT) -> dict[str, Any]:
    detail: dict[str, Any] = {"kind": kind, "status": "unevaluable", "reason": reason}
    if expected is not _ABSENT:
        detail["expected"] = expected
    return detail


def _evaluate_check(check: Mapping[str, Any], output: Any) -> dict[str, Any]:
    """Evaluate a single committed check. Mirrors evaluateCheck switch exactly."""
    kind = check.get("kind")
    inputs = check.get("inputs") or {}
    if not isinstance(inputs, Mapping):
        inputs = {}
    output_path = inputs.get("output_path")
    # `expected` may legitimately be absent; use a sentinel so we can mirror the
    # TS `check.expected` (undefined) inclusion semantics in CheckDetail.
    has_expected = "expected" in check
    expected = check.get("expected")

    if kind == "field_present":
        if not isinstance(output_path, str):
            return _unevaluable(kind, "inputs.output_path is required")
        value = _resolve_dot_path(output, output_path)
        if value is _ABSENT:
            return {
                "kind": kind,
                "status": "unsatisfied",
                "observed": None,
                "reason": f"output_path {output_path} not present",
            }
        return {"kind": kind, "status": "satisfied", "observed": value}

    if kind == "field_equals":
        if not isinstance(output_path, str):
            return _unevaluable(kind, "inputs.output_path is required")
        value = _resolve_dot_path(output, output_path)
        if value is _ABSENT:
            return _unevaluable(
                kind,
                f"output_path {output_path} not present",
                expected if has_expected else _ABSENT,
            )
        ok = _deep_equal(value, expected)
        return {
            "kind": kind,
            "status": "satisfied" if ok else "unsatisfied",
            "observed": value,
            "expected": expected,
        }

    if kind == "numeric_threshold":
        if not isinstance(output_path, str):
            return _unevaluable(kind, "inputs.output_path is required")
        op = expected.get("op") if isinstance(expected, Mapping) else None
        threshold = expected.get("value") if isinstance(expected, Mapping) else None
        if not isinstance(op, str) or op not in THRESHOLD_OPS or not _is_number(threshold):
            return _unevaluable(
                kind,
                'expected must be { op: ">="|">"|"<="|"<"|"==", value: <number> }',
                expected if has_expected else _ABSENT,
            )
        value = _resolve_dot_path(output, output_path)
        if value is _ABSENT:
            return _unevaluable(
                kind,
                f"output_path {output_path} not present",
                expected if has_expected else _ABSENT,
            )
        if not _is_number(value):
            return {
                "kind": kind,
                "status": "unsatisfied",
                "observed": value,
                "expected": expected,
                "reason": "observed value is not a number",
            }
        if op == ">=":
            ok = value >= threshold
        elif op == ">":
            ok = value > threshold
        elif op == "<=":
            ok = value <= threshold
        elif op == "<":
            ok = value < threshold
        else:  # "=="
            ok = value == threshold
        return {
            "kind": kind,
            "status": "satisfied" if ok else "unsatisfied",
            "observed": value,
            "expected": expected,
        }

    if kind == "hash_equals":
        # Hash the resolved value (or the whole output when no path is given).
        if output_path is None:
            target: Any = output
        else:
            target = _resolve_dot_path(output, output_path)
        if target is _ABSENT:
            return _unevaluable(
                kind,
                f"output_path {output_path} not present",
                expected if has_expected else _ABSENT,
            )
        if not _is_content_addressed(expected):
            return _unevaluable(
                kind,
                "expected must be a sha256:<digest> literal",
                expected if has_expected else None,
            )
        observed = _sha256_canonical(target)
        return {
            "kind": kind,
            "status": "satisfied" if observed == expected else "unsatisfied",
            "observed": observed,
            "expected": expected,
        }

    if kind in ("content_type_equals", "http_status_equals"):
        if not isinstance(output_path, str):
            return _unevaluable(kind, "inputs.output_path is required")
        value = _resolve_dot_path(output, output_path)
        if value is _ABSENT:
            return _unevaluable(
                kind,
                f"output_path {output_path} not present",
                expected if has_expected else _ABSENT,
            )
        ok = _deep_equal(value, expected)
        return {
            "kind": kind,
            "status": "satisfied" if ok else "unsatisfied",
            "observed": value,
            "expected": expected,
        }

    if kind == "json_schema":
        # External-artifact check. The ref MUST be content-addressed even though
        # we cannot run validation yet — a mutable ref is rejected outright.
        external_refs = check.get("external_refs")
        schema_ref = (
            external_refs.get("schema_ref")
            if isinstance(external_refs, Mapping)
            else None
        )
        if not _is_content_addressed(schema_ref):
            return _unevaluable(
                kind,
                "external_refs.schema_ref must be a sha256:<digest>",
                external_refs if isinstance(external_refs, Mapping) else None,
            )
        # No JSON Schema validator is in the dependency set for v0.1. Rather than
        # adding one without approval, json_schema is a documented implementation
        # gap and always routes to INDETERMINATE (status unevaluable).
        return _unevaluable(kind, "json_schema_not_implemented", schema_ref)

    return _unevaluable(kind, f"unsupported check kind: {kind}")


def validate_acceptance_spec(spec: Any) -> None:
    """Validate spec shape + external-reference integrity BEFORE evaluation.

    Mutable external refs (``latest``, a URL, ``v1``) are a hard spec error: they
    would let the spec's meaning drift without invalidating ``body_digest``.
    Raises ``DeterministicEvaluationError``. Mirrors validateAcceptanceSpec."""
    if not isinstance(spec, Mapping):
        raise DeterministicEvaluationError("acceptance_spec must be an object")
    checks = spec.get("checks")
    if not isinstance(checks, list):
        raise DeterministicEvaluationError("acceptance_spec.checks must be an array")
    evaluator_type = spec.get("evaluator_type")
    if evaluator_type is not None and evaluator_type != "deterministic":
        raise DeterministicEvaluationError(
            f'evaluator_type must be "deterministic"; got {evaluator_type}'
        )
    for i, check in enumerate(checks):
        if not isinstance(check, Mapping):
            raise DeterministicEvaluationError(f"checks[{i}] must be an object")
        if check.get("kind") not in CHECK_KINDS:
            raise DeterministicEvaluationError(
                f"checks[{i}].kind is unsupported: {check.get('kind')}"
            )
        failure_behavior = check.get("failure_behavior")
        if failure_behavior is not None and failure_behavior not in ("FAIL", "INDETERMINATE"):
            raise DeterministicEvaluationError(
                f'checks[{i}].failure_behavior must be "FAIL" or "INDETERMINATE"'
            )
        refs = check.get("external_refs") or {}
        if isinstance(refs, Mapping):
            for name, ref in refs.items():
                if not _is_content_addressed(ref):
                    raise DeterministicEvaluationError(
                        f"checks[{i}].external_refs.{name} must be a content-addressed "
                        f"sha256:<digest>; mutable references are forbidden (got {ref})"
                    )


def evaluate_acceptance_spec(spec: Mapping[str, Any], output: Any) -> dict[str, Any]:
    """Apply a committed acceptance spec to a submitted output.

    Aggregation (mirrors evaluateAcceptanceSpec):
      * PASS          — every check evaluated and satisfied.
      * FAIL          — at least one ``failure_behavior: FAIL`` check is unsatisfied.
      * INDETERMINATE — at least one unevaluable check (or an unsatisfied
                        ``failure_behavior: INDETERMINATE`` check) and no hard FAIL.
      * EVALUATOR_TIMEOUT — not produced by this pure helper; timeout handling is
                        a documented future gap and is NEVER silently coerced to
                        PASS or FAIL.

    A hard FAIL dominates INDETERMINATE.

    Returns ``{"result": <str>, "checks": [<detail>, ...]}``.
    Raises ``DeterministicEvaluationError`` on a bad spec / external ref."""
    validate_acceptance_spec(spec)

    checks: list[dict[str, Any]] = []
    hard_fail = False
    indeterminate = False

    for check in spec["checks"]:
        detail = _evaluate_check(check, output)
        checks.append(detail)

        behavior = check.get("failure_behavior") or "FAIL"
        if detail["status"] == "unsatisfied":
            if behavior == "FAIL":
                hard_fail = True
            else:
                indeterminate = True
        elif detail["status"] == "unevaluable":
            # Unevaluable cannot be a hard FAIL — it routes to INDETERMINATE
            # regardless of declared failure_behavior (we could not check it).
            indeterminate = True

    if hard_fail:
        result = RESULT_FAIL
    elif indeterminate:
        result = RESULT_INDETERMINATE
    else:
        result = RESULT_PASS

    return {"result": result, "checks": checks}


# ---------------------------------------------------------------------------
# Declared release intent (policy mapping, NOT a release action)
# ---------------------------------------------------------------------------

# Fallback mapping used only when the committed profile carries no release_policy.
# Mirrors the SDK example fixture's mapping. This is DECLARED intent — it is not
# proof of, and does not perform, any actual release/withholding.
_DEFAULT_RELEASE_INTENT = {
    RESULT_PASS: "should release",
    RESULT_FAIL: "should withhold",
    RESULT_INDETERMINATE: "manual_review",
    RESULT_EVALUATOR_TIMEOUT: "manual_review",
}


def derive_declared_release_intent(
    result: str, release_policy: Optional[Mapping[str, Any]]
) -> str:
    """Map an evaluation ``result`` to a DECLARED release intent.

    Prefers the committed ``release_policy`` when present (do not hardcode policy
    the committed body already provides); otherwise falls back to the default
    mapping. ``release_policy`` shape (from the profile):

        { release_on, withhold_on, manual_review_on, timeout_behavior }

    where the first three values are result states and ``timeout_behavior`` is an
    intent label for EVALUATOR_TIMEOUT. This returns declared intent only and
    performs no release."""
    if not isinstance(release_policy, Mapping):
        return _DEFAULT_RELEASE_INTENT[result]

    if result == RESULT_EVALUATOR_TIMEOUT:
        timeout_behavior = release_policy.get("timeout_behavior")
        if isinstance(timeout_behavior, str) and timeout_behavior:
            return timeout_behavior
        return _DEFAULT_RELEASE_INTENT[result]

    # Invert the committed policy: which result triggers each declared intent.
    mapping: dict[Any, str] = {}
    if release_policy.get("release_on") is not None:
        mapping[release_policy["release_on"]] = "should release"
    if release_policy.get("withhold_on") is not None:
        mapping[release_policy["withhold_on"]] = "should withhold"
    if release_policy.get("manual_review_on") is not None:
        mapping[release_policy["manual_review_on"]] = "manual_review"

    return mapping.get(result, _DEFAULT_RELEASE_INTENT[result])
