"""Hosted Path C, Step 2A: the UNSIGNED deterministic evaluation registry.

This module persists and retrieves the unsigned deterministic evaluation record
produced by ``deterministic_evaluator`` for a committed ``action_ref``. It is
deliberately the smallest possible persistence layer and mirrors
``action_commitment_store.py``'s conventions.

What this is NOT (bounded scope for Step 2A):

    * It does NOT sign. There is no key, no ``kid``, no signature field.
    * The stored record is NOT a Continuity Evaluation Receipt and is NOT a
      signed receipt.
    * It does NOT prove payment finality, resource-release finality, actual
      release, execution, objective correctness, or legal sufficiency.

Storage convention. Mirrors the service: one record per line, compact JSON,
``BASE_DIR / "<name>_master.jsonl"``. The ledger is SEPARATE from the action
commitment ledger and the SAR-402 ledgers. Tests MUST monkeypatch
``DETERMINISTIC_EVALUATION_LEDGER`` to a temp path.

One evaluation per committed action. At most one evaluation record is kept per
``action_ref``:

    * first submission for an action_ref -> appended, returns ``True``;
    * re-submission of a canonically-identical record -> no write, returns
      ``False`` (idempotent);
    * ANY canonically-different record for the same action_ref (including a
      different ``submitted_output``) -> raises ``DeterministicEvaluationConflict``
      and never silently overwrites. Re-evaluation requires a NEW Action
      Commitment with a new ``action_ref``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Optional

try:
    import fcntl
except ImportError:  # pragma: no cover - non-posix
    fcntl = None

# Reuse the committed-chain canonicalization + sha256 validator so this store's
# value domain cannot drift from the commitment store / evaluator.
from action_commitment_store import _is_sha256, canonical_json_bytes

BASE_DIR = Path(__file__).resolve().parent

# Separate, append-only Step 2A ledger (NOT the action commitment or SAR-402
# ledgers). Tests monkeypatch this; never written on import.
DETERMINISTIC_EVALUATION_LEDGER = BASE_DIR / "attest_deterministic_evaluations_master.jsonl"

RECORD_TYPE = "deterministic_evaluation_record"
RECORD_VERSION = "deterministic_evaluation_record_v1"

_VALID_RESULTS = frozenset(
    {"PASS", "FAIL", "INDETERMINATE", "EVALUATOR_TIMEOUT"}
)


class DeterministicEvaluationRecordError(ValueError):
    """A record does not carry the governed shape and cannot be stored."""


class DeterministicEvaluationConflict(DeterministicEvaluationRecordError):
    """A different evaluation record already exists for the same action_ref.

    One evaluation per committed action; re-evaluation requires a new Action
    Commitment (new action_ref). This is raised rather than overwriting."""


# ---------------------------------------------------------------------------
# Minimal JSONL helpers (mirror action_commitment_store)
# ---------------------------------------------------------------------------

def _append_jsonl(path: Path, record: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        if fcntl:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            f.write(json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n")
            f.flush()
        finally:
            if fcntl:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


# ---------------------------------------------------------------------------
# Validation (shape only — never signing, never re-evaluation)
# ---------------------------------------------------------------------------

def validate_deterministic_evaluation_record(record: Mapping[str, Any]) -> str:
    """Validate the governed shape and return the record's ``action_ref``.

    Shape only — this store never signs and never re-runs the evaluator. Raises
    ``DeterministicEvaluationRecordError`` on any violation."""
    if not isinstance(record, Mapping):
        raise DeterministicEvaluationRecordError("record must be a JSON object")
    if record.get("record_type") != RECORD_TYPE:
        raise DeterministicEvaluationRecordError(f"record_type must be {RECORD_TYPE!r}")
    if record.get("record_version") != RECORD_VERSION:
        raise DeterministicEvaluationRecordError(
            f"record_version must be {RECORD_VERSION!r}"
        )

    action_ref = record.get("action_ref")
    if not _is_sha256(action_ref):
        raise DeterministicEvaluationRecordError("action_ref must be sha256:<64 hex>")

    if record.get("result") not in _VALID_RESULTS:
        raise DeterministicEvaluationRecordError(
            "result must be one of " + ", ".join(sorted(_VALID_RESULTS))
        )
    if not isinstance(record.get("checks"), list):
        raise DeterministicEvaluationRecordError("checks must be an array")

    intent = record.get("declared_release_intent")
    if not isinstance(intent, str) or not intent:
        raise DeterministicEvaluationRecordError(
            "declared_release_intent must be a non-empty string"
        )

    # ``reason_code`` is OPTIONAL (Option A): present only when it adds audit
    # meaning (e.g. a committed-action boundary case routed to INDETERMINATE).
    # When present it MUST be a non-empty string; clean PASS/FAIL records omit it.
    if "reason_code" in record:
        reason_code = record.get("reason_code")
        if not isinstance(reason_code, str) or not reason_code:
            raise DeterministicEvaluationRecordError(
                "reason_code, when present, must be a non-empty string"
            )

    # An unsigned record MUST NOT masquerade as signed in Step 2A.
    for forbidden in ("signature", "kid", "key_id"):
        if forbidden in record:
            raise DeterministicEvaluationRecordError(
                f"{forbidden!r} is not permitted on an unsigned evaluation record"
            )

    return action_ref


# ---------------------------------------------------------------------------
# Store / retrieve
# ---------------------------------------------------------------------------

def is_valid_action_ref(value: Any) -> bool:
    """Return True when value is a valid sha256:<64 hex> action_ref."""
    return _is_sha256(value)


def get_deterministic_evaluation(action_ref: str) -> Optional[dict[str, Any]]:
    """Return the stored evaluation record for ``action_ref``, or None."""
    if not _is_sha256(action_ref):
        return None
    latest: Optional[dict[str, Any]] = None
    for record in _read_jsonl(DETERMINISTIC_EVALUATION_LEDGER):
        if record.get("action_ref") == action_ref:
            latest = record
    return latest


def store_deterministic_evaluation(record: Mapping[str, Any]) -> bool:
    """Persist an evaluation record. Returns True iff a new record was written.

    Behavior:
      * validates the governed shape;
      * if no record exists for the action_ref -> append, return True;
      * if a canonically-identical record exists -> no write, return False
        (idempotent retry);
      * if ANY canonically-different record exists for the same action_ref
        (including a different ``submitted_output``) -> raise
        ``DeterministicEvaluationConflict`` (never overwrite).

    The store does NOT sign and does NOT re-evaluate."""
    action_ref = validate_deterministic_evaluation_record(record)

    existing = get_deterministic_evaluation(action_ref)
    if existing is not None:
        if canonical_json_bytes(existing) == canonical_json_bytes(record):
            return False  # idempotent: identical record already stored
        raise DeterministicEvaluationConflict(
            "a different deterministic evaluation record already exists for "
            f"action_ref {action_ref!r}; one evaluation per committed action — "
            "re-evaluation requires a new Action Commitment (new action_ref)"
        )

    _append_jsonl(DETERMINISTIC_EVALUATION_LEDGER, dict(record))
    return True
