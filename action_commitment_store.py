"""Hosted Path C, Step 1: the Action Commitment / committed-request registry.

This module is the smallest possible persistence layer that lets a *later*
hosted deterministic evaluator retrieve the committed acceptance spec by
``action_ref`` rather than trusting a caller-submitted spec at evaluation time.
Spec substitution is the threat this closes: the committed spec must come from
the stored Action Request body that was already bound by the digest chain

    body_digest -> request_digest -> action_ref

This store does exactly two things — persist an Action Commitment record and
retrieve it by ``action_ref`` — and nothing else:

    * It NEVER signs, NEVER evaluates acceptance specs, and NEVER proves
      execution, spec satisfaction, or release. It only validates the record's
      shape and recomputes/verifies the digest chain before persisting.
    * It writes to a SEPARATE append-only JSONL ledger
      (``attest_action_commitments_master.jsonl``). It never reads, writes, or
      mutates the SAR-402 receipt ledger or the recording-wrapper ledger.

Storage convention. Mirrors ``sar402_recording_store.py``: one record per line,
compact JSON, ``BASE_DIR / "<name>_master.jsonl"``. Tests MUST monkeypatch
``ACTION_COMMITMENT_LEDGER`` to a temp path so the real store is never touched.

Idempotency / single-active-record (v1). At most one record is kept per
``action_ref``:

    * first submission for an action_ref -> appended, returns ``True``;
    * re-submission of a canonically-equivalent record -> no write, returns
      ``False`` (idempotent);
    * a DIFFERENT record for the same action_ref -> raises
      ``ActionCommitmentConflict`` and never silently overwrites.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping, Optional

try:
    import fcntl
except ImportError:  # pragma: no cover - non-posix
    fcntl = None

BASE_DIR = Path(__file__).resolve().parent

# Separate, append-only Path C registry ledger (NOT the receipt or wrapper
# ledgers). Tests monkeypatch this to a temp path; never written on import.
ACTION_COMMITMENT_LEDGER = BASE_DIR / "attest_action_commitments_master.jsonl"

RECORD_TYPE = "action_commitment_record"
RECORD_VERSION = "action_commitment_record_v1"

ACTION_REQUEST_SCHEMA_ID = "ds.action_request.v0.1"
ACTION_COMMITMENT_SCHEMA_ID = "ds.action_commitment.v0.1"

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class ActionCommitmentRecordError(ValueError):
    """A record does not carry the governed shape / valid digest chain."""


class ActionCommitmentConflict(ActionCommitmentRecordError):
    """A different record already exists for the same action_ref.

    v1 keeps a single active record per action_ref; this is raised rather than
    silently overwriting the existing record."""


# ---------------------------------------------------------------------------
# Canonicalization
# ---------------------------------------------------------------------------
# No shared canonicalization helper is exported for general use in this service
# (each module defines its own ``canonical_bytes``). We define a minimal
# sorted-keys/compact UTF-8 JSON function here. This is the ``sorted-keys,
# compact separators, ensure_ascii=False`` convention and is intended to match
# the value domain of ``@defaultsettlement/canonical``'s ``canonicalJson`` v0.1,
# so a third party can reproduce the exact digested bytes.

def canonical_json_bytes(obj: Any) -> bytes:
    """Canonical JSON bytes: sorted keys, compact separators, UTF-8.

    Matches ``@defaultsettlement/canonical`` ``canonicalJson`` v0.1 value
    domain. Not ad hoc / pretty JSON."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sha256(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(obj)).hexdigest()


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and bool(_SHA256_RE.match(value))


# ---------------------------------------------------------------------------
# Minimal JSONL helpers (mirror sar402_recording_store)
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
# Validation (shape + digest chain only — never crypto, never spec evaluation)
# ---------------------------------------------------------------------------

def validate_action_commitment_record(record: Mapping[str, Any]) -> str:
    """Validate shape + digest chain and return the record's ``action_ref``.

    Validates the governed top-level shape, the Action Request Commitment and
    Action Commitment sub-objects, and recomputes the full digest chain:

        body_digest    == sha256(canonical(request_body))
        request_digest == sha256(canonical(action_request_commitment))
        action_ref     == sha256(canonical(action_commitment))

    Raises ``ActionCommitmentRecordError`` on any violation. This is a binding
    check only; it does NOT validate the acceptance spec (that is the
    evaluator's job)."""
    if not isinstance(record, Mapping):
        raise ActionCommitmentRecordError("record must be a JSON object")

    if record.get("record_type") != RECORD_TYPE:
        raise ActionCommitmentRecordError(f"record_type must be {RECORD_TYPE!r}")
    if record.get("record_version") != RECORD_VERSION:
        raise ActionCommitmentRecordError(
            f"record_version must be {RECORD_VERSION!r}"
        )

    request_body = record.get("request_body")
    if not isinstance(request_body, Mapping):
        raise ActionCommitmentRecordError("request_body must be a JSON object")

    arc = record.get("action_request_commitment")
    if not isinstance(arc, Mapping):
        raise ActionCommitmentRecordError(
            "action_request_commitment must be a JSON object"
        )

    ac = record.get("action_commitment")
    if not isinstance(ac, Mapping):
        raise ActionCommitmentRecordError(
            "action_commitment must be a JSON object"
        )

    action_ref = record.get("action_ref")
    if not _is_sha256(action_ref):
        raise ActionCommitmentRecordError("action_ref must be sha256:<64 hex>")

    # --- Action Request Commitment shape ---
    if arc.get("schema_id") != ACTION_REQUEST_SCHEMA_ID:
        raise ActionCommitmentRecordError(
            f"action_request_commitment.schema_id must be {ACTION_REQUEST_SCHEMA_ID!r}"
        )
    method = arc.get("method")
    if not isinstance(method, str) or not method:
        raise ActionCommitmentRecordError(
            "action_request_commitment.method must be a non-empty string"
        )
    if not isinstance(arc.get("target"), Mapping):
        raise ActionCommitmentRecordError(
            "action_request_commitment.target must be a JSON object"
        )
    content_type = arc.get("content_type")
    if not isinstance(content_type, str) or not content_type:
        raise ActionCommitmentRecordError(
            "action_request_commitment.content_type must be a non-empty string"
        )
    if not _is_sha256(arc.get("body_digest")):
        raise ActionCommitmentRecordError(
            "action_request_commitment.body_digest must be sha256:<64 hex>"
        )

    # --- Action Commitment shape ---
    if ac.get("schema_id") != ACTION_COMMITMENT_SCHEMA_ID:
        raise ActionCommitmentRecordError(
            f"action_commitment.schema_id must be {ACTION_COMMITMENT_SCHEMA_ID!r}"
        )
    agent_id = ac.get("agent_id")
    if not isinstance(agent_id, str) or not agent_id:
        raise ActionCommitmentRecordError(
            "action_commitment.agent_id must be a non-empty string"
        )
    action_type = ac.get("action_type")
    if not isinstance(action_type, str) or not action_type:
        raise ActionCommitmentRecordError(
            "action_commitment.action_type must be a non-empty string"
        )
    if not _is_sha256(ac.get("request_digest")):
        raise ActionCommitmentRecordError(
            "action_commitment.request_digest must be sha256:<64 hex>"
        )
    idempotency_key = ac.get("idempotency_key")
    if not isinstance(idempotency_key, str) or not idempotency_key:
        raise ActionCommitmentRecordError(
            "action_commitment.idempotency_key must be a non-empty string"
        )

    # --- Digest chain: body -> request -> action_ref ---
    computed_body_digest = _sha256(request_body)
    if arc.get("body_digest") != computed_body_digest:
        raise ActionCommitmentRecordError(
            "body_digest does not match sha256(canonical(request_body))"
        )

    computed_request_digest = _sha256(arc)
    if ac.get("request_digest") != computed_request_digest:
        raise ActionCommitmentRecordError(
            "request_digest does not match sha256(canonical(action_request_commitment))"
        )

    computed_action_ref = _sha256(ac)
    if action_ref != computed_action_ref:
        raise ActionCommitmentRecordError(
            "action_ref does not match sha256(canonical(action_commitment))"
        )

    return action_ref


def extract_conditional_release_profile(
    record: Mapping[str, Any],
) -> Optional[dict[str, Any]]:
    """Return ``request_body["ds_conditional_release"]`` when present and a dict.

    This registry does NOT require every Action Commitment to be a
    conditional-release profile, and does NOT validate the acceptance spec
    beyond the digest-chain binding. Spec validation belongs to the evaluator."""
    if not isinstance(record, Mapping):
        return None
    request_body = record.get("request_body")
    if not isinstance(request_body, Mapping):
        return None
    profile = request_body.get("ds_conditional_release")
    return profile if isinstance(profile, dict) else None


# ---------------------------------------------------------------------------
# Store / retrieve
# ---------------------------------------------------------------------------

def get_action_commitment(action_ref: str) -> Optional[dict[str, Any]]:
    """Return the stored record for ``action_ref``, or None.

    v1 keeps a single active record per action_ref; the most recent matching
    record is returned."""
    if not _is_sha256(action_ref):
        return None
    latest: Optional[dict[str, Any]] = None
    for record in _read_jsonl(ACTION_COMMITMENT_LEDGER):
        if record.get("action_ref") == action_ref:
            latest = record
    return latest


def store_action_commitment(record: Mapping[str, Any]) -> bool:
    """Persist an Action Commitment record. Returns True iff a new record was written.

    Behavior:
      * validates shape + digest chain (raises ``ActionCommitmentRecordError``);
      * if no record exists for the action_ref -> append, return True;
      * if a canonically-equivalent record already exists -> no write, return
        False (idempotent);
      * if a DIFFERENT record exists for the same action_ref -> raise
        ``ActionCommitmentConflict`` (never silently overwrite).

    The store does NOT sign or evaluate — it persists the record verbatim."""
    action_ref = validate_action_commitment_record(record)

    existing = get_action_commitment(action_ref)
    if existing is not None:
        if canonical_json_bytes(existing) == canonical_json_bytes(record):
            return False  # idempotent: identical record already stored
        raise ActionCommitmentConflict(
            "a different action commitment record already exists for action_ref "
            f"{action_ref!r}; refusing to overwrite"
        )

    _append_jsonl(ACTION_COMMITMENT_LEDGER, dict(record))
    return True
