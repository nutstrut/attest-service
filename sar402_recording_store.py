"""SAR-402 Path B: persistence for recording-attribution wrappers.

This store is the smallest possible persistence layer for the governed
``sar402_recording_wrapper_v1`` envelope (see ``sar402_recording_wrapper.py`` and
Morpheus ``org/schemas/SAR402_RECORDING_WRAPPER_V1.md``). It does exactly two
things — persist a wrapper and retrieve it by the inner (wrapped) receipt id —
and nothing else:

    * It NEVER builds, signs, or verifies a wrapper (that is the wrapper
      module's job). It only validates that a wrapper carries the governed
      shape before persisting it, and stores/returns the bytes verbatim.
    * It writes to a SEPARATE append-only JSONL ledger from the Path A receipt
      ledger (``attest_receipts_master.jsonl``). It never reads, writes, or
      mutates Path A storage.

Storage convention. The repo persists every ledger as ``BASE_DIR /
"<name>_master.jsonl"`` (see ``attest_service.py``: ``RECEIPT_LEDGER`` etc.),
appended via compact one-record-per-line JSON. We follow that convention rather
than introducing a ``data/`` directory. The Path B ledger is therefore
``attest_recording_wrappers_master.jsonl``. Tests MUST monkeypatch
``RECORDING_WRAPPER_LEDGER`` to a temp path so they never touch the real store.

Idempotency / single-active-wrapper (v1). At most one wrapper is kept per inner
(wrapped) receipt id:

    * first submission for a receipt -> appended, ``store_recording_wrapper``
      returns ``True`` (a write happened);
    * re-submission of a byte/canonically-equivalent wrapper -> no write,
      returns ``False`` (idempotent);
    * submission of a DIFFERENT wrapper for the same wrapped receipt -> raises
      ``RecordingWrapperConflict`` and never silently overwrites the existing
      one.

Path B is not live. This module persists and retrieves only; it has no import
side effects and embeds no key material.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Optional

try:
    import fcntl
except ImportError:  # pragma: no cover - non-posix
    fcntl = None

# Reuse the governed wrapper-contract constants so validation cannot drift from
# the wrapper module / governed schema.
from sar402_recording_wrapper import (
    ALLOWED_RECORDING_CONTEXTS,
    WRAPPER_TYPE,
    WRAPPER_VERSION,
    canonical_bytes,
)

BASE_DIR = Path(__file__).resolve().parent

# Separate, append-only Path B ledger (NOT the Path A receipt ledger). Tests
# monkeypatch this to a temp path; it is never created or written by import.
RECORDING_WRAPPER_LEDGER = BASE_DIR / "attest_recording_wrappers_master.jsonl"


class RecordingWrapperError(ValueError):
    """A wrapper does not carry the governed shape and cannot be stored."""


class RecordingWrapperConflict(RecordingWrapperError):
    """A different wrapper already exists for the same wrapped receipt id.

    v1 keeps a single active wrapper per inner receipt; this is raised rather
    than silently overwriting the existing record."""


# ---------------------------------------------------------------------------
# Minimal JSONL helpers (mirror attest_service's append/read convention)
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
# Validation (shape only — never crypto)
# ---------------------------------------------------------------------------

def validate_wrapper_shape(wrapper: Mapping[str, Any]) -> str:
    """Validate the governed top-level shape and return the wrapped receipt id.

    This is a SHAPE gate, not a signature check (the store never verifies
    crypto). It enforces the governed constants, the recording_context enum
    (``"attestation"`` is rejected), and the presence of the binding/signature
    fields. Raises ``RecordingWrapperError`` on any violation."""
    if not isinstance(wrapper, Mapping):
        raise RecordingWrapperError("wrapper must be a JSON object")

    if wrapper.get("wrapper_type") != WRAPPER_TYPE:
        raise RecordingWrapperError(
            f"wrapper_type must be {WRAPPER_TYPE!r}"
        )
    if wrapper.get("wrapper_version") != WRAPPER_VERSION:
        raise RecordingWrapperError(
            f"wrapper_version must be {WRAPPER_VERSION!r}"
        )

    context = wrapper.get("recording_context")
    if context not in ALLOWED_RECORDING_CONTEXTS:
        raise RecordingWrapperError(
            "recording_context must be one of "
            + ", ".join(ALLOWED_RECORDING_CONTEXTS)
            + f"; {context!r} is not permitted (note: 'attestation' is forbidden)"
        )

    wrapped_receipt_id = wrapper.get("wrapped_receipt_id")
    if not wrapped_receipt_id or not isinstance(wrapped_receipt_id, str):
        raise RecordingWrapperError("wrapped_receipt_id is required")
    if not wrapper.get("wrapped_receipt_digest") or not isinstance(
        wrapper.get("wrapped_receipt_digest"), str
    ):
        raise RecordingWrapperError("wrapped_receipt_digest is required")
    if not wrapper.get("recording_key_id") or not isinstance(
        wrapper.get("recording_key_id"), str
    ):
        raise RecordingWrapperError("recording_key_id is required")
    if not isinstance(wrapper.get("recording_signature"), Mapping):
        raise RecordingWrapperError("recording_signature is required")

    return wrapped_receipt_id


# ---------------------------------------------------------------------------
# Store / retrieve
# ---------------------------------------------------------------------------

def get_recording_wrapper(receipt_id: str) -> Optional[dict[str, Any]]:
    """Return the stored wrapper for ``receipt_id`` (the inner/wrapped id), or None.

    ``receipt_id`` is matched against ``wrapped_receipt_id``. v1 keeps a single
    active wrapper per receipt; the most recent matching record is returned."""
    if not receipt_id or not isinstance(receipt_id, str):
        return None
    latest: Optional[dict[str, Any]] = None
    for record in _read_jsonl(RECORDING_WRAPPER_LEDGER):
        if record.get("wrapped_receipt_id") == receipt_id:
            latest = record
    return latest


def store_recording_wrapper(wrapper: Mapping[str, Any]) -> bool:
    """Persist a recording wrapper. Returns True iff a new record was written.

    Behavior:
      * validates the governed shape (raises ``RecordingWrapperError`` on a bad
        shape, including ``recording_context = "attestation"``);
      * if no wrapper exists for the wrapped receipt id -> append, return True;
      * if an equivalent wrapper already exists (same canonical bytes) -> no
        write, return False (idempotent);
      * if a DIFFERENT wrapper exists for the same wrapped receipt id -> raise
        ``RecordingWrapperConflict`` (never silently overwrite).

    The store does NOT sign or verify — it persists the wrapper verbatim."""
    wrapped_receipt_id = validate_wrapper_shape(wrapper)

    existing = get_recording_wrapper(wrapped_receipt_id)
    if existing is not None:
        if canonical_bytes(existing) == canonical_bytes(wrapper):
            return False  # idempotent: identical wrapper already stored
        raise RecordingWrapperConflict(
            "a different recording wrapper already exists for wrapped_receipt_id "
            f"{wrapped_receipt_id!r}; refusing to overwrite"
        )

    _append_jsonl(RECORDING_WRAPPER_LEDGER, dict(wrapper))
    return True
