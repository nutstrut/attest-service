"""Tests for SAR-402 Path B storage + read endpoint (local/test keys only).

These prove the storage layer (`sar402_recording_store`) and the read-only
endpoint (`attest_service.get_sar402_recording`) WITHOUT production keys,
without deployment, and without touching Path A receipt storage:

  * store/retrieve round-trips through a temp JSONL ledger (never the real one);
  * duplicate-equivalent submission is idempotent (no second write);
  * a conflicting wrapper for the same wrapped receipt is NOT silently
    overwritten;
  * the endpoint returns the governed response shape and the four lookup
    outcomes (200 / 404-no-wrapper / 404-unknown / 422) plus 503 (key
    unavailable) and 500 (verification failure);
  * `recording_context = "attestation"` is rejected by the store;
  * the canonical public_demo receipt (sha256:91e2ae85…) is wrapped and
    retrieved with ONLY an ephemeral test keypair;
  * Path A storage is never written by any Path B operation.

All signing uses an ephemeral, per-process test keypair. No production key, no
real ledger, no env mutation of real key material.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import attest_service as svc  # noqa: E402
import sar402_recording_store as store  # noqa: E402
from sar402_recording_store import (  # noqa: E402
    RecordingWrapperConflict,
    RecordingWrapperError,
    get_recording_wrapper,
    store_recording_wrapper,
)
from sar402_recording_wrapper import build_recording_wrapper  # noqa: E402
from sar402_receipts import record_sar402_receipt  # noqa: E402

from test_sar402_receipts import _unique_payload  # noqa: E402


# Ephemeral, per-process test keypair. NOT a production key, never published.
_TEST_SIGNING_KEY = Ed25519PrivateKey.generate()
TEST_KID = "sar-test-recording-ed25519-ephemeral"

CANONICAL_DEMO_RECEIPT_ID = (
    "sha256:91e2ae85f03c7a8e7df10e8862895b99456cb13abc50b4e23ba84f1c15b3b8c9"
)
CANONICAL_DEMO_PAYLOAD = (
    ROOT
    / "reports/sar402/path-a-demo"
    / "sar402-canonical-public-demo-v2-20260623T234156Z.payload.json"
)


@pytest.fixture
def isolated_store(tmp_path, monkeypatch):
    """Point the Path B ledger at a temp file so the real store is never touched."""
    ledger = tmp_path / "recording_wrappers.jsonl"
    monkeypatch.setattr(store, "RECORDING_WRAPPER_LEDGER", ledger)
    return ledger


@pytest.fixture
def verification_key(monkeypatch):
    """Inject the ephemeral test public key as the endpoint's verification key."""
    monkeypatch.setattr(
        svc, "_recording_public_key", lambda: _TEST_SIGNING_KEY.public_key()
    )


def _inner_receipt(tag: str) -> dict:
    return record_sar402_receipt(_unique_payload(tag), persist=False)["receipt"]


def _wrap(receipt: dict, **kwargs) -> dict:
    return build_recording_wrapper(
        receipt, signing_key=_TEST_SIGNING_KEY, kid=TEST_KID, **kwargs
    )


# ---------------------------------------------------------------------------
# Storage layer
# ---------------------------------------------------------------------------

def test_store_and_retrieve_wrapper(isolated_store):
    receipt = _inner_receipt("store")
    wrapper = _wrap(receipt)
    assert store_recording_wrapper(wrapper) is True

    got = get_recording_wrapper(wrapper["wrapped_receipt_id"])
    assert got is not None
    assert got == wrapper
    assert got["wrapped_receipt_id"] == receipt["receipt_id"]


def test_get_unknown_receipt_returns_none(isolated_store):
    assert get_recording_wrapper("sha256:" + "0" * 64) is None


def test_duplicate_equivalent_submission_is_idempotent(isolated_store):
    wrapper = _wrap(_inner_receipt("idem"))
    assert store_recording_wrapper(wrapper) is True
    # Re-submitting the identical wrapper writes nothing more.
    assert store_recording_wrapper(copy.deepcopy(wrapper)) is False
    assert len(isolated_store.read_text().splitlines()) == 1


def test_conflicting_wrapper_not_silently_overwritten(isolated_store):
    receipt = _inner_receipt("conflict")
    first = _wrap(receipt, recording_context="ingestion")
    assert store_recording_wrapper(first) is True

    # A different wrapper for the SAME wrapped receipt (different context/sig).
    second = _wrap(receipt, recording_context="observation")
    assert second["wrapped_receipt_id"] == first["wrapped_receipt_id"]
    with pytest.raises(RecordingWrapperConflict):
        store_recording_wrapper(second)

    # The original is intact; nothing overwritten.
    assert get_recording_wrapper(receipt["receipt_id"]) == first
    assert len(isolated_store.read_text().splitlines()) == 1


def test_wrapper_shape_required_fields_enforced(isolated_store):
    wrapper = _wrap(_inner_receipt("shape"))
    for field in (
        "wrapper_type",
        "wrapper_version",
        "wrapped_receipt_id",
        "wrapped_receipt_digest",
        "recording_key_id",
        "recording_signature",
    ):
        broken = copy.deepcopy(wrapper)
        del broken[field]
        with pytest.raises(RecordingWrapperError):
            store_recording_wrapper(broken)


def test_attestation_recording_context_rejected_by_store(isolated_store):
    wrapper = _wrap(_inner_receipt("attest"))
    wrapper["recording_context"] = "attestation"
    with pytest.raises(RecordingWrapperError):
        store_recording_wrapper(wrapper)
    # Nothing was written.
    assert not isolated_store.exists() or isolated_store.read_text() == ""


def test_path_a_storage_not_touched_by_wrapper_ops(tmp_path, monkeypatch):
    # Both ledgers point at distinct temp files; Path B ops must leave Path A
    # empty.
    path_a = tmp_path / "receipts.jsonl"
    path_b = tmp_path / "recording_wrappers.jsonl"
    monkeypatch.setattr(svc, "RECEIPT_LEDGER", path_a)
    monkeypatch.setattr(store, "RECORDING_WRAPPER_LEDGER", path_b)

    wrapper = _wrap(_inner_receipt("untouched"))
    store_recording_wrapper(wrapper)

    assert path_b.exists()
    assert not path_a.exists()  # no Path A write occurred


# ---------------------------------------------------------------------------
# Read endpoint
# ---------------------------------------------------------------------------

def test_endpoint_returns_wrapper_and_shape(isolated_store, verification_key):
    receipt = _inner_receipt("endpoint")
    wrapper = _wrap(receipt)
    store_recording_wrapper(wrapper)

    resp = svc.get_sar402_recording(receipt["receipt_id"])
    assert resp["receipt_id"] == receipt["receipt_id"]
    assert resp["wrapper"] == wrapper
    assert resp["wrapper_type"] == "sar402_recording_attribution"
    assert resp["lookup_path"].endswith(receipt["receipt_id"].replace(":", "%3A"))
    # Boundary fields survive the round-trip intact.
    ab = resp["wrapper"]["authority_boundary"]
    assert ab["verifier_has_execution_authority"] is False
    assert ab["verifier_controls_resource_release"] is False
    assert ab["source_evidence_created_by"] == "resource_server"


def test_endpoint_receipt_exists_but_no_wrapper_returns_404(
    tmp_path, monkeypatch, verification_key
):
    # A real Path A receipt is persisted, but no Path B wrapper exists.
    path_a = tmp_path / "receipts.jsonl"
    path_b = tmp_path / "recording_wrappers.jsonl"
    monkeypatch.setattr(svc, "RECEIPT_LEDGER", path_a)
    monkeypatch.setattr(store, "RECORDING_WRAPPER_LEDGER", path_b)

    result = record_sar402_receipt(_unique_payload("nowrapper"))
    receipt_id = result["receipt_id"]

    with pytest.raises(HTTPException) as exc:
        svc.get_sar402_recording(receipt_id)
    assert exc.value.status_code == 404
    assert exc.value.detail == "no recording wrapper found for receipt"


def test_endpoint_unknown_receipt_returns_404(isolated_store, verification_key, monkeypatch, tmp_path):
    monkeypatch.setattr(svc, "RECEIPT_LEDGER", tmp_path / "receipts.jsonl")
    with pytest.raises(HTTPException) as exc:
        svc.get_sar402_recording("sha256:" + "0" * 64)
    assert exc.value.status_code == 404
    assert exc.value.detail == "receipt not found"


def test_endpoint_invalid_receipt_id_returns_422(verification_key):
    for bad in ("not-a-digest", "sha256:xyz", "sha256:" + "0" * 63, "md5:" + "0" * 64):
        with pytest.raises(HTTPException) as exc:
            svc.get_sar402_recording(bad)
        assert exc.value.status_code == 422


def test_endpoint_key_unavailable_returns_503(isolated_store, monkeypatch):
    receipt = _inner_receipt("nokey")
    store_recording_wrapper(_wrap(receipt))
    monkeypatch.setattr(svc, "_recording_public_key", lambda: None)

    with pytest.raises(HTTPException) as exc:
        svc.get_sar402_recording(receipt["receipt_id"])
    assert exc.value.status_code == 503
    assert exc.value.detail == "recording key unavailable"


def test_endpoint_verification_failure_returns_clear_detail(isolated_store, monkeypatch):
    receipt = _inner_receipt("verifyfail")
    store_recording_wrapper(_wrap(receipt))
    # Verify with the WRONG key -> stored wrapper fails verification.
    other = Ed25519PrivateKey.generate()
    monkeypatch.setattr(svc, "_recording_public_key", lambda: other.public_key())

    with pytest.raises(HTTPException) as exc:
        svc.get_sar402_recording(receipt["receipt_id"])
    assert exc.value.status_code == 500
    assert exc.value.detail == "recording wrapper verification failed"


# ---------------------------------------------------------------------------
# Phase 4: canonical public_demo receipt, ephemeral key only
# ---------------------------------------------------------------------------

def test_canonical_public_demo_receipt_wrapped_and_retrieved(
    tmp_path, monkeypatch, verification_key
):
    # Build the inner receipt from the canonical public_demo payload (unpersisted)
    # so its adopted receipt_id is the canonical sha256:91e2ae85… id.
    payload = json.loads(CANONICAL_DEMO_PAYLOAD.read_text(encoding="utf-8"))
    inner = record_sar402_receipt(
        payload, persist=False, receipt_context="public_demo"
    )["receipt"]
    assert inner["receipt_id"] == CANONICAL_DEMO_RECEIPT_ID

    # Isolate both ledgers; Path A must remain untouched throughout.
    path_a = tmp_path / "receipts.jsonl"
    path_b = tmp_path / "recording_wrappers.jsonl"
    monkeypatch.setattr(svc, "RECEIPT_LEDGER", path_a)
    monkeypatch.setattr(store, "RECORDING_WRAPPER_LEDGER", path_b)

    wrapper = _wrap(inner)
    assert wrapper["wrapped_receipt_id"] == CANONICAL_DEMO_RECEIPT_ID
    assert store_recording_wrapper(wrapper) is True

    resp = svc.get_sar402_recording(CANONICAL_DEMO_RECEIPT_ID)
    assert resp["receipt_id"] == CANONICAL_DEMO_RECEIPT_ID
    assert resp["wrapper"]["wrapped_receipt_id"] == CANONICAL_DEMO_RECEIPT_ID
    assert resp["wrapper_type"] == "sar402_recording_attribution"
    # Inner receipt embedded verbatim; Path A storage never written.
    assert resp["wrapper"]["receipt"] == inner
    assert not path_a.exists()
