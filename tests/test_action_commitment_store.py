"""Tests for the hosted Path C, Step 1 Action Commitment registry.

These prove the storage layer (`action_commitment_store`) and the public
read/write routes (`attest_service.post_action_commitment` /
`attest_service.get_action_commitment`) WITHOUT evaluating any acceptance spec,
without signing, and without touching the SAR-402 receipt or recording-wrapper
ledgers:

  * store/retrieve round-trips through a temp JSONL ledger (never the real one);
  * idempotent re-submission of the identical record writes nothing more;
  * a different record for the same action_ref is NOT silently overwritten;
  * shape and full digest-chain (body -> request -> action_ref) are enforced;
  * extract_conditional_release_profile returns the profile iff present;
  * the routes return the governed response shapes and status codes.

The store never signs and never evaluates. It only preserves the committed
request/action chain so a LATER hosted evaluator can retrieve the spec.
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import attest_service as svc  # noqa: E402
import action_commitment_store as store  # noqa: E402
from action_commitment_store import (  # noqa: E402
    ActionCommitmentConflict,
    ActionCommitmentRecordError,
    extract_conditional_release_profile,
    get_action_commitment,
    store_action_commitment,
    validate_action_commitment_record,
)


@pytest.fixture
def isolated_store(tmp_path, monkeypatch):
    """Point the registry ledger at a temp file so the real store is never touched."""
    ledger = tmp_path / "action_commitments.jsonl"
    monkeypatch.setattr(store, "ACTION_COMMITMENT_LEDGER", ledger)
    return ledger


def _make_record(tag: str = "x", with_profile: bool = False) -> dict:
    """Build a valid record whose digest chain is correctly bound."""
    request_body: dict = {"resource": f"urn:example:{tag}", "amount": 1000}
    if with_profile:
        request_body["ds_conditional_release"] = {
            "schema_id": "ds.conditional_release.v0.1",
            "acceptance": {"all_of": [{"field": "delivered", "equals": True}]},
        }

    arc = {
        "schema_id": store.ACTION_REQUEST_SCHEMA_ID,
        "method": "POST",
        "target": {"path": "/v1/deliver", "host": "example.test"},
        "content_type": "application/json",
        "body_digest": store._sha256(request_body),
    }
    ac = {
        "schema_id": store.ACTION_COMMITMENT_SCHEMA_ID,
        "agent_id": f"agent:{tag}",
        "action_type": "sar402.resource_delivery",
        "request_digest": store._sha256(arc),
        "idempotency_key": f"idem-{tag}",
    }
    return {
        "record_type": store.RECORD_TYPE,
        "record_version": store.RECORD_VERSION,
        "request_body": request_body,
        "action_request_commitment": arc,
        "action_commitment": ac,
        "action_ref": store._sha256(ac),
    }


# ---------------------------------------------------------------------------
# Storage layer
# ---------------------------------------------------------------------------

def test_valid_record_stores_and_retrieves(isolated_store):
    record = _make_record("store")
    assert store_action_commitment(record) is True

    got = get_action_commitment(record["action_ref"])
    assert got is not None
    assert got == record


def test_idempotent_duplicate_returns_false(isolated_store):
    record = _make_record("idem")
    assert store_action_commitment(record) is True
    assert store_action_commitment(copy.deepcopy(record)) is False
    assert len(isolated_store.read_text().splitlines()) == 1


def test_different_record_for_same_action_ref_raises_conflict(isolated_store):
    record = _make_record("conflict")
    assert store_action_commitment(record) is True

    # Same action_ref, but a mutated (no longer chain-consistent) body. To force
    # the conflict path we keep the action_ref but change a non-validated trace
    # field so it differs canonically while still validating.
    other = copy.deepcopy(record)
    other["source"] = "different-source"
    with pytest.raises(ActionCommitmentConflict):
        store_action_commitment(other)
    assert len(isolated_store.read_text().splitlines()) == 1
    assert get_action_commitment(record["action_ref"]) == record


def test_invalid_sha_format_rejected(isolated_store):
    record = _make_record("badsha")
    record["action_ref"] = "not-a-sha"
    with pytest.raises(ActionCommitmentRecordError):
        store_action_commitment(record)


def test_body_digest_mismatch_rejected(isolated_store):
    record = _make_record("bodymismatch")
    record["request_body"]["amount"] = 9999  # body changes, digest does not
    with pytest.raises(ActionCommitmentRecordError):
        store_action_commitment(record)


def test_request_digest_mismatch_rejected(isolated_store):
    record = _make_record("reqmismatch")
    record["action_request_commitment"]["method"] = "PUT"  # arc changes
    with pytest.raises(ActionCommitmentRecordError):
        store_action_commitment(record)


def test_action_ref_mismatch_rejected(isolated_store):
    record = _make_record("refmismatch")
    record["action_ref"] = "sha256:" + "0" * 64
    with pytest.raises(ActionCommitmentRecordError):
        store_action_commitment(record)


def test_validate_returns_action_ref(isolated_store):
    record = _make_record("validate")
    assert validate_action_commitment_record(record) == record["action_ref"]


def test_extract_conditional_release_profile_present(isolated_store):
    record = _make_record("profile", with_profile=True)
    profile = extract_conditional_release_profile(record)
    assert isinstance(profile, dict)
    assert profile["schema_id"] == "ds.conditional_release.v0.1"


def test_extract_conditional_release_profile_absent(isolated_store):
    record = _make_record("noprofile")
    assert extract_conditional_release_profile(record) is None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

def test_post_route_stores_valid_record(isolated_store):
    record = _make_record("post")
    resp = svc.post_action_commitment(record)
    assert resp["status"] == "stored"
    assert resp["stored"] is True
    assert resp["action_ref"] == record["action_ref"]
    assert resp["lookup_path"].endswith(record["action_ref"].replace(":", "%3A"))


def test_post_route_idempotent_duplicate_returns_stored_false(isolated_store):
    record = _make_record("postidem")
    assert svc.post_action_commitment(record)["stored"] is True
    assert svc.post_action_commitment(copy.deepcopy(record))["stored"] is False


def test_post_route_conflict_returns_409(isolated_store):
    record = _make_record("postconflict")
    svc.post_action_commitment(record)
    other = copy.deepcopy(record)
    other["source"] = "different"
    with pytest.raises(HTTPException) as exc:
        svc.post_action_commitment(other)
    assert exc.value.status_code == 409


def test_post_route_invalid_record_returns_422(isolated_store):
    record = _make_record("postbad")
    record["action_ref"] = "sha256:" + "0" * 64
    with pytest.raises(HTTPException) as exc:
        svc.post_action_commitment(record)
    assert exc.value.status_code == 422


def test_get_route_returns_record_and_profile_flag(isolated_store):
    record = _make_record("getprofile", with_profile=True)
    svc.post_action_commitment(record)

    resp = svc.get_action_commitment(record["action_ref"])
    assert resp["action_ref"] == record["action_ref"]
    assert resp["record"] == record
    assert resp["has_conditional_release_profile"] is True
    assert resp["lookup_path"].endswith(record["action_ref"].replace(":", "%3A"))


def test_get_route_no_profile_flag_false(isolated_store):
    record = _make_record("getnoprofile")
    svc.post_action_commitment(record)
    resp = svc.get_action_commitment(record["action_ref"])
    assert resp["has_conditional_release_profile"] is False


def test_get_route_missing_returns_404(isolated_store):
    with pytest.raises(HTTPException) as exc:
        svc.get_action_commitment("sha256:" + "0" * 64)
    assert exc.value.status_code == 404


def test_get_route_invalid_action_ref_returns_422(isolated_store):
    for bad in ("not-a-digest", "sha256:xyz", "sha256:" + "0" * 63, "md5:" + "0" * 64):
        with pytest.raises(HTTPException) as exc:
            svc.get_action_commitment(bad)
        assert exc.value.status_code == 422
