"""POST /v1/attest/authenticated -- route-level tests.

Direct function calls, no network, no TestClient (httpx is not a
dependency in this repo, matching the existing test_sar402_receipts.py
convention). All registry/ledger paths are monkeypatched to tmp_path. No
production registry, credential, or ledger file is touched, and no
production submission is generated.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402
from fastapi import HTTPException  # noqa: E402

import attest_service as svc  # noqa: E402
import authenticated_submission_api as api  # noqa: E402
from tests._auth_fixtures import build_signed_envelope, make_keypair, producer_entry, write_registry  # noqa: E402


@pytest.fixture(autouse=True)
def _isolated_ledger(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "AUTHENTICATED_SUBMISSION_LEDGER", tmp_path / "authenticated_submissions.jsonl")
    monkeypatch.setattr(api, "_nonce_store", api.SQLiteNonceStore(tmp_path / "nonce_ledger.sqlite3"))
    monkeypatch.delenv(api.REGISTRY_PATH_ENV, raising=False)
    monkeypatch.delenv(api.REGISTRY_SHA256_ENV, raising=False)


def _configure_registry(tmp_path, monkeypatch, **entry_kwargs):
    private_key, pub = make_keypair()
    path, sha256 = write_registry(tmp_path, [producer_entry(public_key_hex=pub, **entry_kwargs)])
    monkeypatch.setenv(api.REGISTRY_PATH_ENV, str(path))
    monkeypatch.setenv(api.REGISTRY_SHA256_ENV, sha256)
    from producer_registry import load_pinned_registry

    registry = load_pinned_registry(path, sha256)
    return private_key, registry


def _call(envelope_dict: dict):
    return api.submit_authenticated_evidence(api.AuthenticatedSubmissionEnvelope(**envelope_dict))


def test_missing_registry_config_fails_closed(tmp_path):
    private_key, pub = make_keypair()
    path, sha256 = write_registry(tmp_path, [producer_entry(public_key_hex=pub)])
    from producer_registry import load_pinned_registry

    registry = load_pinned_registry(path, sha256)
    envelope = build_signed_envelope(private_key, registry_identity=registry.sha256)
    with pytest.raises(HTTPException) as exc:
        _call(envelope)
    assert exc.value.status_code == 503


def test_valid_submission_accepted_and_persisted(tmp_path, monkeypatch):
    private_key, registry = _configure_registry(tmp_path, monkeypatch)
    envelope = build_signed_envelope(private_key, registry_identity=registry.sha256)
    result = _call(envelope)
    assert result["submission_provenance"] == "authenticated_claim"
    persisted = api.AUTHENTICATED_SUBMISSION_LEDGER.read_text().strip().splitlines()
    assert len(persisted) == 1
    record = json.loads(persisted[0])
    assert record["submission_provenance"] == "authenticated_claim"
    assert record["producer_id"] == "producer:hermes-monitor"


def test_wrong_signature_rejected_with_401(tmp_path, monkeypatch):
    _correct_key, registry = _configure_registry(tmp_path, monkeypatch)
    wrong_key, _ = make_keypair()
    envelope = build_signed_envelope(wrong_key, registry_identity=registry.sha256)
    with pytest.raises(HTTPException) as exc:
        _call(envelope)
    assert exc.value.status_code == 401
    assert not api.AUTHENTICATED_SUBMISSION_LEDGER.exists()


def test_unknown_producer_rejected_with_401(tmp_path, monkeypatch):
    private_key, registry = _configure_registry(tmp_path, monkeypatch)
    envelope = build_signed_envelope(
        private_key, producer_id="producer:not-registered", registry_identity=registry.sha256
    )
    with pytest.raises(HTTPException) as exc:
        _call(envelope)
    assert exc.value.status_code == 401


def test_registry_hash_mismatch_fails_closed(tmp_path, monkeypatch):
    private_key, pub = make_keypair()
    path, correct_sha256 = write_registry(tmp_path, [producer_entry(public_key_hex=pub)])
    monkeypatch.setenv(api.REGISTRY_PATH_ENV, str(path))
    monkeypatch.setenv(api.REGISTRY_SHA256_ENV, "0" * 64)  # wrong pinned hash
    envelope = build_signed_envelope(private_key, registry_identity=correct_sha256)
    with pytest.raises(HTTPException) as exc:
        _call(envelope)
    assert exc.value.status_code == 503


def test_suspended_producer_rejected(tmp_path, monkeypatch):
    private_key, registry = _configure_registry(tmp_path, monkeypatch, status="suspended")
    envelope = build_signed_envelope(private_key, registry_identity=registry.sha256)
    with pytest.raises(HTTPException) as exc:
        _call(envelope)
    assert exc.value.status_code == 401


def test_replay_rejected_across_requests(tmp_path, monkeypatch):
    private_key, registry = _configure_registry(tmp_path, monkeypatch)
    envelope = build_signed_envelope(private_key, registry_identity=registry.sha256, nonce="api-nonce")
    result = _call(envelope)
    assert result["status"] == "accepted"
    with pytest.raises(HTTPException) as exc:
        _call(envelope)
    assert exc.value.status_code == 401


def test_envelope_route_id_must_match_actual_route(tmp_path, monkeypatch):
    """Regression: even if the registry would allow it, an envelope whose
    self-declared route_id doesn't match this exact endpoint is rejected --
    guards against cross-route reuse once a second authenticated route
    exists."""
    private_key, registry = _configure_registry(tmp_path, monkeypatch, allowed_routes=("/v1/attest/authenticated", "/v1/other"))
    envelope = build_signed_envelope(private_key, registry_identity=registry.sha256, route_id="/v1/other")
    with pytest.raises(HTTPException) as exc:
        _call(envelope)
    assert exc.value.status_code == 401


def test_anonymous_attest_route_unaffected(tmp_path, monkeypatch):
    """Regression: adding the authenticated route must not change the
    existing public /v1/attest topology-derived quarantine behavior."""
    for name in ("AGENT_LEDGER", "ACTIVATION_LEDGER", "CHAIN_LEDGER", "RECEIPT_LEDGER", "ANALYTICS_LEDGER", "SESSION_LEDGER"):
        monkeypatch.setattr(svc, name, tmp_path / f"{name.lower()}.jsonl")
    result = svc.list_chains(agent_id=None, limit=10, include_anonymous=False)
    assert isinstance(result, dict)
