from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

import authenticated_submission as auth  # noqa: E402
import producer_registry as reg  # noqa: E402
from tests._auth_fixtures import (  # noqa: E402
    build_signed_envelope,
    make_keypair,
    producer_entry,
    write_registry,
)


def _setup(tmp_path, **entry_kwargs):
    private_key, pub = make_keypair()
    path, sha256 = write_registry(tmp_path, [producer_entry(public_key_hex=pub, **entry_kwargs)])
    registry = reg.load_pinned_registry(path, sha256)
    return private_key, registry


def test_valid_envelope_accepted(tmp_path):
    private_key, registry = _setup(tmp_path)
    envelope = build_signed_envelope(private_key, registry_identity=registry.sha256)
    result = auth.verify_authenticated_submission(
        envelope, registry=registry, nonce_store=auth.NonceStore()
    )
    assert result.submission_provenance == "authenticated_claim"
    assert result.producer_id == "producer:hermes-monitor"


def test_result_never_claims_independently_verified(tmp_path):
    private_key, registry = _setup(tmp_path)
    envelope = build_signed_envelope(private_key, registry_identity=registry.sha256)
    result = auth.verify_authenticated_submission(
        envelope, registry=registry, nonce_store=auth.NonceStore()
    )
    assert result.submission_provenance != "independently_verified"


def test_unknown_producer_rejected(tmp_path):
    private_key, registry = _setup(tmp_path)
    envelope = build_signed_envelope(
        private_key, producer_id="producer:not-registered", registry_identity=registry.sha256
    )
    with pytest.raises(reg.UnknownProducerError):
        auth.verify_authenticated_submission(envelope, registry=registry, nonce_store=auth.NonceStore())


def test_wrong_key_signature_rejected(tmp_path):
    _correct_key, registry = _setup(tmp_path)
    wrong_key, _wrong_pub = make_keypair()
    envelope = build_signed_envelope(wrong_key, registry_identity=registry.sha256)
    with pytest.raises(auth.SignatureVerificationError):
        auth.verify_authenticated_submission(envelope, registry=registry, nonce_store=auth.NonceStore())


def test_malformed_signature_rejected(tmp_path):
    private_key, registry = _setup(tmp_path)
    envelope = build_signed_envelope(private_key, registry_identity=registry.sha256)
    envelope["producer_signature"] = "zz" + envelope["producer_signature"][2:]
    with pytest.raises(auth.SignatureVerificationError):
        auth.verify_authenticated_submission(envelope, registry=registry, nonce_store=auth.NonceStore())


@pytest.mark.parametrize(
    "field,new_value",
    [
        ("subject_agent_id", "agent:someone-else"),
        ("producer_id", "producer:someone-else"),
        ("canonical_payload_digest", "c" * 64),
        ("source_evidence_digest", "d" * 64),
        ("verdict", "FAIL"),
        ("reason_code", "tampered"),
        ("authority_scope", "attest:admin"),
        ("submission_type", "other_type"),
        ("route_id", "/v1/other"),
    ],
)
def test_tampered_signed_field_invalidates_signature(tmp_path, field, new_value):
    private_key, registry = _setup(tmp_path)
    envelope = build_signed_envelope(private_key, registry_identity=registry.sha256)
    envelope[field] = new_value
    with pytest.raises((auth.SignatureVerificationError, reg.ProducerOutOfScopeError, reg.UnknownProducerError)):
        auth.verify_authenticated_submission(envelope, registry=registry, nonce_store=auth.NonceStore())


def test_tampered_timestamp_invalidates_signature(tmp_path):
    private_key, registry = _setup(tmp_path)
    envelope = build_signed_envelope(private_key, registry_identity=registry.sha256)
    envelope["timestamp"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    with pytest.raises(auth.SignatureVerificationError):
        auth.verify_authenticated_submission(envelope, registry=registry, nonce_store=auth.NonceStore())


def test_registry_identity_mismatch_rejected_before_signature_check(tmp_path):
    private_key, registry = _setup(tmp_path)
    envelope = build_signed_envelope(private_key, registry_identity="0" * 64)
    with pytest.raises(auth.RegistryIdentityMismatchError):
        auth.verify_authenticated_submission(envelope, registry=registry, nonce_store=auth.NonceStore())


def test_unsigned_fallback_rejected_missing_signature_field(tmp_path):
    private_key, registry = _setup(tmp_path)
    envelope = build_signed_envelope(private_key, registry_identity=registry.sha256)
    del envelope["producer_signature"]
    with pytest.raises(auth.EnvelopeSchemaError):
        auth.verify_authenticated_submission(envelope, registry=registry, nonce_store=auth.NonceStore())


def test_unsupported_schema_version_rejected(tmp_path):
    private_key, registry = _setup(tmp_path)
    envelope = build_signed_envelope(private_key, registry_identity=registry.sha256, schema_version="ds.authenticated_submission/v2")
    with pytest.raises(auth.EnvelopeSchemaError):
        auth.verify_authenticated_submission(envelope, registry=registry, nonce_store=auth.NonceStore())


def test_expired_timestamp_window_rejected(tmp_path):
    private_key, registry = _setup(tmp_path)
    old_ts = (datetime.now(timezone.utc) - timedelta(seconds=10_000)).isoformat()
    envelope = build_signed_envelope(private_key, registry_identity=registry.sha256, timestamp=old_ts)
    with pytest.raises(auth.TimestampWindowError):
        auth.verify_authenticated_submission(envelope, registry=registry, nonce_store=auth.NonceStore())


def test_future_timestamp_window_rejected(tmp_path):
    private_key, registry = _setup(tmp_path)
    future_ts = (datetime.now(timezone.utc) + timedelta(seconds=10_000)).isoformat()
    envelope = build_signed_envelope(private_key, registry_identity=registry.sha256, timestamp=future_ts)
    with pytest.raises(auth.TimestampWindowError):
        auth.verify_authenticated_submission(envelope, registry=registry, nonce_store=auth.NonceStore())


def test_replayed_nonce_rejected(tmp_path):
    private_key, registry = _setup(tmp_path)
    nonce_store = auth.NonceStore()
    envelope = build_signed_envelope(private_key, registry_identity=registry.sha256, nonce="dupe-nonce")
    auth.verify_authenticated_submission(envelope, registry=registry, nonce_store=nonce_store)
    envelope2 = build_signed_envelope(
        private_key, registry_identity=registry.sha256, nonce="dupe-nonce", submission_id="sub-0002"
    )
    with pytest.raises(auth.ReplayedNonceError):
        auth.verify_authenticated_submission(envelope2, registry=registry, nonce_store=nonce_store)


def test_duplicate_submission_same_nonce_rejected_even_if_identical(tmp_path):
    private_key, registry = _setup(tmp_path)
    nonce_store = auth.NonceStore()
    envelope = build_signed_envelope(private_key, registry_identity=registry.sha256)
    auth.verify_authenticated_submission(envelope, registry=registry, nonce_store=nonce_store)
    with pytest.raises(auth.ReplayedNonceError):
        auth.verify_authenticated_submission(dict(envelope), registry=registry, nonce_store=nonce_store)


def test_different_nonce_same_producer_accepted(tmp_path):
    private_key, registry = _setup(tmp_path)
    nonce_store = auth.NonceStore()
    envelope1 = build_signed_envelope(private_key, registry_identity=registry.sha256, nonce="n1", submission_id="s1")
    envelope2 = build_signed_envelope(private_key, registry_identity=registry.sha256, nonce="n2", submission_id="s2")
    auth.verify_authenticated_submission(envelope1, registry=registry, nonce_store=nonce_store)
    auth.verify_authenticated_submission(envelope2, registry=registry, nonce_store=nonce_store)


def test_out_of_scope_route_rejected_before_signature_meaning_matters(tmp_path):
    private_key, registry = _setup(tmp_path, allowed_routes=("/v1/other",))
    envelope = build_signed_envelope(private_key, registry_identity=registry.sha256)
    with pytest.raises(reg.ProducerOutOfScopeError):
        auth.verify_authenticated_submission(envelope, registry=registry, nonce_store=auth.NonceStore())


def test_confidence_field_is_not_part_of_signed_fields():
    assert "confidence" not in auth.SIGNED_FIELDS


def test_malformed_timestamp_rejected_as_named_error_not_uncaught_valueerror(tmp_path):
    # Signed by the producer with a garbage timestamp value (the API layer's
    # Pydantic model only guarantees `str`, not a parseable ISO value, so a
    # malicious or buggy producer can sign whatever string it likes here).
    # The signature itself is therefore valid; verification must still
    # reject this with a named AuthenticatedSubmissionError, not an
    # uncaught ValueError, when it gets to parsing the timestamp.
    private_key, registry = _setup(tmp_path)
    envelope = build_signed_envelope(private_key, registry_identity=registry.sha256, timestamp="not-a-timestamp")
    with pytest.raises(auth.TimestampWindowError):
        auth.verify_authenticated_submission(envelope, registry=registry, nonce_store=auth.NonceStore())
