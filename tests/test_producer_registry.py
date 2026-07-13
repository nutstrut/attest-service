from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

import producer_registry as reg  # noqa: E402
from tests._auth_fixtures import make_keypair, producer_entry, write_registry  # noqa: E402


def test_unknown_producer_rejected(tmp_path):
    _, pub = make_keypair()
    path, sha256 = write_registry(tmp_path, [producer_entry(public_key_hex=pub)])
    registry = reg.load_pinned_registry(path, sha256)
    with pytest.raises(reg.UnknownProducerError):
        reg.resolve_and_authorize_producer(
            registry,
            producer_id="producer:not-registered",
            route_id="/v1/attest/authenticated",
            submission_type="attest_claim",
            subject_agent_id="agent:morpheus",
        )


@pytest.mark.parametrize("status", ["reserved", "suspended", "retired", "revoked"])
def test_non_active_status_rejected(tmp_path, status):
    _, pub = make_keypair()
    path, sha256 = write_registry(tmp_path, [producer_entry(public_key_hex=pub, status=status)])
    registry = reg.load_pinned_registry(path, sha256)
    with pytest.raises(reg.ProducerLifecycleError):
        reg.resolve_and_authorize_producer(
            registry,
            producer_id="producer:hermes-monitor",
            route_id="/v1/attest/authenticated",
            submission_type="attest_claim",
            subject_agent_id="agent:morpheus",
        )


def test_missing_status_field_rejected_at_load(tmp_path):
    _, pub = make_keypair()
    entry = producer_entry(public_key_hex=pub)
    del entry["status"]
    path, sha256 = write_registry(tmp_path, [entry])
    with pytest.raises(reg.MalformedRegistryError):
        reg.load_pinned_registry(path, sha256)


def test_unsupported_status_value_rejected_at_load(tmp_path):
    _, pub = make_keypair()
    entry = producer_entry(public_key_hex=pub, status="trusted")  # not a lifecycle state
    path, sha256 = write_registry(tmp_path, [entry])
    with pytest.raises(reg.MalformedRegistryError):
        reg.load_pinned_registry(path, sha256)


def test_expired_producer_rejected(tmp_path):
    _, pub = make_keypair()
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    path, sha256 = write_registry(tmp_path, [producer_entry(public_key_hex=pub, valid_until=past)])
    registry = reg.load_pinned_registry(path, sha256)
    with pytest.raises(reg.ProducerExpiredError):
        reg.resolve_and_authorize_producer(
            registry,
            producer_id="producer:hermes-monitor",
            route_id="/v1/attest/authenticated",
            submission_type="attest_claim",
            subject_agent_id="agent:morpheus",
        )


def test_not_yet_valid_producer_rejected(tmp_path):
    _, pub = make_keypair()
    future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    path, sha256 = write_registry(tmp_path, [producer_entry(public_key_hex=pub, valid_from=future)])
    registry = reg.load_pinned_registry(path, sha256)
    with pytest.raises(reg.ProducerNotYetValidError):
        reg.resolve_and_authorize_producer(
            registry,
            producer_id="producer:hermes-monitor",
            route_id="/v1/attest/authenticated",
            submission_type="attest_claim",
            subject_agent_id="agent:morpheus",
        )


def test_out_of_scope_route_rejected(tmp_path):
    _, pub = make_keypair()
    path, sha256 = write_registry(
        tmp_path, [producer_entry(public_key_hex=pub, allowed_routes=("/v1/other",))]
    )
    registry = reg.load_pinned_registry(path, sha256)
    with pytest.raises(reg.ProducerOutOfScopeError):
        reg.resolve_and_authorize_producer(
            registry,
            producer_id="producer:hermes-monitor",
            route_id="/v1/attest/authenticated",
            submission_type="attest_claim",
            subject_agent_id="agent:morpheus",
        )


def test_out_of_scope_submission_type_rejected(tmp_path):
    _, pub = make_keypair()
    path, sha256 = write_registry(
        tmp_path, [producer_entry(public_key_hex=pub, allowed_submission_types=("other_type",))]
    )
    registry = reg.load_pinned_registry(path, sha256)
    with pytest.raises(reg.ProducerOutOfScopeError):
        reg.resolve_and_authorize_producer(
            registry,
            producer_id="producer:hermes-monitor",
            route_id="/v1/attest/authenticated",
            submission_type="attest_claim",
            subject_agent_id="agent:morpheus",
        )


def test_out_of_scope_subject_namespace_rejected(tmp_path):
    _, pub = make_keypair()
    path, sha256 = write_registry(
        tmp_path, [producer_entry(public_key_hex=pub, allowed_subject_namespaces=("agent:hermes",))]
    )
    registry = reg.load_pinned_registry(path, sha256)
    with pytest.raises(reg.ProducerOutOfScopeError):
        reg.resolve_and_authorize_producer(
            registry,
            producer_id="producer:hermes-monitor",
            route_id="/v1/attest/authenticated",
            submission_type="attest_claim",
            subject_agent_id="agent:morpheus",
        )


def test_in_scope_active_producer_accepted(tmp_path):
    _, pub = make_keypair()
    path, sha256 = write_registry(tmp_path, [producer_entry(public_key_hex=pub)])
    registry = reg.load_pinned_registry(path, sha256)
    entry = reg.resolve_and_authorize_producer(
        registry,
        producer_id="producer:hermes-monitor",
        route_id="/v1/attest/authenticated",
        submission_type="attest_claim",
        subject_agent_id="agent:morpheus",
    )
    assert entry.producer_id == "producer:hermes-monitor"


def test_registry_hash_mismatch_rejected(tmp_path):
    _, pub = make_keypair()
    path, _correct_sha256 = write_registry(tmp_path, [producer_entry(public_key_hex=pub)])
    with pytest.raises(reg.RegistryHashMismatchError):
        reg.load_pinned_registry(path, "0" * 64)


def test_missing_registry_file_rejected(tmp_path):
    with pytest.raises(reg.MissingRegistryError):
        reg.load_pinned_registry(tmp_path / "does-not-exist.json", "0" * 64)


def test_shadow_relative_registry_path_rejected(tmp_path):
    with pytest.raises(reg.MissingRegistryError):
        reg.load_pinned_registry(Path("relative/producer_registry.json"), "0" * 64)


def test_duplicate_producer_id_rejected(tmp_path):
    _, pub = make_keypair()
    path, sha256 = write_registry(
        tmp_path,
        [producer_entry(public_key_hex=pub), producer_entry(public_key_hex=pub)],
    )
    with pytest.raises(reg.MalformedRegistryError):
        reg.load_pinned_registry(path, sha256)


def test_namespace_wildcard_does_not_match_unrelated_suffix(tmp_path):
    """Regression: agent:acme* must not match agent:acmeXcorp (a bare
    prefix match, without a boundary check, would let a subject with an
    incidentally-matching string prefix slip through the scope grant)."""
    _, pub = make_keypair()
    path, sha256 = write_registry(
        tmp_path, [producer_entry(public_key_hex=pub, allowed_subject_namespaces=("agent:acme*",))]
    )
    registry = reg.load_pinned_registry(path, sha256)
    with pytest.raises(reg.ProducerOutOfScopeError):
        reg.resolve_and_authorize_producer(
            registry,
            producer_id="producer:hermes-monitor",
            route_id="/v1/attest/authenticated",
            submission_type="attest_claim",
            subject_agent_id="agent:acmeXcorp",
        )
    # But the exact prefix and a colon-delimited child both remain in scope.
    for ok_subject in ("agent:acme", "agent:acme:sub"):
        entry = reg.resolve_and_authorize_producer(
            registry,
            producer_id="producer:hermes-monitor",
            route_id="/v1/attest/authenticated",
            submission_type="attest_claim",
            subject_agent_id=ok_subject,
        )
        assert entry.producer_id == "producer:hermes-monitor"


def test_retired_producer_still_resolvable_for_historical_verification(tmp_path):
    _, pub = make_keypair()
    path, sha256 = write_registry(tmp_path, [producer_entry(public_key_hex=pub, status="retired")])
    registry = reg.load_pinned_registry(path, sha256)
    entry = reg.historical_verification_entry(registry, "producer:hermes-monitor")
    assert entry is not None
    assert entry.status == "retired"
    # But historical resolvability must never imply new-submission authority.
    with pytest.raises(reg.ProducerLifecycleError):
        reg.resolve_and_authorize_producer(
            registry,
            producer_id="producer:hermes-monitor",
            route_id="/v1/attest/authenticated",
            submission_type="attest_claim",
            subject_agent_id="agent:morpheus",
        )
