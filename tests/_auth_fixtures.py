"""Shared test scaffolding for the Phase B/C producer-authentication tests.

Everything here operates on tmp_path-scoped files and in-process Ed25519
keys generated per test run. No production registry, credential, or ledger
is ever touched.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from authenticated_submission import SIGNED_FIELDS, sign_envelope
from producer_registry import SCHEMA_VERSION as REGISTRY_SCHEMA_VERSION
from producer_registry import load_pinned_registry

ENVELOPE_SCHEMA_VERSION = "ds.authenticated_submission/v1"


def make_keypair():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    raw_public = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return private_key, raw_public.hex()


def write_registry(tmp_path: Path, producers: list[dict], filename: str = "producer_registry.json"):
    doc = {"schema_version": REGISTRY_SCHEMA_VERSION, "producers": producers}
    raw = json.dumps(doc, sort_keys=True).encode("utf-8")
    path = tmp_path / filename
    path.write_bytes(raw)
    sha256 = hashlib.sha256(raw).hexdigest()
    return path, sha256


def load_test_registry(path: Path, sha256: str):
    return load_pinned_registry(path, sha256)


def producer_entry(
    producer_id: str = "producer:hermes-monitor",
    *,
    status: str = "active",
    public_key_hex: str,
    allowed_routes=("/v1/attest/authenticated",),
    allowed_submission_types=("attest_claim",),
    allowed_subject_namespaces=("agent:*",),
    valid_from: str | None = None,
    valid_until: str | None = None,
    revoked_at: str | None = None,
) -> dict:
    return {
        "producer_id": producer_id,
        "display_name": "Test Producer",
        "credential_type": "ed25519_signed_assertion",
        "public_key": public_key_hex,
        "allowed_submission_types": list(allowed_submission_types),
        "allowed_subject_namespaces": list(allowed_subject_namespaces),
        "allowed_routes": list(allowed_routes),
        "status": status,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "authority_source": "test-fixture",
        "revoked_at": revoked_at,
        "supersedes": None,
        "notes": None,
    }


def build_signed_envelope(
    private_key: Ed25519PrivateKey,
    *,
    producer_id: str = "producer:hermes-monitor",
    subject_agent_id: str = "agent:morpheus",
    submission_type: str = "attest_claim",
    route_id: str = "/v1/attest/authenticated",
    registry_identity: str,
    timestamp: str | None = None,
    nonce: str = "nonce-0001",
    verdict: str = "PASS",
    reason_code: str = "ok",
    authority_scope: str = "attest:write",
    submission_id: str = "sub-0001",
    request_id: str = "req-0001",
    canonical_payload_digest: str = "a" * 64,
    source_evidence_digest: str = "b" * 64,
    schema_version: str = ENVELOPE_SCHEMA_VERSION,
) -> dict:
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    envelope = {
        "schema_version": schema_version,
        "submission_id": submission_id,
        "producer_id": producer_id,
        "subject_agent_id": subject_agent_id,
        "submission_type": submission_type,
        "route_id": route_id,
        "request_id": request_id,
        "canonical_payload_digest": canonical_payload_digest,
        "source_evidence_digest": source_evidence_digest,
        "verdict": verdict,
        "reason_code": reason_code,
        "timestamp": ts,
        "nonce": nonce,
        "producer_registry_identity": registry_identity,
        "authority_scope": authority_scope,
    }
    assert set(SIGNED_FIELDS) <= set(envelope.keys())
    envelope["producer_signature"] = sign_envelope(private_key, envelope)
    return envelope
