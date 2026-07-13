"""ds.authenticated_submission/v1 -- producer-signed submission envelope
(Phase C).

Wraps the existing, unmodified SAR v0.1 evidence object (or any referenced
source evidence) in a producer-signed envelope. Does not revise SAR v0.1 and
does not itself claim `independently_verified` -- a verified signature only
proves "this exact approved producer submitted this exact payload about this
exact subject, through this exact submission class and authority scope, at
this time" (Decision 2, morpheus/state/DECISIONS.md 2026-07-13). Deterministic
promotion to `independently_verified` is a distinct, later, disabled phase.

Approved per morpheus/state/DECISIONS.md, "Producer-authentication mechanism
and attribution-binding construction" (2026-07-13).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from producer_registry import (
    ProducerRegistryDocument,
    ProducerRegistryEntry,
    resolve_and_authorize_producer,
)

SCHEMA_VERSION = "ds.authenticated_submission/v1"

# Fields that participate in the signed digest, in the exact order the
# producer must sign and the verifier must recompute. `producer_signature`
# is deliberately excluded -- it signs everything else, never itself.
SIGNED_FIELDS = (
    "schema_version",
    "submission_id",
    "producer_id",
    "subject_agent_id",
    "submission_type",
    "route_id",
    "request_id",
    "canonical_payload_digest",
    "source_evidence_digest",
    "verdict",
    "reason_code",
    "timestamp",
    "nonce",
    "producer_registry_identity",
    "authority_scope",
)

DEFAULT_MAX_SKEW_SECONDS = 300


class AuthenticatedSubmissionError(Exception):
    """Base class for every rejection this module can raise."""


class EnvelopeSchemaError(AuthenticatedSubmissionError):
    pass


class RegistryIdentityMismatchError(AuthenticatedSubmissionError):
    pass


class SignatureVerificationError(AuthenticatedSubmissionError):
    pass


class TimestampWindowError(AuthenticatedSubmissionError):
    pass


class ReplayedNonceError(AuthenticatedSubmissionError):
    pass


@dataclass(frozen=True)
class AuthenticatedSubmissionResult:
    producer_id: str
    subject_agent_id: str
    submission_type: str
    route_id: str
    submission_id: str
    envelope_digest_hex: str
    submission_provenance: str  # always "authenticated_claim" -- never "independently_verified"


class NonceStore:
    """Pluggable replay-protection store. Keyed on (producer_id, nonce);
    entries are pruned once they age out of the timestamp window so the
    store does not grow unbounded. Default implementation is in-memory;
    a persisted variant is required before any live deployment so a
    process restart cannot reopen the replay window (deployment-readiness
    concern, not resolved by this in-memory default)."""

    def __init__(self) -> None:
        self._seen: dict[tuple[str, str], datetime] = {}

    def check_and_record(self, producer_id: str, nonce: str, timestamp: datetime, max_skew: timedelta) -> None:
        key = (producer_id, nonce)
        self._prune(timestamp, max_skew)
        if key in self._seen:
            raise ReplayedNonceError(f"nonce {nonce!r} already used by producer {producer_id!r}")
        self._seen[key] = timestamp

    def _prune(self, now: datetime, max_skew: timedelta) -> None:
        cutoff = now - (max_skew * 4)
        stale = [k for k, ts in self._seen.items() if ts < cutoff]
        for k in stale:
            del self._seen[k]


def canonical_json_bytes(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def envelope_digest(envelope: dict[str, Any]) -> bytes:
    """SHA-256 over the canonicalized signed fields, in `SIGNED_FIELDS`
    order/shape only -- unknown extra keys and `producer_signature` never
    participate, so neither can be smuggled in undetected or used to alter
    the signed meaning."""
    missing = [f for f in SIGNED_FIELDS if f not in envelope]
    if missing:
        raise EnvelopeSchemaError(f"envelope missing required signed fields: {missing}")
    signed_view = {f: envelope[f] for f in SIGNED_FIELDS}
    return hashlib.sha256(canonical_json_bytes(signed_view)).digest()


def sign_envelope(private_key: Ed25519PrivateKey, envelope: dict[str, Any]) -> str:
    """Producer-side helper: returns the hex signature for `envelope`
    (which must already contain every field in `SIGNED_FIELDS`)."""
    digest = envelope_digest(envelope)
    return private_key.sign(digest).hex()


def _parse_timestamp(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def verify_authenticated_submission(
    envelope: dict[str, Any],
    *,
    registry: ProducerRegistryDocument,
    nonce_store: NonceStore,
    now: datetime | None = None,
    max_skew_seconds: int = DEFAULT_MAX_SKEW_SECONDS,
) -> AuthenticatedSubmissionResult:
    """Full verification pipeline for one envelope. Raises a specific,
    named exception on the first failing check; never partially accepts.
    Order: schema -> registry identity -> producer resolution/lifecycle/
    scope -> signature -> timestamp window -> nonce replay. Signature
    verification happens after scope resolution because the producer's
    public key itself comes from the pinned registry entry; an unknown or
    out-of-scope producer is rejected before its signature is ever checked,
    so no attacker-controlled key material is trusted for verification."""
    now = now or datetime.now(timezone.utc)
    max_skew = timedelta(seconds=max_skew_seconds)

    if envelope.get("schema_version") != SCHEMA_VERSION:
        raise EnvelopeSchemaError(
            f"unsupported schema_version {envelope.get('schema_version')!r}, expected {SCHEMA_VERSION!r}"
        )
    missing = [f for f in SIGNED_FIELDS if f not in envelope] + (
        ["producer_signature"] if "producer_signature" not in envelope else []
    )
    if missing:
        raise EnvelopeSchemaError(f"envelope missing required fields: {missing}")

    if envelope["producer_registry_identity"] != registry.sha256:
        raise RegistryIdentityMismatchError(
            f"envelope declares registry identity {envelope['producer_registry_identity']!r}, "
            f"verifier has pinned {registry.sha256!r}"
        )

    entry: ProducerRegistryEntry = resolve_and_authorize_producer(
        registry,
        producer_id=envelope["producer_id"],
        route_id=envelope["route_id"],
        submission_type=envelope["submission_type"],
        subject_agent_id=envelope["subject_agent_id"],
        now=now,
    )

    digest = envelope_digest(envelope)
    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(entry.public_key))
        public_key.verify(bytes.fromhex(envelope["producer_signature"]), digest)
    except (InvalidSignature, ValueError) as exc:
        raise SignatureVerificationError(
            f"signature verification failed for producer {entry.producer_id!r}"
        ) from exc

    try:
        submitted_at = _parse_timestamp(envelope["timestamp"])
    except ValueError as exc:
        raise TimestampWindowError(f"timestamp {envelope['timestamp']!r} is not a valid ISO 8601 value") from exc
    if submitted_at > now + max_skew:
        raise TimestampWindowError(f"timestamp {envelope['timestamp']} is too far in the future")
    if submitted_at < now - max_skew:
        raise TimestampWindowError(f"timestamp {envelope['timestamp']} is outside the acceptance window")

    nonce_store.check_and_record(entry.producer_id, envelope["nonce"], submitted_at, max_skew)

    return AuthenticatedSubmissionResult(
        producer_id=entry.producer_id,
        subject_agent_id=envelope["subject_agent_id"],
        submission_type=envelope["submission_type"],
        route_id=envelope["route_id"],
        submission_id=envelope["submission_id"],
        envelope_digest_hex=digest.hex(),
        submission_provenance="authenticated_claim",
    )
