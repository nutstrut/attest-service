"""Approved-producer registry (Phase B).

Governs WHO may submit an authenticated evidence envelope and WHAT they are
scoped to submit. Deliberately separate from `attest_service.py`'s existing
`classify_submission_provenance`, which derives `trusted_internal` from
network topology (header absence) -- that mechanism is not producer
identity and this module never consults it.

Lifecycle discipline mirrors the M22/M23 signer-registry precedent
(settlement-witness) and the D4 registry-state-machine doctrine
(`tools/ds_registry_state_machine.py` in morpheus): facts-only lifecycle
statuses, an explicit pinned registry identity with no shadow-copy fallback,
and deny-by-default resolution for anything not exactly matched.

Approved per morpheus/state/DECISIONS.md, "Producer-authentication mechanism
and attribution-binding construction" (2026-07-13). Not deployed: no
production registry path or credential is wired to a live service by this
module.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "morpheus.producer_registry/v1"

LIFECYCLE_STATES = frozenset({"reserved", "active", "suspended", "retired", "revoked"})

# Only `active` producers are ever accepted for new submissions. The other
# four states are facts a verifier must be able to name (audit, historical
# verification, deliberate lockout) -- none of them silently fall through to
# acceptance.
SUBMISSION_ELIGIBLE_STATES = frozenset({"active"})

REQUIRED_ENTRY_FIELDS = (
    "producer_id",
    "display_name",
    "credential_type",
    "public_key",
    "allowed_submission_types",
    "allowed_subject_namespaces",
    "allowed_routes",
    "status",
)


class ProducerRegistryError(Exception):
    """Base class for every rejection this module can raise."""


class MissingRegistryError(ProducerRegistryError):
    pass


class RegistryHashMismatchError(ProducerRegistryError):
    pass


class MalformedRegistryError(ProducerRegistryError):
    pass


class UnknownProducerError(ProducerRegistryError):
    pass


class ProducerLifecycleError(ProducerRegistryError):
    """Raised for missing/unsupported status, suspended, retired, or revoked producers."""


class ProducerExpiredError(ProducerRegistryError):
    pass


class ProducerNotYetValidError(ProducerRegistryError):
    pass


class ProducerOutOfScopeError(ProducerRegistryError):
    """Raised for route, submission-type, or subject-namespace scope violations."""


@dataclass(frozen=True)
class ProducerRegistryEntry:
    producer_id: str
    display_name: str
    credential_type: str
    public_key: str
    allowed_submission_types: tuple[str, ...]
    allowed_subject_namespaces: tuple[str, ...]
    allowed_routes: tuple[str, ...]
    status: str
    valid_from: str | None = None
    valid_until: str | None = None
    authority_source: str | None = None
    revoked_at: str | None = None
    supersedes: str | None = None
    notes: str | None = None


@dataclass(frozen=True)
class ProducerRegistryDocument:
    schema_version: str
    producers: tuple[ProducerRegistryEntry, ...]
    sha256: str
    path: Path
    by_id: dict[str, ProducerRegistryEntry] = field(default_factory=dict)


def _parse_entry(raw: dict[str, Any]) -> ProducerRegistryEntry:
    missing = [f for f in REQUIRED_ENTRY_FIELDS if f not in raw]
    if missing:
        raise MalformedRegistryError(
            f"producer entry {raw.get('producer_id', '<unknown>')!r} missing required fields: {missing}"
        )
    status = raw["status"]
    if status not in LIFECYCLE_STATES:
        raise MalformedRegistryError(
            f"producer {raw['producer_id']!r} has unsupported status {status!r}; "
            f"must be one of {sorted(LIFECYCLE_STATES)}"
        )
    return ProducerRegistryEntry(
        producer_id=raw["producer_id"],
        display_name=raw["display_name"],
        credential_type=raw["credential_type"],
        public_key=raw["public_key"],
        allowed_submission_types=tuple(raw["allowed_submission_types"]),
        allowed_subject_namespaces=tuple(raw["allowed_subject_namespaces"]),
        allowed_routes=tuple(raw["allowed_routes"]),
        status=status,
        valid_from=raw.get("valid_from"),
        valid_until=raw.get("valid_until"),
        authority_source=raw.get("authority_source"),
        revoked_at=raw.get("revoked_at"),
        supersedes=raw.get("supersedes"),
        notes=raw.get("notes"),
    )


def load_pinned_registry(path: Path, expected_sha256: str) -> ProducerRegistryDocument:
    """Load the registry from an explicit absolute path and verify its exact
    pinned identity. There is no shadow-copy fallback and no permissive
    default: a missing file, a hash mismatch, or a malformed document all
    raise rather than degrading to an empty or partial registry."""
    if not isinstance(path, Path) or not path.is_absolute():
        raise MissingRegistryError(f"registry path must be an explicit absolute path, got {path!r}")
    if not path.exists():
        raise MissingRegistryError(f"registry file does not exist: {path}")
    raw_bytes = path.read_bytes()
    actual_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    if actual_sha256 != expected_sha256:
        raise RegistryHashMismatchError(
            f"registry at {path} has sha256 {actual_sha256}, expected {expected_sha256}"
        )
    try:
        document = json.loads(raw_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise MalformedRegistryError(f"registry at {path} is not valid JSON: {exc}") from exc
    if not isinstance(document, dict) or document.get("schema_version") != SCHEMA_VERSION:
        raise MalformedRegistryError(
            f"registry at {path} has schema_version {document.get('schema_version')!r}, "
            f"expected {SCHEMA_VERSION!r}"
        )
    raw_producers = document.get("producers")
    if not isinstance(raw_producers, list):
        raise MalformedRegistryError(f"registry at {path} has no 'producers' list")
    entries = tuple(_parse_entry(raw) for raw in raw_producers)
    ids = [e.producer_id for e in entries]
    if len(ids) != len(set(ids)):
        raise MalformedRegistryError(f"registry at {path} contains duplicate producer_id values")
    return ProducerRegistryDocument(
        schema_version=SCHEMA_VERSION,
        producers=entries,
        sha256=actual_sha256,
        path=path,
        by_id={e.producer_id: e for e in entries},
    )


def _parse_timestamp(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def resolve_and_authorize_producer(
    registry: ProducerRegistryDocument,
    *,
    producer_id: str,
    route_id: str,
    submission_type: str,
    subject_agent_id: str,
    now: datetime | None = None,
) -> ProducerRegistryEntry:
    """Deny-by-default producer resolution. Every failure mode named in the
    workstream's hard completion test raises a distinct, named exception
    before any signature check, persistence, or eligibility decision."""
    now = now or datetime.now(timezone.utc)
    entry = registry.by_id.get(producer_id)
    if entry is None:
        raise UnknownProducerError(f"producer_id {producer_id!r} is not present in the pinned registry")

    if entry.status not in SUBMISSION_ELIGIBLE_STATES:
        raise ProducerLifecycleError(
            f"producer {producer_id!r} has status {entry.status!r}; only "
            f"{sorted(SUBMISSION_ELIGIBLE_STATES)} may submit new authenticated evidence"
        )

    if entry.valid_from and now < _parse_timestamp(entry.valid_from):
        raise ProducerNotYetValidError(f"producer {producer_id!r} is not valid until {entry.valid_from}")
    if entry.valid_until and now >= _parse_timestamp(entry.valid_until):
        raise ProducerExpiredError(f"producer {producer_id!r} expired at {entry.valid_until}")

    if route_id not in entry.allowed_routes:
        raise ProducerOutOfScopeError(f"producer {producer_id!r} is not authorized for route {route_id!r}")
    if submission_type not in entry.allowed_submission_types:
        raise ProducerOutOfScopeError(
            f"producer {producer_id!r} is not authorized for submission_type {submission_type!r}"
        )
    if not _subject_in_namespace(subject_agent_id, entry.allowed_subject_namespaces):
        raise ProducerOutOfScopeError(
            f"producer {producer_id!r} is not authorized for subject {subject_agent_id!r}"
        )
    return entry


def _subject_in_namespace(subject_agent_id: str, allowed_namespaces: tuple[str, ...]) -> bool:
    """Wildcard matching is boundary-aware: `agent:acme*` matches
    `agent:acme` and `agent:acme:anything`, but not `agent:acmeXcorp` --
    a bare prefix match would let `agent:acme-evil` slip through an
    `agent:acme*` scope grant. A namespace ending in `:*` (or a prefix
    that already ends with `:`, e.g. `agent:*`) is a true open wildcard
    for everything under that namespace."""
    for ns in allowed_namespaces:
        if ns.endswith("*"):
            prefix = ns[:-1]
            if prefix.endswith(":"):
                if subject_agent_id.startswith(prefix):
                    return True
            elif subject_agent_id == prefix or subject_agent_id.startswith(prefix + ":"):
                return True
        elif subject_agent_id == ns:
            return True
    return False


def historical_verification_entry(
    registry: ProducerRegistryDocument, producer_id: str
) -> ProducerRegistryEntry | None:
    """Retired/revoked producers remain resolvable for re-verifying evidence
    they signed while active. This never authorizes a new submission --
    callers doing new-submission authorization must use
    `resolve_and_authorize_producer`, which rejects every non-`active`
    status."""
    return registry.by_id.get(producer_id)
