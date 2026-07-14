"""POST /v1/attest/authenticated -- the one ingestion route enforcing the
Phase B/C producer-authentication pipeline end to end.

Additive only: does not modify any existing route, model, or ledger.
Existing public/anonymous `/v1/attest`-family routes are untouched and
remain governed solely by EXEC-018 quarantine (topology-derived provenance).
`trusted_internal` is not read, written, or referenced here.

Every other existing ingestion route remains, in this workstream's own
vocabulary, "explicitly untrusted" for authenticated-producer purposes until
a later, separately authorized migration cuts it over to this pipeline --
consistent with the per-route/per-executor cutover discipline established
for M24 (PR1: "per-executor cutover, not a single global claim").
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from authenticated_submission import (
    AuthenticatedSubmissionError,
    NonceStoreUnavailableError,
    SQLiteNonceStore,
    verify_authenticated_submission,
)
from producer_registry import ProducerRegistryError, load_pinned_registry

# verify_authenticated_submission raises either an AuthenticatedSubmissionError
# (envelope/signature/timestamp/nonce problems, including a ledger that
# cannot commit -- NonceStoreUnavailableError is itself an
# AuthenticatedSubmissionError subclass so an unavailable replay ledger
# fails closed here the same as any other rejection) or a
# ProducerRegistryError (unknown/lifecycle/scope problems, surfaced via
# resolve_and_authorize_producer) -- both are caller/producer-side
# rejections, mapped to 401 the same way.
_REJECTION_ERRORS = (AuthenticatedSubmissionError, ProducerRegistryError)

router = APIRouter()

BASE_DIR = Path(__file__).resolve().parent
AUTHENTICATED_SUBMISSION_LEDGER = BASE_DIR / "attest_authenticated_submissions_master.jsonl"

REGISTRY_PATH_ENV = "PRODUCER_REGISTRY_PATH"
REGISTRY_SHA256_ENV = "PRODUCER_REGISTRY_SHA256"

# Durable, restart-surviving replay ledger (Phase C follow-up: resolves
# deployment-readiness Blocking Finding 2, "replay protection does not
# survive a process restart"). Path follows the same convention as this
# service's other durable state (the *_master.jsonl files alongside it) --
# a single file, directly under BASE_DIR, not under any tmp/ephemeral
# location. Overridable via env var for tests/deployment flexibility, but
# defaults to a real on-disk path so the module is never accidentally
# imported with an in-memory-only store in production.
NONCE_LEDGER_PATH_ENV = "AUTHENTICATED_SUBMISSION_NONCE_LEDGER_PATH"
_default_nonce_ledger_path = BASE_DIR / "attest_authenticated_nonce_ledger.sqlite3"

# Lazily constructed (not at import time): importing this module must never
# touch disk under BASE_DIR, which is the production data directory --
# tests import this module freely and must never create a real ledger file
# there. `_get_nonce_store()` is the only production call site; tests
# monkeypatch the module-level `_nonce_store` attribute directly to a
# tmp_path-scoped store before any request is handled, which short-circuits
# the lazy construction below entirely.
_nonce_store: SQLiteNonceStore | None = None


def _get_nonce_store() -> SQLiteNonceStore:
    global _nonce_store
    if _nonce_store is None:
        path = os.environ.get(NONCE_LEDGER_PATH_ENV, str(_default_nonce_ledger_path))
        _nonce_store = SQLiteNonceStore(path)
    return _nonce_store


class AuthenticatedSubmissionEnvelope(BaseModel):
    schema_version: str
    submission_id: str
    producer_id: str
    subject_agent_id: str
    submission_type: str
    route_id: str
    request_id: str
    canonical_payload_digest: str
    source_evidence_digest: str | None = None
    verdict: str
    reason_code: str
    timestamp: str
    nonce: str
    producer_registry_identity: str
    authority_scope: str
    producer_signature: str


def _load_registry():
    """No shadow-copy fallback, no permissive default: if the pinned
    registry path/hash are not both explicitly configured, or the file does
    not match, the route fails closed with 503 rather than accepting
    anything."""
    path_str = os.environ.get(REGISTRY_PATH_ENV)
    expected_sha256 = os.environ.get(REGISTRY_SHA256_ENV)
    if not path_str or not expected_sha256:
        raise HTTPException(
            status_code=503,
            detail=f"authenticated-submission ingestion is not configured "
            f"({REGISTRY_PATH_ENV}/{REGISTRY_SHA256_ENV} not set)",
        )
    try:
        return load_pinned_registry(Path(path_str), expected_sha256)
    except ProducerRegistryError as exc:
        raise HTTPException(status_code=503, detail=f"producer registry unavailable: {exc}") from exc


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        import json

        f.write(json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n")


ROUTE_ID = "/v1/attest/authenticated"


@router.post(ROUTE_ID)
def submit_authenticated_evidence(envelope: AuthenticatedSubmissionEnvelope) -> dict[str, Any]:
    # The envelope's route_id is self-declared by the producer and only
    # checked against the registry's allowed_routes list -- nothing ties it
    # to the request that actually arrived here. With one route today that
    # is inert, but it becomes a real cross-route-reuse risk the moment a
    # second authenticated route exists, so this endpoint refuses any
    # envelope that does not declare *this exact* route regardless of what
    # the registry would otherwise allow.
    if envelope.route_id != ROUTE_ID:
        raise HTTPException(
            status_code=401,
            detail=f"envelope route_id {envelope.route_id!r} does not match the route it was submitted to",
        )
    registry = _load_registry()
    try:
        result = verify_authenticated_submission(
            envelope.model_dump(),
            registry=registry,
            nonce_store=_get_nonce_store(),
        )
    except _REJECTION_ERRORS as exc:
        raise HTTPException(status_code=401, detail=f"{type(exc).__name__}: {exc}") from exc

    record = {
        **envelope.model_dump(),
        "submission_provenance": result.submission_provenance,
        "producer_registry_sha256": registry.sha256,
    }
    append_jsonl(AUTHENTICATED_SUBMISSION_LEDGER, record)
    return {
        "status": "accepted",
        "submission_id": result.submission_id,
        "producer_id": result.producer_id,
        "subject_agent_id": result.subject_agent_id,
        "submission_provenance": result.submission_provenance,
    }
