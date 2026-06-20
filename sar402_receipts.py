"""Public SAR-402 receipt ingestion surface: `POST /v1/sar-402/receipts`.

This is the live backend endpoint the `@defaultsettlement/sar-402` TypeScript
middleware POSTs to. An external x402 *resource server* builds a normalized
`sar_402_settlement_v0.1` receipt (it has already verified payment through its
own facilitator and performed its own delivery), and submits that evidence here.
DefaultVerifier *records* the evidence and returns a receipt id + Explorer URL.

Doctrine (non-negotiable). DefaultVerifier records evidence; it does not:
    * execute the resource-server action,
    * authorize or control delivery / resource release,
    * custody or move funds.
This endpoint therefore HARD-REJECTS any payload whose authority binding claims
the opposite (see `authority_binding_errors`). It is fail-safe from the verifier
side: bad input -> clear 4xx (and nothing is stored); internal failure -> clear
5xx; it never fabricates a success and never implies the verifier controlled
delivery.

Distinction from the existing routes:
    * `/v1/attest` is a different *internal* contract (continuity_input +
      sar_input forwarded to internal services). This endpoint is a public
      ingestion surface and does NOT require those shapes.
    * `/pay/url-summary` is an all-in-one paid demo that builds its own receipt.
      This endpoint ingests a receipt an *external* resource server already
      built.

Validation is NOT hand-rolled: the committed Morpheus SAR-402 validator
(`morpheus.sar402.validate.validate_receipt`) enforces the committed schema +
authority boundary + continuity semantics. We layer the explicit Phase-1
authority hard-rejects (and gate-mode refusal) on top, before anything is
stored. Privacy default: we accept hashes + metadata and never require raw
request/response bodies.

Auth (Phase 1, Option B): an optional API key via `SAR402_INGEST_API_KEY`,
enforced ONLY when the env var is set. Unset => early-adopter/demo open access
with strict validation. Rate limiting is a documented TODO (see the design
report); there is no per-IP limiter yet.
"""

from __future__ import annotations

import copy
import os
from typing import Any, Mapping, Optional
from urllib.parse import quote

from fastapi import APIRouter, Body, Header, HTTPException

# The committed, authoritative SAR-402 validator + schema (single source of
# truth). We validate through it; we never bypass or re-implement the schema.
from morpheus.sar402 import schema as sar_schema  # noqa: E402
from morpheus.sar402.validate import (  # noqa: E402
    AuthorityBoundaryError,
    SAR402ValidationError,
    validate_receipt,
)

router = APIRouter()

# Phase-1 supported verification modes for *this* ingestion surface. `gate` is
# intentionally unsupported: a gate receipt asserts an external controller holds
# release authority, which is outside the record-only scope of this endpoint.
SUPPORTED_MODES = ("observe", "record")
REJECTED_MODES = ("gate",)

# Public Explorer URL template. Configurable so the deployment can point at its
# real Explorer frontend; the receipt is *also* always retrievable via the live
# backend route returned as `receipt_lookup_path` (proven by tests).
DEFAULT_EXPLORER_BASE = "https://defaultverifier.com/explorer?receipt_id="

RECEIPT_TYPE = "sar_402_settlement"
# Closest existing receipt context label; this is an externally-ingested,
# real (non-demo) settlement receipt.
RECEIPT_CONTEXT = "real_task"


# ---------------------------------------------------------------------------
# Schema-derived allow-lists (no drift: read from the committed schema)
# ---------------------------------------------------------------------------

def _schema_root_keys() -> set[str]:
    return set(sar_schema.load_schema().get("properties", {}))


def _schema_authority_keys() -> set[str]:
    return set(
        sar_schema.load_schema()
        .get("$defs", {})
        .get("authority_binding", {})
        .get("properties", {})
    )


# ---------------------------------------------------------------------------
# Auth (Option B: optional API key, enforced only when configured)
# ---------------------------------------------------------------------------

def _resolve_env(env: Optional[Mapping[str, str]]) -> Mapping[str, str]:
    return os.environ if env is None else env


def check_auth(authorization: Optional[str], env: Optional[Mapping[str, str]] = None) -> None:
    """Enforce the optional ingest API key.

    No-op unless `SAR402_INGEST_API_KEY` is set. When set, requires
    `Authorization: Bearer <key>` to match. A clear 401 otherwise."""
    env = _resolve_env(env)
    expected = (env.get("SAR402_INGEST_API_KEY") or "").strip()
    if not expected:
        return  # early-adopter / demo open access
    provided = ""
    if authorization:
        token = authorization.strip()
        if token.lower().startswith("bearer "):
            token = token[len("bearer "):].strip()
        provided = token
    if provided != expected:
        raise HTTPException(
            status_code=401,
            detail="SAR-402 ingest requires a valid Authorization: Bearer <api_key>",
        )


# ---------------------------------------------------------------------------
# Authority boundary — explicit Phase-1 hard rejects
# ---------------------------------------------------------------------------

def authority_binding_errors(receipt: Mapping[str, Any]) -> list[str]:
    """Phase-1 authority hard-rejects on the SDK-shaped authority binding.

    These are doctrine, not warnings: a receipt that records verifier execution
    authority / verifier-controlled release damages the credibility of the whole
    system, so we refuse it outright rather than downgrade or rewrite it."""
    errors: list[str] = []
    binding = receipt.get("authority_binding")
    if not isinstance(binding, dict):
        return ["authority_binding: missing or not an object"]

    if binding.get("verifier_has_execution_authority") is not False:
        errors.append(
            "authority_binding.verifier_has_execution_authority must be exactly "
            "false — DefaultVerifier records evidence and never holds execution "
            "authority"
        )
    # Optional in the committed schema but explicit doctrine fields in the SDK.
    if "verifier_controls_resource_release" in binding and (
        binding.get("verifier_controls_resource_release") is not False
    ):
        errors.append(
            "authority_binding.verifier_controls_resource_release must be false — "
            "DefaultVerifier never controls resource release"
        )
    if "resource_server_controls_delivery" in binding and (
        binding.get("resource_server_controls_delivery") is not True
    ):
        errors.append(
            "authority_binding.resource_server_controls_delivery must be true "
            "when present — the resource server controls delivery, not the verifier"
        )
    return errors


# ---------------------------------------------------------------------------
# Schema-conformant projection
# ---------------------------------------------------------------------------

def schema_projection(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Project the received payload onto exactly the committed-schema fields.

    The SDK's payload carries a richer authority binding (the explicit
    `verifier_controls_resource_release` / `resource_server_controls_delivery`
    doctrine booleans) and may carry a `request_digest`; neither is part of the
    committed `sar-402-settlement-v0.1` schema (which is `additionalProperties:
    false`). We enforce those extra fields *ourselves* (see
    `authority_binding_errors`) and validate the canonical fields through the
    committed validator. The full original payload is what we store."""
    root_keys = _schema_root_keys()
    auth_keys = _schema_authority_keys()
    projected = {k: copy.deepcopy(v) for k, v in receipt.items() if k in root_keys}
    binding = projected.get("authority_binding")
    if isinstance(binding, dict):
        projected["authority_binding"] = {
            k: v for k, v in binding.items() if k in auth_keys
        }
    return projected


# ---------------------------------------------------------------------------
# Explorer / lookup links
# ---------------------------------------------------------------------------

def explorer_url_for(receipt_id: str, env: Optional[Mapping[str, str]] = None) -> str:
    env = _resolve_env(env)
    base = (env.get("SAR402_EXPLORER_BASE") or DEFAULT_EXPLORER_BASE)
    return base + quote(receipt_id, safe="")


def lookup_path_for(receipt_id: str) -> str:
    # The live, provable backend route (see attest_service.get_receipt).
    return f"/v1/attest/receipt/{quote(receipt_id, safe='')}"


# ---------------------------------------------------------------------------
# Core (testable) ingestion
# ---------------------------------------------------------------------------

def record_sar402_receipt(
    payload: Mapping[str, Any],
    *,
    authorization: Optional[str] = None,
    env: Optional[Mapping[str, str]] = None,
    persist: bool = True,
) -> dict[str, Any]:
    """Ingest one SAR-402 receipt. Pure/testable core for the route.

    Order matters: auth, then doctrine/authority hard-rejects, then committed
    schema validation, then (only if everything passed) persistence. Nothing is
    stored and no Explorer link is produced for any rejected payload."""
    check_auth(authorization, env)

    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="request body must be a JSON object")

    mode = payload.get("verification_mode")
    if mode in REJECTED_MODES:
        raise HTTPException(
            status_code=422,
            detail=f"verification_mode {mode!r} is not supported by this ingestion "
            "endpoint in Phase 1 (record-only). gate mode asserts an external "
            "release controller and is out of scope here.",
        )

    # Explicit Phase-1 authority hard-rejects (before any persistence).
    auth_errs = authority_binding_errors(payload)
    if auth_errs:
        raise HTTPException(status_code=422, detail={"authority_errors": auth_errs})

    integrity = payload.get("integrity")
    receipt_id = integrity.get("digest") if isinstance(integrity, dict) else None
    if not receipt_id or not isinstance(receipt_id, str):
        raise HTTPException(
            status_code=422,
            detail="integrity.digest is required and is used as the receipt id",
        )

    # Committed schema + authority + continuity validation (never bypassed).
    projection = schema_projection(payload)
    try:
        validate_receipt(projection)
    except AuthorityBoundaryError as exc:
        raise HTTPException(status_code=422, detail={"authority_errors": exc.errors})
    except SAR402ValidationError as exc:
        raise HTTPException(status_code=422, detail={"schema_errors": exc.errors})

    # Build the stored receipt: the full received payload + the assigned id.
    stored = copy.deepcopy(dict(payload))
    stored["receipt_id"] = receipt_id

    derived_agent_id = (
        ((payload.get("identity") or {}).get("derived_identity") or {}).get(
            "derived_agent_id"
        )
    )

    if persist:
        # Persist through the existing receipt machinery so Explorer / recent
        # receipts surface it from the same ledger. A failure here is a real
        # 5xx — we never fake a success when issuance fails.
        try:
            import attest_service as svc  # lazy: avoids import cycle at load time

            svc.write_receipt(
                receipt=stored,
                receipt_type=RECEIPT_TYPE,
                receipt_context=RECEIPT_CONTEXT,
                agent_id=derived_agent_id,
            )
        except HTTPException:
            raise
        except Exception as exc:  # pragma: no cover - defensive
            raise HTTPException(
                status_code=500,
                detail=f"SAR-402 receipt persistence failed: {exc}",
            )

    return {
        "status": "recorded",
        "receipt_id": receipt_id,
        "explorer_url": explorer_url_for(receipt_id, env),
        "receipt_lookup_path": lookup_path_for(receipt_id),
        "profile": payload.get("profile"),
        "schema_id": payload.get("schema_id"),
        "mode": mode,
        "schema_backend": sar_schema.active_backend(),
        "authority_binding": projection.get("authority_binding"),
        "receipt": stored,
    }


@router.post("/v1/sar-402/receipts")
def ingest_sar402_receipt(
    payload: dict = Body(...),
    authorization: Optional[str] = Header(default=None),
):
    """Ingest a resource-server-built SAR-402 receipt and record it.

    See `record_sar402_receipt` for behavior. Returns the receipt id, the
    Explorer URL, the live lookup path, and the stored receipt."""
    return record_sar402_receipt(payload, authorization=authorization)
