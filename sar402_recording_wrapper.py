"""SAR-402 Path B: wrapper-level DefaultVerifier *recording attribution*.

Path B sits strictly ABOVE the Path A receipt. It does not change the inner
SAR-402 schema, the committed validator, the ingestion core
(`sar402_receipts.record_sar402_receipt`), or the stored ledger record. It takes
an already-built Path A receipt (the inner SAR-402 settlement payload, with its
adopted ``receipt_id``) and wraps it in a signed envelope that proves exactly
one thing:

    DefaultVerifier *recorded* this receipt, and that recording act is
    attributable to a named verifier key (``recording_key_id``), such that a
    third party holding the public key can verify the attribution.

This module implements the governed wrapper contract frozen in Morpheus
``org/schemas/SAR402_RECORDING_WRAPPER_V1.md`` (commit ``50b0ba8``):
``wrapper_type = "sar402_recording_attribution"``,
``wrapper_version = "sar402_recording_wrapper_v1"``. **Path B is not live**: this
module builds and verifies wrappers for demo/test use only. It neither publishes
keys, hardcodes a production key, nor has import side effects.

Doctrine boundary (non-negotiable). The recording signature attests to
RECORDING ATTRIBUTION ONLY. It does NOT attest to, and must never be read as,
any of:

    * resource delivery,
    * payment execution,
    * access authorization,
    * release control,
    * legal payment finality,
    * mainnet settlement (when the inner receipt is testnet).

Signing here is NOT execution authority. The verifier records evidence; it does
not deliver, authorize, execute, or finalize. The ``authority_boundary`` block in
every wrapper states this explicitly and machine-readably.

``recording_context`` is an enum of exactly ``"observation"`` or ``"ingestion"``.
``"attestation"`` is FORBIDDEN as a recording context: it can be misread as
attestation to delivery content, payment, access authorization, release control,
or finality. Path B attributes recording only.

What the signature covers. The Ed25519 signature is computed over the canonical
bytes of the wrapper EXCLUDING the ``recording_signature`` field — i.e. over
every wrapper field, the ``authority_boundary`` block, and the full inner
receipt. Tampering with any of those (including the inner receipt) breaks
verification. ``wrapped_receipt_id`` is ADOPTED verbatim from the inner receipt's
id and ``wrapped_receipt_digest`` from its ``integrity.digest`` (the Path A
convention); DefaultVerifier does not recompute or re-issue the content hash — it
signs its *recording* of that content.

Keys. For tests, callers pass the signing/public key explicitly. For an
operational deployment the key MAY be loaded from the environment (hex-encoded
32-byte Ed25519 seed) — but this module neither publishes keys nor hardcodes a
production key, and importing it has no side effects.
"""

from __future__ import annotations

import base64
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# ---------------------------------------------------------------------------
# Wrapper-contract constants (Path B). None of these are part of the inner
# SAR-402 schema; they label and bound the recording envelope only. They mirror
# Morpheus org/schemas/SAR402_RECORDING_WRAPPER_V1.md (commit 50b0ba8).
# ---------------------------------------------------------------------------

WRAPPER_TYPE = "sar402_recording_attribution"
WRAPPER_VERSION = "sar402_recording_wrapper_v1"
RECORDED_BY = "defaultverifier"
RECORDING_SERVICE = "attest-service/sar-402"
SIGNATURE_ALG = "Ed25519"

# Recording-context enum. Exactly these two values are legal. "attestation" is
# explicitly NOT a member (see module doctrine) and MUST be rejected.
RECORDING_CONTEXT_OBSERVATION = "observation"
RECORDING_CONTEXT_INGESTION = "ingestion"
ALLOWED_RECORDING_CONTEXTS = (
    RECORDING_CONTEXT_OBSERVATION,
    RECORDING_CONTEXT_INGESTION,
)
DEFAULT_RECORDING_CONTEXT = RECORDING_CONTEXT_INGESTION

# The machine-readable doctrine boundary carried in every wrapper's
# authority_boundary block. The signature attests to recording attribution ONLY;
# it explicitly does not attest to any of the listed authority/finality
# properties.
SIGNATURE_ATTESTS_TO = "recording_attribution_only"
SOURCE_EVIDENCE_CREATED_BY = "resource_server"

# Always-disclaimed properties (the minimum required set).
DOES_NOT_ATTEST_TO = (
    "resource_delivery",
    "payment_execution",
    "access_authorization",
    "release_control",
    "legal_payment_finality",
)
# Additionally disclaimed when the inner receipt is testnet: the recording does
# not imply mainnet settlement.
MAINNET_SETTLEMENT = "mainnet_settlement"

# Env var names (optional; only read by the convenience loaders below).
ENV_SIGNING_KEY_HEX = "SAR402_RECORDING_SIGNING_KEY_HEX"
ENV_PUBLIC_KEY_HEX = "SAR402_RECORDING_PUBLIC_KEY_HEX"
ENV_KID = "SAR402_RECORDING_KID"


# ---------------------------------------------------------------------------
# Canonicalization (same convention used across the SAR-402 demo path)
# ---------------------------------------------------------------------------

def canonical_bytes(obj: Mapping[str, Any]) -> bytes:
    """Canonical JSON: sorted keys, compact separators, UTF-8.

    This is the ``sorted_keys_compact_v0`` convention used elsewhere in the
    SAR-402 path, so a third party can reproduce the exact signed bytes."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _is_testnet(receipt: Mapping[str, Any]) -> bool:
    """True unless the inner receipt's issuer environment is explicitly mainnet.

    Fail-safe: anything that is not clearly a mainnet/production environment is
    treated as testnet, so the wrapper disclaims mainnet settlement by default."""
    issuer = receipt.get("issuer")
    env = (issuer.get("environment") if isinstance(issuer, dict) else "") or ""
    return env.strip().lower() not in ("mainnet", "production", "prod")


def does_not_attest_to_for(receipt: Mapping[str, Any]) -> list[str]:
    """The disclaimed-properties list for a given inner receipt.

    Always the required minimum set; plus ``mainnet_settlement`` when the inner
    receipt is testnet."""
    disclaimed = list(DOES_NOT_ATTEST_TO)
    if _is_testnet(receipt):
        disclaimed.append(MAINNET_SETTLEMENT)
    return disclaimed


def _authority_boundary_block(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "signature_attests_to": SIGNATURE_ATTESTS_TO,
        "does_not_attest_to": does_not_attest_to_for(receipt),
        "verifier_has_execution_authority": False,
        "verifier_controls_resource_release": False,
        "source_evidence_created_by": SOURCE_EVIDENCE_CREATED_BY,
    }


def _authority_boundary_ok(
    boundary: Any, receipt: Mapping[str, Any]
) -> bool:
    """Verify the authority_boundary block is present and not weakened.

    A missing block, a block that asserts verifier execution authority or
    verifier-controlled release, a wrong ``signature_attests_to`` /
    ``source_evidence_created_by``, or a ``does_not_attest_to`` list that drops
    any required disclaimer all FAIL."""
    if not isinstance(boundary, Mapping):
        return False
    if boundary.get("signature_attests_to") != SIGNATURE_ATTESTS_TO:
        return False
    if boundary.get("verifier_has_execution_authority") is not False:
        return False
    if boundary.get("verifier_controls_resource_release") is not False:
        return False
    if boundary.get("source_evidence_created_by") != SOURCE_EVIDENCE_CREATED_BY:
        return False
    disclaimed = boundary.get("does_not_attest_to")
    if not isinstance(disclaimed, (list, tuple)):
        return False
    required = set(does_not_attest_to_for(receipt))
    if not required.issubset(set(disclaimed)):
        return False
    return True


def _inner_receipt_id(receipt: Mapping[str, Any]) -> str:
    """The inner receipt id (adopted as ``wrapped_receipt_id``).

    Prefer the explicit ``receipt_id`` Path A injects; fall back to
    ``integrity.digest``. Require the two to agree when both are present."""
    integrity = receipt.get("integrity")
    digest = integrity.get("digest") if isinstance(integrity, dict) else None
    explicit = receipt.get("receipt_id")
    rid = explicit or digest
    if not rid or not isinstance(rid, str):
        raise ValueError(
            "inner receipt has no usable receipt_id / integrity.digest to adopt"
        )
    if explicit and digest and explicit != digest:
        raise ValueError(
            "inner receipt_id does not match integrity.digest; refusing to wrap"
        )
    return rid


def _inner_receipt_digest(receipt: Mapping[str, Any]) -> str:
    """The inner receipt integrity digest (adopted as ``wrapped_receipt_digest``)."""
    integrity = receipt.get("integrity")
    digest = integrity.get("digest") if isinstance(integrity, dict) else None
    if not digest or not isinstance(digest, str):
        raise ValueError("inner receipt has no usable integrity.digest")
    return digest


def _signing_view(wrapper: Mapping[str, Any]) -> dict[str, Any]:
    """The exact object that is signed: the wrapper minus the signature field."""
    return {k: v for k, v in wrapper.items() if k != "recording_signature"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def build_recording_wrapper(
    receipt: Mapping[str, Any],
    *,
    signing_key: Ed25519PrivateKey,
    kid: str,
    recording_context: str = DEFAULT_RECORDING_CONTEXT,
    recording_event_id: Optional[str] = None,
    recording_service: str = RECORDING_SERVICE,
    observed_at: Optional[str] = None,
    recorded_at: Optional[str] = None,
    signed_at: Optional[str] = None,
) -> dict[str, Any]:
    """Wrap a Path A SAR-402 receipt in a signed recording-attribution envelope.

    ``receipt`` is the inner SAR-402 settlement payload (with its adopted
    ``receipt_id`` / ``integrity.digest``). It is embedded verbatim and is NOT
    mutated. The returned wrapper matches the governed
    ``sar402_recording_wrapper_v1`` shape and carries a detached Ed25519
    signature over the canonical wrapper-without-signature.

    ``recording_context`` MUST be one of ``"observation"`` / ``"ingestion"``;
    ``"attestation"`` (and any other value) is rejected with ``ValueError``.

    The signature attests to recording attribution ONLY (see module doctrine and
    the ``authority_boundary`` block). It is not delivery, payment, access,
    release, finality, or mainnet settlement, and signing is not execution
    authority."""
    if not isinstance(receipt, Mapping):
        raise TypeError("receipt must be a mapping")
    if not kid or not isinstance(kid, str):
        raise ValueError("kid (recording_key_id) is required")
    if recording_context not in ALLOWED_RECORDING_CONTEXTS:
        raise ValueError(
            "recording_context must be one of "
            + ", ".join(ALLOWED_RECORDING_CONTEXTS)
            + f"; {recording_context!r} is not permitted"
        )

    wrapped_receipt_id = _inner_receipt_id(receipt)
    wrapped_receipt_digest = _inner_receipt_digest(receipt)

    if recording_event_id is None:
        recording_event_id = f"rec:{uuid.uuid4()}"
    if observed_at is None:
        observed_at = _now_iso()
    if recorded_at is None:
        recorded_at = _now_iso()
    if signed_at is None:
        signed_at = _now_iso()

    # The signed portion (everything except the signature itself). Inner receipt
    # is embedded as a deep, JSON-safe copy so the caller's object is not shared.
    signed_view: dict[str, Any] = {
        "wrapper_type": WRAPPER_TYPE,
        "wrapper_version": WRAPPER_VERSION,
        "recording_event_id": recording_event_id,
        "recording_context": recording_context,
        "recorded_by": RECORDED_BY,
        "recording_service": recording_service,
        "recording_key_id": kid,
        "wrapped_receipt_id": wrapped_receipt_id,
        "wrapped_receipt_digest": wrapped_receipt_digest,
        "observed_at": observed_at,
        "recorded_at": recorded_at,
        "signed_at": signed_at,
        "signature_alg": SIGNATURE_ALG,
        "authority_boundary": _authority_boundary_block(receipt),
        "receipt": json.loads(json.dumps(receipt)),
    }

    signature = signing_key.sign(canonical_bytes(signed_view))
    wrapper = dict(signed_view)
    wrapper["recording_signature"] = {
        "alg": SIGNATURE_ALG,
        "kid": kid,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    return wrapper


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------

def verify_recording_wrapper(
    wrapper: Mapping[str, Any],
    *,
    public_key: Ed25519PublicKey,
) -> bool:
    """Verify recording attribution for a wrapped receipt.

    Returns True only if ALL hold:

      * ``wrapper_type`` / ``wrapper_version`` are the governed constants,
      * ``recorded_by`` is DefaultVerifier and ``signature_alg`` is Ed25519,
      * ``recording_context`` is a legal enum value (``"attestation"`` and any
        other value FAIL),
      * ``recording_key_id`` matches ``recording_signature.kid`` and
        ``recording_signature.alg`` matches ``signature_alg``,
      * ``wrapped_receipt_id`` / ``wrapped_receipt_digest`` match the embedded
        inner receipt's id / integrity digest,
      * the ``authority_boundary`` block is present and not weakened, and
      * the Ed25519 signature over the canonical wrapper-without-signature is
        valid for ``public_key``.

    Any tamper — to the inner receipt, to a wrapper field, to the authority
    boundary, or to the signature — returns False.

    This verifies RECORDING ATTRIBUTION ONLY. A True result means
    "DefaultVerifier recorded this receipt under key ``recording_key_id``"; it
    says nothing about delivery, payment, access, release, legal finality, or
    mainnet settlement."""
    if not isinstance(wrapper, Mapping):
        return False

    if wrapper.get("wrapper_type") != WRAPPER_TYPE:
        return False
    if wrapper.get("wrapper_version") != WRAPPER_VERSION:
        return False
    if wrapper.get("recorded_by") != RECORDED_BY:
        return False
    if wrapper.get("signature_alg") != SIGNATURE_ALG:
        return False
    if wrapper.get("recording_context") not in ALLOWED_RECORDING_CONTEXTS:
        return False

    sig_block = wrapper.get("recording_signature")
    if not isinstance(sig_block, Mapping):
        return False
    if sig_block.get("alg") != wrapper.get("signature_alg"):
        return False
    if wrapper.get("recording_key_id") != sig_block.get("kid"):
        return False

    receipt = wrapper.get("receipt")
    if not isinstance(receipt, Mapping):
        return False
    try:
        if wrapper.get("wrapped_receipt_id") != _inner_receipt_id(receipt):
            return False
        if wrapper.get("wrapped_receipt_digest") != _inner_receipt_digest(receipt):
            return False
    except ValueError:
        return False

    if not _authority_boundary_ok(wrapper.get("authority_boundary"), receipt):
        return False

    try:
        signature = base64.b64decode(sig_block.get("signature", ""), validate=True)
    except (ValueError, TypeError):
        return False

    try:
        public_key.verify(signature, canonical_bytes(_signing_view(wrapper)))
    except InvalidSignature:
        return False
    return True


# ---------------------------------------------------------------------------
# Optional env-based key loading (no side effects on import; no key publication)
# ---------------------------------------------------------------------------

def load_signing_key(env: Mapping[str, str]) -> Optional[Ed25519PrivateKey]:
    """Load an Ed25519 signing key from a hex-encoded 32-byte seed, or None."""
    seed_hex = (env.get(ENV_SIGNING_KEY_HEX) or "").strip()
    if not seed_hex:
        return None
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))


def load_public_key(env: Mapping[str, str]) -> Optional[Ed25519PublicKey]:
    """Load an Ed25519 public key from a hex-encoded 32-byte raw key, or None."""
    pub_hex = (env.get(ENV_PUBLIC_KEY_HEX) or "").strip()
    if not pub_hex:
        return None
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))


def load_kid(env: Mapping[str, str]) -> Optional[str]:
    """Load the configured recording_key_id, or None. No default prod kid."""
    return (env.get(ENV_KID) or "").strip() or None


def public_key_hex(signing_key: Ed25519PrivateKey) -> str:
    """Raw public-key bytes (hex) for the given signing key — for publishing the
    verification key to third parties when explicitly intended."""
    raw = signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw.hex()
