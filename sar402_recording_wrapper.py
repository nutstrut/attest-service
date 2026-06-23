"""SAR-402 Path B: wrapper-level DefaultVerifier *recording attribution*.

Path B sits strictly ABOVE the Path A receipt. It does not change the inner
SAR-402 schema, the committed validator, the ingestion core
(`sar402_receipts.record_sar402_receipt`), or the stored ledger record. It takes
an already-built Path A receipt (the inner SAR-402 settlement payload, with its
adopted ``receipt_id``) and wraps it in a signed envelope that proves exactly
one thing:

    DefaultVerifier *recorded* this receipt, and that recording act is
    attributable to a named verifier key (``verifier_kid``), such that a third
    party holding the public key can verify the attribution.

Doctrine boundary (non-negotiable). The recording signature attests to
RECORDING ATTRIBUTION ONLY. It does NOT attest to, and must never be read as,
any of:

    * resource delivery,
    * payment execution,
    * access authorization,
    * release control,
    * legal payment finality.

Signing here is NOT execution authority. The verifier records evidence; it does
not deliver, authorize, execute, or finalize. The ``claims`` block in every
wrapper states this explicitly and machine-readably.

What the signature covers. The Ed25519 signature is computed over the canonical
bytes of the wrapper EXCLUDING the ``recording_signature`` field — i.e. over the
version, recorder, kid, timestamp, receipt_id, the full inner receipt, and the
claims block. Tampering with any of those (including the inner receipt) breaks
verification. ``receipt_id`` is ADOPTED verbatim from the inner receipt's
``integrity.digest`` (the Path A convention); DefaultVerifier does not recompute
or re-issue the content hash — it signs its *recording* of that content.

Keys. For tests, callers pass the signing/public key explicitly. For an
operational deployment the key MAY be loaded from the environment (hex-encoded
32-byte Ed25519 seed) — but this module neither publishes keys nor hardcodes a
production key, and importing it has no side effects.
"""

from __future__ import annotations

import base64
import json
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
# SAR-402 schema; they label and bound the recording envelope only.
# ---------------------------------------------------------------------------

RECORDING_WRAPPER_VERSION = "sar402_recording_wrapper_v0.1"
RECORDED_BY = "defaultverifier"
SIGNATURE_ALG = "Ed25519"

# The machine-readable doctrine boundary carried in every wrapper. The signature
# attests to recording attribution ONLY; it explicitly does not attest to any of
# the listed authority/finality properties.
SIGNATURE_ATTESTS_TO = "recording_attribution_only"
DOES_NOT_ATTEST_TO = (
    "resource_delivery",
    "payment_execution",
    "access_authorization",
    "release_control",
    "legal_payment_finality",
)

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


def _claims_block() -> dict[str, Any]:
    return {
        "signature_attests_to": SIGNATURE_ATTESTS_TO,
        "does_not_attest_to": list(DOES_NOT_ATTEST_TO),
    }


def _inner_receipt_id(receipt: Mapping[str, Any]) -> str:
    """The receipt_id is the inner receipt's adopted content hash.

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


def _signing_view(wrapper: Mapping[str, Any]) -> dict[str, Any]:
    """The exact object that is signed: the wrapper minus the signature field."""
    return {k: v for k, v in wrapper.items() if k != "recording_signature"}


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def build_recording_wrapper(
    receipt: Mapping[str, Any],
    *,
    signing_key: Ed25519PrivateKey,
    kid: str,
    recorded_at: Optional[str] = None,
) -> dict[str, Any]:
    """Wrap a Path A SAR-402 receipt in a signed recording-attribution envelope.

    ``receipt`` is the inner SAR-402 settlement payload (with its adopted
    ``receipt_id`` / ``integrity.digest``). It is embedded verbatim and is NOT
    mutated. The returned wrapper matches the Path B conceptual shape and carries
    a detached Ed25519 signature over the canonical wrapper-without-signature.

    The signature attests to recording attribution ONLY (see module doctrine and
    the ``claims`` block). It is not delivery, payment, access, release, or
    finality, and signing is not execution authority."""
    if not isinstance(receipt, Mapping):
        raise TypeError("receipt must be a mapping")
    if not kid or not isinstance(kid, str):
        raise ValueError("kid (verifier_kid) is required")

    receipt_id = _inner_receipt_id(receipt)
    if recorded_at is None:
        recorded_at = datetime.now(timezone.utc).isoformat()

    # The signed portion (everything except the signature itself).
    signed_view: dict[str, Any] = {
        "recording_wrapper_version": RECORDING_WRAPPER_VERSION,
        "recorded_by": RECORDED_BY,
        "verifier_kid": kid,
        "recorded_at": recorded_at,
        "receipt_id": receipt_id,
        "receipt": json.loads(json.dumps(receipt)),  # deep, JSON-safe copy
        "claims": _claims_block(),
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

    Returns True only if the Ed25519 signature over the canonical
    wrapper-without-signature is valid for ``public_key`` AND the wrapper is
    internally consistent (recorded_by, kid agreement, receipt_id matches the
    inner receipt's adopted content hash). Any tamper — to the inner receipt, to
    a wrapper field, or to the signature — returns False.

    This verifies RECORDING ATTRIBUTION ONLY. A True result means "DefaultVerifier
    recorded this receipt under key ``kid``"; it says nothing about delivery,
    payment, access, release, or legal finality."""
    if not isinstance(wrapper, Mapping):
        return False

    sig_block = wrapper.get("recording_signature")
    if not isinstance(sig_block, Mapping):
        return False
    if sig_block.get("alg") != SIGNATURE_ALG:
        return False

    # Internal consistency: the signed kid must match the signature-block kid,
    # the recorder must be DefaultVerifier, and the receipt_id must be the inner
    # receipt's adopted content hash (not a swapped-in value).
    if wrapper.get("recorded_by") != RECORDED_BY:
        return False
    if wrapper.get("verifier_kid") != sig_block.get("kid"):
        return False
    receipt = wrapper.get("receipt")
    if not isinstance(receipt, Mapping):
        return False
    try:
        if wrapper.get("receipt_id") != _inner_receipt_id(receipt):
            return False
    except ValueError:
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
    """Load the configured verifier_kid, or None. No default prod kid."""
    return (env.get(ENV_KID) or "").strip() or None


def public_key_hex(signing_key: Ed25519PrivateKey) -> str:
    """Raw public-key bytes (hex) for the given signing key — for publishing the
    verification key to third parties when explicitly intended."""
    raw = signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw.hex()
