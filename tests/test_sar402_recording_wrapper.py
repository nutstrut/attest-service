"""Tests for SAR-402 Path B: the recording-attribution wrapper.

These prove the Path B claim boundary and crypto behavior WITHOUT changing the
inner SAR-402 schema or Path A behavior:

  * Path A behavior is unchanged where expected (the inner receipt is embedded
    verbatim; the wrapper adds nothing to and removes nothing from it).
  * The wrapper carries recorded_by, verifier_kid, recorded_at, receipt_id, and
    recording_signature (plus the explicit claims block).
  * Signature verification passes for an untampered wrapped recording.
  * Tampering with the wrapped receipt OR a wrapper field OR the signature causes
    verification to FAIL.
  * The boundary claims are explicit and machine-readable: the signature attests
    to recording attribution only and explicitly does not attest to delivery,
    payment execution, access authorization, release control, or legal finality.
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sar402_receipts import record_sar402_receipt  # noqa: E402
from sar402_recording_wrapper import (  # noqa: E402
    DOES_NOT_ATTEST_TO,
    RECORDED_BY,
    RECORDING_WRAPPER_VERSION,
    SIGNATURE_ALG,
    SIGNATURE_ATTESTS_TO,
    build_recording_wrapper,
    canonical_bytes,
    load_kid,
    load_public_key,
    load_signing_key,
    verify_recording_wrapper,
)

# Reuse the Path A test fixtures so Path B wraps a REAL Path A receipt.
from test_sar402_receipts import _unique_payload  # noqa: E402


# Deterministic test key (NOT a production key).
TEST_SEED = bytes(range(32))
TEST_KID = "sar-test-ed25519-01"


def _signing_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(TEST_SEED)


def _path_a_receipt(tag: str) -> dict:
    """A real Path A inner receipt (with adopted receipt_id), unpersisted."""
    result = record_sar402_receipt(_unique_payload(tag), persist=False)
    return result["receipt"]


def _wrap(tag: str) -> dict:
    return build_recording_wrapper(
        _path_a_receipt(tag), signing_key=_signing_key(), kid=TEST_KID
    )


# ---------------------------------------------------------------------------
# Path A is untouched by wrapping
# ---------------------------------------------------------------------------

def test_path_a_receipt_embedded_verbatim_and_not_mutated():
    receipt = _path_a_receipt("verbatim")
    before = copy.deepcopy(receipt)
    wrapper = build_recording_wrapper(
        receipt, signing_key=_signing_key(), kid=TEST_KID
    )
    # The inner receipt is embedded field-for-field, unchanged...
    assert wrapper["receipt"] == before
    # ...and the original object passed in was not mutated.
    assert receipt == before


def test_path_a_record_result_unchanged_shape():
    # Path B does not alter what Path A returns; wrapping is a pure add-on layer.
    result = record_sar402_receipt(_unique_payload("pathA"), persist=False)
    assert result["status"] == "recorded"
    assert "recording_signature" not in result
    assert "verifier_kid" not in result
    assert "recording_wrapper_version" not in result


# ---------------------------------------------------------------------------
# Required wrapper fields
# ---------------------------------------------------------------------------

def test_wrapper_has_required_fields():
    wrapper = _wrap("fields")
    assert wrapper["recording_wrapper_version"] == RECORDING_WRAPPER_VERSION
    assert wrapper["recorded_by"] == RECORDED_BY == "defaultverifier"
    assert wrapper["verifier_kid"] == TEST_KID
    assert isinstance(wrapper["recorded_at"], str) and wrapper["recorded_at"]
    assert wrapper["receipt_id"] == wrapper["receipt"]["receipt_id"]
    assert wrapper["receipt_id"] == wrapper["receipt"]["integrity"]["digest"]

    sig = wrapper["recording_signature"]
    assert sig["alg"] == SIGNATURE_ALG == "Ed25519"
    assert sig["kid"] == TEST_KID
    assert isinstance(sig["signature"], str) and sig["signature"]


def test_recorded_at_is_caller_supplied_when_given():
    receipt = _path_a_receipt("ts")
    wrapper = build_recording_wrapper(
        receipt,
        signing_key=_signing_key(),
        kid=TEST_KID,
        recorded_at="2026-06-23T00:00:00+00:00",
    )
    assert wrapper["recorded_at"] == "2026-06-23T00:00:00+00:00"


# ---------------------------------------------------------------------------
# Signature verification (happy path)
# ---------------------------------------------------------------------------

def test_signature_verifies_for_untampered_wrapper():
    wrapper = _wrap("verify")
    assert verify_recording_wrapper(
        wrapper, public_key=_signing_key().public_key()
    ) is True


def test_signature_fails_under_wrong_key():
    wrapper = _wrap("wrongkey")
    other = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    assert verify_recording_wrapper(wrapper, public_key=other.public_key()) is False


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------

def test_tamper_inner_receipt_fails_verification():
    wrapper = _wrap("tamperreceipt")
    pub = _signing_key().public_key()
    assert verify_recording_wrapper(wrapper, public_key=pub) is True
    # Swap a field inside the embedded receipt.
    wrapper["receipt"]["payment"]["amount_paid"]["amount"] = "999999"
    assert verify_recording_wrapper(wrapper, public_key=pub) is False


def test_tamper_receipt_id_fails_verification():
    wrapper = _wrap("tamperid")
    pub = _signing_key().public_key()
    # receipt_id no longer matches the inner integrity.digest -> reject.
    wrapper["receipt_id"] = "sha256:" + "0" * 64
    assert verify_recording_wrapper(wrapper, public_key=pub) is False


def test_tamper_wrapper_field_fails_verification():
    wrapper = _wrap("tamperfield")
    pub = _signing_key().public_key()
    wrapper["recorded_at"] = "1999-01-01T00:00:00+00:00"
    assert verify_recording_wrapper(wrapper, public_key=pub) is False


def test_tamper_claims_fails_verification():
    wrapper = _wrap("tamperclaims")
    pub = _signing_key().public_key()
    # Attempt to widen what the signature "attests to" -> breaks the signature.
    wrapper["claims"]["signature_attests_to"] = "payment_execution"
    assert verify_recording_wrapper(wrapper, public_key=pub) is False


def test_tamper_signature_fails_verification():
    wrapper = _wrap("tampersig")
    pub = _signing_key().public_key()
    wrapper["recording_signature"]["signature"] = "AA" + wrapper[
        "recording_signature"
    ]["signature"][2:]
    assert verify_recording_wrapper(wrapper, public_key=pub) is False


def test_kid_mismatch_fails_verification():
    wrapper = _wrap("kidmismatch")
    pub = _signing_key().public_key()
    wrapper["verifier_kid"] = "some-other-kid"
    assert verify_recording_wrapper(wrapper, public_key=pub) is False


# ---------------------------------------------------------------------------
# Explicit, machine-readable claim boundary
# ---------------------------------------------------------------------------

def test_claims_block_is_recording_attribution_only():
    wrapper = _wrap("claims")
    claims = wrapper["claims"]
    assert claims["signature_attests_to"] == SIGNATURE_ATTESTS_TO
    assert claims["signature_attests_to"] == "recording_attribution_only"
    assert claims["does_not_attest_to"] == list(DOES_NOT_ATTEST_TO)


def test_claims_block_disclaims_all_authority_and_finality():
    wrapper = _wrap("disclaim")
    disclaimed = set(wrapper["claims"]["does_not_attest_to"])
    for forbidden in (
        "resource_delivery",
        "payment_execution",
        "access_authorization",
        "release_control",
        "legal_payment_finality",
    ):
        assert forbidden in disclaimed


def test_wrapper_does_not_assert_delivery_or_execution_roles():
    # The recorder is DefaultVerifier; the inner receipt still attributes
    # delivery to the resource server. Path B must not flip those roles.
    wrapper = _wrap("roles")
    assert wrapper["recorded_by"] == "defaultverifier"
    binding = wrapper["receipt"]["authority_binding"]
    assert binding["verifier_has_execution_authority"] is False
    assert binding["verifier_controls_resource_release"] is False
    assert binding["resource_server_controls_delivery"] is True
    assert binding["acting_party"] == "resource_server"


# ---------------------------------------------------------------------------
# Canonicalization determinism + env loaders
# ---------------------------------------------------------------------------

def test_canonical_bytes_are_deterministic_and_order_independent():
    a = {"b": 1, "a": 2, "c": {"y": 1, "x": 2}}
    b = {"c": {"x": 2, "y": 1}, "a": 2, "b": 1}
    assert canonical_bytes(a) == canonical_bytes(b)


def test_env_loaders_optional_and_roundtrip():
    # Unset -> None (no side effects, no default prod kid).
    assert load_signing_key({}) is None
    assert load_public_key({}) is None
    assert load_kid({}) is None

    seed_hex = TEST_SEED.hex()
    env = {"SAR402_RECORDING_SIGNING_KEY_HEX": seed_hex, "SAR402_RECORDING_KID": TEST_KID}
    sk = load_signing_key(env)
    assert sk is not None
    assert load_kid(env) == TEST_KID
    # A wrapper built with the env-loaded key verifies with its public key.
    wrapper = build_recording_wrapper(
        _path_a_receipt("envroundtrip"), signing_key=sk, kid=TEST_KID
    )
    assert verify_recording_wrapper(wrapper, public_key=sk.public_key()) is True


def test_missing_kid_rejected():
    with pytest.raises(ValueError):
        build_recording_wrapper(
            _path_a_receipt("nokid"), signing_key=_signing_key(), kid=""
        )
