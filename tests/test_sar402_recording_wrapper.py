"""Tests for SAR-402 Path B: the recording-attribution wrapper (v1).

These prove the Path B claim boundary and crypto behavior WITHOUT changing the
inner SAR-402 schema or Path A behavior, and pin the governed
``sar402_recording_wrapper_v1`` contract (Morpheus
``org/schemas/SAR402_RECORDING_WRAPPER_V1.md``, commit ``50b0ba8``):

  * Path A behavior is unchanged where expected (the inner receipt is embedded
    verbatim; the wrapper adds nothing to and removes nothing from it).
  * The wrapper carries the governed top-level fields, the authority_boundary
    block, and a detached recording_signature.
  * ``recording_context`` is constrained to observation/ingestion; "attestation"
    (and any other value) is REJECTED.
  * recording_key_id / recording_signature.kid agreement, signature_alg
    agreement, and wrapped_receipt_id / wrapped_receipt_digest binding to the
    inner receipt are all enforced.
  * Signature verification passes for an untampered wrapped recording, and any
    tamper (inner receipt, wrapper field, authority_boundary, signature) FAILS.
  * The authority_boundary is explicit and machine-readable: the signature
    attests to recording attribution only and explicitly disclaims delivery,
    payment execution, access authorization, release control, legal finality,
    and (testnet) mainnet settlement.
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
    ALLOWED_RECORDING_CONTEXTS,
    DEFAULT_RECORDING_CONTEXT,
    DOES_NOT_ATTEST_TO,
    MAINNET_SETTLEMENT,
    RECORDED_BY,
    RECORDING_SERVICE,
    SIGNATURE_ALG,
    SIGNATURE_ATTESTS_TO,
    SOURCE_EVIDENCE_CREATED_BY,
    WRAPPER_TYPE,
    WRAPPER_VERSION,
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


def _wrap(tag: str, **kwargs) -> dict:
    return build_recording_wrapper(
        _path_a_receipt(tag), signing_key=_signing_key(), kid=TEST_KID, **kwargs
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
    assert "recording_key_id" not in result
    assert "wrapper_version" not in result


# ---------------------------------------------------------------------------
# Required wrapper fields (governed v1 shape)
# ---------------------------------------------------------------------------

def test_wrapper_has_required_fields():
    wrapper = _wrap("fields")
    assert wrapper["wrapper_type"] == WRAPPER_TYPE == "sar402_recording_attribution"
    assert wrapper["wrapper_version"] == WRAPPER_VERSION == "sar402_recording_wrapper_v1"
    assert wrapper["recorded_by"] == RECORDED_BY == "defaultverifier"
    assert wrapper["recording_service"] == RECORDING_SERVICE
    assert wrapper["recording_key_id"] == TEST_KID
    assert wrapper["recording_context"] in ALLOWED_RECORDING_CONTEXTS
    assert wrapper["signature_alg"] == SIGNATURE_ALG == "Ed25519"
    assert isinstance(wrapper["recording_event_id"], str) and wrapper["recording_event_id"]
    for ts in ("observed_at", "recorded_at", "signed_at"):
        assert isinstance(wrapper[ts], str) and wrapper[ts]

    # wrapped_receipt_id / digest bind to the inner receipt.
    assert wrapper["wrapped_receipt_id"] == wrapper["receipt"]["receipt_id"]
    assert wrapper["wrapped_receipt_digest"] == wrapper["receipt"]["integrity"]["digest"]

    sig = wrapper["recording_signature"]
    assert sig["alg"] == SIGNATURE_ALG == "Ed25519"
    assert sig["kid"] == TEST_KID
    assert isinstance(sig["signature"], str) and sig["signature"]


def test_default_recording_context_is_ingestion():
    wrapper = _wrap("ctxdefault")
    assert wrapper["recording_context"] == DEFAULT_RECORDING_CONTEXT == "ingestion"


def test_observation_recording_context_allowed():
    wrapper = _wrap("ctxobs", recording_context="observation")
    assert wrapper["recording_context"] == "observation"
    assert verify_recording_wrapper(
        wrapper, public_key=_signing_key().public_key()
    ) is True


def test_timestamps_caller_supplied_when_given():
    wrapper = _wrap(
        "ts",
        observed_at="2026-06-23T00:00:00+00:00",
        recorded_at="2026-06-23T00:00:01+00:00",
        signed_at="2026-06-23T00:00:02+00:00",
    )
    assert wrapper["observed_at"] == "2026-06-23T00:00:00+00:00"
    assert wrapper["recorded_at"] == "2026-06-23T00:00:01+00:00"
    assert wrapper["signed_at"] == "2026-06-23T00:00:02+00:00"


# ---------------------------------------------------------------------------
# recording_context enum: observation/ingestion only; attestation forbidden
# ---------------------------------------------------------------------------

def test_attestation_recording_context_rejected_at_build():
    # "attestation" can be misread as attestation to delivery/payment/finality.
    # Path B attributes recording only -> build MUST reject it.
    with pytest.raises(ValueError):
        _wrap("attestbuild", recording_context="attestation")


def test_arbitrary_recording_context_rejected_at_build():
    with pytest.raises(ValueError):
        _wrap("ctxbad", recording_context="delivery")


def test_attestation_recording_context_fails_verification():
    # Even if a wrapper is hand-crafted with recording_context="attestation",
    # the verifier MUST reject it.
    wrapper = _wrap("attestverify")
    pub = _signing_key().public_key()
    wrapper["recording_context"] = "attestation"
    assert verify_recording_wrapper(wrapper, public_key=pub) is False


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


def test_tamper_wrapped_receipt_id_fails_verification():
    wrapper = _wrap("tamperid")
    pub = _signing_key().public_key()
    # wrapped_receipt_id no longer matches the inner receipt id -> reject.
    wrapper["wrapped_receipt_id"] = "sha256:" + "0" * 64
    assert verify_recording_wrapper(wrapper, public_key=pub) is False


def test_tamper_wrapped_receipt_digest_fails_verification():
    wrapper = _wrap("tamperdigest")
    pub = _signing_key().public_key()
    wrapper["wrapped_receipt_digest"] = "sha256:" + "0" * 64
    assert verify_recording_wrapper(wrapper, public_key=pub) is False


def test_tamper_wrapper_field_fails_verification():
    wrapper = _wrap("tamperfield")
    pub = _signing_key().public_key()
    wrapper["recorded_at"] = "1999-01-01T00:00:00+00:00"
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
    # recording_key_id no longer matches recording_signature.kid.
    wrapper["recording_key_id"] = "some-other-kid"
    assert verify_recording_wrapper(wrapper, public_key=pub) is False


def test_signature_alg_mismatch_fails_verification():
    wrapper = _wrap("algmismatch")
    pub = _signing_key().public_key()
    # recording_signature.alg must equal signature_alg.
    wrapper["recording_signature"]["alg"] = "secp256k1"
    assert verify_recording_wrapper(wrapper, public_key=pub) is False


def test_wrong_wrapper_type_fails_verification():
    wrapper = _wrap("wrongtype")
    pub = _signing_key().public_key()
    wrapper["wrapper_type"] = "sar402_settlement_attestation"
    assert verify_recording_wrapper(wrapper, public_key=pub) is False


def test_wrong_wrapper_version_fails_verification():
    wrapper = _wrap("wrongver")
    pub = _signing_key().public_key()
    wrapper["wrapper_version"] = "sar402_recording_wrapper_v0.1"
    assert verify_recording_wrapper(wrapper, public_key=pub) is False


# ---------------------------------------------------------------------------
# authority_boundary: required, and weakened/missing variants must FAIL
# ---------------------------------------------------------------------------

def test_authority_boundary_block_contents():
    wrapper = _wrap("boundary")
    ab = wrapper["authority_boundary"]
    assert ab["signature_attests_to"] == SIGNATURE_ATTESTS_TO == "recording_attribution_only"
    assert ab["verifier_has_execution_authority"] is False
    assert ab["verifier_controls_resource_release"] is False
    assert ab["source_evidence_created_by"] == SOURCE_EVIDENCE_CREATED_BY == "resource_server"
    disclaimed = set(ab["does_not_attest_to"])
    for forbidden in (
        "resource_delivery",
        "payment_execution",
        "access_authorization",
        "release_control",
        "legal_payment_finality",
    ):
        assert forbidden in disclaimed
    # The test fixture's inner receipt is environment="test" -> testnet ->
    # mainnet_settlement is disclaimed too.
    assert MAINNET_SETTLEMENT in disclaimed


def test_missing_authority_boundary_fails_verification():
    wrapper = _wrap("nobound")
    pub = _signing_key().public_key()
    del wrapper["authority_boundary"]
    assert verify_recording_wrapper(wrapper, public_key=pub) is False


def test_authority_boundary_execution_authority_true_fails_verification():
    wrapper = _wrap("execauth")
    pub = _signing_key().public_key()
    wrapper["authority_boundary"]["verifier_has_execution_authority"] = True
    assert verify_recording_wrapper(wrapper, public_key=pub) is False


def test_authority_boundary_controls_release_true_fails_verification():
    wrapper = _wrap("ctrlrel")
    pub = _signing_key().public_key()
    wrapper["authority_boundary"]["verifier_controls_resource_release"] = True
    assert verify_recording_wrapper(wrapper, public_key=pub) is False


def test_authority_boundary_widened_recording_claim_fails_verification():
    wrapper = _wrap("widen")
    pub = _signing_key().public_key()
    # Attempt to widen what the signature "attests to".
    wrapper["authority_boundary"]["signature_attests_to"] = "payment_execution"
    assert verify_recording_wrapper(wrapper, public_key=pub) is False


def test_authority_boundary_dropped_disclaimer_fails_verification():
    wrapper = _wrap("dropdis")
    pub = _signing_key().public_key()
    # Drop a required disclaimer from does_not_attest_to.
    wrapper["authority_boundary"]["does_not_attest_to"] = [
        d
        for d in wrapper["authority_boundary"]["does_not_attest_to"]
        if d != "payment_execution"
    ]
    assert verify_recording_wrapper(wrapper, public_key=pub) is False


def test_inner_receipt_roles_not_flipped_by_wrapper():
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
