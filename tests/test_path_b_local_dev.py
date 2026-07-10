"""Tests for the SAR-402 Path B local development profile
(``dev/path-b-local/``).

All keys here are ephemeral, per-test fixtures generated with
``Ed25519PrivateKey.generate()`` — never the real production custody
artifact, and never written outside ``tmp_path``.

Covers:
  * local dev credential loads through the unmodified production loader and
    the derived public key matches;
  * the full local signer -> receipt -> verifier round trip succeeds and
    ``verified`` is True;
  * fail-closed: missing credential file, wrong kid, wrong public key, wrong
    credential contents;
  * no secret (seed hex / raw private bytes) ever appears in the round trip
    result or in a raised exception's message;
  * the dev kid is disjoint from both production kids.
"""

from __future__ import annotations

import stat
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
DEV_DIR = ROOT / "dev" / "path-b-local"
for p in (str(ROOT), str(DEV_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

import sar402_pathb_credential as cred  # noqa: E402
import local_credential_profile as profile  # noqa: E402
import run_local_roundtrip as roundtrip  # noqa: E402


def _seed_hex(key: Ed25519PrivateKey) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ).hex()


def _pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


@pytest.fixture()
def dev_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def _write_credential(tmp_path: Path, seed_hex: str) -> Path:
    key_file = tmp_path / "path-b-recording-dev-key"
    key_file.write_text(seed_hex + "\n")
    key_file.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return key_file


def _env(tmp_path: Path, dev_key: Ed25519PrivateKey, *, kid: str = None, pub: str = None) -> dict:
    key_file = _write_credential(tmp_path, _seed_hex(dev_key))
    return {
        "PATH_B_RECORDING_KID": kid if kid is not None else profile.DEV_KID,
        "PATH_B_RECORDING_PUBLIC_KEY_HEX": pub if pub is not None else _pub_hex(dev_key),
        "PATH_B_RECORDING_PRIVATE_KEY_FILE": str(key_file),
    }


# ---------------------------------------------------------------------------
# Local success
# ---------------------------------------------------------------------------

def test_dev_credential_loads_through_production_loader(tmp_path, dev_key):
    env = _env(tmp_path, dev_key)
    path = cred.resolve_private_key_path(env)
    loaded = cred.load_private_key_from_file(path)
    assert cred.derive_public_key_hex(loaded) == _pub_hex(dev_key)


def test_dev_public_key_matches_coherence_gate(tmp_path, dev_key):
    env = _env(tmp_path, dev_key)
    private_key = cred.load_private_key_from_file(cred.resolve_private_key_path(env))
    derived = cred.startup_coherence_gate(
        configured_kid=profile.DEV_KID,
        expected_public_key_hex=_pub_hex(dev_key),
        private_key=private_key,
        producer_supported_kids=[profile.DEV_KID],
    )
    assert derived == _pub_hex(dev_key)


def test_local_receipt_signs_and_verifies(tmp_path, dev_key):
    env = _env(tmp_path, dev_key)
    result = roundtrip.run_roundtrip(env)

    assert result["verified"] is True
    assert result["kid"] == profile.DEV_KID
    assert result["wrapped_receipt_id"]
    assert result["wrapped_receipt_digest"]
    assert result["wrapper_type"] == "sar402_recording_attribution"
    assert result["production_endpoint_contacted"] is False


# ---------------------------------------------------------------------------
# Fail closed
# ---------------------------------------------------------------------------

def test_missing_credential_file_fails_closed(tmp_path, dev_key):
    env = _env(tmp_path, dev_key)
    env["PATH_B_RECORDING_PRIVATE_KEY_FILE"] = str(tmp_path / "does-not-exist")
    with pytest.raises(cred.PathBCredentialError, match="not found"):
        roundtrip.run_roundtrip(env)


def test_wrong_kid_fails_closed(tmp_path, dev_key):
    env = _env(tmp_path, dev_key, kid="defaultverifier-recording-ed25519-1")
    with pytest.raises(cred.PathBCredentialError, match="not in the producer-supported"):
        roundtrip.run_roundtrip(env)


def test_wrong_public_key_fails_closed(tmp_path, dev_key):
    other_key = Ed25519PrivateKey.generate()
    env = _env(tmp_path, dev_key, pub=_pub_hex(other_key))
    with pytest.raises(cred.PathBCredentialError, match="does not match"):
        roundtrip.run_roundtrip(env)


def test_wrong_credential_contents_fails_closed(tmp_path, dev_key):
    env = _env(tmp_path, dev_key)
    Path(env["PATH_B_RECORDING_PRIVATE_KEY_FILE"]).write_text("not-a-valid-seed")
    with pytest.raises(cred.PathBCredentialError, match="malformed"):
        roundtrip.run_roundtrip(env)


def test_missing_env_file_fails_closed(tmp_path):
    with pytest.raises(roundtrip.LocalRoundtripError, match="not found"):
        roundtrip.parse_env_file(tmp_path / "missing.env")


# ---------------------------------------------------------------------------
# No secret logging
# ---------------------------------------------------------------------------

def test_no_secret_value_in_roundtrip_result(tmp_path, dev_key):
    env = _env(tmp_path, dev_key)
    result = roundtrip.run_roundtrip(env)
    seed_hex = _seed_hex(dev_key)
    serialized = repr(result)
    assert seed_hex not in serialized
    assert seed_hex[:32] not in serialized


def test_no_secret_value_in_failure_message(tmp_path, dev_key):
    other_key = Ed25519PrivateKey.generate()
    env = _env(tmp_path, dev_key, pub=_pub_hex(other_key))
    seed_hex = _seed_hex(dev_key)
    with pytest.raises(cred.PathBCredentialError) as exc_info:
        roundtrip.run_roundtrip(env)
    assert seed_hex not in str(exc_info.value)


# ---------------------------------------------------------------------------
# Dev kid is disjoint from production kids
# ---------------------------------------------------------------------------

def test_dev_kid_disjoint_from_production_kids():
    assert profile.DEV_KID not in profile.PRODUCTION_KIDS
    assert profile.DEV_KID != "defaultverifier-recording-ed25519-1"
    assert profile.DEV_KID != "defaultverifier-recording-ed25519-2"


def test_env_var_names_match_dedicated_credential_lane():
    assert set(profile.ENV_KEYS) == {
        cred.ENV_KID,
        cred.ENV_PUBLIC_KEY_HEX,
        cred.ENV_PRIVATE_KEY_FILE,
    }
