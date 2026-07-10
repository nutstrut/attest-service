"""Tests for the dedicated Path B credential lane (``sar402_pathb_credential.py``).

All keys here are ephemeral, per-test fixtures generated with
``Ed25519PrivateKey.generate()`` — never the real, encrypted
``defaultverifier-recording-ed25519-2`` custody artifact. That artifact is
exercised exactly once, outside of this test suite, in the bounded custody
proof (see ``reports/external-actions/sar-402-path-b-final-loader-custody-proof-*``).

Covers:
  * successful load through the final loader + derived public key match;
  * missing credential fails closed;
  * malformed credential fails closed (wrong length, non-hex, uppercase,
    multiple lines, empty file, non-ASCII);
  * private/public mismatch fails closed (coherence gate);
  * kid mismatch fails closed (coherence gate);
  * no secret value (seed hex or raw private bytes) ever appears in a raised
    exception's message;
  * current -1 production behavior (``sar402_recording_wrapper.py`` /
    ``scripts/sar402_pathb_wrap_receipt.py``) is untouched by this module.
"""

from __future__ import annotations

import stat
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import sar402_pathb_credential as cred  # noqa: E402


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
def fixture_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


# ---------------------------------------------------------------------------
# Successful load through the final loader
# ---------------------------------------------------------------------------

def test_successful_credential_load_through_final_loader(tmp_path, fixture_key):
    key_file = tmp_path / cred.CREDENTIAL_FILENAME
    key_file.write_text(_seed_hex(fixture_key) + "\n")
    key_file.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600, matches intended perms

    loaded = cred.load_private_key_from_file(key_file)
    derived = cred.derive_public_key_hex(loaded)

    assert derived == _pub_hex(fixture_key)


def test_successful_load_no_trailing_newline(tmp_path, fixture_key):
    key_file = tmp_path / cred.CREDENTIAL_FILENAME
    key_file.write_text(_seed_hex(fixture_key))  # no trailing newline

    loaded = cred.load_private_key_from_file(key_file)
    assert cred.derive_public_key_hex(loaded) == _pub_hex(fixture_key)


def test_resolve_private_key_path_explicit_override(tmp_path):
    explicit = tmp_path / "somewhere-else"
    env = {cred.ENV_PRIVATE_KEY_FILE: str(explicit)}
    assert cred.resolve_private_key_path(env) == explicit


def test_resolve_private_key_path_credentials_directory(tmp_path):
    env = {"CREDENTIALS_DIRECTORY": str(tmp_path)}
    resolved = cred.resolve_private_key_path(env)
    assert resolved == tmp_path / cred.CREDENTIAL_FILENAME


def test_resolve_private_key_path_fails_closed_when_unconfigured():
    with pytest.raises(cred.PathBCredentialError):
        cred.resolve_private_key_path({})


# ---------------------------------------------------------------------------
# Missing credential fails closed
# ---------------------------------------------------------------------------

def test_missing_credential_file_fails_closed(tmp_path):
    missing = tmp_path / "does-not-exist"
    with pytest.raises(cred.PathBCredentialError, match="not found"):
        cred.load_private_key_from_file(missing)


# ---------------------------------------------------------------------------
# Malformed credential fails closed
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "content",
    [
        "",  # empty
        "deadbeef",  # too short
        "0" * 63,  # one short
        "0" * 65,  # one long
        ("ab01cd23" * 8).upper(),  # uppercase not accepted
        "g" * 64,  # non-hex chars
        ("0" * 64) + "\n" + ("0" * 64),  # multiple lines
        ("0" * 64) + " ",  # trailing space
        " " + ("0" * 64),  # leading space
    ],
)
def test_malformed_credential_fails_closed(tmp_path, content):
    key_file = tmp_path / cred.CREDENTIAL_FILENAME
    key_file.write_text(content)
    with pytest.raises(cred.PathBCredentialError, match="malformed"):
        cred.load_private_key_from_file(key_file)


def test_non_ascii_credential_fails_closed(tmp_path):
    key_file = tmp_path / cred.CREDENTIAL_FILENAME
    key_file.write_bytes("caf\xe9".encode("latin-1"))
    with pytest.raises(cred.PathBCredentialError, match="non-ASCII"):
        cred.load_private_key_from_file(key_file)


# ---------------------------------------------------------------------------
# Coherence gate: private/public mismatch, kid mismatch
# ---------------------------------------------------------------------------

def test_coherence_gate_passes_when_everything_agrees(fixture_key):
    pub_hex = _pub_hex(fixture_key)
    derived = cred.startup_coherence_gate(
        configured_kid="defaultverifier-recording-ed25519-2",
        expected_public_key_hex=pub_hex,
        private_key=fixture_key,
        producer_supported_kids=["defaultverifier-recording-ed25519-2"],
    )
    assert derived == pub_hex


def test_coherence_gate_fails_closed_on_public_key_mismatch(fixture_key):
    other_key = Ed25519PrivateKey.generate()
    with pytest.raises(cred.PathBCredentialError, match="does not match"):
        cred.startup_coherence_gate(
            configured_kid="defaultverifier-recording-ed25519-2",
            expected_public_key_hex=_pub_hex(other_key),
            private_key=fixture_key,
            producer_supported_kids=["defaultverifier-recording-ed25519-2"],
        )


def test_coherence_gate_fails_closed_on_kid_mismatch(fixture_key):
    with pytest.raises(cred.PathBCredentialError, match="not in the producer-supported"):
        cred.startup_coherence_gate(
            configured_kid="defaultverifier-recording-ed25519-1",
            expected_public_key_hex=_pub_hex(fixture_key),
            private_key=fixture_key,
            producer_supported_kids=["defaultverifier-recording-ed25519-2"],
        )


def test_coherence_gate_fails_closed_on_malformed_expected_pubkey(fixture_key):
    with pytest.raises(cred.PathBCredentialError):
        cred.startup_coherence_gate(
            configured_kid="defaultverifier-recording-ed25519-2",
            expected_public_key_hex="not-hex",
            private_key=fixture_key,
            producer_supported_kids=["defaultverifier-recording-ed25519-2"],
        )


# ---------------------------------------------------------------------------
# Env-level loaders fail closed
# ---------------------------------------------------------------------------

def test_load_expected_public_key_hex_fails_closed_when_unset():
    with pytest.raises(cred.PathBCredentialError):
        cred.load_expected_public_key_hex({})


def test_load_expected_public_key_hex_fails_closed_on_bad_format():
    with pytest.raises(cred.PathBCredentialError):
        cred.load_expected_public_key_hex({cred.ENV_PUBLIC_KEY_HEX: "zz"})


def test_load_configured_kid_fails_closed_when_unset():
    with pytest.raises(cred.PathBCredentialError):
        cred.load_configured_kid({})


def test_load_configured_kid_success():
    assert (
        cred.load_configured_kid({cred.ENV_KID: "defaultverifier-recording-ed25519-2"})
        == "defaultverifier-recording-ed25519-2"
    )


# ---------------------------------------------------------------------------
# No secret value ever appears in exception messages
# ---------------------------------------------------------------------------

def test_no_secret_value_in_exception_messages(tmp_path, fixture_key):
    seed_hex = _seed_hex(fixture_key)
    key_file = tmp_path / cred.CREDENTIAL_FILENAME
    # Malformed on purpose (truncated) so it raises, but still contains a
    # prefix of the real seed hex — the error message must not echo it.
    key_file.write_text(seed_hex[:-4])

    with pytest.raises(cred.PathBCredentialError) as exc_info:
        cred.load_private_key_from_file(key_file)
    assert seed_hex not in str(exc_info.value)
    assert seed_hex[:32] not in str(exc_info.value)


def test_no_secret_value_in_coherence_gate_mismatch_message(fixture_key):
    other_key = Ed25519PrivateKey.generate()
    seed_hex = _seed_hex(fixture_key)
    with pytest.raises(cred.PathBCredentialError) as exc_info:
        cred.startup_coherence_gate(
            configured_kid="defaultverifier-recording-ed25519-2",
            expected_public_key_hex=_pub_hex(other_key),
            private_key=fixture_key,
            producer_supported_kids=["defaultverifier-recording-ed25519-2"],
        )
    assert seed_hex not in str(exc_info.value)


def test_fingerprint_never_returns_full_hex():
    pub_hex = _pub_hex(Ed25519PrivateKey.generate())
    fp = cred.fingerprint(pub_hex)
    assert pub_hex not in fp
    assert fp.startswith(pub_hex[:8])
    assert fp.endswith(pub_hex[-8:])


# ---------------------------------------------------------------------------
# Current -1 production behavior is unchanged by this module's existence
# ---------------------------------------------------------------------------

def test_legacy_producer_env_vars_are_a_disjoint_namespace():
    """The dedicated PATH_B_* names must never collide with the live
    SAR402_RECORDING_* names the -1 producer/verifier still read."""
    import sar402_recording_wrapper as legacy

    legacy_names = {
        legacy.ENV_SIGNING_KEY_HEX,
        legacy.ENV_PUBLIC_KEY_HEX,
        legacy.ENV_KID,
    }
    dedicated_names = {cred.ENV_KID, cred.ENV_PUBLIC_KEY_HEX, cred.ENV_PRIVATE_KEY_FILE}
    assert legacy_names.isdisjoint(dedicated_names)


def test_legacy_producer_still_pinned_to_kid_1():
    import attest_service as _svc  # noqa: F401  (bootstraps morpheus package path)

    scripts_dir = str(ROOT / "scripts")
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    import sar402_pathb_wrap_receipt as script

    assert script.EXPECTED_KID == "defaultverifier-recording-ed25519-1"
