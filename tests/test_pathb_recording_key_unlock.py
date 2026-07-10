"""Tests for the SAR-402 Path B runtime unlock helper
(``scripts/pathb-recording-key-unlock.sh``).

All keys/passphrases here are ephemeral, per-test fixtures generated with
``Ed25519PrivateKey.generate()`` and ``secrets.token_hex`` — never the real,
encrypted ``defaultverifier-recording-ed25519-2`` custody artifact. That
artifact is exercised exactly once, outside of this test suite, in the
bounded custody proof
(``reports/external-actions/sar-402-path-b-final-loader-custody-proof-*``).

The script is invoked as a real subprocess (not sourced/mocked) against
temporary directories standing in for systemd's read-only
$CREDENTIALS_DIRECTORY (LoadCredential= inputs) and writable
$RUNTIME_DIRECTORY (RuntimeDirectory= scratch/output space), so these tests
exercise the actual gpg/tar/openssl pipeline the deployed ExecStartPre step
would run.

Covers:
  * successful unlock: correct kid, correct passphrase, matching public key
    -> credential file written with the exact expected seed;
  * wrong configured kid fails closed before any decryption is attempted;
  * wrong public key (artifact's real key doesn't match the expected
    constant) fails closed, no credential file written;
  * missing sealed credential / missing passphrase credential fail closed;
  * malformed archive (missing seed.hex, missing seed.pem, malformed
    seed.hex shape) fails closed;
  * no secret value (passphrase or seed hex) ever appears in the script's
    stdout/stderr.
"""

from __future__ import annotations

import os
import subprocess
import tarfile
import tempfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "pathb-recording-key-unlock.sh"

EXPECTED_KID = "defaultverifier-recording-ed25519-2"
EXPECTED_PUBLIC_KEY_HEX = (
    "e8608e251cce27bfe497da27e97a08d3e1efca4bd4809fb6364fb2af9a34f29e"
)


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


def _pem(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _build_sealed_artifact(
    tmp_path: Path,
    key: Ed25519PrivateKey,
    passphrase: str,
    *,
    omit_seed_hex: bool = False,
    omit_seed_pem: bool = False,
    corrupt_seed_hex: bool = False,
) -> Path:
    """Build a real GPG-symmetric-encrypted tar.gz, mirroring the actual
    custody ceremony's archive contents (seed.hex, seed.pem, public.hex)."""
    build_dir = Path(tempfile.mkdtemp(dir=tmp_path, prefix="build-"))
    stage = build_dir / "stage"
    stage.mkdir()

    if not omit_seed_hex:
        seed_text = "not-valid-hex" if corrupt_seed_hex else _seed_hex(key)
        (stage / "seed.hex").write_text(seed_text + "\n")
    if not omit_seed_pem:
        (stage / "seed.pem").write_bytes(_pem(key))
    (stage / "public.hex").write_text(_pub_hex(key) + "\n")

    archive = build_dir / "artifact.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        for member in sorted(stage.iterdir()):
            tf.add(member, arcname=member.name)

    sealed = build_dir / "sealed.gpg"
    subprocess.run(
        [
            "gpg", "--batch", "--yes", "--quiet",
            "--pinentry-mode", "loopback",
            "--passphrase", passphrase,
            "--symmetric", "--cipher-algo", "AES256",
            "-o", str(sealed), str(archive),
        ],
        check=True,
        capture_output=True,
    )
    return sealed


@pytest.fixture()
def fixture_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def _runtime_dir(creds_dir: Path) -> Path:
    """Mirrors the drop-in's separate, writable RuntimeDirectory=, distinct
    from the read-only $CREDENTIALS_DIRECTORY that LoadCredential= populates."""
    return creds_dir.parent / (creds_dir.name + "-runtime")


def _run_unlock(creds_dir: Path, *, configured_kid: str = EXPECTED_KID,
                 expected_kid: str = EXPECTED_KID,
                 expected_pub: str = EXPECTED_PUBLIC_KEY_HEX):
    runtime_dir = _runtime_dir(creds_dir)
    runtime_dir.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["CREDENTIALS_DIRECTORY"] = str(creds_dir)
    env["RUNTIME_DIRECTORY"] = str(runtime_dir)
    env["PATH_B_RECORDING_KID"] = configured_kid
    env["PATHB_EXPECTED_KID"] = expected_kid
    env["PATHB_EXPECTED_PUBLIC_KEY_HEX"] = expected_pub
    return subprocess.run(
        ["bash", str(SCRIPT)],
        env=env,
        capture_output=True,
        text=True,
    )


def _place_credentials(creds_dir: Path, sealed: Path, passphrase: str):
    creds_dir.mkdir(parents=True, exist_ok=True)
    (creds_dir / "path-b-recording-key-sealed").write_bytes(sealed.read_bytes())
    (creds_dir / "path-b-recording-passphrase").write_text(passphrase)


# ---------------------------------------------------------------------------
# Success path
# ---------------------------------------------------------------------------

def test_valid_unlock_writes_expected_seed(tmp_path, fixture_key):
    passphrase = "correct horse battery staple test only"
    sealed = _build_sealed_artifact(tmp_path, fixture_key, passphrase)
    creds = tmp_path / "creds"
    _place_credentials(creds, sealed, passphrase)

    result = _run_unlock(
        creds,
        expected_pub=_pub_hex(fixture_key),
    )

    assert result.returncode == 0, result.stderr
    out_file = _runtime_dir(creds) / "path-b-recording-signing-key"
    assert out_file.exists()
    assert out_file.read_text() == _seed_hex(fixture_key)
    assert oct(out_file.stat().st_mode)[-3:] == "600"


# ---------------------------------------------------------------------------
# Wrong configured kid
# ---------------------------------------------------------------------------

def test_wrong_configured_kid_fails_closed_before_decrypt(tmp_path, fixture_key):
    passphrase = "correct horse battery staple test only"
    sealed = _build_sealed_artifact(tmp_path, fixture_key, passphrase)
    creds = tmp_path / "creds"
    _place_credentials(creds, sealed, passphrase)

    result = _run_unlock(
        creds,
        configured_kid="defaultverifier-recording-ed25519-1",
        expected_pub=_pub_hex(fixture_key),
    )

    assert result.returncode != 0
    assert "kid" in result.stderr
    assert not (_runtime_dir(creds) / "path-b-recording-signing-key").exists()


def test_missing_configured_kid_fails_closed(tmp_path, fixture_key):
    passphrase = "correct horse battery staple test only"
    sealed = _build_sealed_artifact(tmp_path, fixture_key, passphrase)
    creds = tmp_path / "creds"
    _place_credentials(creds, sealed, passphrase)

    result = _run_unlock(creds, configured_kid="", expected_pub=_pub_hex(fixture_key))

    assert result.returncode != 0
    assert not (_runtime_dir(creds) / "path-b-recording-signing-key").exists()


# ---------------------------------------------------------------------------
# Wrong / mismatched public key
# ---------------------------------------------------------------------------

def test_wrong_public_key_fails_closed(tmp_path, fixture_key):
    passphrase = "correct horse battery staple test only"
    sealed = _build_sealed_artifact(tmp_path, fixture_key, passphrase)
    creds = tmp_path / "creds"
    _place_credentials(creds, sealed, passphrase)

    other_key_pub = _pub_hex(Ed25519PrivateKey.generate())
    result = _run_unlock(creds, expected_pub=other_key_pub)

    assert result.returncode != 0
    assert "public key" in result.stderr
    assert not (_runtime_dir(creds) / "path-b-recording-signing-key").exists()


# ---------------------------------------------------------------------------
# Missing credentials
# ---------------------------------------------------------------------------

def test_missing_sealed_credential_fails_closed(tmp_path, fixture_key):
    passphrase = "correct horse battery staple test only"
    creds = tmp_path / "creds"
    creds.mkdir()
    (creds / "path-b-recording-passphrase").write_text(passphrase)

    result = _run_unlock(creds, expected_pub=_pub_hex(fixture_key))

    assert result.returncode != 0
    assert "sealed credential" in result.stderr
    assert not (_runtime_dir(creds) / "path-b-recording-signing-key").exists()


def test_missing_passphrase_credential_fails_closed(tmp_path, fixture_key):
    passphrase = "correct horse battery staple test only"
    sealed = _build_sealed_artifact(tmp_path, fixture_key, passphrase)
    creds = tmp_path / "creds"
    creds.mkdir()
    (creds / "path-b-recording-key-sealed").write_bytes(sealed.read_bytes())

    result = _run_unlock(creds, expected_pub=_pub_hex(fixture_key))

    assert result.returncode != 0
    assert "passphrase credential" in result.stderr
    assert not (_runtime_dir(creds) / "path-b-recording-signing-key").exists()


def test_wrong_passphrase_fails_closed(tmp_path, fixture_key):
    sealed = _build_sealed_artifact(tmp_path, fixture_key, "the-real-passphrase")
    creds = tmp_path / "creds"
    _place_credentials(creds, sealed, "not-the-real-passphrase")

    result = _run_unlock(creds, expected_pub=_pub_hex(fixture_key))

    assert result.returncode != 0
    assert not (_runtime_dir(creds) / "path-b-recording-signing-key").exists()


# ---------------------------------------------------------------------------
# Malformed archive contents
# ---------------------------------------------------------------------------

def test_malformed_archive_missing_seed_hex_fails_closed(tmp_path, fixture_key):
    passphrase = "correct horse battery staple test only"
    sealed = _build_sealed_artifact(
        tmp_path, fixture_key, passphrase, omit_seed_hex=True
    )
    creds = tmp_path / "creds"
    _place_credentials(creds, sealed, passphrase)

    result = _run_unlock(creds, expected_pub=_pub_hex(fixture_key))

    assert result.returncode != 0
    assert "seed.hex missing" in result.stderr
    assert not (_runtime_dir(creds) / "path-b-recording-signing-key").exists()


def test_malformed_archive_missing_seed_pem_fails_closed(tmp_path, fixture_key):
    passphrase = "correct horse battery staple test only"
    sealed = _build_sealed_artifact(
        tmp_path, fixture_key, passphrase, omit_seed_pem=True
    )
    creds = tmp_path / "creds"
    _place_credentials(creds, sealed, passphrase)

    result = _run_unlock(creds, expected_pub=_pub_hex(fixture_key))

    assert result.returncode != 0
    assert "seed.pem missing" in result.stderr
    assert not (_runtime_dir(creds) / "path-b-recording-signing-key").exists()


def test_malformed_seed_hex_shape_fails_closed(tmp_path, fixture_key):
    passphrase = "correct horse battery staple test only"
    sealed = _build_sealed_artifact(
        tmp_path, fixture_key, passphrase, corrupt_seed_hex=True
    )
    creds = tmp_path / "creds"
    _place_credentials(creds, sealed, passphrase)

    result = _run_unlock(creds, expected_pub=_pub_hex(fixture_key))

    assert result.returncode != 0
    assert "seed.hex is not 64 lowercase hex" in result.stderr
    assert not (_runtime_dir(creds) / "path-b-recording-signing-key").exists()


# ---------------------------------------------------------------------------
# No secret leakage
# ---------------------------------------------------------------------------

def test_no_secret_leakage_on_success(tmp_path, fixture_key):
    passphrase = "correct horse battery staple test only"
    sealed = _build_sealed_artifact(tmp_path, fixture_key, passphrase)
    creds = tmp_path / "creds"
    _place_credentials(creds, sealed, passphrase)

    result = _run_unlock(creds, expected_pub=_pub_hex(fixture_key))

    seed_hex = _seed_hex(fixture_key)
    combined = result.stdout + result.stderr
    assert passphrase not in combined
    assert seed_hex not in combined


def test_no_secret_leakage_on_every_failure_path(tmp_path, fixture_key):
    passphrase = "correct horse battery staple test only"
    seed_hex = _seed_hex(fixture_key)

    scenarios = []

    # wrong passphrase
    sealed_wrong_pass = _build_sealed_artifact(tmp_path, fixture_key, passphrase)
    creds1 = tmp_path / "creds1"
    _place_credentials(creds1, sealed_wrong_pass, "wrong-passphrase")
    scenarios.append(lambda: _run_unlock(creds1, expected_pub=_pub_hex(fixture_key)))

    # wrong public key
    sealed_ok = _build_sealed_artifact(tmp_path, fixture_key, passphrase)
    creds2 = tmp_path / "creds2"
    _place_credentials(creds2, sealed_ok, passphrase)
    scenarios.append(
        lambda: _run_unlock(
            creds2, expected_pub=_pub_hex(Ed25519PrivateKey.generate())
        )
    )

    # malformed seed.hex
    sealed_bad_seed = _build_sealed_artifact(
        tmp_path, fixture_key, passphrase, corrupt_seed_hex=True
    )
    creds3 = tmp_path / "creds3"
    _place_credentials(creds3, sealed_bad_seed, passphrase)
    scenarios.append(lambda: _run_unlock(creds3, expected_pub=_pub_hex(fixture_key)))

    for scenario in scenarios:
        result = scenario()
        assert result.returncode != 0
        combined = result.stdout + result.stderr
        assert passphrase not in combined
        assert seed_hex not in combined


def test_ephemeral_working_directory_not_left_behind(tmp_path, fixture_key):
    passphrase = "correct horse battery staple test only"
    sealed = _build_sealed_artifact(tmp_path, fixture_key, passphrase)
    creds = tmp_path / "creds"
    _place_credentials(creds, sealed, passphrase)

    _run_unlock(creds, expected_pub=_pub_hex(fixture_key))

    leftovers = [
        p for p in _runtime_dir(creds).iterdir()
        if p.name.startswith("pathb-unlock.")
    ]
    assert leftovers == []
