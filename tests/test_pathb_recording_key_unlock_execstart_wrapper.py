"""Tests for the SAR-402 Path B ExecStart= unlock wrapper
(``scripts/pathb-recording-key-unlock-execstart-wrapper.sh``), which
supersedes the rejected ExecStartPre= design after the 2026-07-11
production incident (see
``reports/external-actions/sar-402-path-b-runtime-unlock-service-activation-validation-20260710.md``).

All keys/passphrases here are ephemeral, per-test fixtures — never the
real, encrypted ``defaultverifier-recording-ed25519-2`` custody artifact.

The wrapper is invoked as a real subprocess (not sourced/mocked) against
temporary directories standing in for systemd's read-only
$CREDENTIALS_DIRECTORY and writable $RUNTIME_DIRECTORY, with
$PATHB_WRAPPER_REAL_CMD substituted for the real attest-service start
command so tests can observe the exec handoff without launching uvicorn.

Covers:
  * successful unlock -> PATH_B_RECORDING_PRIVATE_KEY_FILE exported into
    the exec'd process's environment, real command still runs;
  * wrong configured kid / wrong public key / missing credential /
    malformed artifact all fail the *unlock* but the wrapper still execs
    the real command (Path B failure must never block attest-service
    startup — the governing invariant this design exists to enforce);
  * no secret value ever appears in stdout/stderr on any path;
  * ephemeral scratch directory cleaned up on both success and failure;
  * the final decrypted seed file persists (only on success) for the
    exec'd process to consume, with 0600 permissions;
  * exec handoff genuinely replaces the process image (same PID), not a
    fork+exec that would break systemd's PID tracking.
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
SCRIPT = ROOT / "scripts" / "pathb-recording-key-unlock-execstart-wrapper.sh"

EXPECTED_KID = "defaultverifier-recording-ed25519-2"
EXPECTED_PUBLIC_KEY_HEX = (
    "e8608e251cce27bfe497da27e97a08d3e1efca4bd4809fb6364fb2af9a34f29e"
)

MARKER_CMD = "/bin/sh -c 'echo MARKER_EXEC_OK; echo PIDIS:$$; env | grep PATH_B_RECORDING_PRIVATE_KEY_FILE || echo NOKEYVAR'"


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


def _place_credentials(creds_dir: Path, sealed: Path, passphrase: str):
    creds_dir.mkdir(parents=True, exist_ok=True)
    (creds_dir / "path-b-recording-key-sealed").write_bytes(sealed.read_bytes())
    (creds_dir / "path-b-recording-passphrase").write_text(passphrase)


def _run_wrapper(creds_dir: Path, runtime_dir: Path, *,
                  configured_kid: str = EXPECTED_KID,
                  expected_kid: str = EXPECTED_KID,
                  expected_pub: str = EXPECTED_PUBLIC_KEY_HEX,
                  set_creds_dir: bool = True,
                  set_runtime_dir: bool = True):
    runtime_dir.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    if set_creds_dir:
        env["CREDENTIALS_DIRECTORY"] = str(creds_dir)
    else:
        env.pop("CREDENTIALS_DIRECTORY", None)
    if set_runtime_dir:
        env["RUNTIME_DIRECTORY"] = str(runtime_dir)
    else:
        env.pop("RUNTIME_DIRECTORY", None)
    env["PATH_B_RECORDING_KID"] = configured_kid
    env["PATHB_EXPECTED_KID"] = expected_kid
    env["PATHB_EXPECTED_PUBLIC_KEY_HEX"] = expected_pub
    env["PATHB_WRAPPER_REAL_CMD"] = MARKER_CMD
    return subprocess.Popen(
        ["bash", str(SCRIPT)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


# ---------------------------------------------------------------------------
# Success path
# ---------------------------------------------------------------------------

def test_successful_unlock_exports_key_file_and_execs_real_command(tmp_path, fixture_key):
    passphrase = "correct horse battery staple test only"
    sealed = _build_sealed_artifact(tmp_path, fixture_key, passphrase)
    creds = tmp_path / "creds"
    runtime = tmp_path / "runtime"
    _place_credentials(creds, sealed, passphrase)

    proc = _run_wrapper(creds, runtime, expected_pub=_pub_hex(fixture_key))
    stdout, stderr = proc.communicate(timeout=20)

    assert proc.returncode == 0, stderr
    assert "MARKER_EXEC_OK" in stdout
    assert "PATH_B_RECORDING_PRIVATE_KEY_FILE=" in stdout
    assert "NOKEYVAR" not in stdout.splitlines()
    assert "Path B unlock succeeded" in stderr

    out_file = runtime / "path-b-recording-signing-key"
    assert out_file.exists()
    assert out_file.read_text() == _seed_hex(fixture_key)
    assert oct(out_file.stat().st_mode)[-3:] == "600"


def test_exec_handoff_preserves_pid(tmp_path, fixture_key):
    """The wrapper must `exec` the real command, not fork+exec, so systemd's
    $MAINPID tracking stays correct."""
    passphrase = "correct horse battery staple test only"
    sealed = _build_sealed_artifact(tmp_path, fixture_key, passphrase)
    creds = tmp_path / "creds"
    runtime = tmp_path / "runtime"
    _place_credentials(creds, sealed, passphrase)

    proc = _run_wrapper(creds, runtime, expected_pub=_pub_hex(fixture_key))
    launched_pid = proc.pid
    stdout, stderr = proc.communicate(timeout=20)

    pid_line = next(line for line in stdout.splitlines() if line.startswith("PIDIS:"))
    reported_pid = int(pid_line.split(":", 1)[1])
    assert reported_pid == launched_pid


# ---------------------------------------------------------------------------
# Failures are non-fatal to the exec handoff (the governing invariant)
# ---------------------------------------------------------------------------

def test_wrong_kid_fails_unlock_but_still_execs_real_command(tmp_path, fixture_key):
    passphrase = "correct horse battery staple test only"
    sealed = _build_sealed_artifact(tmp_path, fixture_key, passphrase)
    creds = tmp_path / "creds"
    runtime = tmp_path / "runtime"
    _place_credentials(creds, sealed, passphrase)

    proc = _run_wrapper(
        creds, runtime,
        configured_kid="defaultverifier-recording-ed25519-1",
        expected_pub=_pub_hex(fixture_key),
    )
    stdout, stderr = proc.communicate(timeout=20)

    assert proc.returncode == 0, stderr
    assert "MARKER_EXEC_OK" in stdout
    assert "NOKEYVAR" in stdout
    assert "kid" in stderr
    assert "continuing attest-service startup without Path B signing capability" in stderr
    assert not (runtime / "path-b-recording-signing-key").exists()


def test_wrong_public_key_fails_unlock_but_still_execs_real_command(tmp_path, fixture_key):
    passphrase = "correct horse battery staple test only"
    sealed = _build_sealed_artifact(tmp_path, fixture_key, passphrase)
    creds = tmp_path / "creds"
    runtime = tmp_path / "runtime"
    _place_credentials(creds, sealed, passphrase)

    other_pub = _pub_hex(Ed25519PrivateKey.generate())
    proc = _run_wrapper(creds, runtime, expected_pub=other_pub)
    stdout, stderr = proc.communicate(timeout=20)

    assert proc.returncode == 0, stderr
    assert "MARKER_EXEC_OK" in stdout
    assert "NOKEYVAR" in stdout
    assert "public key" in stderr
    assert not (runtime / "path-b-recording-signing-key").exists()


def test_missing_sealed_credential_fails_unlock_but_still_execs(tmp_path, fixture_key):
    passphrase = "correct horse battery staple test only"
    creds = tmp_path / "creds"
    runtime = tmp_path / "runtime"
    creds.mkdir()
    (creds / "path-b-recording-passphrase").write_text(passphrase)

    proc = _run_wrapper(creds, runtime, expected_pub=_pub_hex(fixture_key))
    stdout, stderr = proc.communicate(timeout=20)

    assert proc.returncode == 0, stderr
    assert "MARKER_EXEC_OK" in stdout
    assert "NOKEYVAR" in stdout
    assert "sealed credential" in stderr
    assert not (runtime / "path-b-recording-signing-key").exists()


def test_missing_passphrase_credential_fails_unlock_but_still_execs(tmp_path, fixture_key):
    passphrase = "correct horse battery staple test only"
    sealed = _build_sealed_artifact(tmp_path, fixture_key, passphrase)
    creds = tmp_path / "creds"
    runtime = tmp_path / "runtime"
    creds.mkdir()
    (creds / "path-b-recording-key-sealed").write_bytes(sealed.read_bytes())

    proc = _run_wrapper(creds, runtime, expected_pub=_pub_hex(fixture_key))
    stdout, stderr = proc.communicate(timeout=20)

    assert proc.returncode == 0, stderr
    assert "MARKER_EXEC_OK" in stdout
    assert "NOKEYVAR" in stdout
    assert "passphrase credential" in stderr


def test_malformed_archive_missing_seed_hex_fails_unlock_but_still_execs(tmp_path, fixture_key):
    passphrase = "correct horse battery staple test only"
    sealed = _build_sealed_artifact(tmp_path, fixture_key, passphrase, omit_seed_hex=True)
    creds = tmp_path / "creds"
    runtime = tmp_path / "runtime"
    _place_credentials(creds, sealed, passphrase)

    proc = _run_wrapper(creds, runtime, expected_pub=_pub_hex(fixture_key))
    stdout, stderr = proc.communicate(timeout=20)

    assert proc.returncode == 0, stderr
    assert "MARKER_EXEC_OK" in stdout
    assert "seed.hex missing" in stderr
    assert not (runtime / "path-b-recording-signing-key").exists()


def test_malformed_seed_hex_shape_fails_unlock_but_still_execs(tmp_path, fixture_key):
    passphrase = "correct horse battery staple test only"
    sealed = _build_sealed_artifact(tmp_path, fixture_key, passphrase, corrupt_seed_hex=True)
    creds = tmp_path / "creds"
    runtime = tmp_path / "runtime"
    _place_credentials(creds, sealed, passphrase)

    proc = _run_wrapper(creds, runtime, expected_pub=_pub_hex(fixture_key))
    stdout, stderr = proc.communicate(timeout=20)

    assert proc.returncode == 0, stderr
    assert "MARKER_EXEC_OK" in stdout
    assert "not 64 lowercase hex" in stderr
    assert not (runtime / "path-b-recording-signing-key").exists()


def test_missing_credentials_directory_fails_unlock_but_still_execs(tmp_path, fixture_key):
    creds = tmp_path / "creds"
    runtime = tmp_path / "runtime"

    proc = _run_wrapper(creds, runtime, expected_pub=_pub_hex(fixture_key), set_creds_dir=False)
    stdout, stderr = proc.communicate(timeout=20)

    assert proc.returncode == 0, stderr
    assert "MARKER_EXEC_OK" in stdout
    assert "CREDENTIALS_DIRECTORY not set" in stderr


def test_missing_runtime_directory_fails_unlock_but_still_execs(tmp_path, fixture_key):
    passphrase = "correct horse battery staple test only"
    sealed = _build_sealed_artifact(tmp_path, fixture_key, passphrase)
    creds = tmp_path / "creds"
    runtime = tmp_path / "runtime"
    _place_credentials(creds, sealed, passphrase)

    proc = _run_wrapper(creds, runtime, expected_pub=_pub_hex(fixture_key), set_runtime_dir=False)
    stdout, stderr = proc.communicate(timeout=20)

    assert proc.returncode == 0, stderr
    assert "MARKER_EXEC_OK" in stdout
    assert "RUNTIME_DIRECTORY not set" in stderr


# ---------------------------------------------------------------------------
# No secret leakage
# ---------------------------------------------------------------------------

def test_no_secret_leakage_across_all_paths(tmp_path, fixture_key):
    passphrase = "correct horse battery staple test only"
    seed_hex = _seed_hex(fixture_key)

    runs = []

    sealed_ok = _build_sealed_artifact(tmp_path, fixture_key, passphrase)
    creds_ok = tmp_path / "creds-ok"
    runtime_ok = tmp_path / "runtime-ok"
    _place_credentials(creds_ok, sealed_ok, passphrase)
    runs.append(_run_wrapper(creds_ok, runtime_ok, expected_pub=_pub_hex(fixture_key)))

    creds_wrongpass = tmp_path / "creds-wrongpass"
    runtime_wrongpass = tmp_path / "runtime-wrongpass"
    _place_credentials(creds_wrongpass, sealed_ok, "definitely-wrong-passphrase")
    runs.append(_run_wrapper(creds_wrongpass, runtime_wrongpass, expected_pub=_pub_hex(fixture_key)))

    creds_wrongpub = tmp_path / "creds-wrongpub"
    runtime_wrongpub = tmp_path / "runtime-wrongpub"
    _place_credentials(creds_wrongpub, sealed_ok, passphrase)
    runs.append(_run_wrapper(
        creds_wrongpub, runtime_wrongpub,
        expected_pub=_pub_hex(Ed25519PrivateKey.generate()),
    ))

    for proc in runs:
        stdout, stderr = proc.communicate(timeout=20)
        assert proc.returncode == 0
        assert "MARKER_EXEC_OK" in stdout
        combined = stdout + stderr
        assert passphrase not in combined
        assert "definitely-wrong-passphrase" not in combined
        assert seed_hex not in combined


# ---------------------------------------------------------------------------
# Cleanup behavior
# ---------------------------------------------------------------------------

def test_scratch_directory_cleaned_up_on_success(tmp_path, fixture_key):
    passphrase = "correct horse battery staple test only"
    sealed = _build_sealed_artifact(tmp_path, fixture_key, passphrase)
    creds = tmp_path / "creds"
    runtime = tmp_path / "runtime"
    _place_credentials(creds, sealed, passphrase)

    proc = _run_wrapper(creds, runtime, expected_pub=_pub_hex(fixture_key))
    proc.communicate(timeout=20)

    leftovers = [p for p in runtime.iterdir() if p.name.startswith("pathb-unlock.")]
    assert leftovers == []
    # the final key file itself is NOT scratch — it must persist for the
    # exec'd process to consume
    assert (runtime / "path-b-recording-signing-key").exists()


def test_scratch_directory_cleaned_up_on_failure(tmp_path, fixture_key):
    passphrase = "correct horse battery staple test only"
    sealed = _build_sealed_artifact(tmp_path, fixture_key, passphrase, corrupt_seed_hex=True)
    creds = tmp_path / "creds"
    runtime = tmp_path / "runtime"
    _place_credentials(creds, sealed, passphrase)

    proc = _run_wrapper(creds, runtime, expected_pub=_pub_hex(fixture_key))
    proc.communicate(timeout=20)

    leftovers = [p for p in runtime.iterdir() if p.name.startswith("pathb-unlock.")]
    assert leftovers == []
    assert not (runtime / "path-b-recording-signing-key").exists()
