"""Tests for the SAR-402 Path B operator script `scripts/sar402_pathb_wrap_receipt.py`.

These prove the operator step end-to-end WITHOUT production keys, without the
real Path A / Path B ledgers, and without the real /etc/default/attest-service:

  * a missing receipt aborts nonzero;
  * a missing signing key aborts nonzero;
  * a wrong kid aborts nonzero;
  * --dry-run builds but never writes;
  * a successful run writes through the store;
  * a re-run with the same wrapper is idempotent (no second write);
  * a conflicting wrapper for the same receipt aborts safely (nonzero).

All signing uses an ephemeral, per-process test keypair. No production key, no
real ledger, no env-file mutation of real key material.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT), str(ROOT / "scripts")):
    if p not in sys.path:
        sys.path.insert(0, p)

# Importing attest_service first puts the morpheus package on sys.path (via
# pay_url_summary), matching how the other SAR-402 tests bootstrap.
import attest_service as _svc  # noqa: E402,F401
import sar402_recording_store as store  # noqa: E402
import sar402_pathb_wrap_receipt as script  # noqa: E402
from sar402_recording_wrapper import build_recording_wrapper  # noqa: E402
from sar402_receipts import record_sar402_receipt  # noqa: E402

from test_sar402_receipts import _unique_payload  # noqa: E402

# Ephemeral test key + the script's pinned production kid (so the kid gate
# passes for the happy-path tests). The SEED is a test seed, never published.
_TEST_SIGNING_KEY = Ed25519PrivateKey.generate()
_TEST_SEED_HEX = _TEST_SIGNING_KEY.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption(),
).hex()
PINNED_KID = script.EXPECTED_KID


def _inner_receipt(tag: str) -> dict:
    return record_sar402_receipt(_unique_payload(tag), persist=False)["receipt"]


def _write_path_a_record(ledger: Path, inner: dict) -> str:
    """Append a Path A ledger record (top-level receipt_id + nested receipt)."""
    import json

    receipt_id = inner["receipt_id"]
    record = {"receipt_id": receipt_id, "receipt_type": "sar402", "receipt": inner}
    with ledger.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
    return receipt_id


def _env_file(tmp_path: Path, *, seed_hex: str | None, kid: str | None) -> Path:
    lines = []
    if seed_hex is not None:
        lines.append(f"SAR402_RECORDING_SIGNING_KEY_HEX={seed_hex}")
    if kid is not None:
        lines.append(f"SAR402_RECORDING_KID={kid}")
    path = tmp_path / "recording.env"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """Point both ledgers at temp files so no real store is ever touched."""
    receipt_ledger = tmp_path / "receipts.jsonl"
    wrapper_ledger = tmp_path / "recording_wrappers.jsonl"
    monkeypatch.setattr(script, "RECEIPT_LEDGER", receipt_ledger)
    monkeypatch.setattr(store, "RECORDING_WRAPPER_LEDGER", wrapper_ledger)
    return receipt_ledger, wrapper_ledger


def _good_env(tmp_path) -> Path:
    return _env_file(tmp_path, seed_hex=_TEST_SEED_HEX, kid=PINNED_KID)


# ---------------------------------------------------------------------------
# Refusals
# ---------------------------------------------------------------------------

def test_missing_receipt_fails(isolated, tmp_path):
    env = _good_env(tmp_path)
    rc = script.main(
        ["--receipt-id", "sha256:" + "0" * 64, "--env-file", str(env)]
    )
    assert rc != 0


def test_missing_signing_key_fails(isolated, tmp_path):
    receipt_ledger, _ = isolated
    rid = _write_path_a_record(receipt_ledger, _inner_receipt("nokey"))
    env = _env_file(tmp_path, seed_hex=None, kid=PINNED_KID)
    rc = script.main(["--receipt-id", rid, "--env-file", str(env)])
    assert rc != 0


def test_wrong_kid_fails(isolated, tmp_path):
    receipt_ledger, wrapper_ledger = isolated
    rid = _write_path_a_record(receipt_ledger, _inner_receipt("badkid"))
    env = _env_file(tmp_path, seed_hex=_TEST_SEED_HEX, kid="some-other-kid")
    rc = script.main(["--receipt-id", rid, "--env-file", str(env)])
    assert rc != 0
    assert not wrapper_ledger.exists()


# ---------------------------------------------------------------------------
# Dry-run / write / idempotency / conflict
# ---------------------------------------------------------------------------

def test_dry_run_does_not_write(isolated, tmp_path):
    receipt_ledger, wrapper_ledger = isolated
    rid = _write_path_a_record(receipt_ledger, _inner_receipt("dry"))
    env = _good_env(tmp_path)
    rc = script.main(["--receipt-id", rid, "--env-file", str(env), "--dry-run"])
    assert rc == 0
    assert store.get_recording_wrapper(rid) is None
    assert not wrapper_ledger.exists()


def test_successful_write_calls_store(isolated, tmp_path, monkeypatch):
    receipt_ledger, _ = isolated
    rid = _write_path_a_record(receipt_ledger, _inner_receipt("write"))
    env = _good_env(tmp_path)

    calls = []
    real_store = store.store_recording_wrapper

    def _spy(wrapper):
        calls.append(wrapper)
        return real_store(wrapper)

    monkeypatch.setattr(script, "store_recording_wrapper", _spy)

    rc = script.main(["--receipt-id", rid, "--env-file", str(env)])
    assert rc == 0
    assert len(calls) == 1
    stored = store.get_recording_wrapper(rid)
    assert stored is not None
    assert stored["recording_key_id"] == PINNED_KID


def test_idempotent_existing_wrapper(isolated, tmp_path):
    receipt_ledger, _ = isolated
    inner = _inner_receipt("idem")
    rid = _write_path_a_record(receipt_ledger, inner)
    env = _good_env(tmp_path)

    # Pre-seed an equivalent wrapper using the SAME key/kid + fixed timestamps so
    # the script's rebuilt wrapper is canonically identical (idempotent no-write).
    fixed = {
        "recording_event_id": "rec:fixed",
        "observed_at": "2026-06-24T00:00:00+00:00",
        "recorded_at": "2026-06-24T00:00:00+00:00",
        "signed_at": "2026-06-24T00:00:00+00:00",
    }
    pre = build_recording_wrapper(
        inner, signing_key=_TEST_SIGNING_KEY, kid=PINNED_KID, **fixed
    )
    assert store.store_recording_wrapper(pre) is True

    # Patch the script's builder to produce the identical wrapper.
    import sar402_pathb_wrap_receipt as scr

    def _build(receipt, *, signing_key, kid):
        return build_recording_wrapper(
            receipt, signing_key=signing_key, kid=kid, **fixed
        )

    scr.build_recording_wrapper = _build  # type: ignore[assignment]
    try:
        rc = scr.main(["--receipt-id", rid, "--env-file", str(env)])
    finally:
        scr.build_recording_wrapper = build_recording_wrapper  # type: ignore[assignment]
    assert rc == 0
    # Still exactly one record (no second append).
    _, wrapper_ledger = isolated
    assert wrapper_ledger.read_text().strip().count("\n") == 0


def test_conflict_handled(isolated, tmp_path):
    receipt_ledger, _ = isolated
    inner = _inner_receipt("conflict")
    rid = _write_path_a_record(receipt_ledger, inner)
    env = _good_env(tmp_path)

    # Pre-seed a DIFFERENT (but valid) wrapper for the same wrapped receipt.
    pre = build_recording_wrapper(
        inner,
        signing_key=_TEST_SIGNING_KEY,
        kid=PINNED_KID,
        recording_context="observation",
    )
    assert store.store_recording_wrapper(pre) is True

    rc = script.main(["--receipt-id", rid, "--env-file", str(env)])
    assert rc != 0
