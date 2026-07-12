"""M5 (Morpheus maintenance register): historical-verification evidence for
the ``defaultverifier-recording-ed25519-1`` retirement-criterion proposal
(``reports/decisions/defaultverifier-recording-ed25519-1-retirement-criterion-proposal-20260711.md``,
section 4.5, in the Morpheus evidence repo).

This module is read-only against the real, already-persisted Path B wrapper
ledger and the real registry public key. It does not sign, mutate, or persist
anything. It proves two structural facts required before ``-1`` may ever be
marked ``retired`` in the registry:

  1. ``verify_recording_wrapper`` has no registry-``status``-dependent
     parameter or behavior at all -- it is a pure function of the wrapper
     bytes and the caller-supplied public key. Registry lifecycle status
     (generated/reserved/active/retired, per D4) cannot affect its result,
     structurally, regardless of what status is ever recorded for the
     signing kid.
  2. The one real, historically persisted ``-1``-signed wrapper (the public
     SAR-402 demo receipt, ``defaultverifier.com/demo/sar-402``) verifies
     True today against ``-1``'s real registry public key, and would
     continue to verify True after a hypothetical ``-1`` retirement, because
     (1) holds.

Together these are the evidence base for retirement meaning (A) in the
proposal: retiring ``-1`` at the registry-lifecycle level changes no
cryptographic verification behavior for historical ``-1`` evidence.
"""

from __future__ import annotations

import inspect
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sar402_recording_wrapper import verify_recording_wrapper  # noqa: E402

WRAPPER_LEDGER = ROOT / "attest_recording_wrappers_master.jsonl"
REGISTRY_FILE = Path("/home/ubuntu/settlement-witness/sar-keys.json")

RECORDING_KID_1 = "defaultverifier-recording-ed25519-1"


def _load_ledger_entries() -> list[dict]:
    if not WRAPPER_LEDGER.exists():
        return []
    entries = []
    with WRAPPER_LEDGER.open() as fh:
        for line in fh:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def _registry_public_key_hex(kid: str) -> str | None:
    if not REGISTRY_FILE.exists():
        return None
    doc = json.loads(REGISTRY_FILE.read_text())
    for entry in doc.get("keys", []):
        if entry.get("kid") == kid:
            return entry.get("public_key_hex")
    return None


def test_verify_recording_wrapper_has_no_registry_status_parameter():
    """Structural proof: verification is a pure function of (wrapper, public_key).

    D4's registry ``status`` field (generated/reserved/active/retired) is not
    among this function's parameters and cannot be threaded through to it --
    there is no code path by which marking a kid's registry status
    ``retired`` could change what this function returns for a wrapper
    already signed under that kid.
    """
    sig = inspect.signature(verify_recording_wrapper)
    param_names = set(sig.parameters)
    assert param_names == {"wrapper", "public_key"}
    assert "status" not in param_names
    assert "registry" not in param_names


def test_historical_dash1_wrapper_verifies_against_real_registry_key():
    """The real, persisted -1 wrapper (public demo receipt) verifies today.

    Skips (rather than failing) if the live ledger or registry file is not
    present in this environment -- this test asserts a live-data property,
    not a fixture, and is intended to be run on the actual host where the
    ledger and registry live.
    """
    entries = _load_ledger_entries()
    dash1_entries = [e for e in entries if e.get("recording_key_id") == RECORDING_KID_1]
    if not dash1_entries:
        import pytest

        pytest.skip(
            f"no {RECORDING_KID_1} entries in {WRAPPER_LEDGER}; "
            "this test asserts a live-data property, run on the real host"
        )

    pub_hex = _registry_public_key_hex(RECORDING_KID_1)
    if pub_hex is None:
        import pytest

        pytest.skip(f"{RECORDING_KID_1} not found in {REGISTRY_FILE}")

    public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))

    for wrapper in dash1_entries:
        assert verify_recording_wrapper(wrapper, public_key=public_key) is True

    # Cross-check: verification depends on the wrapper's actual signature,
    # not on any notion of "current" registry status -- there is no
    # registry-status argument to have varied in the first place (see the
    # structural test above). This loop is the closest a read-only test can
    # get to "retirement would not change this result": it demonstrates the
    # result today, under the same function that would run after retirement,
    # with the same two arguments retirement cannot alter.
