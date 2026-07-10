#!/usr/bin/env python3
"""SAR-402 Path B: complete local development round trip.

    local Path B signer
            |
            v
    SAR-402 receipt generation
            |
            v
    local verifier
            |
            v
    receipt verification

Exercises the *real* production credential-loader architecture
(``sar402_pathb_credential.py`` and ``sar402_recording_wrapper.py``,
byte-for-byte unmodified) against a local development key and a Path A
receipt built with ``persist=False`` (never written to the production
ledger). No production endpoint, production key, or production registry is
contacted anywhere in this path.

Fail-closed behavior is identical to production: a missing credential file,
wrong kid, or public/private key mismatch aborts before any signing happens
(``sar402_pathb_credential.startup_coherence_gate``).

Never prints, logs, or returns private key material — only the safe result
fields (kid, wrapped receipt id/digest, timestamps, verified bool).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Optional

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
for p in (str(REPO_ROOT), str(HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)

import sar402_pathb_credential as cred  # noqa: E402
from sar402_recording_wrapper import (  # noqa: E402
    build_recording_wrapper,
    verify_recording_wrapper,
)
from local_credential_profile import DEV_KID, ENV_KEYS  # noqa: E402


class LocalRoundtripError(Exception):
    """A refusal/abort condition. Messages never contain key material."""


def parse_env_file(path: Path) -> dict[str, str]:
    """Read ONLY the three PATH_B_RECORDING_* vars from a shell-style env file.

    Mirrors ``scripts/sar402_pathb_wrap_receipt.py``'s ``parse_env_file`` so
    the local dev workflow and the production operator script share the same
    narrow, auditable env-file parsing convention."""
    if not path.exists():
        raise LocalRoundtripError(f"env file not found: {path}")
    env: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key not in ENV_KEYS:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        env[key] = value
    return env


def build_sample_path_a_receipt(tag: str = "path-b-local-dev") -> dict[str, Any]:
    """A Path A SAR-402 receipt built for local use only, never persisted.

    Imports ``sar402_receipts`` lazily (it bootstraps the morpheus package
    path via ``attest_service`` on import, matching the existing test
    convention) and calls ``record_sar402_receipt(..., persist=False)`` so no
    write ever reaches the production ledger. Reuses the exact SDK-shaped
    fixture payload the ingestion tests already validate against
    (``tests/test_sar402_receipts.py::_unique_payload``), rather than a
    hand-rolled shape that would drift from the real schema."""
    import attest_service as _svc  # noqa: F401
    from sar402_receipts import record_sar402_receipt

    tests_dir = REPO_ROOT / "tests"
    if str(tests_dir) not in sys.path:
        sys.path.insert(0, str(tests_dir))
    from test_sar402_receipts import _unique_payload

    payload = _unique_payload(tag)
    return record_sar402_receipt(payload, persist=False)["receipt"]


def run_roundtrip(env: Mapping[str, str]) -> dict[str, Any]:
    """Full local signer -> receipt -> verifier round trip.

    Returns only safe, non-secret fields. Raises ``LocalRoundtripError`` /
    ``sar402_pathb_credential.PathBCredentialError`` fail-closed on any
    misconfiguration, before any signing is attempted."""
    configured_kid = cred.load_configured_kid(env)
    expected_public_key_hex = cred.load_expected_public_key_hex(env)
    key_path = cred.resolve_private_key_path(env)
    private_key = cred.load_private_key_from_file(key_path)

    derived = cred.startup_coherence_gate(
        configured_kid=configured_kid,
        expected_public_key_hex=expected_public_key_hex,
        private_key=private_key,
        producer_supported_kids=[DEV_KID],
    )

    receipt = build_sample_path_a_receipt()
    wrapper = build_recording_wrapper(
        receipt,
        signing_key=private_key,
        kid=configured_kid,
        recording_context="observation",
    )
    verified = verify_recording_wrapper(wrapper, public_key=private_key.public_key())

    return {
        "kid": wrapper["recording_key_id"],
        "public_key_fingerprint": cred.fingerprint(derived),
        "wrapped_receipt_id": wrapper["wrapped_receipt_id"],
        "wrapped_receipt_digest": wrapper["wrapped_receipt_digest"],
        "observed_at": wrapper["observed_at"],
        "recorded_at": wrapper["recorded_at"],
        "signed_at": wrapper["signed_at"],
        "wrapper_type": wrapper["wrapper_type"],
        "recording_context": wrapper["recording_context"],
        "verified": verified,
        "production_endpoint_contacted": False,
    }


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--env-file",
        default=str(HERE / ".env.local"),
        help="local env file with the three PATH_B_RECORDING_* vars "
        "(default: dev/path-b-local/.env.local, gitignored)",
    )
    args = parser.parse_args(argv)

    try:
        env = parse_env_file(Path(args.env_file))
        result = run_roundtrip(env)
    except (LocalRoundtripError, cred.PathBCredentialError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    for key, value in result.items():
        print(f"{key}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
