#!/usr/bin/env python3
"""SAR-402 Path B operator step: wrap exactly ONE Path A receipt.

This is a small, auditable operator script. It takes one already-stored Path A
SAR-402 receipt (by inner ``receipt_id``), builds the governed
``sar402_recording_wrapper_v1`` recording-attribution envelope over it using the
PRODUCTION recording key supplied via environment variables, and persists it
through the existing recording store (``store_recording_wrapper``).

It does the one production wrapper step and nothing else: it never generates,
publishes, or prints key material; never touches Path A storage; never starts a
server; and never deploys. Path B remains "record-only" — the signature attests
to DefaultVerifier's RECORDING act, not to delivery, payment, access, release,
finality, or mainnet settlement (see the wrapper's ``authority_boundary``).

Key material is read via the dedicated Path B credential lane
(``sar402_pathb_credential.py``): ``PATH_B_RECORDING_PRIVATE_KEY_FILE``
(explicit path to a decrypted seed — e.g. the live, already-unlocked
``$RUNTIME_DIRECTORY/path-b-recording-signing-key`` from the running
``attest-service.service`` wrapper) or ``$CREDENTIALS_DIRECTORY``,
``PATH_B_RECORDING_KID``, and ``PATH_B_RECORDING_PUBLIC_KEY_HEX`` — never the
legacy ``SAR402_RECORDING_*`` names, which this script no longer reads. The
active production kid is pinned: the script refuses any kid other than
``defaultverifier-recording-ed25519-2`` (rotated 2026-07-11 from
``-1``, see
``reports/approvals/sar-402-path-b-producer-verifier-rotation-decision-20260710.md``
and
``reports/approvals/sar-402-path-b-production-rotation-execution-decision-20260711.md``).
It fails closed, with no fallback to any other key, on any credential-lane
error (missing/malformed credential, kid mismatch, derived-public-key
mismatch).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Optional

from sar402_recording_store import store_recording_wrapper, RecordingWrapperConflict
from sar402_recording_wrapper import build_recording_wrapper
import sar402_pathb_credential as pathb_credential

# Repo root is the parent of this scripts/ directory; the Path A receipt ledger
# follows attest_service.py's convention (BASE_DIR / "<name>_master.jsonl").
REPO_ROOT = Path(__file__).resolve().parents[1]
RECEIPT_LEDGER = REPO_ROOT / "attest_receipts_master.jsonl"

# The single active production recording kid (published at
# https://defaultverifier.com/.well-known/sar-keys.json). Any other kid is
# refused — this script does not mint or roll keys.
EXPECTED_KID = "defaultverifier-recording-ed25519-2"

# The three (and only three) env vars this script reads from an --env-file,
# now the dedicated Path B credential-lane namespace (never the legacy,
# shared SAR402_RECORDING_* names).
ENV_KEYS = (
    pathb_credential.ENV_PRIVATE_KEY_FILE,
    pathb_credential.ENV_PUBLIC_KEY_HEX,
    pathb_credential.ENV_KID,
)


class OperatorError(Exception):
    """A refusal/abort condition that maps to a nonzero exit with a clear message."""


def parse_env_file(path: Path) -> dict[str, str]:
    """Read ONLY the three Path B credential-lane vars from a shell-style env
    file.

    Lines look like ``KEY=value`` (optionally ``export KEY=value``), with ``#``
    comments and optional surrounding quotes. Any key not in ``ENV_KEYS`` is
    ignored, so unrelated secrets in the file are never loaded into memory."""
    if not path.exists():
        raise OperatorError(f"env file not found: {path}")
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


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    """Append-only JSONL reader (mirrors attest_service.read_jsonl)."""
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def _contains_receipt_id(value: Any, receipt_id: str) -> bool:
    """True if ``receipt_id`` appears under any ``receipt_id`` key in ``value``.

    Mirrors attest_service.contains_receipt_id so we match the same records the
    live read endpoint matches."""
    if isinstance(value, dict):
        for key, nested in value.items():
            if key == "receipt_id" and nested == receipt_id:
                return True
            if _contains_receipt_id(nested, receipt_id):
                return True
    if isinstance(value, list):
        return any(_contains_receipt_id(item, receipt_id) for item in value)
    return False


def find_inner_receipt(receipt_id: str, ledger: Path) -> Optional[dict[str, Any]]:
    """Locate the Path A ledger record for ``receipt_id`` and return its inner
    SAR payload.

    Follows attest_service.find_receipt (latest matching record wins). Per the
    Path A storage convention, the inner SAR-402 payload is carried under a
    top-level ``receipt`` field; when present we return that, otherwise the
    record itself."""
    latest: Optional[dict[str, Any]] = None
    for record in read_jsonl(ledger):
        if _contains_receipt_id(record, receipt_id):
            latest = record
    if latest is None:
        return None
    inner = latest.get("receipt")
    if isinstance(inner, dict):
        return inner
    return latest


def _safe_metadata(wrapper: Mapping[str, Any], *, written: bool, dry_run: bool) -> dict[str, Any]:
    """Public, non-secret fields only — never key material or the signature."""
    return {
        "written": written,
        "dry_run": dry_run,
        "kid": wrapper.get("recording_key_id"),
        "wrapped_receipt_id": wrapper.get("wrapped_receipt_id"),
        "wrapped_receipt_digest": wrapper.get("wrapped_receipt_digest"),
        "wrapper_type": wrapper.get("wrapper_type"),
        "recording_context": wrapper.get("recording_context"),
    }


def _print_metadata(meta: Mapping[str, Any]) -> None:
    for key in (
        "written",
        "dry_run",
        "kid",
        "wrapped_receipt_id",
        "wrapped_receipt_digest",
        "wrapper_type",
        "recording_context",
    ):
        print(f"{key}: {meta.get(key)}")


def run(args: argparse.Namespace) -> int:
    # 1. Resolve key material source via the dedicated Path B credential lane
    #    (never the legacy shared SAR402_RECORDING_* names).
    if args.env_file:
        env = parse_env_file(Path(args.env_file))
    else:
        import os
        env = {k: os.environ[k] for k in ENV_KEYS if k in os.environ}
        # $CREDENTIALS_DIRECTORY, if present in the real environment, is a
        # fallback resolution path the credential lane itself understands —
        # pass it through unfiltered by ENV_KEYS since it is not a secret.
        cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")
        if cred_dir:
            env["CREDENTIALS_DIRECTORY"] = cred_dir

    # 2. Load + validate through the credential lane. Fails closed, no
    #    fallback to any other key, on any error (never echoes key material).
    try:
        signing_key, derived_pub_hex = pathb_credential.load_and_check(env)
    except pathb_credential.PathBCredentialError as exc:
        raise OperatorError(f"credential lane refused to load key material: {exc}")

    try:
        configured_kid = pathb_credential.load_configured_kid(env)
        expected_pub_hex = pathb_credential.load_expected_public_key_hex(env)
    except pathb_credential.PathBCredentialError as exc:
        raise OperatorError(f"credential lane configuration error: {exc}")

    # 3. Coherence gate: configured kid must be exactly this script's pinned
    #    production kid, and the derived public key must match what's
    #    configured as expected — fail closed on any mismatch.
    try:
        pathb_credential.startup_coherence_gate(
            configured_kid=configured_kid,
            expected_public_key_hex=expected_pub_hex,
            private_key=signing_key,
            producer_supported_kids=(EXPECTED_KID,),
        )
    except pathb_credential.PathBCredentialError as exc:
        raise OperatorError(str(exc))

    kid = configured_kid

    # 4. Locate the Path A receipt.
    receipt = find_inner_receipt(args.receipt_id, RECEIPT_LEDGER)
    if receipt is None:
        raise OperatorError(
            f"receipt {args.receipt_id!r} not found in {RECEIPT_LEDGER.name}"
        )

    # 5. Build the wrapper (also validates the inner receipt / id binding).
    wrapper = build_recording_wrapper(receipt, signing_key=signing_key, kid=kid)

    # 6. Dry-run: built/verified but nothing persisted.
    if args.dry_run:
        _print_metadata(_safe_metadata(wrapper, written=False, dry_run=True))
        return 0

    # 7. Persist through the existing store.
    try:
        wrote = store_recording_wrapper(wrapper)
    except RecordingWrapperConflict as exc:
        raise OperatorError(
            "CONFLICT: a different recording wrapper already exists for "
            f"{wrapper.get('wrapped_receipt_id')!r}; refusing to overwrite "
            f"({exc})"
        )

    if not wrote:
        print("note: equivalent wrapper already stored — idempotent, no write")
    _print_metadata(_safe_metadata(wrapper, written=wrote, dry_run=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Wrap exactly one SAR-402 Path A receipt with a Path B "
        "recording-attribution wrapper (production key from env).",
    )
    parser.add_argument("--receipt-id", required=True, help="inner SAR-402 receipt id")
    parser.add_argument(
        "--env-file",
        default=None,
        help="optional shell env file to read the three SAR402_RECORDING_* vars from",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="build/verify the wrapper but do NOT store it",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except OperatorError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
