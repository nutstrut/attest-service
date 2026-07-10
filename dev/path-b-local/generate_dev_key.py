#!/usr/bin/env python3
"""Generate a local-only SAR-402 Path B development key.

Produces a fresh Ed25519 keypair, writes the private seed (hex, the same
64-lowercase-hex-char format ``sar402_pathb_credential.py`` requires) to a
0600 file under ``.local-credentials/`` in this repo, and prints the public
key hex / fingerprint / kid so they can be pasted into a local ``.env.local``.

Never prints, logs, or returns the private key material. Never contacts any
production endpoint or writes to any production registry. Refuses to
overwrite an existing credential file unless ``--force`` is passed, so a
careless re-run cannot silently orphan a key already in use by a running
local signer.
"""

from __future__ import annotations

import argparse
import stat
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import sar402_pathb_credential as cred  # noqa: E402
from local_credential_profile import (  # noqa: E402
    DEFAULT_CREDENTIAL_PATH,
    DEV_KID,
)


def generate() -> tuple[str, str]:
    """Return (seed_hex, public_key_hex) for a freshly generated dev key."""
    key = Ed25519PrivateKey.generate()
    seed_hex = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ).hex()
    public_hex = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    return seed_hex, public_hex


def write_credential(seed_hex: str, path: Path, *, force: bool) -> None:
    if path.exists() and not force:
        raise SystemExit(
            f"refusing to overwrite existing dev credential at {path} "
            "(pass --force to replace it)"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(seed_hex + "\n")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--path",
        default=str(DEFAULT_CREDENTIAL_PATH),
        help="where to write the local dev credential file (default: "
        f"{DEFAULT_CREDENTIAL_PATH})",
    )
    parser.add_argument(
        "--force", action="store_true", help="overwrite an existing dev credential"
    )
    args = parser.parse_args(argv)

    seed_hex, public_hex = generate()
    path = Path(args.path)
    write_credential(seed_hex, path, force=args.force)

    print(f"kid: {DEV_KID}")
    print(f"public_key_hex: {public_hex}")
    print(f"fingerprint: {cred.fingerprint(public_hex)}")
    print(f"credential_file: {path}")
    print()
    print("Paste into dev/path-b-local/.env.local (copy from .env.local.example):")
    print(f"  PATH_B_RECORDING_KID={DEV_KID}")
    print(f"  PATH_B_RECORDING_PUBLIC_KEY_HEX={public_hex}")
    print(f"  PATH_B_RECORDING_PRIVATE_KEY_FILE={path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
