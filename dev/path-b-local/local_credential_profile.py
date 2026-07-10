"""SAR-402 Path B: local development credential profile.

Defines the constants for the *local-only* development key identity used to
exercise the Path B credential lane (``sar402_pathb_credential.py``) end to
end without ever touching production custody or production registries.

This module defines names and defaults only. It does not generate keys
(``generate_dev_key.py`` does that) and does not sign anything
(``run_local_roundtrip.py`` does that).
"""

from __future__ import annotations

from pathlib import Path

# The local development kid. Deliberately distinct from both production kids
# (`defaultverifier-recording-ed25519-1`, the active producer/verifier pin,
# and `defaultverifier-recording-ed25519-2`, the prepared-but-inactive
# rotation target) so it can never be mistaken for either in a registry, a
# log line, or a config diff.
DEV_KID = "defaultverifier-recording-dev-ed25519-1"

# Production kids this profile must never collide with (used by tests to
# assert the disjointness, not read at runtime).
PRODUCTION_KIDS = (
    "defaultverifier-recording-ed25519-1",
    "defaultverifier-recording-ed25519-2",
)

# Default local credential storage location, relative to the attest-service
# repo root. Gitignored; never uploaded, never placed in a production
# registry or systemd LoadCredential= source.
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CREDENTIAL_DIR = REPO_ROOT / ".local-credentials"
DEFAULT_CREDENTIAL_FILENAME = "path-b-recording-dev-key"
DEFAULT_CREDENTIAL_PATH = DEFAULT_CREDENTIAL_DIR / DEFAULT_CREDENTIAL_FILENAME

# The three dedicated Path B credential-lane env vars (from
# sar402_pathb_credential.py) that this local profile populates. Same names,
# same loader, same fail-closed semantics as production — only the values
# differ.
ENV_KEYS = (
    "PATH_B_RECORDING_KID",
    "PATH_B_RECORDING_PUBLIC_KEY_HEX",
    "PATH_B_RECORDING_PRIVATE_KEY_FILE",
)
