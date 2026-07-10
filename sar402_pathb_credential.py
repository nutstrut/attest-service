"""SAR-402 Path B: dedicated credential lane for the recording-wrapper signing key.

This is the "final loader" for ``defaultverifier-recording-ed25519-2`` (and any
future Path B recording key rotation) — the code path a real Path B producer
must use to load its private key once activated, and the code path this
module's decrypt-and-discard custody proof round-trips through.

Why a separate module. The existing Path B producer
(``sar402_recording_wrapper.py`` / ``scripts/sar402_pathb_wrap_receipt.py``)
reads ``SAR402_RECORDING_SIGNING_KEY_HEX`` from the *shared* environment (or an
``--env-file`` of the same three vars) and is pinned to kid
``defaultverifier-recording-ed25519-1``. That pin, and that shared-namespace
loading path, are both staying exactly as they are — this module does not
change them. This module is the *new*, dedicated, file/credential-backed lane
so that:

  * Path B key material never has to live in ``/etc/default/attest-service``
    (the shared attest-service env file), the same shared-surface pattern that
    caused the 2026-07-09 settlement-witness signer-namespace collision, and
  * a future rotation to a systemd credential (``LoadCredential=``,
    ``$CREDENTIALS_DIRECTORY``) has a ready, tested loader to point at instead
    of inventing one during the rotation itself.

Namespace. Exactly three dedicated variables, never reused from the
``SAR402_RECORDING_*`` names:

    PATH_B_RECORDING_KID
    PATH_B_RECORDING_PUBLIC_KEY_HEX
    PATH_B_RECORDING_PRIVATE_KEY_FILE

Key file format. A single line of exactly 64 lowercase hex characters (a
raw 32-byte Ed25519 seed, hex-encoded) — the same convention the Path B
custody ceremony already produced (``seed.hex``). One optional trailing
newline is tolerated; anything else (extra whitespace, extra lines, wrong
length, non-hex characters, uppercase) is rejected. This is deliberately the
simplest correctly-specified format, not a new bespoke one — see the
post-incident hardening packet's ``-04`` lesson.

Credential-directory resolution. When ``PATH_B_RECORDING_PRIVATE_KEY_FILE``
is not set explicitly and the process is running under a systemd unit with
``LoadCredential=``, the loader looks for
``$CREDENTIALS_DIRECTORY/path-b-recording-signing-key``. Neither resolving is
an error by itself; only actually needing and failing to find a private key
is (fail closed).

Safety invariant honored throughout this module: no function here ever
returns, logs, or raises an exception containing the private-key bytes, the
seed hex, or any substring of either. Only public key material (which is not
secret) and short fingerprints of it appear in return values or messages.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterable, Mapping, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# ---------------------------------------------------------------------------
# Dedicated namespace — never shared with SAR402_RECORDING_* or any other
# signer's env vars.
# ---------------------------------------------------------------------------

ENV_KID = "PATH_B_RECORDING_KID"
ENV_PUBLIC_KEY_HEX = "PATH_B_RECORDING_PUBLIC_KEY_HEX"
ENV_PRIVATE_KEY_FILE = "PATH_B_RECORDING_PRIVATE_KEY_FILE"

# The credential filename systemd's LoadCredential= is expected to expose,
# i.e. a unit stanza of the form ``LoadCredential=path-b-recording-signing-key:<src>``
# surfaces the decrypted seed at ``$CREDENTIALS_DIRECTORY/path-b-recording-signing-key``.
CREDENTIAL_FILENAME = "path-b-recording-signing-key"

_HEX_SEED_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX_PUBLIC_RE = re.compile(r"^[0-9a-f]{64}$")

_SEED_BYTES_LEN = 32


class PathBCredentialError(Exception):
    """A fail-closed credential-lane error. Messages never contain key material."""


def fingerprint(public_key_hex: str) -> str:
    """A short, safe, non-reversible display form of a *public* key hex string.

    Public key material is not secret, but full values still should not be
    scattered through logs/reports; callers use this truncated form instead."""
    value = (public_key_hex or "").strip().lower()
    if len(value) < 16:
        return "invalid"
    return f"{value[:8]}…{value[-8:]}"


def resolve_private_key_path(env: Mapping[str, str]) -> Path:
    """Resolve the private-key credential file path, fail closed if unresolvable.

    Resolution order:
      1. ``PATH_B_RECORDING_PRIVATE_KEY_FILE`` if set (explicit override).
      2. ``$CREDENTIALS_DIRECTORY/path-b-recording-signing-key`` if
         ``CREDENTIALS_DIRECTORY`` is set (systemd ``LoadCredential=``).

    Raises ``PathBCredentialError`` if neither is available. Never reads the
    file's contents."""
    explicit = (env.get(ENV_PRIVATE_KEY_FILE) or "").strip()
    if explicit:
        return Path(explicit)

    creds_dir = (env.get("CREDENTIALS_DIRECTORY") or "").strip()
    if creds_dir:
        return Path(creds_dir) / CREDENTIAL_FILENAME

    raise PathBCredentialError(
        f"no private-key credential source configured: set {ENV_PRIVATE_KEY_FILE} "
        f"explicitly, or run under systemd LoadCredential= so CREDENTIALS_DIRECTORY "
        f"is populated — refusing to proceed"
    )


def load_private_key_from_file(path: Path) -> Ed25519PrivateKey:
    """Load and strictly validate an Ed25519 private key from a credential file.

    Accepts only the documented format: exactly 64 lowercase hex characters,
    optionally followed by a single trailing newline. Any other content
    (missing file, wrong length, non-hex, uppercase, extra lines/whitespace,
    unreadable permissions) fails closed with ``PathBCredentialError`` and
    never echoes the file's content."""
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        raise PathBCredentialError(
            f"private-key credential file not found at configured path "
            f"({path.name}) — refusing to sign"
        )
    except PermissionError:
        raise PathBCredentialError(
            f"private-key credential file not readable ({path.name}) — refusing to sign"
        )
    except OSError as exc:
        raise PathBCredentialError(
            f"private-key credential file could not be read ({path.name}: {exc.__class__.__name__}) — refusing to sign"
        )

    text = raw.decode("ascii", errors="strict") if _is_ascii(raw) else None
    if text is None:
        raise PathBCredentialError(
            "malformed private-key credential file: non-ASCII content — refusing to sign"
        )

    # Tolerate exactly one trailing newline; nothing else.
    if text.endswith("\n"):
        body = text[:-1]
    else:
        body = text
    if "\n" in body or "\r" in body:
        raise PathBCredentialError(
            "malformed private-key credential file: multiple lines — refusing to sign"
        )

    if not _HEX_SEED_RE.match(body):
        raise PathBCredentialError(
            "malformed private-key credential file: expected exactly 64 lowercase "
            "hex characters — refusing to sign"
        )

    seed = bytes.fromhex(body)
    if len(seed) != _SEED_BYTES_LEN:
        raise PathBCredentialError(
            "malformed private-key credential file: decoded seed is not 32 bytes — refusing to sign"
        )

    try:
        return Ed25519PrivateKey.from_private_bytes(seed)
    except ValueError:
        raise PathBCredentialError(
            "private-key credential file did not decode to a valid Ed25519 seed — refusing to sign"
        )


def _is_ascii(raw: bytes) -> bool:
    try:
        raw.decode("ascii", errors="strict")
        return True
    except UnicodeDecodeError:
        return False


def load_expected_public_key_hex(env: Mapping[str, str]) -> str:
    """Load and validate the configured expected public key (hex), fail closed."""
    value = (env.get(ENV_PUBLIC_KEY_HEX) or "").strip().lower()
    if not value:
        raise PathBCredentialError(
            f"{ENV_PUBLIC_KEY_HEX} is not configured — refusing to sign"
        )
    if not _HEX_PUBLIC_RE.match(value):
        raise PathBCredentialError(
            f"{ENV_PUBLIC_KEY_HEX} is not 64 lowercase hex characters — refusing to sign"
        )
    return value


def load_configured_kid(env: Mapping[str, str]) -> str:
    """Load the configured Path B kid, fail closed if unset."""
    value = (env.get(ENV_KID) or "").strip()
    if not value:
        raise PathBCredentialError(f"{ENV_KID} is not configured — refusing to sign")
    return value


def derive_public_key_hex(private_key: Ed25519PrivateKey) -> str:
    """Raw public-key bytes (hex) for a loaded private key. Public, not secret."""
    from cryptography.hazmat.primitives import serialization

    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw.hex()


def startup_coherence_gate(
    *,
    configured_kid: str,
    expected_public_key_hex: str,
    private_key: Ed25519PrivateKey,
    producer_supported_kids: Iterable[str],
) -> str:
    """Verify configured kid / expected pubkey / loaded credential / producer
    support all agree before any signing is permitted.

    All four of the following must hold, or this raises ``PathBCredentialError``
    (fail closed, no fallback to any other key):

      * ``configured_kid`` is one of ``producer_supported_kids``;
      * the public key derived from ``private_key`` equals
        ``expected_public_key_hex`` (case-insensitive hex compare);

    Returns the derived public key hex on success (for safe-fingerprint
    logging by the caller)."""
    supported = set(producer_supported_kids)
    if configured_kid not in supported:
        raise PathBCredentialError(
            f"configured kid {configured_kid!r} is not in the producer-supported "
            f"kid set {sorted(supported)!r} — refusing to sign"
        )

    expected = (expected_public_key_hex or "").strip().lower()
    if not _HEX_PUBLIC_RE.match(expected):
        raise PathBCredentialError(
            "expected public key is not valid 64-hex-char material — refusing to sign"
        )

    derived = derive_public_key_hex(private_key)
    if derived.lower() != expected:
        raise PathBCredentialError(
            "derived public key from loaded private credential does not match "
            "the configured expected public key — refusing to sign "
            f"(configured kid {configured_kid!r})"
        )

    return derived


def load_and_check(env: Optional[Mapping[str, str]] = None) -> tuple[Ed25519PrivateKey, str]:
    """Convenience end-to-end loader: resolve path, load key, validate format only.

    Does NOT run the coherence gate (kid/producer-support checks) — callers
    that need the full startup gate should call ``startup_coherence_gate``
    separately with their producer's supported-kid set. Returns
    ``(private_key, derived_public_key_hex)``."""
    env = env if env is not None else os.environ
    path = resolve_private_key_path(env)
    private_key = load_private_key_from_file(path)
    derived = derive_public_key_hex(private_key)
    return private_key, derived
