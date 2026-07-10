#!/usr/bin/env bash
# SAR-402 Path B recording-key runtime unlock helper.
#
# Design record: reports/approvals/sar-402-path-b-runtime-passphrase-delivery-decision-20260710.md
# Implementation plan: reports/strategy/sar-402-path-b-runtime-unlock-implementation-plan-20260710.md
#
# Intended to run as the attest-service.service ExecStartPre step, invoked by
# systemd with $CREDENTIALS_DIRECTORY already populated via LoadCredential=
# and $RUNTIME_DIRECTORY already created via RuntimeDirectory=
# (see ../systemd/pathb-credential.conf). NOT installed by adding this file
# to the repo — deployment is a separate, later step.
#
# Reads the sealed artifact and its passphrase ONLY from
# $CREDENTIALS_DIRECTORY (never directly from /root/... — that indirection is
# systemd's LoadCredential=, not this script). $CREDENTIALS_DIRECTORY is
# mounted read-only by systemd, so it cannot hold this script's own output —
# decryption work and the final decrypted seed both live under
# $RUNTIME_DIRECTORY instead (a separate, writable, tmpfs-backed directory
# systemd creates via RuntimeDirectory=, torn down when the unit stops).
# The final seed is written to
# $RUNTIME_DIRECTORY/path-b-recording-signing-key, which the drop-in also
# exports as PATH_B_RECORDING_PRIVATE_KEY_FILE (an explicit, non-secret path
# override) so sar402_pathb_credential.py's resolve_private_key_path() reads
# it directly rather than assuming $CREDENTIALS_DIRECTORY holds the output.
#
# Fails closed on every precondition: missing credential, wrong configured
# kid, malformed archive, wrong/missing seed material, or derived public key
# mismatch. Never echoes the passphrase, the seed, or any substring of
# either to stdout/stderr, a log, or a file outside $RUNTIME_DIRECTORY.

set -euo pipefail

# Expected identity for this specific rotation instance. Overridable via env
# only for test purposes (PATHB_EXPECTED_KID / PATHB_EXPECTED_PUBLIC_KEY_HEX)
# — production invocation relies on the defaults below, not the override.
EXPECTED_KID="${PATHB_EXPECTED_KID:-defaultverifier-recording-ed25519-2}"
EXPECTED_PUBLIC_KEY_HEX="${PATHB_EXPECTED_PUBLIC_KEY_HEX:-e8608e251cce27bfe497da27e97a08d3e1efca4bd4809fb6364fb2af9a34f29e}"

fail() {
    echo "pathb-unlock: $1" >&2
    exit 1
}

[[ -n "${CREDENTIALS_DIRECTORY:-}" ]] || fail "CREDENTIALS_DIRECTORY is not set — refusing to proceed"
[[ -d "$CREDENTIALS_DIRECTORY" ]] || fail "CREDENTIALS_DIRECTORY does not exist — refusing to proceed"
[[ -n "${RUNTIME_DIRECTORY:-}" ]] || fail "RUNTIME_DIRECTORY is not set — refusing to proceed"
[[ -d "$RUNTIME_DIRECTORY" ]] || fail "RUNTIME_DIRECTORY does not exist — refusing to proceed"

sealed="$CREDENTIALS_DIRECTORY/path-b-recording-key-sealed"
passphrase_file="$CREDENTIALS_DIRECTORY/path-b-recording-passphrase"
out="$RUNTIME_DIRECTORY/path-b-recording-signing-key"

# Configured kid must be supplied (e.g. by a dedicated, non-secret env file
# read into PATH_B_RECORDING_KID) and must equal the identity this script's
# sealed artifact was ceremony-generated for. This is a labeling check, not
# a cryptographic one — the cryptographic check is the derived-public-key
# comparison below. Checked first, before any secret is touched, so a
# misconfigured deployment never even attempts decryption.
configured_kid="${PATH_B_RECORDING_KID:-}"
[[ -n "$configured_kid" ]] || fail "PATH_B_RECORDING_KID is not configured — refusing to proceed"
[[ "$configured_kid" == "$EXPECTED_KID" ]] || fail "configured kid does not match this unlock script's expected kid — refusing to proceed"

[[ -r "$sealed" ]] || fail "sealed credential not found or unreadable — refusing to proceed"
[[ -r "$passphrase_file" ]] || fail "passphrase credential not found or unreadable — refusing to proceed"

work="$(mktemp -d "$RUNTIME_DIRECTORY/pathb-unlock.XXXXXX")"
cleanup() {
    # Best-effort shred of every extracted file before removing the
    # directory; never fails the overall exit code on shred/rm errors.
    find "$work" -type f -exec shred -u {} \; 2>/dev/null || true
    rm -rf "$work" 2>/dev/null || true
}
trap cleanup EXIT

# GPG diagnostic/status output is discarded specifically so no filename,
# partial-key, or passphrase-adjacent diagnostic text reaches stderr/logs.
if ! gpg --batch --yes --quiet --pinentry-mode loopback \
        --passphrase-file "$passphrase_file" \
        --decrypt "$sealed" 2>/dev/null | tar -xz -C "$work" 2>/dev/null; then
    fail "decrypt/extract failed (wrong passphrase or corrupt artifact) — refusing to proceed"
fi

seed_file="$work/seed.hex"
pem_file="$work/seed.pem"
[[ -f "$seed_file" ]] || fail "malformed artifact: seed.hex missing — refusing to proceed"
[[ -f "$pem_file" ]] || fail "malformed artifact: seed.pem missing — refusing to proceed"

seed="$(tr -d '\n' < "$seed_file")"
[[ "$seed" =~ ^[0-9a-f]{64}$ ]] || fail "malformed artifact: seed.hex is not 64 lowercase hex characters — refusing to proceed"

derived_pub="$(openssl pkey -in "$pem_file" -pubout -outform DER 2>/dev/null | tail -c 32 | xxd -p -c 32 || true)"
[[ -n "$derived_pub" ]] || fail "could not derive public key from decrypted credential — refusing to proceed"
[[ "$derived_pub" == "$EXPECTED_PUBLIC_KEY_HEX" ]] || fail "derived public key does not match expected public key — refusing to proceed"

umask 077
printf '%s' "$seed" > "$out"

echo "pathb-unlock: unlock succeeded for kid $configured_kid (public key fingerprint ${derived_pub:0:8}...${derived_pub: -8})"
