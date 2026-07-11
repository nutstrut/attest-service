#!/usr/bin/env bash
# SAR-402 Path B recording-key runtime unlock — ExecStart= wrapper.
#
# Design record: reports/approvals/sar-402-path-b-runtime-passphrase-delivery-decision-20260710.md
# Implementation plan: reports/strategy/sar-402-path-b-runtime-unlock-implementation-plan-20260710.md
# Supersedes the rejected ExecStartPre= design — see "Why ExecStartPre was
# rejected" in the implementation plan and
# reports/external-actions/sar-402-path-b-runtime-unlock-service-activation-validation-20260710.md
# for the incident that found it.
#
# Runs as attest-service.service's ExecStart= itself (not ExecStartPre=),
# because $CREDENTIALS_DIRECTORY populated by LoadCredential= was confirmed,
# via a real production incident on this host's systemd 249, to be visible
# to a unit's ExecStart= process but NOT to its ExecStartPre= process.
#
# Not installed by adding this file to the repo — deployment is a separate,
# later, explicitly authorized step.
#
# Governing invariant, load-bearing for this script's control flow:
# credential loading is NOT signing authorization, and Path B recording
# capability is NOT yet wired into the live producer or verifier (both
# stay pinned to defaultverifier-recording-ed25519-1 regardless of what
# this script does). Therefore a Path B unlock failure must NEVER prevent
# attest-service itself from starting — Path A ingestion, delegated-identity
# receipts, and TrustScore all depend on this same process. This is the
# defect that caused the 2026-07-11 production outage under the rejected
# ExecStartPre= design (an unprefixed ExecStartPre failure aborted the
# whole unit); this wrapper's unlock_pathb() failing is always non-fatal
# to the exec handoff at the bottom of this script.
#
# Reads the sealed artifact and its passphrase ONLY from
# $CREDENTIALS_DIRECTORY (never directly from /root/... — that indirection
# is systemd's LoadCredential=, not this script). $CREDENTIALS_DIRECTORY is
# mounted read-only, so all scratch work and the final decrypted seed live
# under $RUNTIME_DIRECTORY (writable, tmpfs, torn down with the unit)
# instead. On success, PATH_B_RECORDING_PRIVATE_KEY_FILE is exported so it
# survives the final `exec` into the real attest-service start command —
# prepared key material becomes available to the process, but that is
# still distinct from the live producer/verifier ever choosing to use it
# (a separate, later, explicitly authorized rotation step).
#
# Never echoes the passphrase, the seed, or any substring of either to
# stdout/stderr, a log, or a file outside $RUNTIME_DIRECTORY.

set -uo pipefail
# Deliberately NOT `set -e`: a Path B unlock failure must fall through to
# the final exec, not abort this script.

EXPECTED_KID="${PATHB_EXPECTED_KID:-defaultverifier-recording-ed25519-2}"
EXPECTED_PUBLIC_KEY_HEX="${PATHB_EXPECTED_PUBLIC_KEY_HEX:-e8608e251cce27bfe497da27e97a08d3e1efca4bd4809fb6364fb2af9a34f29e}"

# The real attest-service start command. Overridable only for tests/disposable
# validation (PATHB_WRAPPER_REAL_CMD) — production relies on the default.
REAL_START_CMD="${PATHB_WRAPPER_REAL_CMD:-/home/ubuntu/attest-service/start.sh}"

log() {
    echo "pathb-unlock-wrapper: $1" >&2
}

# Returns 0 and exports PATH_B_RECORDING_PRIVATE_KEY_FILE on success.
# Returns 1 on any failure. Never causes the calling script to exit.
unlock_pathb() {
    if [[ -z "${CREDENTIALS_DIRECTORY:-}" ]]; then
        log "CREDENTIALS_DIRECTORY not set — Path B unlock skipped"
        return 1
    fi
    if [[ -z "${RUNTIME_DIRECTORY:-}" ]]; then
        log "RUNTIME_DIRECTORY not set — Path B unlock skipped"
        return 1
    fi

    local sealed="$CREDENTIALS_DIRECTORY/path-b-recording-key-sealed"
    local passphrase_file="$CREDENTIALS_DIRECTORY/path-b-recording-passphrase"
    local out="$RUNTIME_DIRECTORY/path-b-recording-signing-key"

    local configured_kid="${PATH_B_RECORDING_KID:-}"
    if [[ -z "$configured_kid" ]]; then
        log "PATH_B_RECORDING_KID not configured — Path B unlock skipped"
        return 1
    fi
    if [[ "$configured_kid" != "$EXPECTED_KID" ]]; then
        log "configured kid does not match this wrapper's expected kid — Path B unlock skipped"
        return 1
    fi

    if [[ ! -r "$sealed" ]]; then
        log "sealed credential not found or unreadable — Path B unlock skipped"
        return 1
    fi
    if [[ ! -r "$passphrase_file" ]]; then
        log "passphrase credential not found or unreadable — Path B unlock skipped"
        return 1
    fi

    local work
    work="$(mktemp -d "$RUNTIME_DIRECTORY/pathb-unlock.XXXXXX" 2>/dev/null)"
    if [[ -z "$work" ]]; then
        log "could not create scratch directory — Path B unlock skipped"
        return 1
    fi
    _pathb_cleanup_work() {
        find "$work" -type f -exec shred -u {} \; 2>/dev/null || true
        rm -rf "$work" 2>/dev/null || true
    }

    if ! gpg --batch --yes --quiet --pinentry-mode loopback \
            --passphrase-file "$passphrase_file" \
            --decrypt "$sealed" 2>/dev/null | tar -xz -C "$work" 2>/dev/null; then
        log "decrypt/extract failed (wrong passphrase or corrupt artifact) — Path B unlock skipped"
        _pathb_cleanup_work
        return 1
    fi

    local seed_file="$work/seed.hex"
    local pem_file="$work/seed.pem"
    if [[ ! -f "$seed_file" ]]; then
        log "malformed artifact: seed.hex missing — Path B unlock skipped"
        _pathb_cleanup_work
        return 1
    fi
    if [[ ! -f "$pem_file" ]]; then
        log "malformed artifact: seed.pem missing — Path B unlock skipped"
        _pathb_cleanup_work
        return 1
    fi

    local seed
    seed="$(tr -d '\n' < "$seed_file")"
    if [[ ! "$seed" =~ ^[0-9a-f]{64}$ ]]; then
        log "malformed artifact: seed.hex is not 64 lowercase hex characters — Path B unlock skipped"
        _pathb_cleanup_work
        return 1
    fi

    local derived_pub
    derived_pub="$(openssl pkey -in "$pem_file" -pubout -outform DER 2>/dev/null | tail -c 32 | xxd -p -c 32 || true)"
    if [[ -z "$derived_pub" ]]; then
        log "could not derive public key from decrypted credential — Path B unlock skipped"
        _pathb_cleanup_work
        return 1
    fi
    if [[ "$derived_pub" != "$EXPECTED_PUBLIC_KEY_HEX" ]]; then
        log "derived public key does not match expected public key — Path B unlock skipped"
        _pathb_cleanup_work
        return 1
    fi

    umask 077
    printf '%s' "$seed" > "$out"
    _pathb_cleanup_work

    export PATH_B_RECORDING_PRIVATE_KEY_FILE="$out"
    log "Path B unlock succeeded for kid $configured_kid (public key fingerprint ${derived_pub:0:8}...${derived_pub: -8})"
    return 0
}

if unlock_pathb; then
    :
else
    log "continuing attest-service startup without Path B signing capability"
fi

# exec replaces this script's own process image with the real start
# command, preserving systemd's PID/signal/lifecycle expectations for
# ExecStart= — the wrapper does not remain as a parent/supervisor process.
# eval (not bare word-splitting) is required so a quoted, multi-word
# PATHB_WRAPPER_REAL_CMD override (test/disposable-unit use only) parses
# correctly; REAL_START_CMD is never attacker- or request-controlled — it
# comes only from this script's own default or a trusted unit/test
# environment, never from network input.
eval "exec $REAL_START_CMD"
