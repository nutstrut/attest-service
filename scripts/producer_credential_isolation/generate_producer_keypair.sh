#!/usr/bin/env bash
# generate_producer_keypair.sh -- mint an Ed25519 keypair for one producer
# principal, executed AS that principal (never as root, never as `ubuntu`),
# so the private key is created already owned by the one account authorized
# to read it and is never staged through any other account's filesystem
# view.
#
# STATUS: reviewed, inert setup script. This session does NOT run this
# script against any real producer_id -- no production key exists as a
# result of this workstream. See the readiness packet for what a follow-up
# session must do before this is safe to run for real (create the actual
# `producer-<id>` OS user first, via setup_producer_principal.sh, under
# separate authorization).
#
# Fail-closed: refuses to overwrite an existing key (no silent rotation),
# refuses to run as any user other than the target producer principal,
# refuses to proceed if the target directory is not already 0700 owned by
# the caller.
#
# Usage (run AS the producer principal, e.g.):
#   sudo -u producer-<producer_id> \
#       ./generate_producer_keypair.sh <producer_id>
#
# Requires `openssl` (present on the target host; no new dependency).
# Prints the hex-encoded raw public key to stdout on success -- that value,
# and only that value, is what goes into config/producer_registry.json's
# `public_key` field for this producer. The private key file never leaves
# the credential directory and this script never prints, logs, or copies
# it anywhere.

set -euo pipefail

CRED_ROOT="${ATTEST_PRODUCER_CREDENTIAL_ROOT:-/etc/attest-producer-credentials}"

fail() {
    echo "generate_producer_keypair.sh: FAIL: $*" >&2
    exit 1
}

producer_id="${1:-}"
[ -n "$producer_id" ] || fail "usage: $0 <producer_id>"
echo "$producer_id" | grep -Eq '^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$' \
    || fail "producer_id '$producer_id' does not match ^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]\$"

expected_user="producer-${producer_id}"
actual_user="$(id -un)"
[ "$actual_user" = "$expected_user" ] \
    || fail "must be run as ${expected_user}, not ${actual_user} -- the private key must be created by the" \
            " principal that will own it, never staged through root or any other account's session"

cred_dir="${CRED_ROOT}/${producer_id}"
[ -d "$cred_dir" ] || fail "credential directory ${cred_dir} does not exist -- run setup_producer_principal.sh first"

dir_mode="$(stat -c '%a' "$cred_dir")"
dir_owner="$(stat -c '%U' "$cred_dir")"
[ "$dir_mode" = "700" ] || fail "credential directory ${cred_dir} is mode ${dir_mode}, expected 700 -- refusing" \
    " to write a key into a directory whose permissions were not established by setup_producer_principal.sh"
[ "$dir_owner" = "$expected_user" ] || fail "credential directory ${cred_dir} is owned by ${dir_owner}," \
    " expected ${expected_user}"

key_path="${cred_dir}/producer.ed25519.pem"
pub_path="${cred_dir}/producer.ed25519.pub.hex"

[ -e "$key_path" ] && fail "private key already exists at ${key_path} -- refusing to overwrite/rotate silently;" \
    " remove it explicitly first if rotation is genuinely intended"

umask 077
openssl genpkey -algorithm ed25519 -out "$key_path"
chmod 0600 "$key_path"

# Extract the raw 32-byte public key as hex -- this is the exact form
# `producer_registry.py`'s `public_key` field and
# `authenticated_submission.py`'s `Ed25519PublicKey.from_public_bytes`
# expect (raw bytes, not PEM/DER-wrapped).
openssl pkey -in "$key_path" -pubout -outform DER | tail -c 32 | xxd -p -c 32 > "$pub_path"
chmod 0600 "$pub_path"

echo "generate_producer_keypair.sh: OK -- private key at ${key_path} (0600, owned ${expected_user})"
echo "generate_producer_keypair.sh: public key (hex, for producer_registry.json):"
cat "$pub_path"
