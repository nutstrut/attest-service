#!/usr/bin/env bash
# setup_producer_principal.sh -- create the dedicated OS principal and
# credential directory for one approved authenticated-evidence producer.
#
# STATUS: reviewed, idempotent, fail-closed setup script. INERT until a
# separately authorized session runs it against a real producer_id on the
# production host. This session does not execute it against any real
# producer, service account, or credential -- see prove_isolation_locally.sh
# for the throwaway, temp-named proof run this workstream actually
# performed to validate the mechanism below.
#
# Mechanism selected (see the readiness packet for the full evaluation):
# dedicated OS user + file-held Ed25519 key ("Candidate A"), the smallest
# viable isolation primitive on a single Linux host with no new services,
# no new infra, and no dependency beyond coreutils/openssl already present.
#
# What this script does, in order, all idempotent (safe to re-run):
#   1. Create a dedicated system group and system user for the producer,
#      no login shell, no home directory login use, if they do not already
#      exist. Refuses to proceed if a user of that name exists but is NOT
#      a no-login system account (defends against colliding with an
#      unrelated pre-existing account of the same name).
#   2. Create the producer's credential directory
#      (/etc/attest-producer-credentials/<producer_id>/) owned
#      <producer-user>:<producer-group>, mode 0700. Parent directory
#      created 0755 root:root so only the leaf is opened up, and only to
#      its own principal.
#   3. Does NOT generate a keypair. Key generation is a separate,
#      explicit, one-time step (generate_producer_keypair.sh) so that
#      "set up the principal" and "mint a credential for it" are two
#      reviewable actions, not one, and so this script can be re-run
#      safely (e.g. to fix permissions) without any risk of clobbering an
#      existing key.
#   4. Fixes permissions/ownership on every re-run (converges to the
#      target state) rather than only acting on first creation, so drift
#      (e.g. an accidental chmod by someone else) is self-healing on the
#      next run.
#
# Fail-closed: any unexpected state (step 1's collision guard, missing
# `useradd`/`groupadd`, non-root invocation, etc.) aborts with a non-zero
# exit and changes nothing further. `set -euo pipefail` throughout.
#
# Usage:
#   sudo ./setup_producer_principal.sh <producer_id>
#
# <producer_id> must match ^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$ (mirrors the
# producer_registry.py producer_id convention) and becomes:
#   OS user/group:  producer-<producer_id>
#   credential dir: /etc/attest-producer-credentials/<producer_id>/

set -euo pipefail

CRED_ROOT="${ATTEST_PRODUCER_CREDENTIAL_ROOT:-/etc/attest-producer-credentials}"

fail() {
    echo "setup_producer_principal.sh: FAIL: $*" >&2
    exit 1
}

[ "$(id -u)" -eq 0 ] || fail "must be run as root (via sudo) -- refusing to proceed unprivileged"

producer_id="${1:-}"
[ -n "$producer_id" ] || fail "usage: $0 <producer_id>"
echo "$producer_id" | grep -Eq '^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$' \
    || fail "producer_id '$producer_id' does not match ^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]\$"

os_user="producer-${producer_id}"
os_group="producer-${producer_id}"
cred_dir="${CRED_ROOT}/${producer_id}"

echo "setup_producer_principal.sh: target user=${os_user} group=${os_group} cred_dir=${cred_dir}"

# --- Step 1: group -----------------------------------------------------
if getent group "$os_group" >/dev/null 2>&1; then
    echo "setup_producer_principal.sh: group ${os_group} already exists, leaving as-is"
else
    groupadd --system "$os_group"
    echo "setup_producer_principal.sh: created system group ${os_group}"
fi

# --- Step 1: user --------------------------------------------------------
if id "$os_user" >/dev/null 2>&1; then
    shell="$(getent passwd "$os_user" | cut -d: -f7)"
    if [ "$shell" != "/usr/sbin/nologin" ] && [ "$shell" != "/bin/false" ] && [ "$shell" != "/sbin/nologin" ]; then
        fail "user ${os_user} already exists with login shell '${shell}' -- refusing to reuse a" \
             " pre-existing account that was not created as a no-login system principal by this script"
    fi
    echo "setup_producer_principal.sh: user ${os_user} already exists as a no-login system account, leaving as-is"
else
    useradd --system --gid "$os_group" --no-create-home --shell /usr/sbin/nologin --comment \
        "attest-service authenticated-producer principal ${producer_id} (isolation boundary, not a login account)" \
        "$os_user"
    echo "setup_producer_principal.sh: created system user ${os_user} (no login, no home)"
fi

# --- Step 2: credential directory ---------------------------------------
mkdir -p "$CRED_ROOT"
chown root:root "$CRED_ROOT"
chmod 0755 "$CRED_ROOT"

mkdir -p "$cred_dir"
chown "${os_user}:${os_group}" "$cred_dir"
chmod 0700 "$cred_dir"

echo "setup_producer_principal.sh: OK -- ${cred_dir} is 0700, owned ${os_user}:${os_group}"
echo "setup_producer_principal.sh: no key generated by this script -- run generate_producer_keypair.sh next"
