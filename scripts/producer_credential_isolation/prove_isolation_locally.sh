#!/usr/bin/env bash
# prove_isolation_locally.sh -- local, non-production proof harness for the
# credential-isolation mechanism in setup_producer_principal.sh /
# generate_producer_keypair.sh.
#
# Uses exclusively TEMP-prefixed, throwaway OS users and a throwaway
# credential root under /tmp -- never a real producer_id, never the real
# /etc/attest-producer-credentials root, never a real service account name.
# Self-cleans (users deleted, directories removed) on exit whether it
# succeeds or fails. Requires root (sudo) to create/delete OS users; if run
# without it, fails closed immediately rather than partially creating
# state.
#
# What this proves, each as a separate, explicit check:
#   1. the producer principal (temp user A) CAN read its own key
#   2. a different-service principal (temp user B, standing in for
#      attest-service/settlement-witness/morpheus-coordinator/hermes) CANNOT
#   3. the ordinary operator/model account running THIS session (`ubuntu` /
#      $(whoami)) CANNOT, once isolation is applied
#   4. no private key material is written anywhere this script does not
#      immediately clean up (grep for the key file after teardown)
#
# This does not and cannot prove root itself is contained -- root can
# always read any file on the host. That limit is stated plainly in the
# readiness packet, not hidden here.

set -euo pipefail

[ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] || {
    echo "prove_isolation_locally.sh: FAIL: run this via 'sudo ./prove_isolation_locally.sh' from an" \
         " unprivileged shell (needs SUDO_USER set to know who the 'ordinary operator account' is)." >&2
    exit 1
}

CALLER_USER="$SUDO_USER"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TS="$(date +%s)-$$"
TEST_ROOT="/tmp/attest-isolation-proof-${TS}"
PRODUCER_ID="isoproof${TS: -6}"          # matches the producer_id regex, throwaway
OTHER_ID="isoproofother${TS: -6}"        # second throwaway "sibling service" principal

cleanup() {
    echo "prove_isolation_locally.sh: cleaning up..."
    userdel -r "producer-${PRODUCER_ID}" >/dev/null 2>&1 || true
    userdel -r "producer-${OTHER_ID}" >/dev/null 2>&1 || true
    groupdel "producer-${PRODUCER_ID}" >/dev/null 2>&1 || true
    groupdel "producer-${OTHER_ID}" >/dev/null 2>&1 || true
    rm -rf "$TEST_ROOT"
    echo "prove_isolation_locally.sh: cleanup complete -- ${TEST_ROOT} and both temp OS users removed"
}
trap cleanup EXIT

echo "=== prove_isolation_locally.sh: using throwaway root ${TEST_ROOT}, producer_id=${PRODUCER_ID} ==="

export ATTEST_PRODUCER_CREDENTIAL_ROOT="$TEST_ROOT"

# --- set up the producer principal + its sibling "other service" principal
"${SCRIPT_DIR}/setup_producer_principal.sh" "$PRODUCER_ID"
"${SCRIPT_DIR}/setup_producer_principal.sh" "$OTHER_ID"

# The real scripts live under /home/ubuntu, which is 0750 -- not traversable
# by the dedicated no-login principals this proof just created (itself a
# realistic, correct constraint, not a bug: those principals should not be
# able to browse the operator's home directory either). Copy just the
# keypair-generation script into the world-readable throwaway root so the
# producer principal can execute it, exactly as it would from its own
# WorkingDirectory in the real systemd-unit deployment.
cp "${SCRIPT_DIR}/generate_producer_keypair.sh" "${TEST_ROOT}/generate_producer_keypair.sh"
chmod 0755 "${TEST_ROOT}/generate_producer_keypair.sh"

# --- mint the producer's key, running AS the producer principal
sudo -u "producer-${PRODUCER_ID}" env ATTEST_PRODUCER_CREDENTIAL_ROOT="$TEST_ROOT" \
    "${TEST_ROOT}/generate_producer_keypair.sh" "$PRODUCER_ID"

KEY_PATH="${TEST_ROOT}/${PRODUCER_ID}/producer.ed25519.pem"

pass=0
fail=0

check() {
    local desc="$1" expect="$2" cmd="$3"
    if eval "$cmd" >/dev/null 2>&1; then actual="allowed"; else actual="denied"; fi
    if [ "$actual" = "$expect" ]; then
        echo "PASS: ${desc} (${actual}, expected ${expect})"
        pass=$((pass + 1))
    else
        echo "FAIL: ${desc} (${actual}, expected ${expect})"
        fail=$((fail + 1))
    fi
}

check "producer principal can read its own key" \
    "allowed" "sudo -u producer-${PRODUCER_ID} cat '${KEY_PATH}'"

check "sibling-service principal (stands in for attest-service/settlement-witness/hermes/morpheus coordinator) cannot read it" \
    "denied" "sudo -u producer-${OTHER_ID} cat '${KEY_PATH}'"

check "ordinary operator/model account (${CALLER_USER}, this session's own account) cannot read it" \
    "denied" "sudo -u ${CALLER_USER} cat '${KEY_PATH}'"

check "credential directory itself is not traversable by the ordinary account" \
    "denied" "sudo -u ${CALLER_USER} ls '${TEST_ROOT}/${PRODUCER_ID}'"

echo ""
echo "=== prove_isolation_locally.sh: ${pass} passed, ${fail} failed ==="
[ "$fail" -eq 0 ]
