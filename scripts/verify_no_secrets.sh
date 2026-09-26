#!/bin/bash
set -euo pipefail

# verify_no_secrets.sh — syntactic guardrail: the delivery service and the
# public transition of a window never touch group secrets.
# Usage: ./scripts/verify_no_secrets.sh
#
# The modules of cityg-core that the delivery service and auditors run
# (ds, window, audit, packet, registry, smm, tree) check windows against
# public state only. Their production code (everything before the first
# #[cfg(test)] of a file) must never name a device identity, an X-Wing
# private key, an epoch secret, a member path, a node secret or a signing
# operation. Test code builds members as fixtures and is not scanned.
#
# This is a grep-based check, not a proof: the protocol argument is in
# docs/specs.md (section 18) and docs/formal/.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PUBLIC_MODULES=(
    crates/cityg-core/src/ds.rs
    crates/cityg-core/src/window.rs
    crates/cityg-core/src/audit.rs
    crates/cityg-core/src/packet.rs
    crates/cityg-core/src/registry.rs
    crates/cityg-core/src/smm.rs
    crates/cityg-core/src/tree.rs
)
FORBIDDEN='DeviceIdentity|EpochSecrets|KemSecret|MemberPath|decapsulate|node_key|fresh_secret|commit_secret|joiner_secret|init_secret|msg_secret|external_init|external_key|\bSecret\b|\.sign\(|sign_fields|crypto::unwrap|unwrap\(&'

echo "═══════════════════════════════════════════════════════════"
echo "City-G guardrail — the delivery service holds no group secret"
echo "═══════════════════════════════════════════════════════════"
echo ""

# Production part of a Rust file: up to its first #[cfg(test)].
production_lines() {
    awk '/^[[:space:]]*#\[cfg\(test\)\]/ { exit } { printf "%s:%d:%s\n", FILENAME, FNR, $0 }' "$1"
}

FAILED=0
echo "Check: no secret-holding type or derivation in the public modules..."
HITS=""
for file in "${PUBLIC_MODULES[@]}"; do
    if [[ ! -f "$file" ]]; then
        HITS+="$file: missing"$'\n'
        continue
    fi
    found="$(production_lines "$file" | grep -E "$FORBIDDEN" || true)"
    if [[ -n "$found" ]]; then
        HITS+="$found"$'\n'
    fi
done
if [[ -n "$HITS" ]]; then
    echo "  FAILED:"
    printf '%s' "$HITS" | sed 's/^/    /'
    FAILED=1
else
    echo "  PASSED"
fi
echo ""

echo "═══════════════════════════════════════════════════════════"
if [[ $FAILED -eq 0 ]]; then
    echo "ALL CHECKS PASSED"
    exit 0
fi
echo "SOME CHECKS FAILED — review the findings above"
exit 1
