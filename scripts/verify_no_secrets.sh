#!/bin/bash
set -euo pipefail

# verify_no_secrets.sh — syntactic guardrail: the delivery service must not
# touch group secrets.
# Usage: ./scripts/verify_no_secrets.sh [--no-build]
#
# The server-side crates (cityg-server, cityg-runtime, cityg-api,
# cityg-worker) run cityg_core::ledger::GroupLedger, which verifies commits
# against public state only. They must never use the member-side types that
# hold secrets: GroupSession, DeviceIdentity, the key schedule, KEM
# decapsulation or message decryption. Test code (tests.rs files and
# everything after the first #[cfg(test)] of a file) builds members as
# fixtures and is not scanned.
#
# This is a grep-based check, not a proof: the protocol argument is in
# docs/specs.md (server blindness) and docs/formal/.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BUILD=1
if [[ "${1:-}" == "--no-build" ]]; then
    BUILD=0
fi

SERVER_CRATES=(
    crates/cityg-server/src
    crates/cityg-runtime/src
    crates/cityg-api/src
    crates/cityg-worker/src
)
FORBIDDEN='GroupSession|DeviceIdentity|key_schedule|KeySchedule|decapsulate|DecapsulationKey|SecretKey|\.decrypt\(|decrypt_|epoch_secret|init_secret|encryption_secret|export_secret'

echo "═══════════════════════════════════════════════════════════"
echo "City-G guardrail — the delivery service holds no group secret"
echo "═══════════════════════════════════════════════════════════"
echo ""

FAILED=0

# Production part of a Rust file: up to its first #[cfg(test)].
production_lines() {
    awk '/^[[:space:]]*#\[cfg\(test\)\]/ { exit } { printf "%s:%d:%s\n", FILENAME, FNR, $0 }' "$1"
}

echo "Check 1: no secret-holding types in server-side production code..."
HITS=""
while IFS= read -r file; do
    case "$file" in
        */tests.rs | */tests/*) continue ;;
    esac
    found="$(production_lines "$file" | grep -E "$FORBIDDEN" || true)"
    if [[ -n "$found" ]]; then
        HITS+="$found"$'\n'
    fi
done < <(find "${SERVER_CRATES[@]}" -name '*.rs' | sort)
if [[ -n "$HITS" ]]; then
    echo "  FAILED:"
    printf '%s' "$HITS" | sed 's/^/    /'
    FAILED=1
else
    echo "  PASSED"
fi
echo ""

echo "Check 2: the ledger verifies with public state only..."
LEDGER=crates/cityg-core/src/ledger.rs
found="$(production_lines "$LEDGER" | grep -E "$FORBIDDEN|use crate::(key_schedule|kem)" || true)"
if [[ -n "$found" ]]; then
    echo "  FAILED:"
    printf '%s\n' "$found" | sed 's/^/    /'
    FAILED=1
else
    echo "  PASSED"
fi
echo ""

echo "Check 3: server-side crates do not depend on member-side crates..."
for manifest in crates/cityg-server/Cargo.toml crates/cityg-runtime/Cargo.toml \
    crates/cityg-api/Cargo.toml crates/cityg-worker/Cargo.toml; do
    # Dev-dependencies (test fixtures) are allowed.
    if sed '/^\[dev-dependencies\]/,$d' "$manifest" | grep -q "cityg-api-client"; then
        echo "  FAILED: $manifest depends on cityg-api-client"
        FAILED=1
    fi
done
if [[ $FAILED -eq 0 ]]; then
    echo "  PASSED"
fi
echo ""

if [[ $BUILD -eq 1 ]]; then
    echo "Check 4: the server-side crates build and their tests pass..."
    LOG="$(mktemp)"
    if cargo test --locked --quiet -p cityg-server -p cityg-runtime -p cityg-api -p cityg-worker > "$LOG" 2>&1; then
        echo "  PASSED"
    else
        echo "  FAILED:"
        tail -n 80 "$LOG"
        FAILED=1
    fi
    rm -f "$LOG"
    echo ""
fi

echo "═══════════════════════════════════════════════════════════"
if [[ $FAILED -eq 0 ]]; then
    echo "ALL CHECKS PASSED"
    exit 0
fi
echo "SOME CHECKS FAILED — review the findings above"
exit 1
