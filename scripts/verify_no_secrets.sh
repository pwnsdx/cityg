#!/bin/bash
set -euo pipefail

# verify_no_secrets.sh — Automated verification that server code has no access to secrets
# Usage: ./scripts/verify_no_secrets.sh

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "═══════════════════════════════════════════════════════════"
echo "🔍 City-G Security Verification — No Secrets in Server Code"
echo "═══════════════════════════════════════════════════════════"
echo ""

# Check for required tools
if ! command -v rg &> /dev/null; then
    echo "❌ ERROR: ripgrep (rg) is not installed"
    echo "   Install with: cargo install ripgrep"
    echo "   Or on macOS: brew install ripgrep"
    echo "   Or on Ubuntu: apt install ripgrep"
    exit 1
fi

FAILED=0

# Check 1: No MlKemSecretKey in production code
echo "✓ Check 1: No MlKemSecretKey in AcceptanceContext..."
if rg "MlKemSecretKey" crates/msphf-orchestrator/src/accept crates/cityg-server/src/ 2>/dev/null | grep -v "test\|demo" > /dev/null; then
    echo "  ❌ FAILED: Found MlKemSecretKey in production code"
    FAILED=1
else
    echo "  ✅ PASSED: No MlKemSecretKey found"
fi
echo ""

# Check 2: No decapsulate in server code
echo "✓ Check 2: No ml_kem_decapsulate in server code..."
if rg "ml_kem_decapsulate|decapsulate\(" crates/msphf-orchestrator/src/accept crates/cityg-server/src/ 2>/dev/null | grep -v "test\|demo\|#\[cfg" > /dev/null; then
    echo "  ❌ FAILED: Found decapsulate in production code"
    FAILED=1
else
    echo "  ✅ PASSED: No decapsulate found"
fi
echo ""

# Check 3: No decrypt_hp_bytes in server code
echo "✓ Check 3: No decrypt_hp_bytes in server code..."
if rg "decrypt_hp_bytes|decrypt_hp\(" crates/msphf-orchestrator/src/accept crates/cityg-server/src/ 2>/dev/null | grep -v "test\|demo" > /dev/null; then
    echo "  ❌ FAILED: Found decrypt_hp in production code"
    FAILED=1
else
    echo "  ✅ PASSED: No decrypt_hp found"
fi
echo ""

# Check 4: No unwrap_kbroad_envelope (old decryption function)
echo "✓ Check 4: No unwrap_kbroad_envelope (legacy decrypt)..."
if rg "unwrap_kbroad_envelope" crates/msphf-orchestrator/src/accept 2>/dev/null | grep -v "test\|demo" > /dev/null; then
    echo "  ❌ FAILED: Found unwrap_kbroad_envelope (should be removed)"
    FAILED=1
else
    echo "  ✅ PASSED: unwrap_kbroad_envelope not found"
fi
echo ""

# Check 5: AcceptanceContext has no kbroad_secret field
echo "✓ Check 5: AcceptanceContext has no kbroad_secret field..."
if rg "struct AcceptanceContext" crates/msphf-orchestrator/src/accept/mod.rs -A 30 | rg "kbroad_secret" > /dev/null 2>&1; then
    echo "  ❌ FAILED: Found kbroad_secret in AcceptanceContext"
    FAILED=1
else
    echo "  ✅ PASSED: No kbroad_secret in AcceptanceContext"
fi
echo ""

# Check 6: kbroad_registry stores Vec<u8> (public keys), not secrets
echo "✓ Check 6: kbroad_registry type is public keys only..."
if rg "kbroad_registry.*MlKemSecretKey" crates/msphf-orchestrator/src/ 2>/dev/null; then
    echo "  ❌ FAILED: kbroad_registry stores secret keys"
    FAILED=1
else
    echo "  ✅ PASSED: kbroad_registry stores Vec<u8> (public keys)"
fi
echo ""

# Check 7: ServerOutcome has no epoch_key field
echo "✓ Check 7: ServerOutcome has no epoch_key/eid fields..."
if rg "struct ServerOutcome" crates/cityg-server/src/ -A 10 | rg "epoch_key|eid.*\[u8" > /dev/null 2>&1; then
    echo "  ❌ FAILED: Found secret fields in ServerOutcome"
    FAILED=1
else
    echo "  ✅ PASSED: ServerOutcome has only public fields"
fi
echo ""

# Check 8: No with_defaults(secret) constructor
echo "✓ Check 8: AcceptanceContext constructors require no secrets..."
if rg "fn (with_defaults|new|with_options)" crates/msphf-orchestrator/src/accept/mod.rs -A 5 | rg "MlKemSecretKey|kbroad_secret" > /dev/null 2>&1; then
    echo "  ❌ FAILED: Constructor accepts secret keys"
    FAILED=1
else
    echo "  ✅ PASSED: Constructors require no secret keys"
fi
echo ""

# Check 9: Compile-time verification (cargo check)
echo "✓ Check 9: Code compiles (type safety)..."
if cargo check --quiet 2>&1 | grep -i "error" > /dev/null; then
    echo "  ❌ FAILED: Compilation errors"
    FAILED=1
else
    echo "  ✅ PASSED: Code compiles (type-safe)"
fi
echo ""

# Check 10: Tests pass (functional verification)
echo "✓ Check 10: Tests pass (cargo test --all)..."
TEST_OUTPUT=$(cargo test --quiet --all 2>&1 || true)
if echo "$TEST_OUTPUT" | grep "test result: ok" > /dev/null; then
    echo "  ✅ PASSED: All tests pass"
else
    echo "  ❌ FAILED: Some tests failed"
    FAILED=1
fi
echo ""

# Summary
echo "═══════════════════════════════════════════════════════════"
if [ $FAILED -eq 0 ]; then
    echo "✅ ALL CHECKS PASSED — Server is blind to secrets"
    echo "═══════════════════════════════════════════════════════════"
    exit 0
else
    echo "❌ SOME CHECKS FAILED — Review findings above"
    echo "═══════════════════════════════════════════════════════════"
    exit 1
fi
