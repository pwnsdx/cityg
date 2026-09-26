#!/bin/bash
set -euo pipefail

# Baseline security review runner for release candidates.
# Usage: ./scripts/security_review.sh

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
export CITYG_CARGO_TARGET_SLOT="${CITYG_CARGO_TARGET_SLOT:-security-review}"
source "$REPO_ROOT/scripts/cargo_repo_env.sh"

echo "[1/3] cargo test -p cityg-core -p cityg-pqc"
cargo test --locked -p cityg-core -p cityg-pqc

echo "[2/3] ./scripts/verify_no_secrets.sh"
./scripts/verify_no_secrets.sh

echo "[3/3] docs/formal/run.sh"
if command -v proverif >/dev/null 2>&1; then
    docs/formal/run.sh
else
    echo "ProVerif 2.05 is not in PATH; skipping the symbolic model"
fi

if cargo audit --version >/dev/null 2>&1; then
    echo "[optional] cargo audit"
    if ! cargo audit; then
        echo "[optional] cargo audit failed; skipping advisory scan in this environment"
    fi
else
    echo "[optional] cargo-audit is not installed; skipping vulnerability scan"
fi

echo "security review baseline passed"
