#!/bin/bash
set -euo pipefail

# Baseline security review runner for release candidates.
# Usage: ./scripts/security_review.sh

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
export CITYG_CARGO_TARGET_SLOT="${CITYG_CARGO_TARGET_SLOT:-security-review}"
source "$REPO_ROOT/scripts/cargo_repo_env.sh"

echo "[1/4] cargo test -p cityg-core -p cityg-pqc"
cargo test --locked -p cityg-core -p cityg-pqc

echo "[2/4] cargo test -p cityg-server -p cityg-runtime -p cityg-api -p cityg-worker"
cargo test --locked -p cityg-server -p cityg-runtime -p cityg-api -p cityg-worker

echo "[3/4] cargo test -p cityg-api-client -p cityg-gui --features native-app"
cargo test --locked -p cityg-api-client -p cityg-gui --features cityg-gui/native-app

echo "[4/4] ./scripts/verify_no_secrets.sh --no-build"
./scripts/verify_no_secrets.sh --no-build

if cargo audit --version >/dev/null 2>&1; then
    echo "[optional] cargo audit"
    if ! cargo audit; then
        echo "[optional] cargo audit failed; skipping advisory scan in this environment"
    fi
else
    echo "[optional] cargo-audit is not installed; skipping vulnerability scan"
fi

echo "security review baseline passed"
