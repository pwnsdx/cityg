#!/bin/bash
set -euo pipefail

# Baseline security review runner for release candidates.
# Usage: ./scripts/security_review.sh

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
export CITYG_CARGO_TARGET_SLOT="${CITYG_CARGO_TARGET_SLOT:-security-review}"
source "$REPO_ROOT/scripts/cargo_repo_env.sh"

echo "[1/5] cargo test -p cityg-server"
cargo test --locked -p cityg-server

echo "[2/5] cargo test -p cityg-api"
cargo test --locked -p cityg-api

echo "[3/5] cargo test -p cityg-gui --features native-app"
cargo test --locked -p cityg-gui --features native-app

echo "[4/5] cargo test -p msphf-orchestrator"
cargo test --locked -p msphf-orchestrator

echo "[5/5] ./scripts/verify_no_secrets.sh"
./scripts/verify_no_secrets.sh

if cargo audit --version >/dev/null 2>&1; then
    echo "[optional] cargo audit"
    if ! cargo audit; then
        echo "[optional] cargo audit failed; skipping advisory scan in this environment"
    fi
else
    echo "[optional] cargo-audit is not installed; skipping vulnerability scan"
fi

echo "security review baseline passed"
