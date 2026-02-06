#!/bin/bash
set -euo pipefail

# Baseline security review runner for release candidates.
# Usage: ./scripts/security_review.sh

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "[1/5] cargo test -p cityg-server"
cargo test -p cityg-server

echo "[2/5] cargo test -p cityg-api"
cargo test -p cityg-api

echo "[3/5] cargo test -p cityg-gui --features native-app"
cargo test -p cityg-gui --features native-app

echo "[4/5] cargo test -p msphf-orchestrator"
cargo test -p msphf-orchestrator

echo "[5/5] ./scripts/verify_no_secrets.sh"
./scripts/verify_no_secrets.sh

if cargo audit --version >/dev/null 2>&1; then
    echo "[optional] cargo audit"
    cargo audit
else
    echo "[optional] cargo-audit is not installed; skipping vulnerability scan"
fi

echo "security review baseline passed"
