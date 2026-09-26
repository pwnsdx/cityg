#!/usr/bin/env bash
# Local mirror of the CI checks: formatting, strict clippy, tests, the
# delivery-service guardrail and, when ProVerif is installed, the symbolic
# model and those of the research notes. Set CITYG_FAST=1 to stop after the
# tests.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"
export CITYG_CARGO_TARGET_SLOT="${CITYG_CARGO_TARGET_SLOT:-local-ci}"
source "$ROOT_DIR/scripts/cargo_repo_env.sh"

STRICT_CLIPPY=(
  -D warnings
  -A clippy::never_loop
  -D clippy::panic
  -D clippy::unwrap_used
  -D clippy::expect_used
  -D clippy::todo
  -D clippy::unimplemented
)

log_step() {
  printf '\n==> %s\n' "$1"
}

log_step "cargo fmt --all -- --check"
cargo fmt --all -- --check

log_step "cargo clippy --workspace --all-features --all-targets --no-deps"
cargo clippy --workspace --all-features --all-targets --no-deps --locked -- "${STRICT_CLIPPY[@]}"

if cargo nextest --version >/dev/null 2>&1; then
  log_step "cargo nextest run --workspace --profile ci"
  cargo nextest run --workspace --profile ci --locked
  log_step "cargo test --workspace --doc"
  cargo test --workspace --doc --locked
else
  log_step "cargo test --workspace (cargo-nextest not installed)"
  cargo test --workspace --locked
fi

if [[ "${CITYG_FAST:-0}" == "1" ]]; then
  printf '\nFast local checks passed (CITYG_FAST=1).\n'
  exit 0
fi

log_step "./scripts/verify_no_secrets.sh"
./scripts/verify_no_secrets.sh

log_step "scale test (release)"
cargo test -p cityg-core --release --locked --test scale -- --ignored --nocapture

if command -v proverif >/dev/null 2>&1; then
  log_step "docs/formal/run.sh"
  docs/formal/run.sh
  log_step "docs/research/formal-messages/run.sh"
  docs/research/formal-messages/run.sh
  log_step "docs/research/formal-parity/run.sh"
  docs/research/formal-parity/run.sh
else
  echo "Skipping the symbolic model (ProVerif 2.05 not in PATH)"
fi

printf '\nAll local CI checks passed.\n'
