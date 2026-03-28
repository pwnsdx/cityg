#!/usr/bin/env bash

# shellcheck shell=bash

if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
  _cityg_cargo_env_source="${BASH_SOURCE[0]}"
elif [[ -n "${ZSH_VERSION:-}" ]]; then
  _cityg_cargo_env_source="${(%):-%N}"
else
  _cityg_cargo_env_source="$0"
fi

CITYG_REPO_ROOT="${CITYG_REPO_ROOT:-$(cd "$(dirname "$_cityg_cargo_env_source")/.." && pwd)}"
CITYG_REPO_CARGO_HOME="${CITYG_REPO_CARGO_HOME:-$CITYG_REPO_ROOT/.cargo-home}"
CITYG_REPO_HOME="${CITYG_REPO_HOME:-$CITYG_REPO_ROOT/.home}"
CITYG_REPO_TARGET_ROOT="${CITYG_REPO_TARGET_ROOT:-$CITYG_REPO_ROOT/.cargo-target}"
CITYG_CARGO_TARGET_SLOT="${CITYG_CARGO_TARGET_SLOT:-manual}"

mkdir -p "$CITYG_REPO_CARGO_HOME"
mkdir -p "$CITYG_REPO_HOME"
mkdir -p "$CITYG_REPO_TARGET_ROOT/$CITYG_CARGO_TARGET_SLOT"

if [[ ! -f "$CITYG_REPO_CARGO_HOME/config.toml" ]]; then
  cat >"$CITYG_REPO_CARGO_HOME/config.toml" <<'EOF'
[registries.crates-io]
protocol = "sparse"
EOF
fi

if [[ "${CITYG_PRESERVE_HOME:-0}" != "1" ]]; then
  export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
  export HOME="$CITYG_REPO_HOME"
fi

export CARGO_HOME="$CITYG_REPO_CARGO_HOME"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$CITYG_REPO_TARGET_ROOT/$CITYG_CARGO_TARGET_SLOT}"

# Native GUI/test flows exercise deep barrier recovery + protobuf/crypto stacks
# and exceed the default per-thread stack on some hosts. Keep a repo-local floor
# unless the caller explicitly overrides it.
export RUST_MIN_STACK="${RUST_MIN_STACK:-67108864}"

unset _cityg_cargo_env_source
