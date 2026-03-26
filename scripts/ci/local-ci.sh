#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"
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

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $cmd"
    exit 1
  fi
}

platform_cache_key() {
  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m | tr '[:upper:]' '[:lower:]')"
  printf '%s-%s' "$os" "$arch"
}

setup_ci_tooling_path() {
  local cache_key tool_root
  cache_key="$(platform_cache_key)"
  tool_root="${CITYG_TOOL_ROOT:-$ROOT_DIR/.ci/tools/$cache_key}"
  mkdir -p "$tool_root/bin"
  export CITYG_TOOL_ROOT="$tool_root"
  export PATH="$tool_root/bin:$PATH"
}

ensure_linux_parity_image() {
  local image base_image
  image="${CITYG_LINUX_PARITY_IMAGE:-cityg/local-ci:rust-1.91-bookworm-v1}"
  base_image="${CITYG_LINUX_PARITY_BASE_IMAGE:-rust:1.91-bookworm}"

  if [[ "${CITYG_DISABLE_PARITY_IMAGE_CACHE:-0}" == "1" ]]; then
    LINUX_PARITY_IMAGE="$base_image"
    return
  fi

  if docker image inspect "$image" >/dev/null 2>&1; then
    LINUX_PARITY_IMAGE="$image"
    return
  fi

  log_step "Building cached Linux parity image: $image"
  docker build --platform linux/amd64 -t "$image" -f - . <<EOF
FROM $base_image
RUN apt-get update && apt-get install -y --no-install-recommends \\
    ca-certificates \\
    pkg-config \\
    libxcb1-dev \\
    libxkbcommon-dev \\
    libxkbcommon-x11-dev \\
    ripgrep \\
 && rm -rf /var/lib/apt/lists/*
RUN rustup component add rustfmt clippy
EOF
  LINUX_PARITY_IMAGE="$image"
}

run_linux_parity_container() {
  require_cmd docker
  local run_args=(
    --rm
    --platform linux/amd64
    -e CITYG_IN_CONTAINER=1
    -e CITYG_SKIP_DOCKER=1
    -e CITYG_SKIP_NEXTEST="${CITYG_SKIP_NEXTEST:-0}"
    -e CITYG_SKIP_GUI="${CITYG_SKIP_GUI:-0}"
    -e CITYG_FAST="${CITYG_FAST:-0}"
    -v "$ROOT_DIR:/workspace"
    -w /workspace
  )

  if [[ "${CITYG_DOCKER_CACHE_VOLUMES:-1}" == "1" ]]; then
    run_args+=(
      -v cityg-linux-ci-cargo-registry:/usr/local/cargo/registry
      -v cityg-linux-ci-cargo-git:/usr/local/cargo/git
    )
  fi

  if [[ "${CITYG_DISABLE_PARITY_IMAGE_CACHE:-0}" == "1" ]]; then
    local base_image
    base_image="${CITYG_LINUX_PARITY_BASE_IMAGE:-rust:1.91-bookworm}"
    log_step "Running Linux parity checks in $base_image container"
    docker run "${run_args[@]}" "$base_image" bash -lc '
      set -euo pipefail
      export PATH="$CARGO_HOME/bin:$PATH"
      apt-get update
      apt-get install -y --no-install-recommends \
        ca-certificates \
        pkg-config \
        libxcb1-dev \
        libxkbcommon-dev \
        libxkbcommon-x11-dev \
        ripgrep
      rustup component add rustfmt clippy
      ./scripts/ci/local-ci.sh
    '
    return
  fi

  ensure_linux_parity_image
  log_step "Running Linux parity checks in $LINUX_PARITY_IMAGE container"
  docker run "${run_args[@]}" "$LINUX_PARITY_IMAGE" bash -lc '
    set -euo pipefail
    export PATH="$CARGO_HOME/bin:$PATH"
    ./scripts/ci/local-ci.sh
  '
}

ensure_nextest() {
  if [[ "${CITYG_SKIP_NEXTEST:-0}" == "1" ]]; then
    echo "Skipping nextest (CITYG_SKIP_NEXTEST=1)"
    return
  fi
  if cargo nextest --version >/dev/null 2>&1; then
    return
  fi
  echo "cargo-nextest not found; installing with cargo install cargo-nextest --locked --root $CITYG_TOOL_ROOT"
  cargo install cargo-nextest --locked --root "$CITYG_TOOL_ROOT"
}

ensure_gui_linux_deps() {
  if [[ "${CITYG_SKIP_GUI:-0}" == "1" ]]; then
    echo "Skipping GUI checks (CITYG_SKIP_GUI=1)"
    return
  fi
  if [[ "$(uname -s)" != "Linux" ]]; then
    return
  fi
  require_cmd pkg-config

  local missing=()
  for lib in xcb xkbcommon xkbcommon-x11; do
    if ! pkg-config --exists "$lib"; then
      missing+=("$lib")
    fi
  done

  if (( ${#missing[@]} > 0 )); then
    echo "ERROR: missing native GUI libraries: ${missing[*]}"
    echo "Install on Ubuntu/Debian:" \
      "sudo apt-get update && sudo apt-get install -y --no-install-recommends pkg-config libxcb1-dev libxkbcommon-dev libxkbcommon-x11-dev"
    exit 1
  fi
}

run_host_checks() {
  require_cmd cargo
  require_cmd rg
  setup_ci_tooling_path
  ensure_nextest
  ensure_gui_linux_deps

  log_step "cargo fmt --all -- --check"
  cargo fmt --all -- --check

  log_step "cargo clippy --workspace --all-features --all-targets --no-deps"
  cargo clippy --workspace --all-features --all-targets --no-deps --locked -- "${STRICT_CLIPPY[@]}"

  log_step "cargo check --workspace --all-targets"
  cargo check --workspace --all-targets --locked

  if [[ "${CITYG_SKIP_NEXTEST:-0}" != "1" ]]; then
    log_step "cargo nextest run --workspace --profile ci --exclude dudect-harness"
    cargo nextest run --workspace --profile ci --exclude dudect-harness --locked
  fi

  if [[ "${CITYG_FAST:-0}" == "1" ]]; then
    echo "Skipping secret scan, package tests and release builds (CITYG_FAST=1)"
    return
  fi

  log_step "./scripts/verify_no_secrets.sh"
  ./scripts/verify_no_secrets.sh

  log_step "cargo test -p cityg-server"
  cargo test -p cityg-server --locked

  log_step "cargo test -p cityg-api"
  cargo test -p cityg-api --locked

  if [[ "${CITYG_SKIP_GUI:-0}" != "1" ]]; then
    log_step "cargo test -p cityg-gui --features native-app"
    cargo test -p cityg-gui --features native-app --locked
  fi

  log_step "cargo build --release -p cityg-api"
  cargo build --release -p cityg-api --locked

  if [[ "${CITYG_SKIP_GUI:-0}" != "1" ]]; then
    log_step "cargo build --release -p cityg-gui --features native-app"
    cargo build --release -p cityg-gui --features native-app --locked
  fi
}

if [[ "${CITYG_IN_CONTAINER:-0}" != "1" && "${CITYG_HOST_ONLY:-0}" != "1" ]]; then
  if [[ "${CITYG_USE_CONTAINER:-0}" == "1" || "$(uname -s)" != "Linux" ]]; then
    run_linux_parity_container
    if [[ "${CITYG_SKIP_DOCKER:-0}" == "1" ]]; then
      echo "Skipping Docker artifact build (CITYG_SKIP_DOCKER=1)"
    else
      require_cmd docker
      log_step "docker build -f Dockerfile -t cityg-api:local-ci ."
      docker build -f Dockerfile -t cityg-api:local-ci .
    fi
    printf '\nAll local CI parity checks passed.\n'
    exit 0
  fi
fi

run_host_checks

if [[ "${CITYG_SKIP_DOCKER:-0}" == "1" ]]; then
  echo "Skipping Docker artifact build (CITYG_SKIP_DOCKER=1)"
else
  require_cmd docker
  log_step "docker build -f Dockerfile -t cityg-api:local-ci ."
  docker build -f Dockerfile -t cityg-api:local-ci .
fi

printf '\nAll local CI parity checks passed.\n'
