#!/usr/bin/env bash
# Collect hardware and toolchain information for Annex V evidence records.

set -euo pipefail

{
  echo "# System Information"
  echo
  echo "## OS / Kernel"
  uname -a
  echo
  echo "## CPU"
  lscpu
  echo
  echo "## Memory"
  free -h
  echo
  echo "## Valgrind"
  valgrind --version || true
  echo
  echo "## Rust Toolchains"
  rustup show
} > docs/evidence/system-info.md

echo "System information written to docs/evidence/system-info.md"
