#!/usr/bin/env bash
# Hostile-input suite: tampered commits, update paths, signatures and
# encodings, forged senders, forks, admissions without authority, and the
# delivery service's handling of malformed requests.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

: "${CITYG_CARGO_TARGET_SLOT:=protocol-mutation-suite}"
source "$SCRIPT_DIR/cargo_repo_env.sh"

cd "$REPO_ROOT"

cargo test --locked -p cityg-core -- \
  tampering_is_detected \
  tampered_paths_are_rejected \
  registry_and_signature_are_enforced \
  signatures_and_encodings_are_checked \
  a_member_cannot_speak_for_another \
  forks_and_foreign_commits_are_rejected \
  joins_need_an_admission_from_a_current_admin \
  a_vacant_group_cannot_be_taken_over_with_a_stale_invite \
  decode_requires_deterministic_bytes \
  rejects_duplicate_keys_floats_and_tags \
  --nocapture
cargo test --locked -p cityg-server -p cityg-runtime -- --nocapture
