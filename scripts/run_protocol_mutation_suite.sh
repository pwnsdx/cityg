#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

: "${CITYG_CARGO_TARGET_SLOT:=protocol-mutation-suite}"
source "$SCRIPT_DIR/cargo_repo_env.sh"

cd "$REPO_ROOT"

cargo test --locked -p cityg-server \
  hostile_barrier_update_mutations_fail_closed_without_poisoning_restart_recovery \
  -- --nocapture
cargo test --locked -p cityg-server \
  hostile_barrier_update_byte_flip_sweep_fail_closed_without_poisoning_restart_recovery \
  -- --nocapture
cargo test --locked -p cityg-server \
  prop_authority_bound_refresh_bundle_mutations_fail_closed_without_poisoning_live_state \
  -- --nocapture
cargo test --locked -p cityg-server \
  malformed_refresh_concurrent_with_honest_join_preserves_live_state \
  -- --nocapture
cargo test --locked -p cityg-server \
  malformed_refresh_concurrent_with_honest_join_does_not_poison_restart_recovery \
  -- --nocapture

cargo test --locked -p cityg-api-client --lib \
  tests::barrier_resolve_revoked_occupancies_rejects_deployment_profile_manifest_mismatch_across_pages \
  -- --exact --nocapture
cargo test --locked -p cityg-api-client --lib \
  tests::barrier_resolve_join_occupancies_since_rejects_global_history_attestation_mismatch_across_pages \
  -- --exact --nocapture
cargo test --locked -p cityg-api-client --lib \
  tests::barrier_fetch_public_tree_rejects_deployment_profile_manifest_mismatch_across_pages \
  -- --exact --nocapture

cargo test --locked -p cityg-gui --bin cityg-gui \
  native::tests::epoch_sync_rejects_barrier_bundle_history_commitment_mismatch \
  --features native-app -- --exact --nocapture
cargo test --locked -p cityg-gui --bin cityg-gui \
  native::tests::epoch_sync_rejects_barrier_bundle_fs_policy_version_mismatch \
  --features native-app -- --exact --nocapture
cargo test --locked -p cityg-gui --bin cityg-gui \
  native::tests::perform_fetch_rejects_sender_leaf_spoofing_with_mismatched_public_key \
  --features native-app -- --exact --nocapture
